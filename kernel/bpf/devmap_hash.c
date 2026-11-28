/* SPDX-License-Identifier: GPL-2.0 */
/* Hash-based device maps for the BPF userspace API. */
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/hash.h>
#include <linux/log2.h>
#include <linux/netdevice.h>
#include <linux/nsproxy.h>
#include <linux/rculist.h>
#include <linux/sched.h>
#include <linux/slab.h>

struct devmap_entry {
	struct hlist_node node;
	struct rcu_head rcu;
	struct net_device *dev;
	u32 key;
	u32 ifindex;
};

struct devmap_hash {
	struct bpf_map map;
	struct list_head list;
	u32 count;
	u32 bucket_bits;
	struct hlist_head buckets[];
};

static LIST_HEAD(devmaps);
static DEFINE_SPINLOCK(devmaps_lock);

static u32 devmap_bucket(const struct devmap_hash *table, u32 key)
{
	return hash_32(key, table->bucket_bits);
}

static struct devmap_entry *devmap_find(const struct devmap_hash *table, u32 key)
{
	struct devmap_entry *entry;

	hlist_for_each_entry_rcu(entry, &table->buckets[devmap_bucket(table, key)],
				 node)
		if (entry->key == key)
			return entry;
	return NULL;
}

static void devmap_entry_free(struct rcu_head *rcu)
{
	struct devmap_entry *entry = container_of(rcu, struct devmap_entry, rcu);

	dev_put(entry->dev);
	kfree(entry);
}

static void devmap_remove(struct devmap_hash *table, struct devmap_entry *entry)
{
	hlist_del_rcu(&entry->node);
	table->count--;
	call_rcu(&entry->rcu, devmap_entry_free);
}

static struct bpf_map *devmap_alloc(union bpf_attr *attr)
{
	struct devmap_hash *table;
	unsigned long flags;
	u64 size, cost;
	u32 buckets;
	int ret;

	if (!capable(CAP_NET_ADMIN))
		return ERR_PTR(-EPERM);
	if (!attr->max_entries || attr->max_entries > (1U << 30) ||
	    attr->key_size != sizeof(u32) || attr->value_size != sizeof(u32) ||
	    attr->map_flags & ~(BPF_F_RDONLY | BPF_F_WRONLY | BPF_F_RDONLY_PROG))
		return ERR_PTR(-EINVAL);

	buckets = max(2UL, roundup_pow_of_two(attr->max_entries));
	size = sizeof(*table) + (u64)buckets * sizeof(struct hlist_head);
	cost = size + (u64)attr->max_entries * sizeof(struct devmap_entry);
	if (cost >= U32_MAX - PAGE_SIZE)
		return ERR_PTR(-E2BIG);
	cost = PAGE_ALIGN(cost) >> PAGE_SHIFT;
	ret = bpf_map_precharge_memlock(cost);
	if (ret)
		return ERR_PTR(ret);

	table = bpf_map_area_alloc(size);
	if (!table)
		return ERR_PTR(-ENOMEM);

	table->map.map_type = attr->map_type;
	table->map.key_size = attr->key_size;
	table->map.value_size = attr->value_size;
	table->map.max_entries = attr->max_entries;
	table->map.pages = cost;
	table->bucket_bits = ilog2(buckets);
	spin_lock_irqsave(&devmaps_lock, flags);
	list_add(&table->list, &devmaps);
	spin_unlock_irqrestore(&devmaps_lock, flags);
	return &table->map;
}

static void devmap_free(struct bpf_map *map)
{
	struct devmap_hash *table = container_of(map, struct devmap_hash, map);
	unsigned long flags;
	u32 bucket;

	spin_lock_irqsave(&devmaps_lock, flags);
	list_del(&table->list);
	spin_unlock_irqrestore(&devmaps_lock, flags);
	synchronize_rcu();

	for (bucket = 0; bucket < (1U << table->bucket_bits); bucket++) {
		struct devmap_entry *entry;
		struct hlist_node *next;

		hlist_for_each_entry_safe(entry, next, &table->buckets[bucket], node)
			devmap_entry_free(&entry->rcu);
		cond_resched();
	}
	bpf_map_area_free(table);
}

static void *devmap_lookup(struct bpf_map *map, void *key)
{
	struct devmap_hash *table = container_of(map, struct devmap_hash, map);
	struct devmap_entry *entry = devmap_find(table, *(u32 *)key);

	return entry ? &entry->ifindex : NULL;
}

static int devmap_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct devmap_hash *table = container_of(map, struct devmap_hash, map);
	struct devmap_entry *entry = key ? devmap_find(table, *(u32 *)key) : NULL;
	struct hlist_node *node;
	u32 bucket = 0;

	if (entry) {
		node = rcu_dereference_raw(hlist_next_rcu(&entry->node));
		if (node) {
			*(u32 *)next_key = hlist_entry(node, struct devmap_entry, node)->key;
			return 0;
		}
		bucket = devmap_bucket(table, entry->key) + 1;
	}
	while (bucket < (1U << table->bucket_bits)) {
		node = rcu_dereference_raw(hlist_first_rcu(&table->buckets[bucket++]));
		if (node) {
			*(u32 *)next_key = hlist_entry(node, struct devmap_entry, node)->key;
			return 0;
		}
	}
	return -ENOENT;
}

static int devmap_update(struct bpf_map *map, void *key, void *value, u64 mode)
{
	struct devmap_hash *table = container_of(map, struct devmap_hash, map);
	u32 ifindex = *(u32 *)value, index = *(u32 *)key;
	struct devmap_entry *entry, *old;
	struct net_device *dev;
	unsigned long flags;
	int ret = 0;

	if (mode > BPF_EXIST || !ifindex || ifindex > INT_MAX)
		return -EINVAL;
	entry = kmalloc(sizeof(*entry), GFP_ATOMIC | __GFP_NOWARN);
	if (!entry)
		return -ENOMEM;

	spin_lock_irqsave(&devmaps_lock, flags);
	old = devmap_find(table, index);
	if (old && mode == BPF_NOEXIST) {
		ret = -EEXIST;
		goto out;
	}
	if (!old && mode == BPF_EXIST) {
		ret = -ENOENT;
		goto out;
	}
	if (!old && table->count == map->max_entries) {
		ret = -E2BIG;
		goto out;
	}

	/*
	 * Serialize insertion with the unregister callback. The callback
	 * removes entries published before it acquires the same lock.
	 */
	dev = dev_get_by_index_rcu(current->nsproxy->net_ns, ifindex);
	if (!dev || dev->reg_state != NETREG_REGISTERED) {
		ret = -EINVAL;
		goto out;
	}
	dev_hold(dev);
	entry->dev = dev;
	entry->key = index;
	entry->ifindex = ifindex;

	if (old) {
		hlist_replace_rcu(&old->node, &entry->node);
		call_rcu(&old->rcu, devmap_entry_free);
	} else {
		hlist_add_head_rcu(&entry->node, &table->buckets[devmap_bucket(table, index)]);
		table->count++;
	}
out:
	spin_unlock_irqrestore(&devmaps_lock, flags);
	if (ret)
		kfree(entry);
	return ret;
}

static int devmap_delete(struct bpf_map *map, void *key)
{
	struct devmap_hash *table = container_of(map, struct devmap_hash, map);
	struct devmap_entry *entry;
	unsigned long flags;

	spin_lock_irqsave(&devmaps_lock, flags);
	entry = devmap_find(table, *(u32 *)key);
	if (entry)
		devmap_remove(table, entry);
	spin_unlock_irqrestore(&devmaps_lock, flags);
	return entry ? 0 : -ENOENT;
}

static int devmap_notify(struct notifier_block *notifier, unsigned long event,
			 void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct devmap_hash *table;
	unsigned long flags;

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;

	spin_lock_irqsave(&devmaps_lock, flags);
	list_for_each_entry(table, &devmaps, list) {
		u32 bucket;

		for (bucket = 0; bucket < (1U << table->bucket_bits); bucket++) {
			struct devmap_entry *entry;
			struct hlist_node *next;

			hlist_for_each_entry_safe(entry, next, &table->buckets[bucket], node)
				if (entry->dev == dev)
					devmap_remove(table, entry);
		}
	}
	spin_unlock_irqrestore(&devmaps_lock, flags);
	return NOTIFY_DONE;
}

static struct notifier_block devmap_notifier = {
	.notifier_call = devmap_notify,
};

static const struct bpf_map_ops devmap_ops = {
	.map_alloc = devmap_alloc,
	.map_free = devmap_free,
	.map_get_next_key = devmap_next_key,
	.map_lookup_elem = devmap_lookup,
	.map_update_elem = devmap_update,
	.map_delete_elem = devmap_delete,
};

static struct bpf_map_type_list devmap_type __read_mostly = {
	.ops = &devmap_ops,
	.type = BPF_MAP_TYPE_DEVMAP_HASH,
};

static int __init devmap_init(void)
{
	int ret = register_netdevice_notifier(&devmap_notifier);

	if (ret)
		return ret;
	bpf_register_map_type(&devmap_type);
	return 0;
}
late_initcall(devmap_init);
