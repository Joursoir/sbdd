#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/bio.h>
#include <linux/bvec.h>
#include <linux/init.h>
#include <linux/wait.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/numa.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/moduleparam.h>
#include <linux/spinlock_types.h>

#define SBDD_NAME              "sbdd"
#define SBDD_BDEV_MODE         (FMODE_READ | FMODE_WRITE)
#define MAX_RAID_DISK          6

struct raiddisk {
	sector_t                capacity;
	unsigned int            max_sectors;
	struct block_device     *bdev;
};

struct sbdd {
	wait_queue_head_t       exitwait;
	spinlock_t              datalock;
	atomic_t                deleting;
	atomic_t                refs_cnt;
	sector_t                capacity;
	struct gendisk          *gd;
	struct request_queue    *q;
	struct block_device     *bdev;
	struct raiddisk         disks[MAX_RAID_DISK];
};

static struct sbdd      __sbdd;
static int              __sbdd_major = 0;
static struct bio_set   __sbdd_bio_set;
static char             *__sbdd_disk = "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00001";

static char *__sbdd_disklist[MAX_RAID_DISK] = { NULL };
static unsigned int __sbdd_diskcount;

struct sbdd_io_bio {
	struct bio              *original_bio;
};

static void io_end_bio(struct bio *bio)
{
	struct sbdd_io_bio *io_bio = bio->bi_private;

	pr_debug("I/O operation is completed\n");

	io_bio->original_bio->bi_status = bio->bi_status;
	bio_endio(io_bio->original_bio);
	bio_put(bio);
	kfree(io_bio);

	if (atomic_dec_and_test(&__sbdd.refs_cnt))
		wake_up(&__sbdd.exitwait);
}

/*static sector_t sbdd_xfer(struct bio_vec* bvec, sector_t pos, int dir)
{
	void *buff = page_address(bvec->bv_page) + bvec->bv_offset;
	sector_t len = bvec->bv_len >> SBDD_SECTOR_SHIFT;
	size_t offset;
	size_t nbytes;

	if (pos + len > __sbdd.capacity)
		len = __sbdd.capacity - pos;

	offset = pos << SBDD_SECTOR_SHIFT;
	nbytes = len << SBDD_SECTOR_SHIFT;

	spin_lock(&__sbdd.datalock);

	if (dir)
		memcpy(__sbdd.data + offset, buff, nbytes);
	else
		memcpy(buff, __sbdd.data + offset, nbytes);

	spin_unlock(&__sbdd.datalock);

	pr_debug("pos=%6llu len=%4llu %s\n", pos, len, dir ? "written" : "read");

	return len;
}*/

static void sbdd_xfer_bio(struct bio *bio)
{
	struct bio *bio_clone;
	struct sbdd_io_bio *io_bio;

	io_bio = kmalloc(sizeof(*io_bio), GFP_KERNEL);
	if (!io_bio) {
		pr_err("unable to allocate space for struct io_bio\n");
		return;
	}
	io_bio->original_bio = bio;

	bio_clone = bio_clone_fast(bio, GFP_NOIO, &__sbdd_bio_set);
	if (!bio_clone) {
		pr_err("unable to clone bio\n");
		kfree(io_bio);
		return;
	}

	bio_set_dev(bio_clone, __sbdd.bdev);
	bio_clone->bi_opf |= REQ_PREFLUSH | REQ_FUA;
	bio_clone->bi_private = io_bio;
	bio_clone->bi_end_io = io_end_bio;

	pr_debug("submitting bio...\n");
	submit_bio(bio_clone);
}

static blk_qc_t sbdd_make_request(struct request_queue *q, struct bio *bio)
{
	if (atomic_read(&__sbdd.deleting)) {
		pr_err("unable to process bio while deleting\n");
		bio_io_error(bio);
		return BLK_STS_IOERR;
	}

	atomic_inc(&__sbdd.refs_cnt);

	sbdd_xfer_bio(bio);

	return BLK_STS_OK;
}

/*
There are no read or write operations. These operations are performed by
the request() function associated with the request queue of the disk.
*/
static struct block_device_operations const __sbdd_bdev_ops = {
	.owner = THIS_MODULE,
};

static int sbdd_create(void)
{
	int ret = 0;
	int disk = 0;
	unsigned short lblock_size;
	unsigned int max_sectors;
	sector_t totalsize = 0;

	ret = bioset_init(&__sbdd_bio_set, BIO_POOL_SIZE, 0, 0);
	if (ret) {
		pr_err("create BIO set failed: %d\n", ret);
		return ret;
	}

	/*
	This call is somewhat redundant, but used anyways by tradition.
	The number is to be displayed in /proc/devices (0 for auto).
	*/
	pr_info("registering blkdev\n");
	__sbdd_major = register_blkdev(0, SBDD_NAME);
	if (__sbdd_major < 0) {
		pr_err("call register_blkdev() failed with %d\n", __sbdd_major);
		return -EBUSY;
	}

	memset(&__sbdd, 0, sizeof(struct sbdd));

	spin_lock_init(&__sbdd.datalock);
	init_waitqueue_head(&__sbdd.exitwait);

	pr_info("allocating queue\n");
	__sbdd.q = blk_alloc_queue(GFP_KERNEL);
	if (!__sbdd.q) {
		pr_err("call blk_alloc_queue() failed\n");
		return -EINVAL;
	}
	blk_queue_make_request(__sbdd.q, sbdd_make_request);

	/* A disk must have at least one minor */
	pr_info("allocating disk\n");
	__sbdd.gd = alloc_disk(1);

	/* Get a handle on the device */
	pr_info("opening %s\n", __sbdd_disk);
	__sbdd.bdev = blkdev_get_by_path(__sbdd_disk, SBDD_BDEV_MODE, THIS_MODULE);
	if (!__sbdd.bdev || IS_ERR(__sbdd.bdev)) {
		pr_err("blkdev_get_by_path(\"%s\") failed with %ld\n",
				__sbdd_disk, PTR_ERR(__sbdd.bdev));
		return -ENOENT;
	}

	for (disk = 0; disk < __sbdd_diskcount; disk++) {
		pr_info("[%d] opening %s", disk, __sbdd_disklist[disk]);

		__sbdd.disks[disk].bdev = blkdev_get_by_path(
				__sbdd_disklist[disk], SBDD_BDEV_MODE, THIS_MODULE);
		if (!__sbdd.disks[disk].bdev || IS_ERR(__sbdd.disks[disk].bdev)) {
			pr_err("blkdev_get_by_path(\"%s\") failed with %ld\n",
					__sbdd_disklist[disk],
					PTR_ERR(__sbdd.disks[disk].bdev));
			return -ENOENT;
		}

		/* Set up device characteristics */
		__sbdd.disks[disk].capacity = get_capacity(__sbdd.disks[disk].bdev->bd_disk);
		pr_info("[%d] capacity: %llu\n", disk, __sbdd.disks[disk].capacity);

		/* Get the smallest disk size in the set */
		if (disk == 0) {
			totalsize = __sbdd.disks[disk].capacity;
		} else {
			if (__sbdd.disks[disk].capacity < totalsize) {
				totalsize = __sbdd.disks[disk].capacity;
			}
		}
		__sbdd.disks[disk].max_sectors = queue_max_hw_sectors(bdev_get_queue(__sbdd.disks[disk].bdev));
		pr_info("[%d] max_sectors = %d\n", disk, __sbdd.disks[disk].max_sectors);
	}

	pr_info("%d disks processed\n", disk);

	disk--;
	/* `totalsize` equals the smallest disk size, simply multiple it out to disk count */
	totalsize *= __sbdd_diskcount;

	/* Configure queue */
	lblock_size = bdev_logical_block_size(__sbdd.bdev);
	blk_queue_logical_block_size(__sbdd.q, lblock_size);
	pr_info("\tlogical block size: %u\n", lblock_size);

	/* Configure gendisk */
	__sbdd.gd->queue = __sbdd.q;
	__sbdd.gd->major = __sbdd_major;
	__sbdd.gd->first_minor = 0;
	__sbdd.gd->fops = &__sbdd_bdev_ops;
	/* Represents name in /proc/partitions and /sys/block */
	scnprintf(__sbdd.gd->disk_name, DISK_NAME_LEN, SBDD_NAME);
	__sbdd.capacity = get_capacity(__sbdd.bdev->bd_disk);
	set_capacity(__sbdd.gd, __sbdd.capacity);
	pr_info("\tdevice capacity: %llu\n", __sbdd.capacity);

	max_sectors = queue_max_hw_sectors(bdev_get_queue(__sbdd.bdev));
	blk_queue_max_hw_sectors(__sbdd.q, max_sectors);
	pr_info("\tmax sectors: %u\n", max_sectors);

	/*
	Allocating gd does not make it available, add_disk() required.
	After this call, gd methods can be called at any time. Should not be
	called before the driver is fully initialized and ready to process reqs.
	*/
	pr_info("adding disk\n");
	add_disk(__sbdd.gd);

	return ret;
}

static void sbdd_delete(void)
{
	int disk;

	atomic_set(&__sbdd.deleting, 1);

	wait_event(__sbdd.exitwait, !atomic_read(&__sbdd.refs_cnt));

	/* gd will be removed only after the last reference put */
	if (__sbdd.gd) {
		pr_info("deleting disk\n");
		del_gendisk(__sbdd.gd);
	}

	if (__sbdd.bdev) {
		pr_info("release a handle on the %s\n", __sbdd_disk);
		blkdev_put(__sbdd.bdev, SBDD_BDEV_MODE);
	}

	for (disk = 0; disk < __sbdd_diskcount; disk++) {
		if (__sbdd.disks[disk].bdev) {
			pr_info("release a handle on the %s\n", __sbdd_disklist[disk]);
			blkdev_put(__sbdd.disks[disk].bdev, SBDD_BDEV_MODE);
		}
	}

	if (__sbdd.q) {
		pr_info("cleaning up queue\n");
		blk_cleanup_queue(__sbdd.q);
	}

	if (__sbdd.gd)
		put_disk(__sbdd.gd);

	memset(&__sbdd, 0, sizeof(struct sbdd));

	if (__sbdd_major > 0) {
		pr_info("unregistering blkdev\n");
		unregister_blkdev(__sbdd_major, SBDD_NAME);
		__sbdd_major = 0;
	}

	bioset_exit(&__sbdd_bio_set);
}

/*
Note __init is for the kernel to drop this function after
initialization complete making its memory available for other uses.
There is also __initdata note, same but used for variables.
*/
static int __init sbdd_init(void)
{
	int ret = 0;

	pr_info("starting initialization...\n");
	ret = sbdd_create();

	if (ret) {
		pr_warn("initialization failed\n");
		sbdd_delete();
	} else {
		pr_info("initialization complete\n");
	}

	return ret;
}

/*
Note __exit is for the compiler to place this code in a special ELF section.
Sometimes such functions are simply discarded (e.g. when module is built
directly into the kernel). There is also __exitdata note.
*/
static void __exit sbdd_exit(void)
{
	pr_info("exiting...\n");
	sbdd_delete();
	pr_info("exiting complete\n");
}

/* Called on module loading. Is mandatory. */
module_init(sbdd_init);

/* Called on module unloading. Unloading module is not allowed without it. */
module_exit(sbdd_exit);

/* Set desired target disk with insmod */
module_param_named(disk, __sbdd_disk, charp, S_IRUGO);

/* Set desired disk list with insmod */
module_param_array_named(disklist, __sbdd_disklist, charp, &__sbdd_diskcount, S_IRUGO);

/* Note for the kernel: a free license module. A warning will be outputted without it. */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple Block Device Driver");
