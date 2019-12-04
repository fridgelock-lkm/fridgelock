#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pm.h>
#include <linux/platform_device.h>
#include <linux/sched/signal.h>
#include <linux/suspend.h>
#include <linux/umh.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/kallsyms.h>
#include <linux/page-flags.h>

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/writeback.h>
#include <linux/sysctl.h>
#include <linux/gfp.h>
#include <linux/device-mapper.h>
#include <linux/types.h>
#include <linux/pagevec.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>

#include "userspace_device.h"
#include "mm_crypt.h"

#define DRIVER_LICENSE "GPL"
#define DRIVER_AUTHOR  "Fabian Franzen <franzen@sec.in.tum.de>, Manuel Andreas <manuel.andreas@tum.de>, Manuel Huber <manuel.huber@aisec.fraunhofer.de>"
#define DRIVER_DESC    "RAM encryption module faking both a character device and a platform device driver"

#define USERSPACE_PATH "/usr/local/bin/fridgelock_stage1"

int enc_init(void);
void enc_cleanup(void);
int drop_caches(void);
int zero_free_pages(void);
static int late_suspend(struct device *dev);
static int notifier_hook(struct notifier_block *, unsigned long, void *);
static int early_resume(struct device *dev);

extern struct task_struct *suspend_task;
extern struct task_struct *resume_task;
static struct platform_device *pdev;

char *encdec_key = NULL;
unsigned int key_len = 0;

wait_queue_head_t resume_queue;
extern int resume_ready;
extern int resume_done;
extern int userspace_thawed;
extern int paths_received;

extern char *cryptdevice_paths;
extern unsigned short cryptdevice_paths_len;

char *userspace_argv[] = {USERSPACE_PATH, NULL};

struct pglist_data *(*first_online_pgdat_ptr)(void) = NULL;
struct zone *(*next_zone_ptr)(struct zone *zone) = NULL;
void (*ksys_sync_ptr)(void) = NULL;

static long zeroed_pages = 0;

static struct dev_pm_ops pops = {
	.prepare = late_suspend,
	.resume = early_resume,
};

static struct notifier_block pm_nb = {
	.notifier_call = notifier_hook,
};

static struct platform_driver ramenc_driver = {
	.driver = {
		.name = "ramenc_driver",
		.pm = &pops,
	}
};

static int notifier_hook(struct notifier_block *nb, unsigned long val, void *up)
{
	switch (val) {
	case PM_SUSPEND_PREPARE:

		/* Make userspace not freezable */
		/*
		for_each_process_thread(p, t) {
			int i;
			for (i = 0; i < ARRAY_SIZE(hot_processes); i++) {
				if (strcmp(t->comm, hot_processes[i]) == 0) {
					printk(KERN_INFO "[fridgelock] Skipping freeze of %s with pid %d\n", t->comm, t->pid);
					t->flags |= PF_NOFREEZE;
				}
			}

		}
		*/

		/* Sync filesystems so we can clear more cached data */
		ksys_sync_ptr = (void (*)(void))kallsyms_lookup_name("ksys_sync");
		if (ksys_sync_ptr == NULL) {
			return -1;
		}
		ksys_sync_ptr();

		printk(KERN_INFO "[fridgelock] Started resumer: %d\n", call_usermodehelper(userspace_argv[0], userspace_argv, NULL, UMH_WAIT_EXEC));
		//printk(KERN_INFO "[fridgelock] Started suspender: %d\n", call_usermodehelper(suspend_argv[0], suspend_argv, NULL, UMH_WAIT_EXEC));

		/* To avoid race conditions, wait for resumer to be up and waiting */

		printk(KERN_INFO "[fridgelock] Waiting for receiver to give us the paths..\n");
		wait_event_interruptible(resume_queue, (paths_received == 1));

		printk(KERN_INFO "[fridgelock] Resumer up\n");

		break;
	case PM_POST_SUSPEND:

		printk(KERN_INFO "[fridgelock] Userspace is now up again after resume and decryption\n");
		userspace_thawed = 1;
		wake_up_interruptible(&resume_queue);

		/* reset wait conditions */
		resume_ready = 0;
		resume_done = 0;
		paths_received = 0;
		//userspace_thawed = 0;

		printk(KERN_INFO "[fridgelock] Completely done with module\n");

		break;
	}

	return 0;
}

struct iv_essiv_private {
	struct crypto_shash *hash_tfm;
	u8 *salt;
};

struct iv_benbi_private {
	int shift;
};

#define LMK_SEED_SIZE 64 /* hash + 0 */
struct iv_lmk_private {
	struct crypto_shash *hash_tfm;
	u8 *seed;
};

#define TCW_WHITENING_SIZE 16
struct iv_tcw_private {
	struct crypto_shash *crc32_tfm;
	u8 *iv_seed;
	u8 *whitening;
};

struct iv_eboiv_private {
	struct crypto_cipher *tfm;
};

/*
 * The fields in here must be read only after initialization.
 */
struct crypt_config {
	struct dm_dev *dev;
	sector_t start;

	struct percpu_counter n_allocated_pages;

	struct workqueue_struct *io_queue;
	struct workqueue_struct *crypt_queue;

	spinlock_t write_thread_lock;
	struct task_struct *write_thread;
	struct rb_root write_tree;

	char *cipher;
	char *cipher_string;
	char *cipher_auth;
	char *key_string;

	const struct crypt_iv_operations *iv_gen_ops;
	union {
		struct iv_essiv_private essiv;
		struct iv_benbi_private benbi;
		struct iv_lmk_private lmk;
		struct iv_tcw_private tcw;
		struct iv_eboiv_private eboiv;
	} iv_gen_private;
	u64 iv_offset;
	unsigned int iv_size;
	unsigned short int sector_size;
	unsigned char sector_shift;

	/* ESSIV: struct crypto_cipher *essiv_tfm */
	void *iv_private;
	union {
		struct crypto_skcipher **tfms;
		struct crypto_aead **tfms_aead;
	} cipher_tfm;
	unsigned tfms_count;
	unsigned long cipher_flags;

	/*
	 * Layout of each crypto request:
	 *
	 *   struct skcipher_request
	 *      context
	 *      padding
	 *   struct dm_crypt_request
	 *      padding
	 *   IV
	 *
	 * The padding is added so that dm_crypt_request and the IV are
	 * correctly aligned.
	 */
	unsigned int dmreq_start;

	unsigned int per_bio_data_size;

	unsigned long flags;
	unsigned int key_size;
	unsigned int key_parts;      /* independent parts in key buffer */
	unsigned int key_extra_size; /* additional keys length */
	unsigned int key_mac_size;   /* MAC key size for authenc(...) */

	unsigned int integrity_tag_size;
	unsigned int integrity_iv_size;
	unsigned int on_disk_tag_size;

	/*
	 * pool for per bio private data, crypto requests,
	 * encryption requeusts/buffer pages and integrity tags
	 */
	unsigned tag_pool_max_sectors;
	mempool_t tag_pool;
	mempool_t req_pool;
	mempool_t page_pool;

	struct bio_set bs;
	struct mutex bio_alloc_lock;

	u8 *authenc_key; /* space for keys in authenc() format (if used) */
	u8 key[0];
};

static int crypt_message_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	// TODO: This relies on x86-64
	// TODO: Make this work for more than 1 partition
	struct dm_target* ti = (struct dm_target *) regs->di;
	unsigned argc = regs->si;
	char **argv = (char **) regs->dx;
	/*
	int i;
	for (i =0; i < argc; i++) {
		printk(KERN_INFO "Argv[%d]: '%s'\n", i, argv[i]);
	}
	*/

	if (encdec_key) {
		memset(encdec_key, '\x00', key_len);
		kfree(encdec_key);
		encdec_key = NULL;
		key_len = 0;
	}

	if (argc == 2 && !strcmp(argv[1], "wipe")) {
		// retrieve key from crypt_config
		struct crypt_config *cc = ti->private;
		key_len = cc->key_size;
		encdec_key = kmalloc(cc->key_size, GFP_KERNEL);
		memcpy(encdec_key, cc->key, cc->key_size);
	} else if (argc == 3 && !strcmp(argv[1], "set")) {
		// retrieve key from argv[2]
		char *hex_key = argv[2];
		key_len = strlen(hex_key) / 2;
		encdec_key = kmalloc(key_len, GFP_KERNEL);
		hex2bin(encdec_key, hex_key, key_len);
	}

	// Might contain bad chars...
	/*
	for (i = 0; i < key_len; i++) {
		printk(KERN_INFO "New key is: '%c'\n", encdec_key[i]);
	}
	*/
	
	return 0;
}

#define DISABLE_W_PROTECTED_MEMORY \
    do { \
        preempt_disable(); \
        write_cr0(read_cr0() & (~ 0x10000)); \
    } while (0);
#define ENABLE_W_PROTECTED_MEMORY \
    do { \
        preempt_enable(); \
        write_cr0(read_cr0() | 0x10000); \
    } while (0);

static int invalidate_inode_page_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	//TODO: This relies on x86-64
	struct page *page = (struct page*) regs->di;
	struct address_space *mapping = page_mapping(page);
	*((void**)&ri->data) = page;
	if (!mapping) {
		//printk(KERN_INFO "[fridgelock] Skipping page without address_space\n");
		return 0;
	}
	if ((page->flags & (1 << PG_dirty)) || (page->flags & (1 << PG_writeback))) {
		//printk(KERN_INFO "[fridgelock] Skipping dirty / writeback page\n");
		return 0;
	}
	if (page_mapped(page)) {
		//printk(KERN_INFO "[fridgelock] Skipping mapped page\n");
		return 0;
	}
	void *addr = kmap_atomic(page);
	// TODO: huge pages 
	if (addr) {
		//printk(KERN_INFO "Memsetting page with flags: %lx\n", page->flags);
		//printk(KERN_INFO "Mapped addr:: %px\n", addr);
		DISABLE_W_PROTECTED_MEMORY
		zeroed_pages++;
		memset(addr, '\0', PAGE_SIZE);
		ENABLE_W_PROTECTED_MEMORY
	}
	kunmap_atomic(addr);
	return 0;
}

static int invalidate_inode_page_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
	// We are called with locks to page held
	//struct page *page = (struct page*) ri->data;

	// Check if the page was really invalidated
	if(regs_return_value(regs) == 0) {
		//printk(KERN_INFO "TODO: BUG()?\n");
	}
	return 0;
}

/*
 * Evict all not needed pages (e.g. containing files from disk) from the page cache
 * and overwrite them with zeros. We will instrument the invalidate_inode_page
 * function, which will get called during the freeing process.
 */
int drop_caches(void) {
	struct file* drop_file;
	char op;
	loff_t off;
	int ret;

	struct kretprobe rp = {
		.handler	= invalidate_inode_page_ret,
		.entry_handler  = invalidate_inode_page_entry,
		.kp.symbol_name = "invalidate_inode_page",
		.data_size = sizeof(struct page*),
		.maxactive = 0
	};

	ret = register_kretprobe(&rp);
	if(ret < 0) {
		pr_err("[fridgelock] Couldn't register retprobe");
		return -1;
	}

	drop_file = filp_open("/proc/sys/vm/drop_caches", O_WRONLY, 0);
	if (drop_file == NULL) {
		printk(KERN_INFO "[fridgelock] Failed opening the drop caches file\n");
		return -1;
	}

	/* drop slab cache */
	op = '2';
	off = 0;
	if (kernel_write(drop_file, &op, sizeof(op), &off) != sizeof(op)) {
		printk(KERN_INFO "[fridgelock] Failed writing to the drop caches file\n");
		return -1;
	}
	unregister_kretprobe(&rp);

	//Close file again	
	filp_close(drop_file, NULL);
	return 0;
}

int zero_free_pages(void) {
	/* walk free pages */
	unsigned long flags, order, t;
	struct list_head *l;
	struct page *page;
	struct zone *zone;
	void *addr;

	first_online_pgdat_ptr = (struct pglist_data *(*)(void)) kallsyms_lookup_name("first_online_pgdat");
	next_zone_ptr = (struct zone *(*)(struct zone *zone)) kallsyms_lookup_name("next_zone");

	if(first_online_pgdat_ptr == NULL || next_zone_ptr == NULL)
		return -1;

	for (zone = (first_online_pgdat_ptr())->node_zones; zone; zone = next_zone_ptr(zone)) {
		spin_lock_irqsave(&zone->lock, flags);
		for_each_migratetype_order(order, t) {
			//printk(KERN_INFO "Processing this many free pages: %ld\n", zone->free_area[order].nr_free);
			list_for_each(l, &zone->free_area[order].free_list[t]) {
				if (l == NULL) {
					break;
				}
				/* clear page */
				page = list_entry(l, struct page, lru);
				addr = kmap(page);
				/* TODO: huge pages */
				zeroed_pages++;
				memset(addr, '\0', PAGE_SIZE);
				kunmap(page);

			}
		}
		spin_unlock_irqrestore(&zone->lock, flags);
	}

	return 0;
}

static int suspend_device(const char* dev_path)
{
	int (*dm_suspend_ptr)(struct mapped_device *, unsigned) = (int (*)(struct mapped_device*, unsigned)) kallsyms_lookup_name("dm_suspend");
	int (*crypt_message_ptr)(struct dm_target *, unsigned, char **, char *, unsigned) = (int (*)(struct dm_target *, unsigned, char **, char *, unsigned)) kallsyms_lookup_name("crypt_message");
	struct dm_table *(*dm_get_live_table_ptr)(struct mapped_device *, int *) = (struct dm_table *(*)(struct mapped_device *, int *)) kallsyms_lookup_name("dm_get_live_table");
	void (*dm_put_live_table_ptr)(struct mapped_device *, int) = (void (*)(struct mapped_device *, int)) kallsyms_lookup_name("dm_put_live_table");
	unsigned int (*dm_table_get_num_targets_ptr)(struct dm_table *) = (unsigned int (*)(struct dm_table *)) kallsyms_lookup_name("dm_table_get_num_targets");
	struct dm_target *(*dm_table_get_target_ptr)(struct dm_table *, unsigned int) = (struct dm_target *(*)(struct dm_table *, unsigned int)) kallsyms_lookup_name("dm_table_get_target");

	int i;
	int r = 0;
	char res;
	int srcu_idx;
	struct dm_target* target;
	struct dm_table* table;
	char* dummy_argv[] = {"key", "wipe"};
	dev_t dev = dm_get_dev_t(dev_path);
	struct mapped_device *md = dm_get_md(dev);

	if (dm_suspend_ptr == NULL) {
		printk(KERN_INFO "dm_suspend_ptr is NULL\n");
		r = -1;
		goto out;
	}

	if (md == NULL) {
		printk(KERN_INFO "mapped_device for path: %s is NULL\n", dev_path);
		r = -1;
		goto out;
	}


	r = dm_suspend_ptr(md, 0);
	if (r) {
		printk(KERN_INFO "dm_suspend failed: %d\n", r);
		goto md_out;
	}

	table = dm_get_live_table_ptr(md, &srcu_idx);
	if (table == NULL) {
		printk(KERN_INFO "dm_table* is NULL\n");
		goto md_out;
	}

	for (i = 0; i < dm_table_get_num_targets_ptr(table); i++) {
		target = dm_table_get_target_ptr(table, 0);
		if (target == NULL) {
			printk(KERN_INFO "dm_target* is NULL\n");
			goto table_out;
		}
		r = crypt_message_ptr(target, 2, dummy_argv, &res, 0);
		if (r) {
			printk(KERN_INFO "crypt_message failed: %d\n", r);
			goto table_out;
		}
	}

table_out:
	dm_put_live_table_ptr(md, srcu_idx);
md_out:
	dm_put(md);
out:

	return r;
}

static int suspend_devices(void)
{
	unsigned short idx = 0;
	while (idx < cryptdevice_paths_len) {
		const char *cur = cryptdevice_paths + idx;

		printk(KERN_INFO "[fridgelock] Suspending device: [%s]\n", cur);
		if (suspend_device(cur)) {
			printk(KERN_INFO "[fridgelock] suspend of device: [%s] failed\n", cur);
			return -1;
		}

		idx += strlen(cur) + 1;
	}

	return 0;
}

static int late_suspend(struct device *device)
{

	if (suspend_devices()) {
		printk(KERN_INFO "[fridgelock] suspend of devices failed\n");
		return -1;
	}

	printk(KERN_INFO "[fridgelock] Starting to drop caches\n");
	
	if (drop_caches()) {
		printk(KERN_INFO "[fridgelock] Dropping page caches failed\n");
		return -1;
	}

	printk(KERN_INFO "[fridgelock] Starting to zero free pages\n");

	if (zero_free_pages()) {
		printk(KERN_INFO "[fridgelock] Zeroing out free pages failed\n");
		return -1;
	}

	printk(KERN_INFO "[fridgelock] Zeroed out: %ld pages in total\n", zeroed_pages);
	zeroed_pages = 0;
	printk(KERN_INFO "[fridgelock] Starting to encrypt pages\n");

	if (encrypt_processes()) {
		printk(KERN_INFO "[fridgelock] Encrypting processes failed\n");
		return -1;
	}

	if (encdec_key) {
		memset(encdec_key, '\x00', key_len);
		kfree(encdec_key);
		encdec_key = NULL;
		key_len = 0;
	}


	return 0;
}

static int early_resume(struct device *dev)
{
	printk(KERN_INFO "[fridgelock] Just entered resume!\n");
	if (resume_task == NULL) {
		panic("[fridgelock] resume_task was NULL, something must be wrong with the resumer process\n");
	}
	resume_ready = 1;
	wake_up_interruptible(&resume_queue);
	printk(KERN_INFO "[fridgelock] Resume process should now be up again\n");
	/* Wait until userspace tells us to continue */
	wait_event_interruptible(resume_queue, (resume_done == 1));
	/* now decrypt the processes (TODO: with the received key) */
	if (decrypt_processes()) {
		printk(KERN_INFO "[fridgelock] Decrypting processes failed\n");
	}
	return 0;
}


struct kretprobe rp = {
	.entry_handler  = crypt_message_entry,
	.kp.symbol_name = "crypt_message",
	.maxactive = 0
};

int __init enc_init(void)
{
	int ret;
	if (userspace_device_init()) {
		printk(KERN_INFO "Failed to initialize userspace driver\n");
		goto error;
	}

	if (platform_driver_register(&ramenc_driver)) {
		printk(KERN_INFO "[fridgelock] Failed to register suspend/resume hook driver");
		goto error;
	}

	pdev = platform_device_register_simple("ramenc_driver", -1, NULL, 0);
	if (IS_ERR(pdev)) {
		printk(KERN_INFO "[fridgelock] Failed to register suspend/resume platform device");
		goto error2;
	}

	if (resolve_functions()) {
		printk(KERN_INFO "[fridgelockrypt] Failed resolving adresses for non-exported symbols\n");
		goto error3;
	}


	ret = register_kretprobe(&rp);
	if(ret < 0) {
		pr_err("[fridgelock] Couldn't register retprobe");
		return -1;
	}

	register_pm_notifier(&pm_nb);

	init_waitqueue_head(&resume_queue);

	printk(KERN_INFO "[fridgelock] Successfully registered suspend/resume hook");

	return 0;

error3:
	platform_device_unregister(pdev);
error2:
	platform_driver_unregister(&ramenc_driver);
error:
	userspace_device_cleanup();
	return -1;
}

void __exit enc_cleanup(void)
{
	printk(KERN_INFO "[fridgelock] Cleaning up RAM encryption driver\n");

	unregister_kretprobe(&rp);
	unregister_pm_notifier(&pm_nb);
	platform_device_unregister(pdev);
	platform_driver_unregister(&ramenc_driver);
	userspace_device_cleanup();
}


module_init(enc_init);
module_exit(enc_cleanup);

MODULE_LICENSE(DRIVER_LICENSE);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
