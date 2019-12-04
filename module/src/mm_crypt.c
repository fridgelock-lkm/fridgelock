/*
 * kernel/mm_crypt.c - Functions to encrypt/print/set descriptors/vmas/pages
 *
 */
#include <linux/interrupt.h>
#include <linux/suspend.h>
#include <linux/export.h>
#include <linux/syscalls.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/crypto.h>
#include <linux/sched.h>
#include <asm/tlbflush.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <crypto/skcipher.h>
#include <linux/crypto.h>
#include <linux/page-flags.h>
#include <linux/list.h>

#include "mm_crypt.h"

#ifdef CONFIG_RAMENC

struct enc_args {
	enc_process_t *current_proc;
	struct task_struct *t;
};

struct work_wrapper {
	struct work_struct real_work;
	struct enc_args enc_args;
};

struct encrypted_page {
	struct page* page;
	struct list_head list;
};

struct encrypted_process {
	struct task_struct *task;
	struct enc_process *enc_proc;
	struct work_wrapper* work;
	struct list_head list;
};

struct page_walk_data {
	enc_pgs_list_t **pgs_entry_list;
	long proc_total_enc_pgs;
};

LIST_HEAD(enc_processes_list);
LIST_HEAD(encrypted_page_list);

static DECLARE_COMPLETION(freezer_barrier);
int barrier_count = 0;
struct crypto_skcipher *tfm = NULL;
unsigned long thaw_start_time = 0;

static long long total_enc_pgs = 0;


static const char *(*arch_vma_name_ptr)(struct vm_area_struct *vma) = NULL;
static int (*ptep_set_access_flags_ptr)(struct vm_area_struct *vma,
	unsigned long address, pte_t *ptep, pte_t entry, int dirty) = NULL;
static int (*vma_is_stack_for_current_ptr)(struct vm_area_struct *vma) = NULL;
static struct anon_vma *(*page_get_anon_vma_ptr)(struct page *page);
static int (*page_mapped_in_vma_ptr)(struct page *page, struct vm_area_struct *vma);
static unsigned long (*KSTK_ESP_ptr)(struct task_struct *task);

//static struct page *(*_vm_normal_page_ptr)(struct vm_area_struct *vma, unsigned long addr,
//			     pte_t pte, bool with_public_device);
static struct vm_area_struct *(*vma_interval_tree_iter_first_ptr)(struct rb_root_cached *root,
				unsigned long start, unsigned long last);
static struct vm_area_struct *(*vma_interval_tree_iter_next_ptr)(struct vm_area_struct *node,
				unsigned long start, unsigned long last);

static int (*walk_page_vma_ptr)(struct vm_area_struct *vma, struct mm_walk *walk) = NULL;

#define RET_IF_NULL(arg) do {if((arg) == NULL) return -1;} while(0);
#define RESOLVE(name) do {if((name##_ptr = (void*) kallsyms_lookup_name(#name)) == NULL){ printk(KERN_ERR "Failed to resolve:" #name "\n"); return -1;}} while(0);

int resolve_functions(void)
{
	RESOLVE(arch_vma_name);
	RESOLVE(ptep_set_access_flags);
	RESOLVE(vma_is_stack_for_current);
	RESOLVE(page_get_anon_vma);
	RESOLVE(page_mapped_in_vma);
	//RESOLVE(_vm_normal_page);
	RESOLVE(vma_interval_tree_iter_first);
	RESOLVE(vma_interval_tree_iter_next);
	RESOLVE(KSTK_ESP);
	RESOLVE(walk_page_vma);

	return 0;
}

/* Check if the vma is being used as a stack by this task */
//TODO: This is supposedly prone to races
static int vma_is_stack_for_task(struct task_struct *t, struct vm_area_struct *vma)
{
	return (vma->vm_start <= KSTK_ESP_ptr(t) && vma->vm_end >= KSTK_ESP_ptr(t));
}

/*
 * freezer_enlist_vma - Enlist a selected VMA in the process structure
 *
 * @current_proc: process structure pointer to add the VMA entry in
 * @ref_mmap: pointer to the vm_area_struct that is being enlisted
 * @segment: segment type the VMA belongs to (meta data)
 *
 * return: 0 - successfully enlisted, -1 - memory allocation error
 */
static int freezer_enlist_vma(struct task_struct *task,
	enc_process_t *current_proc,
	struct vm_area_struct *ref_mmap,
	mem_segment_t segment)
{
	enc_vma_list_t *vma_entry_tmp;

	vma_entry_tmp = (enc_vma_list_t *) kmalloc(sizeof(enc_vma_list_t), GFP_KERNEL);
	if(!vma_entry_tmp) {
		printk("__refrigerator [%s] PID: %d Could not allocate memory in kernel for vm area list!\n",
			__func__, task->pid);
		return -1;
	}
#ifdef CONFIG_RAMENC_PERF_PROFILING
	current_proc->perf.num_vma++;
#endif
	vma_entry_tmp->segment = segment;
	vma_entry_tmp->was_not_writable = 0;
	vma_entry_tmp->vma_ref = ref_mmap;
	vma_entry_tmp->next = current_proc->enc_vma;
	current_proc->enc_vma = vma_entry_tmp;

	return 0;
}

/*
 * freezer_enlist_page - Enlist a selected page in the encryption list
 * return: 0 - successfully enlisted, -1 - memory allocation error
 */
static int freezer_enlist_page(struct task_struct *task, enc_pgs_list_t **page_list, struct page *page, bool was_clean,
	bool was_young, bool avoid_pgft, pte_t *pte, struct vm_area_struct *vma_ref, int counter)
{
	enc_pgs_list_t *pgs_entry_tmp;
	pgs_entry_tmp = (enc_pgs_list_t *) kmalloc(sizeof(enc_pgs_list_t), GFP_KERNEL);
	if(!pgs_entry_tmp) {
		printk("__refrigerator [%s] PID: %d Could not allocate memory in kernel for page list!\n",
			__func__, task->pid);
		return -1;
	}

	//initialization
	pgs_entry_tmp->page = page;
	pgs_entry_tmp->was_clean = was_clean;
	pgs_entry_tmp->was_young = was_young;
	pgs_entry_tmp->avoid_pgft = avoid_pgft;
	pgs_entry_tmp->vma_ref = vma_ref;
	pgs_entry_tmp->pte = pte;
	pgs_entry_tmp->counter = counter;
	//linking next element
	pgs_entry_tmp->next = *page_list;
	//return new list
	*page_list = pgs_entry_tmp;

	return 0;
}

static int pte_walk_save_pages(pte_t *pte, unsigned long addr, unsigned long next, struct mm_walk *walk)
{
	struct page* page;
	if (pte_present(*pte)) {
		page = pte_page(*pte);
		/*
		enc_page = kmalloc(sizeof(struct encrypted_page), GFP_KERNEL);
		enc_page->page = page;
		list_add(&enc_page->list, &encrypted_page_list);
		*/
		page->flags |= (1UL << __NR_PAGEFLAGS);
	}
	return 0;
}

/**
 * freezer_find_segments - gets the memory segments of the freezing process's
 * that were selected in user space
 * This function parses the memory area of the calling process and enlists all VMAs
 * of the memory sections @mem_sections. The VMA list for the process is
 * then added to the @head of an encrypted process list.
 *
 * @mem_sections: sections of the process memory area selected for encryption
 */
enc_process_t* freezer_find_segments(struct task_struct *task, char mem_sections)
{
	const char *name;
	// vm area reference structure for searching
	struct vm_area_struct *ref_mmap;
	int tot_segments = 0;
	pid_t tid;
	// structure to be added to the encrypting proc list
	enc_process_t *current_proc = NULL;
	// file mode to identify the type of file backed segments (regular, socket, device etc.)
	umode_t file_mode;

	current_proc = (enc_process_t *) kmalloc(sizeof(enc_process_t), GFP_KERNEL);
	if(!current_proc) {
		printk("__refrigerator [%s] PID: %d Could not allocate memory in kernel for process list!\n",
			__func__, task->pid);
		return NULL;
	}

	current_proc->is_encrypted = 0;
	current_proc->enc_vma = NULL;
	current_proc->pgs_list = NULL;
	current_proc->total_enc_pgs = 0;
#ifdef CONFIG_RAMENC_PERF_PROFILING
	current_proc->perf.num_vma = 0;
	current_proc->perf.num_vma_total = 0;
	current_proc->perf.num_cow_pgs = 0;
	current_proc->perf.num_pgs_skipped = 0;
	current_proc->perf.num_present_pgs = 0;
	current_proc->perf.num_total_pgs = 0;
	current_proc->perf.num_enc_dec_pgs = 0;
#endif

	ref_mmap = task->mm->mmap;
	while(ref_mmap != NULL) {

#ifdef CONFIG_RAMENC_DEBUG
		print_vm_area_struct(task, ref_mmap);
#endif
#ifdef CONFIG_RAMENC_PERF_PROFILING
		current_proc->perf.num_vma_total++;
#endif
		// these cases would be covered by checking for non-regular files
		// and on other platforms/versions for possibly special segments
		// according to mm.h, these can be e.g., IO, PFNMAP, RESERVED, ...
		if (ref_mmap->vm_flags & VM_SPECIAL) {
			pr_debug("__refrigerator [%s] PID: %d Skip SPECIAL VMA\n",
				__func__, task->pid);
			goto next_iter;
		}
		// Code segment consists of only one VMA
		if(ref_mmap->vm_mm->start_code >= ref_mmap->vm_start &&
		   ref_mmap->vm_mm->end_code <= ref_mmap->vm_end) {
			if(mem_sections & TEXT_FLAG) {
				freezer_enlist_vma(task, current_proc, ref_mmap, TEXT_SEG);
				pr_debug("__refrigerator [%s] PID: %d found vma %p, segment name: %s\n",
					__func__, task->pid, ref_mmap, "CODE");
			}
			goto next_iter;
		}

		// It is possible that the data segment is covered by more than one VMA or within one VMA
		// ||vma1_start-----------vm_data_start<=======vma1_end||||vma2_start=======>vm_data_end------vma2_end||
		// Three checks for data section VMA qualification:
		// 1.check if VMA start lies between data section limits
		// 2.check if VMA end lies between data section limits
		// 3.check if data section limits lie within one VMA
		if((ref_mmap->vm_start >= ref_mmap->vm_mm->start_data  && ref_mmap->vm_start <= ref_mmap->vm_mm->end_data) ||
		   (ref_mmap->vm_end   >= ref_mmap->vm_mm->start_data  && ref_mmap->vm_end   <= ref_mmap->vm_mm->end_data) ||
		   ((ref_mmap->vm_mm->start_data >= ref_mmap->vm_start  && ref_mmap->vm_mm->start_data <= ref_mmap->vm_end) &&
		   (ref_mmap->vm_mm->end_data   >= ref_mmap->vm_start  && ref_mmap->vm_mm->end_data   <= ref_mmap->vm_end))) {
			if(mem_sections & DATA_FLAG) {
				freezer_enlist_vma(task, current_proc, ref_mmap, DATA_SEG);
				pr_debug("__refrigerator [%s] PID: %d found vma %p, segment name: %s\n",
					__func__, task->pid, ref_mmap, "DATA");
			}
			goto next_iter;
		}

		// The data and code section are also file backed segments, but we select them separately
		if(ref_mmap->vm_file) {
			if(mem_sections & FILE_FLAG) {
				// skip non-regular segments
				// This is how a regular file is identified. All others are either sockets,
				// directories, links, block or character devices
				file_mode = ref_mmap->vm_file->f_path.dentry->d_inode->i_mode;
				if((file_mode & S_IFMT) == S_IFREG) {
					// only skip read-only exec segments (e.g., libraries)
					if(!((ref_mmap->vm_flags & VM_EXEC) && (!(ref_mmap->vm_flags &
							VM_WRITE)))) {
						freezer_enlist_vma(task, current_proc, ref_mmap, FILE_SEG);
						pr_debug("__refrigerator [%s] PID: %d found vma %p, segment name: FILE [%s]\n",
							__func__, task->pid, ref_mmap, ref_mmap->vm_file->f_path.dentry->d_iname);
					}
					else
						pr_debug("__refrigerator [%s] PID: %d SKIPPED ROEXEC FILE vma %p, segment name: FILE [%s]\n",
						__func__, task->pid, ref_mmap, ref_mmap->vm_file->f_path.dentry->d_iname);
				}
				else
					pr_debug("__refrigerator [%s] PID: %d SKIPPED NONREG FILE vma %p, segment name: FILE [%s]\n",
						__func__, task->pid, ref_mmap, ref_mmap->vm_file->f_path.dentry->d_iname);
			}
			goto next_iter;
		}

		// Special segments or stack/heap/other anonymous
		name = arch_vma_name_ptr(ref_mmap);
		if (name) {
			pr_debug("__refrigerator [%s] PID: %d SKIPPED SPECIAL SEGMENT vma %p, segment name: SPECIAL [%s]\n",
				__func__, task->pid, ref_mmap, name);
			goto next_iter;
		}
		else {
			// exception on some platforms (e.g., ARM vdso)
			// this condition indicates for another special segment
			if (!ref_mmap->vm_mm) {
			pr_debug("__refrigerator [%s] PID: %d SKIPPED SPECIAL SEGMENT vma %p, segment name: SPECIAL [vdso]\n",
				__func__, task->pid, ref_mmap);
				goto next_iter;
			}
			// heap section
			if (ref_mmap->vm_mm->brk >= ref_mmap->vm_start &&
			    ref_mmap->vm_mm->start_brk <= ref_mmap->vm_end) {
				if(mem_sections & HEAP_FLAG) {
					freezer_enlist_vma(task, current_proc, ref_mmap, HEAP_SEG);
					pr_debug("__refrigerator [%s] PID: %d found vma %p, segment name: %s\n",
						__func__, task->pid, ref_mmap, "HEAP");
				}
				goto next_iter;
			}

			//stack section
			tid = vma_is_stack_for_task(task, ref_mmap);
			if (tid != 0) {
				if(mem_sections & STCK_FLAG) {
					if (ref_mmap->vm_mm->start_stack>=ref_mmap->vm_start &&
					    ref_mmap->vm_mm->start_stack<=ref_mmap->vm_end) {
						freezer_enlist_vma(task, current_proc, ref_mmap, STACK_SEG);
						pr_debug("__refrigerator [%s] PID: %d found vma %p, segment name: %s\n",
							__func__, task->pid, ref_mmap, "STACK");
					} else	{
						freezer_enlist_vma(task, current_proc, ref_mmap, THREAD_STACK_SEG);
						pr_debug("__refrigerator [%s] PID: %d found vma %p, segment name: %s\n",
							__func__, task->pid, ref_mmap, "THREAD_STCK");
					}
				}
				goto next_iter;
			}

			//can represent BSS or other anonymous mappings
			if(mem_sections & ANON_FLAG) {
				freezer_enlist_vma(task, current_proc, ref_mmap, ANON_SEG);
				pr_debug("__refrigerator [%s] PID: %d found vma %p, segment name: ANON\n",
					__func__, task->pid, ref_mmap);
			}
			goto next_iter;
		}
next_iter:
		// goto next node in the vma list
		ref_mmap = ref_mmap->vm_next;
		tot_segments++;
	}
#ifdef CONFIG_RAMENC_PERF_PROFILING
	current_proc->perf.num_vma_total = tot_segments;
#endif
	pr_debug("__refrigerator [%s] PID: %d finished, total segments found: %d\n",
		__func__, task->pid, tot_segments);
	return current_proc;
}

struct pgcrypt_result {
	struct completion *async_barrier;
	struct scatterlist *pg_array;
	int max_iters;
	atomic_t *enc_ctr;
	struct skcipher_request *enc_req;
	long long unsigned int *iv_string;
};

void pgcrypt_complete(struct crypto_async_request *req, int err)
{
	struct pgcrypt_result *res = req->data;
	if (err == -EINPROGRESS) {
		complete(res->async_barrier);
		return;
	}
	else if (err != 0) {
		printk("__refrigerator [%s] PID: (THIS IS THE WRONG PID)%d Error %d while page encryption in callback!\n",
			__func__, current->pid, err);
	}

	atomic_dec(res->enc_ctr);
	kfree(res->pg_array);
	skcipher_request_free(res->enc_req);
	kfree(res);
}

static int pte_walk(pte_t *pte, unsigned long addr, unsigned long next, struct mm_walk *walk)
{
	unsigned long current_start_addr = 0;
	unsigned long current_end_addr = 0;

	bool pte_changed = false;
	int mapcount;
	bool avoid_pgft;
	bool was_clean;
	bool was_young;
	//long proc_total_enc_pgs = 0;
	struct task_struct *task = walk->mm->owner;
	struct page_walk_data *data = walk->private;
	struct page *page = NULL;
#ifdef CONFIG_RAMENC_PERF_PROFILING
	current_proc->perf.num_total_pgs++;
#endif
	// get the linux kernel page table entry
	// check if the pte is valid and present
	if (pte_present(*pte)) {
#ifdef CONFIG_RAMENC_PERF_PROFILING
		current_proc->perf.num_present_pgs++;
		vma_entry_tmp->perf.num_present_pgs++;
#endif
		avoid_pgft = false;
		was_clean = false;
		was_young = false;
#ifdef CONFIG_RAMENC_DEBUG
		print_pte(task, pte, walk->vma, i);
#endif
		// get page frame PTE refers to
		// vm_normal_page would also work, but with our checks below we
		// implicitly exclude special pages
		page = pte_page(*pte);

		/*
		struct encrypted_page *enc_page;
		list_for_each_entry(enc_page, &encrypted_page_list, list) {
			if (page_to_phys(enc_page->page) == page_to_phys(page)) {
				return 0;
			}
		}
		*/

		if (!trylock_page(page)) {
#ifdef CONFIG_RAMENC_PERF_PROFILING
			// increment counter for total skipped pages for the current process thread
			current_proc->perf.num_pgs_skipped++;
#endif
			pr_debug("__refrigerator [%s] PID: %d, page %p locked\n",
				   __func__, task->pid, page);
			return 0;
		}

		/* If page already marked as encrypted dont enlist it */
		if (page->flags & (1UL << __NR_PAGEFLAGS)) {
			unlock_page(page);
			return 0;
		}
		//TODO further investigate
		if (PageSlab(page))
			mapcount = 0;
		else
			mapcount = page_mapcount(page);
		// if mapcount is less than one then it is a special kernel/driver mapping
		// no need to encrypt/decrypt
		if (mapcount < 1) {
#ifdef CONFIG_RAMENC_PERF_PROFILING
			//increment counter for total skipped pages for the current process thread
			current_proc->perf.num_pgs_skipped++;
#endif
			pr_debug("__refrigerator [%s] PID: %d, page %p special mapping, don't touch!\n",
				__func__, task->pid, page);
			unlock_page(page);
			return 0;
		}

		page->flags |= (1UL << __NR_PAGEFLAGS);

		unlock_page(page);

		/* Add page to the list of already encrypted pages */
		/*
		enc_page = kmalloc(sizeof(struct encrypted_page), GFP_KERNEL);
		enc_page->page = page;
		list_add(&enc_page->list, &encrypted_page_list);
		*/
		

		//inc page-to-be-encrypted counter
		data->proc_total_enc_pgs++;

		// avoid page fault when pte is not writable
		if (!pte_write(*pte)) {
			avoid_pgft = true;
			if (mapcount > 1) {
#ifdef CONFIG_RAMENC_PERF_PROFILING
				current_proc->perf.num_cow_pgs++;
#endif
				pr_debug("__refrigerator [%s] PID: %d, page %p, avoid cow, make page writable!\n",
					__func__, task->pid, page);
			}
		}

		// recover clean state after encryption/decryption
		if(!pte_dirty(*pte)) {
			was_clean = true;
		}
		// recover young state after encryption/decryption
		if(pte_young(*pte)) {
			was_young = true;
		}

		// make the linux and ARM PTEs writable if VMA is not writable
		if(avoid_pgft) {
			pte_changed =  __mk_pte_writable(task, walk->vma, pte, addr);
			if(!pte_changed) {
				printk("__refrigerator [%s] PID: %d, pte %p, UNEXPECTED pte was not changed (should be made writable)!\n",
					__func__, task->pid, pte);
			}
		}

		current_start_addr = addr;
		current_end_addr = current_start_addr + (1<<PAGE_SHIFT);
		pr_debug("__refrigerator [%s] PID: %d working from start addr: %08lx to end addr: %08lx\n",
			__func__, task->pid, current_start_addr, current_end_addr);
		//if (!_vm_normal_page_ptr(walk->vma, addr, *pte, false))
		//	pr_debug("__refrigerator [%s] PID: %d UNEXPECTED encrypting a non-normal page\n", __func__, task->pid);

		// enlist page in list to be encrypted
		if (freezer_enlist_page(task, data->pgs_entry_list, page, was_clean, was_young,
				avoid_pgft, pte, walk->vma, 0)) { /* TODO: make a real counter instead of 0 */
			printk("__refrigerator [%s] PID: %d UNEXPECTED could not add page to list\n",
				__func__, task->pid);
		}
	}
	return 0;
}

static int hugetlb_walk (pte_t *pte, unsigned long hmask, unsigned long addr, unsigned long next, struct mm_walk *walk)
{
	printk(KERN_INFO "Skipping huge pages for now\n");
	BUG();
	return 0;
}

/**
 * freezer_secure_vm_areas - en/decrypts the enlisted VMAs page-wise
 *
 * @vma_entry_tmp: current process's structure containing VMA list
 * @enc_dec      : 1 - encrypt ; 0 - decrypts
 * @crypt_tfm    : crypto API tranfsormation to be used for en/decryption
 *
 * This function parses the vm areas list and en/decrypts them with the provided
 * crypto API transformation. VM areas which are write protected are unprotected
 * before en/decryption and their state recovered after. Only pages that are
 * in the RAM are en/decrypted. The pages are made writable before the cipher
 * operation and their state recoverd after.
 *
 */
void freezer_secure_vm_areas(struct task_struct *task, enc_process_t *current_proc, bool enc_dec, void *crypt_tfm)
{
	// page and PTE related variables
	bool pte_changed = false;
	pte_t *pte = NULL;
	long proc_total_enc_pgs = 0;
	struct completion async_barrier;
	atomic_t finish_ctr;
	int enc_ret;

	// variables for en-/decryption
	// get the current process's VMA list head
	enc_vma_list_t *vma_entry_tmp = current_proc->enc_vma;
	enc_pgs_list_t *pgs_entry_list = NULL;
	enc_pgs_list_t *pgs_entry_tmp = NULL;

	long long unsigned int iv_cp[2];
	struct crypto_skcipher *tfm = crypt_tfm;
	struct scatterlist *sg = NULL;
	struct skcipher_request *req = NULL;
	struct pgcrypt_result *pgres_data = NULL;

	// decryption
	if (!enc_dec) {
		// get the stored list of pages to be en/decrypted for the task and the total num of pages
		pgs_entry_list = current_proc->pgs_list;
		proc_total_enc_pgs = current_proc->total_enc_pgs;
		if (pgs_entry_list == NULL)
			pr_debug("__refrigerator [%s] PID: %d UNEXPECTED pgs_list == NULL! (total_enc_pgs:%ld)\n",
				__func__, task->pid, proc_total_enc_pgs);
		pgs_entry_tmp = pgs_entry_list;
		// prepare pte's for decryption (reset later after decryption)
		while (pgs_entry_tmp) {
			if(pgs_entry_tmp->avoid_pgft) {
				pte_changed =  __mk_pte_writable(task, pgs_entry_tmp->vma_ref, pgs_entry_tmp->pte,
					pgs_entry_tmp->vma_ref->vm_start+((pgs_entry_tmp->counter)<<PAGE_SHIFT));
				if(!pte_changed) {
					printk("__refrigerator [%s] PID: %d, pte %p, UNEXPECTED pte was not changed (should be made writable)!\n",
						__func__, task->pid, pte);
				}
			}
			pgs_entry_tmp = pgs_entry_tmp->next;
		}
	}
	// encryption
	else {
		// go through the entire list of previously identified vmas
		while(vma_entry_tmp) {
			struct page_walk_data page_walk_data = {
				.pgs_entry_list = &pgs_entry_list,
				.proc_total_enc_pgs = 0
			};

			struct mm_walk walker = {
				.pte_entry = pte_walk,
				.hugetlb_entry = hugetlb_walk,
				.mm = task->mm,
				.private = &page_walk_data
			};

#ifdef CONFIG_RAMENC_PERF_PROFILING
			vma_entry_tmp->perf.num_present_pgs = 0;
			vma_entry_tmp->perf.num_enc_dec_pgs = 0;
#endif
			// make the VMA writable if not writable
			if(!(vma_entry_tmp->vma_ref->vm_flags & VM_WRITE)) {
				pr_debug("__refrigerator [%s] PID: %d, make VMA %p writable!\n",
					__func__, task->pid, vma_entry_tmp->vma_ref);
				spin_lock(&task->mm->page_table_lock);
				// mark the VMA writable
				vma_entry_tmp->vma_ref->vm_flags |= VM_WRITE;
				spin_unlock(&task->mm->page_table_lock);
				// mark the VMA "was not writable"
				vma_entry_tmp->was_not_writable = 1;
			}

			pr_debug("__refrigerator [%s] PID: %d, encrypt vma: %p\n",
				__func__, task->pid, vma_entry_tmp->vma_ref);

			down_read(&task->mm->mmap_sem);
			walk_page_vma_ptr(vma_entry_tmp->vma_ref, &walker);
			up_read(&task->mm->mmap_sem);

			proc_total_enc_pgs += page_walk_data.proc_total_enc_pgs;

			// get the next VMA in the thread list
			vma_entry_tmp = vma_entry_tmp->next;
		}
		// store this information for later decryption
		current_proc->pgs_list = pgs_entry_list;
		current_proc->total_enc_pgs = proc_total_enc_pgs;
	}

	total_enc_pgs += proc_total_enc_pgs;
    // enc and dec case, if there are pages to be en/decrypted
    if (proc_total_enc_pgs) {
		int i = 0;
		int rem_pgs;
		int pgs_to_alloc;
		int max_iterations;
		pgs_entry_tmp = pgs_entry_list;
		rem_pgs = proc_total_enc_pgs;

		init_completion(&async_barrier);
		atomic_set(&finish_ctr, 0);
		max_iterations = proc_total_enc_pgs / MAX_SG;
		if (proc_total_enc_pgs % MAX_SG)
			max_iterations++;
		while (rem_pgs > 0) {
			if (rem_pgs < MAX_SG)
				pgs_to_alloc = rem_pgs;
			else
				pgs_to_alloc = MAX_SG;
			sg = (struct scatterlist *) kmalloc(pgs_to_alloc * sizeof(struct scatterlist), GFP_KERNEL);
			if (!sg)
				printk("__refrigerator [%s] PID: %d failed to allocate scatterlist!\n",
					__func__, task->pid);

			pgres_data = (struct pgcrypt_result *) kmalloc(sizeof(struct pgcrypt_result), GFP_KERNEL);
			if (!pgres_data)
				printk("__refrigerator [%s] PID: %d failed to allocate pgcrypt_result!\n",
					__func__, task->pid);
			pgres_data->async_barrier = &async_barrier;
			pgres_data->pg_array = sg;
			pgres_data->max_iters = max_iterations;
			pgres_data->enc_ctr = &finish_ctr;
			req = skcipher_request_alloc(tfm, GFP_KERNEL);

			if (!req) {
				printk("__refrigerator [%s] PID: %d Could not allocate skcipher req\n",
					__func__, task->pid);
			}
			pgres_data->enc_req = req;

			iv_cp[0] = 0x0;
			iv_cp[1] = page_to_phys(pgs_entry_list->page);
			pgres_data->iv_string = iv_cp;

			skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, pgcrypt_complete, pgres_data);
				//| CRYPTO_TFM_REQ_MAY_SLEEP, pgcrypt_complete, pgres_data);

			sg_init_table(sg, pgs_to_alloc);

			//printk(KERN_INFO "pgs to alloc: %d\n", pgs_to_alloc);

			for (i = 0; i < pgs_to_alloc; i++) {
				if (pgs_entry_tmp == NULL)
					printk("__refrigerator [%s] PID: %d Unexpected page list failure!\n",
						__func__, task->pid);
				sg_set_page(sg + i, pgs_entry_tmp->page, (1<<PAGE_SHIFT), 0);
				pgs_entry_tmp = pgs_entry_tmp->next;
			}

			skcipher_request_set_crypt(req, sg, sg, (1<<PAGE_SHIFT)*pgs_to_alloc, &iv_cp);
			atomic_inc(&finish_ctr);

			if(enc_dec) {
				// encrypt plain text in scratch pad
				enc_ret = crypto_skcipher_encrypt(req);
			} else {
				// decrypt cipher text to plain text
				enc_ret = crypto_skcipher_decrypt(req);
			}
			switch (enc_ret) {
			// immediate success
			case 0:
				atomic_dec(&finish_ctr);
				kfree(sg);
				skcipher_request_free(req);
				kfree(pgres_data);
				break;
			case -EBUSY:
				printk("__refrigerator [%s] PID: %d, wait, because EBUSY while enc1/dec0 (%d): %x\n",
					__func__, task->pid, enc_dec, crypto_skcipher_get_flags(tfm));
				wait_for_completion(&async_barrier);
				reinit_completion(&async_barrier);
				break;
			case -EINPROGRESS:
				printk("__refrigerator [%s] PID: %d, EINPROGRESS while enc1/dec0 (%d): %x\n",
					__func__, task->pid, enc_dec, crypto_skcipher_get_flags(tfm));
				break;
			// unknown error
			default:
				atomic_dec(&finish_ctr);
				printk("__refrigerator [%s] PID: %d, UNEXPECTED %d pages failed to enc1/dec0 (%d): %x\n",
					__func__, task->pid, pgs_to_alloc, enc_dec, crypto_skcipher_get_flags(tfm));
			}
			rem_pgs = rem_pgs - pgs_to_alloc;
		}
		while (atomic_read(&finish_ctr) > 0) {
			printk("__refrigerator [%s] PID: %d, wait 8ms for %d enc1/dec0 (%d) operations to return (%x)\n",
			__func__, task->pid, atomic_read(&finish_ctr), enc_dec, crypto_skcipher_get_flags(tfm));
			msleep(8);
		}
		pgs_entry_tmp = pgs_entry_list;
		while (pgs_entry_tmp) {

			// recover ARM PTEs to previous state
			pte_changed =  __mk_pte_wrprotected(task, pgs_entry_tmp->vma_ref, pgs_entry_tmp->pte,
					pgs_entry_tmp->vma_ref->vm_start+((pgs_entry_tmp->counter)<<PAGE_SHIFT),
					pgs_entry_tmp->avoid_pgft, pgs_entry_tmp->was_clean, pgs_entry_tmp->was_young);

			// unexpected behaviour, if PTE does not change with avoid_pgft flag set
			if(!pte_changed && pgs_entry_tmp->avoid_pgft) {
				printk("__refrigerator [%s] PID: %d UNEXPECTED pte %p was not changed "
					"(should reconstruct previously altered values)!\n",
					__func__, task->pid, pgs_entry_tmp->pte);
			}

#ifdef CONFIG_RAMENC_DEBUG
			print_pte(task, pgs_entry_tmp->pte, pgs_entry_tmp->vma_ref, pgs_entry_tmp->counter);
#endif
			pgs_entry_tmp = pgs_entry_tmp->next;
		}
    }
	// VMA RESET LOOP
	vma_entry_tmp = current_proc->enc_vma;
	while (vma_entry_tmp) {
		// recover initial state of VMA in kernel
		if(vma_entry_tmp->was_not_writable) {
			pr_debug("__refrigerator [%s] PID: %d make VMA %p write protected!\n",
				__func__, task->pid, vma_entry_tmp->vma_ref);
			spin_lock(&task->mm->page_table_lock);
			vma_entry_tmp->vma_ref->vm_flags &= ~(VM_WRITE);
			spin_unlock(&task->mm->page_table_lock);
			vma_entry_tmp->was_not_writable = 0;
		}
		vma_entry_tmp = vma_entry_tmp->next;
	}
#ifdef CONFIG_RAMENC_PERF_PROFILING
	//set counter for total encrypted/decrypted pages for the current process thread
	current_proc->perf.num_enc_dec_pgs = proc_total_enc_pgs;
#endif
}

void proc_free_vmas(enc_vma_list_t *vma_entry)
{
	enc_vma_list_t *vma_entry_tmp = vma_entry;

	while(vma_entry_tmp) {
		vma_entry_tmp = vma_entry->next;
		kfree(vma_entry);
		vma_entry = vma_entry_tmp;
	}
}

void proc_free_pglist(enc_pgs_list_t *enc_pglist)
{
	enc_pgs_list_t *pg_entry_tmp = enc_pglist;

	while(pg_entry_tmp) {
		pg_entry_tmp = enc_pglist->next;
		kfree(enc_pglist);
		enc_pglist = pg_entry_tmp;
	}
}

bool __mk_pte_writable(struct task_struct *task, struct vm_area_struct *vma, pte_t* pte, unsigned long address)
{
	pte_t pte_val = *pte;
	int changed = 0;

	if(!pte_write(pte_val)) {
		pte_val = pte_mkwrite(pte_val);
		// for ARM we make the PTE dirty, since ARM checks for access permissions based on this bit
		pte_val = pte_mkdirty(pte_val);

		spin_lock(&task->mm->page_table_lock);
		changed = ptep_set_access_flags_ptr(vma, address, pte, pte_val, 1);
		// in accordance with e.g., mm/memory.c, we could use update_mmu_cache
		// and probably do some flush cache_page or flush_tlb_age, but our system also works without
		//if (changed)
		//	update_mmu_cache(vma, address, pte);
		spin_unlock(&task->mm->page_table_lock);
	}

	return changed;
}

bool __mk_pte_wrprotected(struct task_struct *task, struct vm_area_struct *vma,  pte_t* pte, unsigned long address,
			  bool was_rdonly, bool was_clean, bool was_young)
{
	pte_t pte_val = *pte;
	int changed = 0;

	// recover read only state
	if(was_rdonly)
	        pte_val = pte_wrprotect(pte_val);

	// recover clean state
	if(was_clean)
	        pte_val = pte_mkclean(pte_val);
	else
	        pte_val = pte_mkdirty(pte_val);

	// recover young state
	if(was_young)
		pte_val = pte_mkyoung(pte_val);
	else
		pte_val = pte_mkold(pte_val);

        spin_lock(&task->mm->page_table_lock);
        //changed = ptep_set_access_flags(vma, address, pte, pte_val, 0);
changed = ptep_set_access_flags_ptr(vma, address, pte, pte_val, 1);
	// in accordance with e.g., mm/memory.c, we could use update_mmu_cache
	// and probably do some flush cache_page or flush_tlb_age, but our system also works without
	//if (changed)
	//	update_mmu_cache(vma, address, pte);
	spin_unlock(&task->mm->page_table_lock);

	return changed;
}

#ifdef CONFIG_RAMENC_DEBUG
void print_mm_struct(struct task_struct *task) {
	printk("__refrigerator PID: %d, mm_struct: %p, "
		"code: %08lx-%08lx, data: %08lx-%08lx, "
		"brk: %08lx-%08lx, stack at: %08lx, arg: %08lx-%08lx, "
		"env: %08lx-%08lx, "
		"mm_users/count/frozen: %d/%d/%d, "
		"map_count: %d, total_vm: %08lu, def_flags: %08lx\n",
		task->pid, task->mm,
		task->mm->start_code, task->mm->end_code, task->mm->start_data, task->mm->end_data,
		task->mm->start_brk, task->mm->brk, task->mm->start_stack, task->mm->arg_start, task->mm->arg_end,
		task->mm->env_start, task->mm->env_end,
		//atomic_read(&current->mm->mm_users), atomic_read(&current->mm->mm_count), atomic_read(&current->mm->mm_frozen),
		atomic_read(&task->mm->mm_users), atomic_read(&task->mm->mm_count), 0,
		task->mm->map_count, task->mm->total_vm, task->mm->def_flags);
}

void print_vm_area_struct(struct task_struct *task, struct vm_area_struct *vma) {
	if (!vma)
		printk("__refrigerator PID: %d, vma_area_struct NULL\n", task->pid);
	else
		printk("__refrigerator PID: %d, vm_area_struct %p, "
			"from mm_struct: %p, vm_start: %08lx-%08lx, "
			"vm_page_prot %08lx, vm_flags %08lx, "
			"(MAYSHARE %lu, SHARED %lu, LOCKED: %lu, SPECIAL: %lu), "
			"vm_file %p, arch_vma_name: %s, vm_is_stack: %d\n",
			task->pid, vma,
			vma->vm_mm, vma->vm_start, vma->vm_end,
			(unsigned long) pgprot_val(vma->vm_page_prot), vma->vm_flags,
			vma->vm_flags & VM_MAYSHARE, vma->vm_flags & VM_SHARED, vma->vm_flags & VM_LOCKED,
			vma->vm_flags & VM_SPECIAL,
			vma->vm_file, arch_vma_name_ptr(vma), vma_is_stack_for_current_task(task, vma));
}

void print_pte(struct task_struct *task, pte_t *pte, struct vm_area_struct *vma, int num_iter) {
	int cow_page = 0;
	struct page *page = NULL;

	if (!pte || !vma)
		printk("__refrigerator PID: %d pte_t NULL or VMA NULL\n", task->pid);
	else {
		if ((vma->vm_flags & VM_WRITE) && (!pte_write(*pte)))
			cow_page = 1;
		page = pte_page(*pte);

		printk("__refrigerator PID: %d, PTE %p, vma addr: %p, "
			"pte_val %08lx, vma_start: %08lx, num_iter: %d, cow_page: %d, "
			"writable: %d, present: %d, dirty: %d, young: %d, exec: %d, "
			"page_addr: %p, _count: %d, _mapcount: %d, _compound: %d, _head: %d, _tail: %d, "
			"PG_LRU: %lu, _locked: %lu, _private: %lu, _private_2: %lu, _writeback: %lu, "
			"_reserved: %lu, _slab: %lu, _swapcache: %lu, _active: %lu, _unevictable: %lu, "
			"_mlock: %lu, _hwpoison: %lu\n",
			task->pid, pte, vma,
			(unsigned long) pte_val(*pte), vma->vm_start, num_iter, cow_page,
			pte_write(*pte), pte_present(*pte), pte_dirty(*pte), pte_young(*pte), pte_exec(*pte),
			page, page_count(page), PageSlab(page) ? 0 : page_mapcount(page), PageCompound(page), PageHead(page), PageTail(page),
			page->flags & (1 << PG_lru), page->flags & (1 << PG_locked), page->flags & (1 << PG_private), page->flags & (1 << PG_private_2), page->flags & (1 << PG_writeback),
			page->flags & (1 << PG_reserved), page->flags & (1 << PG_slab), page->flags & (1 << PG_swapcache), page->flags & (1 << PG_active), page->flags & (1 << PG_unevictable),
			page->flags & (__PG_MLOCKED), page->flags & (__PG_HWPOISON));
	}
}
#endif

static void encrypt_function(struct work_struct *work_arg) {
	struct work_wrapper *work = container_of(work_arg, struct work_wrapper, real_work);
	pr_debug("__refrigerator [%s] PID: %d encrypting selected segments of mm_struct %p\n",
		__func__, work->enc_args.t->pid, work->enc_args.t->mm);
	// encrypt all VMAs in process list
	freezer_secure_vm_areas(work->enc_args.t, work->enc_args.current_proc, 1, tfm);
	work->enc_args.current_proc->is_encrypted = 1;
	/* add process to list of encrypted processes */
}


int encrypt_processes(void)
{
	struct timespec64 before, after;
	unsigned long long before_ms, after_ms;
	enc_process_t *current_proc = NULL;
	struct task_struct *p, *t;

	/* Allocate the skcipher */
	if (!tfm) {
		tfm = crypto_alloc_skcipher(CRYPT_ALG, CRYPTO_ALG_TYPE_ABLKCIPHER, 0);
		if(IS_ERR(tfm)) {
			printk("__refrigerator [%s] Could not allocate block cipher: %s\n",
				__func__, CRYPT_ALG);
			tfm = NULL;
		} else {
			printk("__refrigerator [%s] Allocated block cipher driver: %s\n",
				__func__, crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)));
			if (crypto_skcipher_setkey(tfm, encdec_key, key_len)) {
				printk("__refrigerator [%s] Could not set block cipher key!\n",
					__func__);
				crypto_free_skcipher(tfm);
				tfm = NULL;
			}
			if (IV_LEN != crypto_skcipher_ivsize(tfm)) {
				printk("__refrigerator [%s] IV lengths do not match (%d)!\n",
				__func__, crypto_skcipher_ivsize(tfm));
				crypto_free_skcipher(tfm);
				tfm = NULL;
			}
		}
	}

	total_enc_pgs = 0;


	/* Collect pages of all user space tasks that are still running, i.e. not frozen */
	for_each_process(p) {
		int frozen_count = 0;
		for_each_thread(p, t) {
			if (t->flags & PF_NOFREEZE) {
				//printk(KERN_INFO "[fridgelock] Thread considered for protection (because of non-frozen) %s (PID %d)\n", t->comm, t->pid);
				continue;
			}
			/* Indicates kernel thread */
			if (t->mm == NULL) {
				//printk(KERN_INFO "[fridgelock] Thread considered for protection (because of no mm_struct) %s (PID %d)\n", t->comm, t->pid);
				continue;
			}
			frozen_count++;
		}

		t = p;

		if (t->mm && frozen_count != atomic_read(&t->mm->mm_users)) {
			struct vm_area_struct *cur_vma = t->mm->mmap;
			
			//printk(KERN_INFO "Protecting process: %s\n", t->comm);
			while(cur_vma != NULL) {

				struct mm_walk walker = {
					.pte_entry = pte_walk_save_pages,
					.hugetlb_entry = hugetlb_walk,
					.mm = t->mm,
					.private = NULL
				};

				walk_page_vma_ptr(cur_vma, &walker);
				
				cur_vma = cur_vma->vm_next;
			}
		}
	}

	// timestamp for measuring page encryption time
	ktime_get_real_ts64(&before);
	before_ms = 1000 * before.tv_sec + (before.tv_nsec / 1000000);

	for_each_process(p) {
		int frozen_count = 0;
		for_each_thread(p, t) {
			if (t->flags & PF_NOFREEZE) {
				//printk(KERN_INFO "[fridgelock] Skipping encryption of thread (because of non-frozen) %s (PID %d)\n", t->comm, t->pid);
				continue;
			}
			/* Indicates kernel thread */
			if (t->mm == NULL) {
				//printk(KERN_INFO "[fridgelock] Skipping encryption of thread (because of no mm_struct) %s (PID %d)\n", t->comm, t->pid);
				continue;
			}
			frozen_count++;
		}

		t = p;

		//printk(KERN_INFO "[fridgelock] mm_users: %d for process %s\n", atomic_read(&t->mm->mm_users), t->comm);
		/* Only encrypt if all threads of the process were frozen */
		if (t->mm && frozen_count == atomic_read(&t->mm->mm_users)) {
			//printk(KERN_INFO "[fridgelock] Can encrypt: [%s]\n", p->comm);
			if (!tfm || IS_ERR(tfm)) {
				printk("__refrigerator [%s] PID: %d UNEXPECTED TFM returned is NULL. Skipping encryption!\n",
					__func__, t->pid);
			} else {
#ifdef CONFIG_RAMENC_DEBUG
				print_mm_struct(t);
#endif
				// populate the VMAs for this task
				current_proc = freezer_find_segments(t, 0x3f);

				if(!current_proc)
					printk("__refrigerator [%s] PID: %d no segments found, skip en-/decryption!\n",
						__func__, t->pid);
			}
		} else {
			current_proc = NULL;
			pr_debug("[fridgelock] Can't encrypt [%s] at [%px]", t->comm, t->mm);
			pr_debug("__refrigerator [%s] PID: %d I may skip encryption/decryption of the following mm_struct %p\n",
				__func__, t->pid, t->mm);
		}
		if(current_proc && !current_proc->is_encrypted) {
	#ifdef CONFIG_RAMENC_PERF_PROFILING
			current_proc->perf.encrypting_pid = t->pid;
	#endif
			// flag the thread memory area as encrypted to avoid re-encryption
			struct work_wrapper *work = kmalloc(sizeof(*work), GFP_KERNEL);
			INIT_WORK(&work->real_work, encrypt_function);
			work->enc_args.t = t;
			work->enc_args.current_proc = current_proc;

			queue_work(system_unbound_wq, &work->real_work);

			struct encrypted_process *enc_proc;
			enc_proc = kmalloc(sizeof(*enc_proc), GFP_KERNEL);
			enc_proc->task = t;
			enc_proc->enc_proc = current_proc;
			enc_proc->work = work;
			INIT_LIST_HEAD(&enc_proc->list);
			list_add(&enc_proc->list, &enc_processes_list);
		}
	}

	flush_workqueue(system_unbound_wq);
	struct encrypted_process *enc_proc;
	list_for_each_entry(enc_proc, &enc_processes_list, list) {
		//flush_work(&enc_proc->work->real_work);
		kfree(enc_proc->work);
	}

	ktime_get_real_ts64(&after);
	after_ms = 1000 * after.tv_sec + (after.tv_nsec / 1000000);

	printk(KERN_INFO "Total encryption time: %llums = ~ %llus\n", after_ms - before_ms, after.tv_sec - before.tv_sec);
	printk(KERN_INFO "Total count of encrypted pages: %lld\n", total_enc_pgs);

	crypto_free_skcipher(tfm);
	tfm = NULL;

	return 0;
}

int decrypt_processes(void)
{
	struct timespec64 before, after;
	unsigned long long before_ms, after_ms;

	struct encrypted_process *enc_proc = NULL;
	struct list_head *pos = NULL;
	struct list_head *tmp = NULL;

	/* Allocate the skcipher */
	if (!tfm) {
		tfm = crypto_alloc_skcipher(CRYPT_ALG, CRYPTO_ALG_TYPE_ABLKCIPHER, 0);
		if(IS_ERR(tfm)) {
			printk("__refrigerator [%s] Could not allocate block cipher: %s\n",
				__func__, CRYPT_ALG);
			tfm = NULL;
		} else {
			printk("__refrigerator [%s] Allocated block cipher driver: %s\n",
				__func__, crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm)));
			if (crypto_skcipher_setkey(tfm, encdec_key, key_len)) {
				printk("__refrigerator [%s] Could not set block cipher key!\n",
					__func__);
				crypto_free_skcipher(tfm);
				tfm = NULL;
			}
			if (IV_LEN != crypto_skcipher_ivsize(tfm)) {
				printk("__refrigerator [%s] IV lengths do not match (%d)!\n",
				__func__, crypto_skcipher_ivsize(tfm));
				crypto_free_skcipher(tfm);
				tfm = NULL;
			}
		}
	}
	if (!tfm || IS_ERR(tfm)) {
		printk("__refrigerator [%s] UNEXPECTED TFM returned is NULL. Skipping decryption!\n",
			__func__);
		return -1;
	}

	ktime_get_real_ts64(&before);
	before_ms = 1000 * before.tv_sec + (before.tv_nsec / 1000000);

	list_for_each_safe(pos, tmp, &enc_processes_list) {
		struct task_struct *t = enc_proc->task;

		enc_proc = list_entry(pos, struct encrypted_process, list);
		pr_debug("fridgelock [%s] %s [%d] I am decrypting the mm_struct %p\n",
			__func__, t->comm, t->pid, t->mm);

		// decrypt all VMAs in process list
		freezer_secure_vm_areas(enc_proc->task, enc_proc->enc_proc, 0, tfm);
#ifdef CONFIG_RAMENC_DEBUG
		print_current_mm_struct(enc_proc->task);
#endif
		if(enc_proc->enc_proc->enc_vma) {
			proc_free_vmas(enc_proc->enc_proc->enc_vma);
			enc_proc->enc_proc->enc_vma = NULL;
		}
		if (enc_proc->enc_proc->pgs_list) {
			proc_free_pglist(enc_proc->enc_proc->pgs_list);
			enc_proc->enc_proc->pgs_list = NULL;
		}
		// free current_proc structure
		list_del(pos);
		kfree(enc_proc);
		enc_proc = NULL;
	}
	
	pos = NULL;
	tmp = NULL;

	ktime_get_real_ts64(&after);
	after_ms = 1000 * after.tv_sec + (after.tv_nsec / 1000000);

	printk(KERN_INFO "Total decryption time: %llums = ~ %llus\n", after_ms - before_ms, after.tv_sec - before.tv_sec);
	crypto_free_skcipher(tfm);
	tfm = NULL;

	return 0;
}

#endif
