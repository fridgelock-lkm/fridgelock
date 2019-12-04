#ifndef _MM_CRYPT_H
#define _MM_CRYPT_H

#define CONFIG_RAMENC
//#define CONFIG_RAMENC_DEBUG

#ifdef CONFIG_RAMENC
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>
#include <linux/semaphore.h>
#include <linux/ktime.h>
#include <linux/mman.h>
#include <linux/scatterlist.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/page-flags.h>
#include <linux/completion.h>
#include <linux/rmap.h>
#include <linux/hardirq.h>
#include <linux/pagemap.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/mm.h>
#endif

extern struct crypto_skcipher *tfm;
extern unsigned long thaw_start_time;

extern char *encdec_key;
extern unsigned int key_len;

extern int resolve_functions(void);
extern int encrypt_processes(void);
extern int decrypt_processes(void);

/*
 * Keylength depending on AES128/256 and a default key if none is set
 * TODO: in productive systems, remove the test key, zero out the key after enc/dec
 * and enforce that a key different to the zero-byte sequence is set.
 */
#ifndef CONFIG_RAMENC_AES_128
#define KEY_LEN 32
#else
#define KEY_LEN 16
#endif

#define IV_LEN 16

#ifdef CONFIG_RAMENC_SINGLE_BLKCIPH
#define CRYPT_ALG "xts(aes)"
#else
#define CRYPT_ALG "xts(aes)"
#endif

#define DEFAULT_SEGMENTS 0x0

#define MAX_SG 128

/*
 * For each VMA (struct enc_vma_list), we store its type based on that enum.
 * This meta data can help us to treat the types differently during encryption, which is however not required
 * at the moment. Furthermore, we use the types for our performance profiling measurements.
 * The difference to the flags below is that we can further differentiate between the segments
 * to be encrypted. For example, THREAD_STACK is the currently only one, which is implicitly included
 * when selecting the stack segment from user space
 */
typedef enum mem_segment {
	TEXT_SEG = 0,
	DATA_SEG,
	STACK_SEG,
	HEAP_SEG,
	ANON_SEG,
	FILE_SEG,
	THREAD_STACK_SEG
} mem_segment_t;

/*
 * We write a hex key to the segments file from user space, which we parse to a char.
 * Depending on the bits set in the char, we use the flags below to recognize which segments we encrypt.
 * The system initializes to 0 by default, such that non-encrypting freezer cgroups
 * work as usual. Memory section selection bit layout.
 *
 * FILE  ANON  HEAP  STACK  DATA  TEXT
 *   5     4     3     2      1    0
 *
 * To encrypt all segments, write 3f (111111) to the segments file.
 */
#define TEXT_FLAG (1<<TEXT_SEG)
#define DATA_FLAG (1<<DATA_SEG)
#define STCK_FLAG (1<<STACK_SEG)
#define HEAP_FLAG (1<<HEAP_SEG)
#define ANON_FLAG (1<<ANON_SEG)
#define FILE_FLAG (1<<FILE_SEG)

#ifdef CONFIG_RAMENC_PERF_PROFILING
/*
 * Statistics for a process including its threads.
 */
struct perf_members_proc {
	int    encrypting_pid;
	int    num_vma;
	int    num_vma_total;
	long   num_present_pgs;
	long   num_total_pgs;
	long   num_pgs_skipped;
	long   num_cow_pgs;
	long   num_enc_dec_pgs;
};

/*
 * Statistics for an encrypting VMA
 */
struct perf_members_vma {
	long num_present_pgs;
	long num_enc_dec_pgs;
};
#endif

/*
 * List of VMAs beloning to a process to be encrypted.
 * This list represents the VMAs belonging to the previously
 * selected memory segments.
 */
typedef struct enc_vma_list {
#ifdef CONFIG_RAMENC_PERF_PROFILING
	struct perf_members_vma perf;
#endif
	bool was_not_writable;
	mem_segment_t segment;
	struct vm_area_struct *vma_ref;
        struct enc_vma_list *next;
} enc_vma_list_t;

typedef struct enc_pgs_list {
	struct page *page;
	bool was_clean;
	struct vm_area_struct *vma_ref;
	bool was_young;
	bool avoid_pgft;
	pte_t *pte;
	struct enc_pgs_list *next;
	int counter;
} enc_pgs_list_t;

/*
 * A process to encrypted. This struct is also associated with
 * the encrypting threads.
 */
typedef struct enc_process {
#ifdef CONFIG_RAMENC_PERF_PROFILING
	struct perf_members_proc perf;
#endif
        enc_vma_list_t *enc_vma;
        int    is_encrypted;
	enc_pgs_list_t *pgs_list;
	long total_enc_pgs;
} enc_process_t;

pte_t* __get_pte(struct task_struct *task, struct mm_struct* mm, unsigned long addr);
bool __mk_pte_writable(struct task_struct *task, struct vm_area_struct* vma, pte_t* pte, unsigned long address);
bool __mk_pte_wrprotected(struct task_struct *task, struct vm_area_struct *vma, pte_t* pte, unsigned long address,
                          bool was_rdonly, bool was_clean, bool was_young);
#ifdef CONFIG_RAMENC_DEBUG
void print_current_mm_struct(struct task_struct *task);
void print_vm_area_struct(struct task_struct *task, struct vm_area_struct *vma);
void print_pte(struct task_struct *task, pte_t *pte, struct vm_area_struct *vma, int num_iter);

#endif
#endif /* _LINUX_MM_CRYPT_H  */
