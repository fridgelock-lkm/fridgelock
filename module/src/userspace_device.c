#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/freezer.h>
#include <linux/sched/signal.h>
#include <linux/mutex.h>
#include <linux/slab.h>
//#include <linux/sched.h>

#include "userspace_device.h"

#define DRIVER_NAME "ramenc"
#define BUF_SIZE 256

//static ssize_t recv_password(struct file *, const char __user *, size_t, loff_t *);
static ssize_t write_response(struct file *, char __user *, size_t, loff_t *);
static long device_ioctl(struct file *, unsigned int, unsigned long);
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);

static dev_t dev;
static struct cdev cdev;
static struct class* class;
struct task_struct *resume_task = NULL;
static int device_created = 0;
extern wait_queue_head_t resume_queue;

int resume_ready = 0;
int resume_done = 0;
int paths_received = 0;
int userspace_thawed = 0;

char *cryptdevice_paths = NULL;
unsigned short cryptdevice_paths_len = 0;

static struct file_operations fops = {
	//.write = recv_password,
	.read = write_response,
	.open = device_open,
	.release = device_release,
	.unlocked_ioctl = device_ioctl,
	//.release: device_release
};

int userspace_device_init(void)
{
	printk(KERN_INFO "[fridgelock] Initializing userspace driver\n");

	if (alloc_chrdev_region(&dev , 0, 1, DRIVER_NAME) < 0)
		goto error;
	//printk(KERN_INFO "[fridgelock] Allocated userspace character device: (Major/Minor) (%d/%d)", MAJOR(dev), MINOR(dev));
	if ((class = class_create(THIS_MODULE, DRIVER_NAME)) == NULL)
		goto error;
	cdev_init(&cdev, &fops);
	if (device_create(class, NULL, dev, NULL, DRIVER_NAME) == NULL)
		goto error;
	device_created = 1;

	if (cdev_add(&cdev, dev, 1) == -1)
		goto error;
	
	return 0;
error:
	userspace_device_cleanup();
	return -1;
}

void userspace_device_cleanup(void)
{
	if (device_created) {
		device_destroy(class, dev);
		cdev_del(&cdev);
	}
	if (class)
		class_destroy(class);
	if (MAJOR(dev) > 0)
		unregister_chrdev_region(dev, 1);
}

static int handle_devices_received(char __user *buf)
{
	unsigned long r;
	unsigned short len;
	r = copy_from_user(&len, buf, sizeof(len));
	if (r) {
		printk(KERN_INFO "failed to retrieve cryptdevice path buffer length\n");
		return -1;
	}
	
	if (cryptdevice_paths)
		kfree(cryptdevice_paths);

	cryptdevice_paths = kmalloc(len, GFP_KERNEL);
	if (cryptdevice_paths == NULL) {
		printk(KERN_INFO "failed to allocate cryptdevice path buffer\n");
		return -1;
	}

	cryptdevice_paths_len = len;

	r = copy_from_user(cryptdevice_paths, buf + sizeof(len), len);
	if (r) {
		printk(KERN_INFO "failed to retrieve cryptdevice path buffer\n");
		return -1;
	}

	return 0;
}

static long device_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	printk(KERN_INFO "[fridgelock] Inside ioctl. cmd: %d arg: %ld", cmd, arg);

	switch (cmd) {
	/* TODO: Wrap this magic number in an enum */
	case 0:
		printk(KERN_INFO "Putting resumer to sleep now\n");
		wait_event_interruptible(resume_queue, (resume_ready == 1));
		printk(KERN_INFO "Resumer woke up from sleep\n");
		break;
	case 1:
		/* Done with resuming partitions */
		resume_done = 1;
		wake_up_interruptible(&resume_queue);
		userspace_thawed = 0;
		printk(KERN_INFO "[fridgelock] Waiting for resumer to finish\n");
		wait_event_interruptible(resume_queue, (userspace_thawed == 1));
		printk(KERN_INFO "[fridgelock] Resumer finished!\n");
		break;
	case 1337:
		/* retrieve devices to suspend */
		resume_task = current;
		handle_devices_received((char *) arg);
		printk(KERN_INFO "Paths received\n");
		paths_received = 1;
		wake_up_interruptible(&resume_queue);
		printk(KERN_INFO "Woke up\n");
		break;
	case 3:
		/* retrieve passphrase */
		break;
	}

	return 0;
}

static int device_open(struct inode *i, struct file *f)
{
	printk(KERN_INFO "[fridgelock] Inside device_open\n");
	/* Don't freeze our userspace tasks */
	current->flags |= PF_NOFREEZE;
	return 0;
}

static int device_release(struct inode *i, struct file *f) {
	printk(KERN_INFO "[fridgelock] Inside device_close\n");
	return 0;
}

/* Unnecessary */
static ssize_t write_response (struct file *filp, char __user *buf, size_t len, loff_t *offset)
{
	return -1;
} 
/*
static ssize_t recv(struct file *filp, const char __user *buf, size_t len, loff_t *offset)
{
	int r;
	char *recv_buf;
	printk(KERN_INFO "[fridgelock] Writing to this device..\n");
	recv_buf = kmalloc(len, GFP_KERNEL);
	r = copy_from_user(recv_buf, buf, len);

	if (r < 0)
		printk(KERN_INFO "[fridgelock] ERROR: Could not copy from user to kernel space");
		//TODO: BUG()
	
	



	return r;
}
*/
