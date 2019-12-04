#ifndef _USERSPACE_DEVICE_H_
#define _USERSPACE_DEVICE_H_

#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>

int userspace_device_init(void);
void userspace_device_cleanup(void);

#endif
