#ifndef VIRTMMU__
#define VIRTMMU__

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>

struct virtmmu_device {
  struct cdev cdev;
};

static int virtmmu_open(struct inode* _inode, struct file* _file);

static ssize_t virtmmu_read(struct file *file, char __user *user_buffer, size_t size, loff_t *offset);
#endif
