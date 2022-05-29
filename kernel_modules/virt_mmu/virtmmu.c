#include "virtmmu.h"

MODULE_DESCRIPTION("Virtual MMU");
MODULE_AUTHOR("John");
MODULE_LICENSE("GPL");

const int VIRTMMU_MAJOR = 42;
const int VIRTMMU_MINOR = 0;

const struct file_operations virtmmu_ops = {
    .owner = THIS_MODULE,
    .open = virtmmu_open,
    .read = virtmmu_read,
};

struct virtmmu_device virtmmu_dev;

static int virtmmu_init(void) {
  int err;
  printk("Initializing virtual mmu\n");
  err = register_chrdev_region(MKDEV(VIRTMMU_MAJOR, 0), VIRTMMU_MINOR,
                               "virtmmu_driver");
  if (err != 0) {
    /* report error */
    printk("FUCK");
    return err;
  }

  cdev_init(&virtmmu_dev.cdev, &virtmmu_ops);
  cdev_add(&virtmmu_dev.cdev, MKDEV(VIRTMMU_MAJOR, 0), 1);
  return 0;
}

static void virtmmu_exit(void) { 
  printk("Exiting virtual mmu\n"); 
  cdev_del(&virtmmu_dev.cdev);
  unregister_chrdev_region(MKDEV(VIRTMMU_MAJOR, 0), VIRTMMU_MINOR);
}

static int virtmmu_open(struct inode *_inode, struct file *_file) {
  pid_t userpid;
  userpid = current->pid;
  printk("PID: %d\n", userpid);
  return 0;
}

static ssize_t virtmmu_read(struct file *file, char __user *user_buffer,
                            size_t size, loff_t *offset) {
  pid_t userpid;
  userpid = current->pid;
  return 0;
}

module_init(virtmmu_init);
module_exit(virtmmu_exit);
