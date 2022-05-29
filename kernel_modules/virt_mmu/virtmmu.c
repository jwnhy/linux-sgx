#include "virtmmu.h"

MODULE_DESCRIPTION("Virtual MMU");
MODULE_AUTHOR("John");
MODULE_LICENSE("GPL");

const int VIRTMMU_MAJOR = 42;
const int VIRTMMU_MINOR = 0;
const int PAGESIZE = 4096;
const int PTESIZE = 8;

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
    printk("Initialization failed\n");
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

static ssize_t virtmmu_read(struct file *file, char __user *userbuffer,
                            size_t size, loff_t *ptoff) {
  uint64_t *pagebuffer, virtaddr, physaddr;
  size_t pagecnt, i;
  spinlock_t *ptl;
  pte_t *ptep, pte;
  struct mm_struct *mm;
  pagebuffer = (uint64_t *)userbuffer;

  printk("Size: %lx\n", size);

  mm = current->mm;
  virtaddr = *ptoff * PAGESIZE / PTESIZE;
  pagebuffer = (uint64_t *)userbuffer;
  pagecnt = size / PTESIZE;
  for (i = 0; i < pagecnt; i++) {
    if (follow_pte(mm, virtaddr, &ptep, &ptl)) {
      put_user(0x0, &pagebuffer[i]);
    } else {
      pte = *ptep;
      physaddr = pte_pfn(pte) << PAGE_SHIFT;
      put_user(physaddr, &pagebuffer[i]);
      pte_unmap_unlock(ptep, ptl);
    }
    virtaddr += PAGESIZE;
  }
  return pagecnt * sizeof(uint64_t);
}

module_init(virtmmu_init);
module_exit(virtmmu_exit);
