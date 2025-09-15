/**
 * Output cr3 of all processes via /proc/uarf_cr3
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#define PROCFS_NAME "uarf_cr3"

static struct proc_dir_entry *proc_file;

#define PROCFS_BUF_SIZE 1024
static char buf[PROCFS_BUF_SIZE];

static int proc_open(__attribute((unused)) struct inode *inode,
                     __attribute((unused)) struct file *file) {
    pr_debug("Opened /proc/%s\n", PROCFS_NAME);
    return 0;
}

#include <asm/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched.h>

// Source: <https://carteryagemann.com/pid-to-cr3.html>
unsigned long pid_to_cr3(int pid) {
    struct task_struct *task;
    struct mm_struct *mm;
    void *cr3_virt;
    unsigned long cr3_phys;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);

    if (task == NULL)
        return 0; // pid has no task_struct

    mm = task->mm;

    // mm can be NULL in some rare cases (e.g. kthreads)
    // when this happens, we should check active_mm
    if (mm == NULL) {
        mm = task->active_mm;
    }

    if (mm == NULL)
        return 0; // this shouldn't happen, but just in case

    cr3_virt = (void *) mm->pgd;
    cr3_phys = virt_to_phys(cr3_virt);

    return cr3_phys;
}

static ssize_t proc_read(struct file *file, char __user *buffer, size_t length,
                         loff_t *offset) {
    pr_debug("Reading /proc/%s with offset %lld\n", PROCFS_NAME, *offset);
    pr_debug("Current /proc/%s content: %s\n", PROCFS_NAME, buf);

    size_t cr3_output_len = 0;
    struct task_struct *task;

    char *cr3_output = kmalloc(1024, GFP_KERNEL);
    if (!cr3_output) {
        return -ENOMEM;
    }

    // Handle the offset (for sequential reading)
    if (*offset > 0) {
        kfree(cr3_output);
        return 0;
    }

    for_each_process(task) {
        unsigned long cr3 = pid_to_cr3(task->pid);

        if (cr3) {
            cr3_output_len +=
                scnprintf(cr3_output + cr3_output_len, 1024 - cr3_output_len,
                          "%d, %s, 0x%lx\n", task->pid, task->comm, cr3);

            if (cr3_output_len >= 1024) {
                break;
            }
        }
    }

    if (length < cr3_output_len) {
        cr3_output_len = length;
    }

    if (copy_to_user(buffer, cr3_output, cr3_output_len)) {
        kfree(cr3_output);
        return -EFAULT;
    }

    *offset += cr3_output_len;

    kfree(cr3_output);

    return cr3_output_len; // Return the number of bytes read
}

static int proc_release(__attribute((unused)) struct inode *inode,
                        __attribute((unused)) struct file *file) {
    pr_debug("Closed /proc/%s\n", PROCFS_NAME);
    return 0;
}

static const struct proc_ops proc_file_fops = {
    .proc_open = proc_open,
    .proc_read = proc_read,
    .proc_release = proc_release,
};

static int __init uarf_cr3_init(void) {
    pr_info("Module proofs loaded\n");

    proc_file = proc_create(PROCFS_NAME, 0644, NULL, &proc_file_fops);
    if (!proc_file) {
        pr_alert("Could not initialize /proc/%s\n", PROCFS_NAME);
        return -ENOMEM;
    }

    pr_info("Created /proc/%s\n", PROCFS_NAME);
    return 0;
}

static void __exit uarf_cr3_exit(void) {
    pr_info("Module uarf_cr3 removed\n");
    proc_remove(proc_file);
    pr_info("Removed /proc/%s\n", PROCFS_NAME);
}

module_init(uarf_cr3_init);
module_exit(uarf_cr3_exit);

MODULE_LICENSE("GPL");
