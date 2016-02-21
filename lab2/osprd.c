#include <linux/version.h>
#include <linux/autoconf.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/sched.h>
#include <linux/kernel.h>  /* printk() */
#include <linux/errno.h>   /* error codes */
#include <linux/types.h>   /* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/wait.h>
#include <linux/file.h>

#include "spinlock.h"
#include "osprd.h"

/* The size of an OSPRD sector. */
#define SECTOR_SIZE	512

/* This flag is added to an OSPRD file's f_flags to indicate that the file
 * is locked. */
#define F_OSPRD_LOCKED	0x80000

/* eprintk() prints messages to the console.
 * (If working on a real Linux machine, change KERN_NOTICE to KERN_ALERT or
 * KERN_EMERG so that you are sure to see the messages.  By default, the
 * kernel does not print all messages to the console.  Levels like KERN_ALERT
 * and KERN_EMERG will make sure that you will see messages.) */
#define eprintk(format, ...) printk(KERN_NOTICE format, ## __VA_ARGS__)

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("CS 111 RAM Disk");
// EXERCISE: Pass your names into the kernel as the module's authors.
MODULE_AUTHOR("Richard Sun");
MODULE_AUTHOR("Michael Li");

#define OSPRD_MAJOR	222

/* This module parameter controls how big the disk will be.
 * You can specify module parameters when you load the module,
 * as an argument to insmod: "insmod osprd.ko nsectors=4096" */
static int nsectors = 32;
module_param(nsectors, int, 0);


/* Linked list for locking pids */
typedef struct node {
	struct node *next;
	unsigned pid;
} node_t;

typedef struct linked_list {
	node_t *head;
	node_t *tail;
	unsigned size;
} linked_list_t;

void linked_list_init(linked_list_t *ll) {
	ll->head = ll->tail = NULL;
	ll->size = 0;
}

void linked_list_push(linked_list_t *ll, unsigned pid) {
	node_t *new_node = (node_t*)kmalloc(sizeof(node_t), GFP_ATOMIC);
	new_node->next = NULL;
	new_node->pid = pid;
	if (ll->tail) {
		ll->tail->next = new_node;
	} else {
		ll->head = new_node;
	}
	ll->tail = new_node;
	ll->size++;
}

unsigned linked_list_pop(linked_list_t *ll) {
	if (!ll->head) {
		return 0;
	}
	node_t *old_head = ll->head;
	unsigned old_pid = old_head->pid;
	ll->head = ll->head->next;
	kfree(old_head);
	ll->size--;
	eprintk("dec size: %d\n", ll->size);
	return old_pid;
}

void linked_list_free(linked_list_t *ll) {
	node_t *curr = ll->head;
	node_t *next;
	while (curr) {
		next = curr->next;
		kfree(curr);
		curr = next;
	}
}

int linked_list_remove(linked_list_t *ll, unsigned pid) {
	// iterate through list and check node's pid against parameter
	node_t *prevNode = NULL;
	node_t *currNode = ll->head;
	while (currNode != NULL) {
		if (currNode->pid == pid) {
			node_t *del = currNode;
			if (currNode == ll->tail)
				ll->tail = prevNode;
			currNode = currNode->next;
			if (prevNode != NULL) {
				// not first node
				prevNode->next = currNode;
			}
			else {
				// removing first node
				ll->head = currNode;
			}

			ll->size--;
			kfree(del);

			return 1;
		}
		prevNode = currNode;
		currNode = currNode->next;
	}
	// pid not found
	return 0;
}

int linked_list_count(linked_list_t *ll, int pid) {
	node_t *curr = ll->head;
	while (curr) {
		if (curr->pid == pid)
			return 1;
		curr = curr->next;
	}
	return 0;
}

int return_valid_ticket(linked_list_t *invalid_tickets, int ticket_tail) {
	while (++ticket_tail) {
		if (linked_list_count(invalid_tickets, ticket_tail))
			linked_list_remove(invalid_tickets, ticket_tail);
		else
			break;
	}
	return ticket_tail;
}


/* Design problem: crypto code */

uint8_t jenkins_hash(char *passwd) {
	uint32_t hash = 0;
	int i;
	for (i = 0; passwd[i] != '\0'; i++) {
		hash += passwd[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return (uint8_t)(hash & 0xFF);
}

void xor_cipher(char *buf, size_t len, uint8_t hash) {
	size_t i;
	for (i = 0; i < len; i++) {
		/* extract one byte of the hash */
		//int shift = (i % sizeof(uint32_t)) * 8;
		//char hash_byte = (hash >> shift) & 0xFF;

		//dest[i] = src[i] ^ hash;
		buf[i] ^= hash;
	}
}

/* The internal representation of our device. */
typedef struct osprd_info {
	uint8_t *data;                  // The data array. Its size is
	                                // (nsectors * SECTOR_SIZE) bytes.

	osp_spinlock_t mutex;           // Mutex for synchronizing access to
					// this block device

	unsigned ticket_head;		// Currently running ticket for
					// the device lock

	unsigned ticket_tail;		// Next available ticket for
					// the device lock

	wait_queue_head_t blockq;       // Wait queue for tasks blocked on
					// the device lock

	/* HINT: You may want to add additional fields to help
	         in detecting deadlock. */

	linked_list_t read_locking_pids;
	unsigned write_locking_pid;
	linked_list_t invalid_tickets;

	uint8_t passwd_hash;

	// The following elements are used internally; you don't need
	// to understand them.
	struct request_queue *queue;    // The device request queue.
	spinlock_t qlock;		// Used internally for mutual
	                                //   exclusion in the 'queue'.
	struct gendisk *gd;             // The generic disk.
} osprd_info_t;

#define NOSPRD 4
static osprd_info_t osprds[NOSPRD];


// Declare useful helper functions

/*
 * file2osprd(filp)
 *   Given an open file, check whether that file corresponds to an OSP ramdisk.
 *   If so, return a pointer to the ramdisk's osprd_info_t.
 *   If not, return NULL.
 */
static osprd_info_t *file2osprd(struct file *filp);

/*
 * for_each_open_file(task, callback, user_data)
 *   Given a task, call the function 'callback' once for each of 'task's open
 *   files.  'callback' is called as 'callback(filp, user_data)'; 'filp' is
 *   the open file, and 'user_data' is copied from for_each_open_file's third
 *   argument.
 */
static void for_each_open_file(struct task_struct *task,
			       void (*callback)(struct file *filp,
						osprd_info_t *user_data),
			       osprd_info_t *user_data);


/*
 * osprd_process_request(d, req)
 *   Called when the user reads or writes a sector.
 *   Should perform the read or write, as appropriate.
 */
static void osprd_process_request(osprd_info_t *d, struct request *req)
{
	if (!blk_fs_request(req)) {
		end_request(req, 0);
		return;
	}

	// EXERCISE: Perform the read or write request by copying data between
	// our data array and the request's buffer.
	// Hint: The 'struct request' argument tells you what kind of request
	// this is, and which sectors are being read or written.
	// Read about 'struct request' in <linux/blkdev.h>.
	// Consider the 'req->sector', 'req->current_nr_sectors', and
	// 'req->buffer' members, and the rq_data_dir() function.

	// Your code here.
	unsigned request_type;
	uint8_t *data_ptr;
	request_type = rq_data_dir(req);
	data_ptr = d->data + req->sector * SECTOR_SIZE;
	eprintk("passwd_hash: %d\n", d->passwd_hash);
	if (request_type == READ) {
		memcpy((void*)req->buffer, (void*)data_ptr,
			req->current_nr_sectors * SECTOR_SIZE);
	}
	else if (request_type == WRITE) {
		memcpy((void*)data_ptr, (void*)req->buffer,
			req->current_nr_sectors * SECTOR_SIZE);
	}
	eprintk("Should process request...\n");

	end_request(req, 1);
}


// This function is called when a /dev/osprdX file is opened.
// You aren't likely to need to change this.
static int osprd_open(struct inode *inode, struct file *filp)
{
	// Always set the O_SYNC flag. That way, we will get writes immediately
	// instead of waiting for them to get through write-back caches.
	filp->f_flags |= O_SYNC;
	return 0;
}


// This function is called when a /dev/osprdX file is finally closed.
// (If the file descriptor was dup2ed, this function is called only when the
// last copy is closed.)
static int osprd_close_last(struct inode *inode, struct file *filp)
{
	if (filp) {
		osprd_info_t *d = file2osprd(filp);
		//int filp_writable = filp->f_mode & FMODE_WRITE;

		// EXERCISE: If the user closes a ramdisk file that holds
		// a lock, release the lock.  Also wake up blocked processes
		// as appropriate.

		// Your code here.
		osprd_ioctl(inode, filp, OSPRDIOCRELEASE, 0);
	}
	
	return 0;
}


/*
 * osprd_lock
 */

/*
 * osprd_ioctl(inode, filp, cmd, arg)
 *   Called to perform an ioctl on the named file.
 */
int osprd_ioctl(struct inode *inode, struct file *filp,
		unsigned int cmd, char *passwd)
{
	osprd_info_t *d = file2osprd(filp);	// device info
	int r = 0;			// return value: initially 0

	// is file open for writing?
	int filp_writable = (filp->f_mode & FMODE_WRITE) != 0;

	// This line avoids compiler warnings; you may remove it.
	(void) filp_writable, (void) d;

	// Set 'r' to the ioctl's return value: 0 on success, negative on error
	eprintk("cmd: %d\n", cmd);

	if (cmd == OSPRDIOCACQUIRE) {

		// EXERCISE: Lock the ramdisk.
		//
		// If *filp is open for writing (filp_writable), then attempt
		// to write-lock the ramdisk; otherwise attempt to read-lock
		// the ramdisk.
		//
                // This lock request must block using 'd->blockq' until:
		// 1) no other process holds a write lock;
		// 2) either the request is for a read lock, or no other process
		//    holds a read lock; and
		// 3) lock requests should be serviced in order, so no process
		//    that blocked earlier is still blocked waiting for the
		//    lock.
		//
		// If a process acquires a lock, mark this fact by setting
		// 'filp->f_flags |= F_OSPRD_LOCKED'.  You also need to
		// keep track of how many read and write locks are held:
		// change the 'osprd_info_t' structure to do this.
		//
		// Also wake up processes waiting on 'd->blockq' as needed.
		//
		// If the lock request would cause a deadlock, return -EDEADLK.
		// If the lock request blocks and is awoken by a signal, then
		// return -ERESTARTSYS.
		// Otherwise, if we can grant the lock request, return 0.

		// 'd->ticket_head' and 'd->ticket_tail' should help you
		// service lock requests in order.  These implement a ticket
		// order: 'ticket_tail' is the next ticket, and 'ticket_head'
		// is the ticket currently being served.  You should set a local
		// variable to 'd->ticket_head' and increment 'd->ticket_head'.
		// Then, block at least until 'd->ticket_tail == local_ticket'.
		// (Some of these operations are in a critical section and must
		// be protected by a spinlock; which ones?)

		// Your code here (instead of the next two lines).
		eprintk("Attempting to acquire\n");
		unsigned my_ticket;
		// check deadlock protection
		osp_spin_lock(&d->mutex);
		if (d->write_locking_pid == current->pid) {
			osp_spin_unlock(&d->mutex);
			return -EDEADLK;
		}
		my_ticket = d->ticket_head;
		d->ticket_head++;
		osp_spin_unlock(&d->mutex);
		eprintk("pid = %d\n", current->pid);

		if (filp_writable) {
			eprintk("write %d\n", d->write_locking_pid);
			// write lock
			if (wait_event_interruptible(d->blockq,
				(eprintk("write locking: %d\nticket_tail: %d\nmy_ticket: %d\nsize: %d\n", d->write_locking_pid, d->ticket_tail, my_ticket, d->read_locking_pids.size) || 1)
				&&   d->ticket_tail == my_ticket
				&& d->write_locking_pid == 0
				&& d->read_locking_pids.size == 0
				)) {
				eprintk("wait_event_interruptible: %d\n", current->pid);
				//osp_spin_lock(&d->mutex);
				// if blocked
				if(d->ticket_tail == my_ticket) {
					// this process is being served
					d->ticket_tail = return_valid_ticket(
						&d->invalid_tickets, d->ticket_tail);
					wake_up_all(&d->blockq);
				}
				else {
					// not being served

					// add spin lock for good measure
					osp_spin_lock(&d->mutex);
					linked_list_push(&d->invalid_tickets, my_ticket);
					osp_spin_unlock(&d->mutex);
				}
				//osp_spin_unlock(&d->mutex);
				return -ERESTARTSYS;
			}
			else {
				// acquire the lock
				eprintk("acquire write lock\n");
				osp_spin_lock(&d->mutex);
				filp->f_flags |= F_OSPRD_LOCKED;
				d->write_locking_pid = current->pid;
				d->ticket_tail = return_valid_ticket(
					&d->invalid_tickets, d->ticket_tail);
				osp_spin_unlock(&d->mutex);
				wake_up_all(&d->blockq);
				return 0;
			}
		}
		else {
			//read lock
			eprintk("read\n");
			if (wait_event_interruptible(d->blockq,
				(eprintk("read locking size: %d\nticket_tail: %d\nmy_ticket: %d\n", d->read_locking_pids.size, d->ticket_tail, my_ticket) || 1)
				&&   d->ticket_tail == my_ticket
				&& d->write_locking_pid == 0)) {
				//osp_spin_lock(&d->mutex);
				// if blocked
				if(d->ticket_tail == my_ticket) {
					// this process is being served
					d->ticket_tail = return_valid_ticket(
						&d->invalid_tickets, d->ticket_tail);
					wake_up_all(&d->blockq);
				}
				else {
					// not being served

					// add spin lock for good measure
					osp_spin_lock(&d->mutex);
					linked_list_push(&d->invalid_tickets, my_ticket);
					osp_spin_unlock(&d->mutex);
				}
				//osp_spin_unlock(&d->mutex);
				return -ERESTARTSYS;
			}
			else {
				// acquire the lock
				eprintk("read lock\n");
				osp_spin_lock(&d->mutex);
				filp->f_flags |= F_OSPRD_LOCKED;
				linked_list_push(&d->read_locking_pids, current->pid);
				d->ticket_tail = return_valid_ticket(
					&d->invalid_tickets, d->ticket_tail);
				osp_spin_unlock(&d->mutex);
				wake_up_all(&d->blockq);
				return 0;
			}
		}

	} else if (cmd == OSPRDIOCTRYACQUIRE) {

		// EXERCISE: ATTEMPT to lock the ramdisk.
		//
		// This is just like OSPRDIOCACQUIRE, except it should never
		// block.  If OSPRDIOCACQUIRE would block or return deadlock,
		// OSPRDIOCTRYACQUIRE should return -EBUSY.
		// Otherwise, if we can grant the lock request, return 0.

		// Your code here (instead of the next two lines).
		eprintk("Attempting to try acquire\n");
		if (filp_writable) {
			osp_spin_lock(&d->mutex);
			if (d->write_locking_pid != 0 || d->read_locking_pids.size != 0) {
				osp_spin_unlock(&d->mutex);
				return -EBUSY;
			}
			filp->f_flags |= F_OSPRD_LOCKED;
			d->write_locking_pid = current->pid;
			osp_spin_unlock(&d->mutex);
			return 0;
		}
		else {
			osp_spin_lock(&d->mutex);
			if (d->write_locking_pid != 0) {
				osp_spin_unlock(&d->mutex);
				return -EBUSY;
			}
			filp->f_flags |= F_OSPRD_LOCKED;
			linked_list_push(&d->read_locking_pids, current->pid);
			osp_spin_unlock(&d->mutex);
			return 0;
		}

	} else if (cmd == OSPRDIOCRELEASE) {

		// EXERCISE: Unlock the ramdisk.
		//
		// If the file hasn't locked the ramdisk, return -EINVAL.
		// Otherwise, clear the lock from filp->f_flags, wake up
		// the wait queue, perform any additional accounting steps
		// you need, and return 0.

		// Your code here (instead of the next line).
		if (!(filp->f_flags & F_OSPRD_LOCKED)) {
			// ramdisk isn't locked
			return -EINVAL;
		}
		if (filp_writable) {
			// see if this process has write lock
			osp_spin_lock(&d->mutex);
			if (d->write_locking_pid != current->pid) {
				return -EINVAL;
			}
			eprintk("release\n");
			d->write_locking_pid = 0;
			if (d->read_locking_pids.size == 0) {
				eprintk("unsetting flag\n");
				filp->f_flags ^= F_OSPRD_LOCKED;
			}
			osp_spin_unlock(&d->mutex);
			wake_up_all(&d->blockq);
			return 0;
		}
		else {
			eprintk("!!!!!reached\n");
			if (d->read_locking_pids.size == 0) {
				return -EINVAL;
			}
			osp_spin_lock(&d->mutex);
			int removeStatus = linked_list_remove(&d->read_locking_pids, current->pid);
			eprintk("%d\n", removeStatus);
			if (removeStatus) {
				if (d->read_locking_pids.size == 0 && d->write_locking_pid == 0) {
					filp->f_flags ^= F_OSPRD_LOCKED;
				}
				wake_up_all(&d->blockq);
				//return 0;
			}
			osp_spin_unlock(&d->mutex);
			return removeStatus ? 0 : -EINVAL;
		}

	}
	else if (cmd == OSPRDIOCPASSWD) {
		char *buf = (char*)kmalloc(20, GFP_ATOMIC);
		if (copy_from_user(buf, (const char __user*) passwd, 20)) {
			kfree(buf);
			return -EFAULT;
		}
		d->passwd_hash = jenkins_hash(buf);
		eprintk("OSPRDIOCPASSWD: %d\n", d->passwd_hash);
		return 0;
	}
	else {
		r = -ENOTTY; /* unknown command */
		eprintk("not recognized\n");
	}
	return r;
}


// Initialize internal fields for an osprd_info_t.

static void osprd_setup(osprd_info_t *d)
{
	/* Initialize the wait queue. */
	init_waitqueue_head(&d->blockq);
	osp_spin_lock_init(&d->mutex);
	d->ticket_head = d->ticket_tail = 0;
	/* Add code here if you add fields to osprd_info_t. */
	linked_list_init(&d->read_locking_pids);
	linked_list_init(&d->invalid_tickets);
	d->write_locking_pid = 0;
	d->passwd_hash = 0;
}


/*****************************************************************************/
/*         THERE IS NO NEED TO UNDERSTAND ANY CODE BELOW THIS LINE!          */
/*                                                                           */
/*****************************************************************************/

// Process a list of requests for a osprd_info_t.
// Calls osprd_process_request for each element of the queue.

static void osprd_process_request_queue(request_queue_t *q)
{
	osprd_info_t *d = (osprd_info_t *) q->queuedata;
	struct request *req;

	while ((req = elv_next_request(q)) != NULL)
		osprd_process_request(d, req);
}


// Some particularly horrible stuff to get around some Linux issues:
// the Linux block device interface doesn't let a block device find out
// which file has been closed.  We need this information.

static struct file_operations osprd_blk_fops;
static int (*blkdev_release)(struct inode *, struct file *);
static ssize_t (*blkdev_read)(struct file *, char __user *, size_t, loff_t *);
static ssize_t (*blkdev_write)(struct file *, char __user *, size_t, loff_t *);

static int _osprd_release(struct inode *inode, struct file *filp)
{
	if (file2osprd(filp))
		osprd_close_last(inode, filp);
	return (*blkdev_release)(inode, filp);
}

static ssize_t _osprd_read(struct file *filp, char __user *usr, size_t size,
			loff_t *loff) {
	ssize_t ret = (*blkdev_read)(filp, usr, size, loff);
	osprd_info_t *d = file2osprd(filp);
	if (!d)
		return ret;

	char *buf = (char*)kmalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	int copy_ret = copy_from_user(buf, usr, size);
	if (copy_ret < 0) {
		kfree(buf);
		return -1;
	}

	xor_cipher(buf, size, d->passwd_hash);
	
	copy_ret = copy_to_user(usr, buf, size);
	kfree(buf);
	if(copy_ret)
		return -1;
	return ret;
}

static ssize_t _osprd_write(struct file *filp, char __user *usr, size_t size,
			loff_t *loff) {
	ssize_t ret = (*blkdev_write)(filp, usr, size, loff);
	osprd_info_t *d = file2osprd(filp);
	if (!d)
		return ret;

	char *buf  = (char*)kmalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	int copy_ret = copy_from_user(buf, usr, size);
	if (copy_ret) {
		kfree(buf);
		return -1;
	}

	xor_cipher(buf, size, d->passwd_hash);

	copy_ret = copy_to_user(usr, buf, size);
	kfree(buf);
	if (copy_ret)
		return -1;
	return ret;
}

static int _osprd_open(struct inode *inode, struct file *filp)
{
	if (!osprd_blk_fops.open) {
		memcpy(&osprd_blk_fops, filp->f_op, sizeof(osprd_blk_fops));

		blkdev_release = osprd_blk_fops.release;
		osprd_blk_fops.release = _osprd_release;

		blkdev_read = osprd_blk_fops.read;
		osprd_blk_fops.read = _osprd_read;

		blkdev_write = osprd_blk_fops.write;
		osprd_blk_fops.write = _osprd_write;
	}
	filp->f_op = &osprd_blk_fops;
	return osprd_open(inode, filp);
}


// The device operations structure.

static struct block_device_operations osprd_ops = {
	.owner = THIS_MODULE,
	.open = _osprd_open,
	// .release = osprd_release, // we must call our own release
	.ioctl = osprd_ioctl
};


// Given an open file, check whether that file corresponds to an OSP ramdisk.
// If so, return a pointer to the ramdisk's osprd_info_t.
// If not, return NULL.

static osprd_info_t *file2osprd(struct file *filp)
{
	if (filp) {
		struct inode *ino = filp->f_dentry->d_inode;
		if (ino->i_bdev
		    && ino->i_bdev->bd_disk
		    && ino->i_bdev->bd_disk->major == OSPRD_MAJOR
		    && ino->i_bdev->bd_disk->fops == &osprd_ops)
			return (osprd_info_t *) ino->i_bdev->bd_disk->private_data;
	}
	return NULL;
}


// Call the function 'callback' with data 'user_data' for each of 'task's
// open files.

static void for_each_open_file(struct task_struct *task,
		  void (*callback)(struct file *filp, osprd_info_t *user_data),
		  osprd_info_t *user_data)
{
	int fd;
	task_lock(task);
	spin_lock(&task->files->file_lock);
	{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 13)
		struct files_struct *f = task->files;
#else
		struct fdtable *f = task->files->fdt;
#endif
		for (fd = 0; fd < f->max_fds; fd++)
			if (f->fd[fd])
				(*callback)(f->fd[fd], user_data);
	}
	spin_unlock(&task->files->file_lock);
	task_unlock(task);
}


// Destroy a osprd_info_t.

static void cleanup_device(osprd_info_t *d)
{
	wake_up_all(&d->blockq);
	if (d->gd) {
		del_gendisk(d->gd);
		put_disk(d->gd);
	}
	if (d->queue)
		blk_cleanup_queue(d->queue);
	if (d->data)
		vfree(d->data);

	linked_list_free(&d->read_locking_pids);
	linked_list_free(&d->invalid_tickets);
}


// Initialize a osprd_info_t.

static int setup_device(osprd_info_t *d, int which)
{
	memset(d, 0, sizeof(osprd_info_t));

	/* Get memory to store the actual block data. */
	if (!(d->data = vmalloc(nsectors * SECTOR_SIZE)))
		return -1;
	memset(d->data, 0, nsectors * SECTOR_SIZE);

	/* Set up the I/O queue. */
	spin_lock_init(&d->qlock);
	if (!(d->queue = blk_init_queue(osprd_process_request_queue, &d->qlock)))
		return -1;
	blk_queue_hardsect_size(d->queue, SECTOR_SIZE);
	d->queue->queuedata = d;

	/* The gendisk structure. */
	if (!(d->gd = alloc_disk(1)))
		return -1;
	d->gd->major = OSPRD_MAJOR;
	d->gd->first_minor = which;
	d->gd->fops = &osprd_ops;
	d->gd->queue = d->queue;
	d->gd->private_data = d;
	snprintf(d->gd->disk_name, 32, "osprd%c", which + 'a');
	set_capacity(d->gd, nsectors);
	add_disk(d->gd);

	/* Call the setup function. */
	osprd_setup(d);

	return 0;
}

static void osprd_exit(void);


// The kernel calls this function when the module is loaded.
// It initializes the 4 osprd block devices.

static int __init osprd_init(void)
{
	int i, r;

	// shut up the compiler
	(void) for_each_open_file;
#ifndef osp_spin_lock
	(void) osp_spin_lock;
	(void) osp_spin_unlock;
#endif

	/* Register the block device name. */
	if (register_blkdev(OSPRD_MAJOR, "osprd") < 0) {
		printk(KERN_WARNING "osprd: unable to get major number\n");
		return -EBUSY;
	}

	/* Initialize the device structures. */
	for (i = r = 0; i < NOSPRD; i++)
		if (setup_device(&osprds[i], i) < 0)
			r = -EINVAL;

	if (r < 0) {
		printk(KERN_EMERG "osprd: can't set up device structures\n");
		osprd_exit();
		return -EBUSY;
	} else
		return 0;
}


// The kernel calls this function to unload the osprd module.
// It destroys the osprd devices.

static void osprd_exit(void)
{
	int i;
	for (i = 0; i < NOSPRD; i++)
		cleanup_device(&osprds[i]);
	unregister_blkdev(OSPRD_MAJOR, "osprd");
}


// Tell Linux to call those functions at init and exit time.
module_init(osprd_init);
module_exit(osprd_exit);
