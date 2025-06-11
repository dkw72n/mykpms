/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <linux/err.h>
#include <syscall.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <asm/current.h>
#include <kputils.h>
KPM_NAME("hidemm");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("dkw72n");
KPM_DESCRIPTION("hide from maps/smaps");
#define LOGI(fmt, ...) pr_info("[+] KP I " fmt "\n", ##__VA_ARGS__)

const char *margs = 0;
enum hook_type hook_type = NONE;

enum pid_type
{
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};
struct pid_namespace;
pid_t (*__task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;


#define DEF_HOOK(rt, fn, args) \
static rt (*orig_##fn) args = NULL; \
static rt (*fn) args = NULL; \
static rt hook_##fn args

#define INIT_HOOK(fn) \
    fn = (typeof(fn))kallsyms_lookup_name(#fn);\
    LOGI(#fn ": %llx", fn);\
    hook((void*)fn, (void*)hook_##fn, (void**)&orig_##fn);\

#define DO_UNHOOK(fn) \
    unhook(fn);

struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
    //...
};

struct vm_area_struct;

static void fix_seq_file(struct seq_file *m, size_t start, size_t end){
    char *found = strnstr(&m->buf[start], "libVkLayer", end-start);
    if (found) {
        // LOGI("  %s", &m->buf[start]);
        size_t k = start;
        while(m->buf[k] != ' ') k++;
        strcpy(&m->buf[k], " ---p 00000000 00:00 0\n");
        m->count = k + strlen(&m->buf[k]);
        // *found = '?';
    }
}
/*
static void (*orig_show_map_vma)(struct seq_file *m, struct vm_area_struct *vma) = NULL;
static void (*show_map_vma)(struct seq_file *m, struct vm_area_struct *vma) = NULL;
static void hook_show_map_vma(struct seq_file *m, struct vm_area_struct *vma) 
*/
DEF_HOOK(void, show_map_vma, (struct seq_file *m, struct vm_area_struct *vma))
{
    // LOGI("  buf:%llx, %lx, %lx, %lx | %llx", m->buf, m->size, m->from, m->count, vma);
    size_t count = m->count;
    orig_show_map_vma(m, vma);
    fix_seq_file(m, count, m->count);
    // LOGI("  %s", &m->buf[count]);
}

struct dentry;
struct inode;
struct delayed_call;
DEF_HOOK(const char*, proc_map_files_get_link, (struct dentry *dentry, struct inode *inode, struct delayed_call *done))
{
    const char* link = orig_proc_map_files_get_link(dentry, inode, done);
    if (IS_ERR(link)){
        return link;
    }
    // LOGI("get link: %s", link);
    if (strstr(link, "libVkLayer")){
        return ERR_PTR(-EPERM);
    }
	return link;
}

DEF_HOOK(int, proc_pid_readlink, (struct dentry * dentry, char __user * buffer, int buflen))
{
    char tmp[64];
    int err = orig_proc_pid_readlink(dentry, buffer, buflen);
    if (err > 0){
        int n = err >= 64 ? 64 : err;
        compat_strncpy_from_user(tmp, buffer + err - n, n);
        if (strnstr(tmp, "libVkLayer", 64)){
            compat_copy_to_user((void*)proc_pid_readlink, buffer, err);
            err = -EACCES;
        }
    }
    return err;
}

DEF_HOOK(int, proc_map_files_readdir, (struct file *file, struct dir_context *ctx))
{
    return -EACCES;
}

#define FOREACH_HOOK(FN) \
    FN(show_map_vma) \
    FN(proc_map_files_readdir) \
    // FN(proc_map_files_get_link) \
    // FN(proc_pid_readlink) \
    

static long hidemm_init(const char *args, const char *event, void *__user reserved)
{
    margs = args;
    LOGI("hidemm init ..., args: %s", margs);

    __task_pid_nr_ns = (typeof(__task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    LOGI("kernel function __task_pid_nr_ns addr: %llx", __task_pid_nr_ns);

    FOREACH_HOOK(INIT_HOOK);

    if (!margs) {
        pr_warn("no args specified\n");
        return 0;
    }

    return 0;
}

static long hidemm_control0(const char *args, char *__user out_msg, int outlen)
{
    LOGI("hidemm control, args: %s", args);
    return 0;
}

static long hidemm_exit(void *__user reserved)
{
    LOGI("kpm-syscall-hook-demo exit ...");
    FOREACH_HOOK(DO_UNHOOK);
    return 0;
}

KPM_INIT(hidemm_init);
KPM_CTL0(hidemm_control0);
KPM_EXIT(hidemm_exit);