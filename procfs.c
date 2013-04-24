/*
 * Copyright (c) 2009 Daniel Lezcano <daniel.lezcano@free.fr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * Author : Daniel Lezcano <daniel.lezcano@free.fr>
 *
 * ---
 * fuse procfs proxy:
 *
 * The following program allows to overlap the /proc directory in
 * order to hide or modify content to be showed to the user.
 *
 * Definitions:
 *  - a file/directory showed as it is in the real /proc is a 'proxy'
 *  - a file/directory hidden from the initial /proc is a 'shadow'
 *  - a file/directory changed from the initial /proc is a 'mirror'
 *
 * At the init time, we did not bind mounted the old /proc, so we grab
 * a reference on it and use the openat, opendirat, etc ... to relatively
 * work with the old /proc directory
 *
 * When one of the ops is called (eg. open), we check if the file is
 * hidden, otherwise we check if it is mirrored, otherwise we call the
 * real file function syscall (here open).
 *
 * This program is intented to be extended ...
 */

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <libgen.h>
#include <errno.h>
#include <dirent.h>
#include <mntent.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

/*
 * mirror_ops : file operations to be used for hooking the file content on /proc
 */
struct mirror_ops {
	int (*open)(const char *, struct fuse_file_info *);
	int (*read)(const char *, char *, size_t, off_t, struct fuse_file_info *);
	int (*write)(const char *, const char *, size_t, off_t, struct fuse_file_info *);
	int (*release)(const char *, struct fuse_file_info *);
};

static int meminfo_open(const char *, struct fuse_file_info *);
static int meminfo_read(const char *, char *, size_t, off_t, struct fuse_file_info *);
static int meminfo_release(const char *, struct fuse_file_info *);

static struct mirror_ops meminfo_ops = {
	.open    = meminfo_open,
	.read    = meminfo_read,
	.release = meminfo_release,
};

static int uptime_open(const char *, struct fuse_file_info *);
static int uptime_read(const char *, char *, size_t, off_t, struct fuse_file_info *);
static int uptime_release(const char *, struct fuse_file_info *);

static struct mirror_ops uptime_ops = {
	.open    = uptime_open,
	.read    = uptime_read,
	.release = uptime_release,
};

struct uptime {
	struct timeval uptime;
	struct timeval idle;
};
/*
 * descriptor for proxy file : when the file is opened, the descriptor is fd
 * is stored in order to be reused in the read, write, etc ... functions
 */
struct proxy_file {
	int fd;
};

/*
 * descriptor for mirror : at the open time, the filename is checked against
 * the mirror hash table and the corresponding ops are retrieved and stored
 * in this structure
 */
struct mirror_file {
	struct mirror_ops *ops;
	void *data;
};

enum {
	PROCFS_PROXY,
	PROCFS_MIRROR,
};

/*
 * Global structure when initialization fuse-procfs.
 *  - procdir is the reference on the old /proc mounting point
 *  - subdir is a working variable when walking on the dir tree
 *  - shadow_hash contains the files/directory to be hidden
 *  - mirror_hash contains the files to be mirrored with their ops
 *  - uptime is the uptime readen at init time
 */
struct procfs_info {
	DIR *procdir;
	DIR *subdir;
	struct hsearch_data shadow_hash;
	struct hsearch_data mirror_hash;
	struct uptime uptime;
};

/*
 * General file descriptor wrapping all the information for each kind of file
 * - type describes if it is a mirror or a proxy file
 * - the union contains the information for the file
 * - private_data contains something specific stored at open time
 */
struct procfs_file {
	int type;
	union {
		struct proxy_file proxy;
		struct mirror_file mirror;
	} file;

	void *private_data;
};

/*
 * Statically define the list of the entries we want to hide
 */
static ENTRY shadow_entries[] = {
	{ "sys", NULL },
};

/*
 * Statically define the list of the entries we want to mirror
 */
static ENTRY mirror_entries[] = {
	{ "meminfo", &meminfo_ops },
	{ "uptime", &uptime_ops },
};

#define ARRAY_SIZE(t) (sizeof(t) / sizeof(t[0]))
#define SHADOW_HASH_SIZE 32
#define MIRROR_HASH_SIZE 32

/*
 * a simple wrapper function to find an entry in the hash
 */
ENTRY *hash_find(char *key, struct hsearch_data *hash)
{
	ENTRY entry, *pentry;

	entry.key = key;

	hsearch_r(entry, FIND, &pentry, hash);

	return pentry;
}

/*** fuse ops definitions ***/

static int procfs_readlink(const char *path, char *buf, size_t bufsiz)
{
	struct fuse_context *context = fuse_get_context();
	struct procfs_info *fsinfo = context->private_data;
	char *bname = strchr(path, '/');
	int ret;

	if (strcmp(path, "/"))
		bname += 1;

	ret = readlinkat(dirfd(fsinfo->procdir), bname, buf, bufsiz);
	if (ret < 0)
		return -errno;

	buf[ret] = '\0';

	return 0;
}

static int procfs_getattr(const char *path, struct stat *stbuf)
{
	struct fuse_context *context = fuse_get_context();
	struct procfs_info *fsinfo = context->private_data;
	char *bname = strchr(path, '/');
	struct mirror_ops *ops;
	ENTRY *entry;

	if (strcmp(path, "/"))
		bname += 1;

 	if (hash_find(bname, &fsinfo->shadow_hash))
 		return -ENOENT;

	if (fstatat(dirfd(fsinfo->procdir), bname, stbuf, AT_SYMLINK_NOFOLLOW))
 		return -errno;

	return 0;
}

static int procfs_open(const char *path, struct fuse_file_info *fi)
{
	struct fuse_context *context = fuse_get_context();
	struct procfs_info *fsinfo = context->private_data;
	struct procfs_file *pfile;
	char *bname = strchr(path, '/');
	ENTRY *entry;

	if (strcmp(path, "/"))
		bname += 1;

	/* this path is hidden */
 	if (hash_find(bname, &fsinfo->shadow_hash))
 		return -ENOENT;

	pfile = malloc(sizeof(*pfile));
	if (!pfile)
		return -ENOMEM;

	fi->fh = (typeof(fi->fh))pfile;

	/* this path must be mirrored */
	entry = hash_find(bname, &fsinfo->mirror_hash);
	if (entry) {
		pfile->type = PROCFS_MIRROR;
		pfile->file.mirror.ops = entry->data;
		if (pfile->file.mirror.ops->open)
			return pfile->file.mirror.ops->open(path, fi);
	}

	/* default we proxy the file */
	pfile->type = PROCFS_PROXY;
	pfile->file.proxy.fd = openat(dirfd(fsinfo->procdir), bname, fi->flags);
	if (pfile->file.proxy.fd < 0) {
		free(pfile);
		return -errno;
	}

	return 0;
}

static int procfs_read(const char *path, char *buf, size_t size,
		      off_t offset, struct fuse_file_info *fi)
{
	int ret;
	struct procfs_file *pfile = (typeof(pfile))fi->fh;;

	if (!offset)
		lseek(pfile->file.proxy.fd, 0, SEEK_SET);

	switch (pfile->type) {

	case PROCFS_MIRROR:
		ret = pfile->file.mirror.ops->read(path, buf, size, offset, fi);
		break;

	case PROCFS_PROXY:
		ret = read(pfile->file.proxy.fd, buf, size);
		if (ret < 0)
			return -errno;
		break;
	default:
		ret = -EIO;
	}

	return ret;
}

static int procfs_write(const char *path, const char *buf, size_t size,
		       off_t offset, struct fuse_file_info *fi)
{
	int ret;
	struct procfs_file *pfile = (typeof(pfile))fi->fh;;

	if (!offset)
		lseek(pfile->file.proxy.fd, 0, SEEK_SET);

	switch (pfile->type) {

	case PROCFS_MIRROR:
		ret = pfile->file.mirror.ops->write(path, buf, size, offset, fi);
		break;

	case PROCFS_PROXY:
		ret = write(pfile->file.proxy.fd, buf, size);
		if (ret < 0)
			return -errno;
		break;
	default:
		ret = -EIO;
	}

	return ret;
}

static int procfs_release(const char *path, struct fuse_file_info *fi)
{
	struct procfs_file *pfile = (typeof(pfile))fi->fh;;
	int ret;

	switch (pfile->type) {

	case PROCFS_MIRROR:
		ret = pfile->file.mirror.ops->release(path, fi);
		break;

	case PROCFS_PROXY:
		if (close(pfile->file.proxy.fd))
			ret = -errno;
		break;
	default:
		ret = -EIO;
	}

	free(pfile);

	return ret;
}

static int procfs_opendir(const char *path, struct fuse_file_info *fi)
{
	struct fuse_context *context = fuse_get_context();
	struct procfs_info *fsinfo = context->private_data;
	char *bname;
	int fd;

	if (!strcmp(path, "/")) {
		fsinfo->subdir = fsinfo->procdir;
		return 0;
	}

	bname = strchr(path, '/') + 1;

	if (hash_find(bname, &fsinfo->shadow_hash))
		return -ENOENT;

	fd = openat(dirfd(fsinfo->procdir), bname, O_DIRECTORY);
	if (fd < 0)
		return -errno;

	fsinfo->subdir = fdopendir(fd);

	return 0;
}

static int procfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	struct fuse_context *context = fuse_get_context();
	struct procfs_info *fsinfo = context->private_data;
        struct dirent dirent, *direntp;

	if (!offset)
		rewinddir(fsinfo->subdir);

        while (!readdir_r(fsinfo->subdir, &dirent, &direntp) && direntp) {

		if (hash_find(direntp->d_name, &fsinfo->shadow_hash))
			continue;

		if (filler(buf, direntp->d_name, NULL, offset++))
			break;
	}

	return 0;
}

static int procfs_releasedir(const char *path, struct fuse_file_info *fi)
{
	struct fuse_context *context = fuse_get_context();
	struct procfs_info *fsinfo = context->private_data;
	DIR *subdir = fsinfo->subdir;

	fsinfo->subdir = NULL;
	if (subdir && subdir != fsinfo->procdir)
		closedir(subdir);

	return 0;
}

static int procfs_init_hash(struct hsearch_data *hash, size_t hash_size,
			    ENTRY entries[], size_t entries_size)
{
	int i;
	ENTRY *pentry;

	memset(hash, 0, sizeof(*hash));

	if (!hcreate_r(hash_size, hash))
		return -1;

	for (i = 0; i < entries_size; i++)
		if (!hsearch_r(entries[i], ENTER, &pentry, hash))
			return -1;

	return 0;
}

static int procfs_init_uptime(struct procfs_info *fsinfo)
{
	FILE *file;

	file = fopen("/proc/uptime", "r");
	if (!file)
		return -1;

	fscanf(file, "%lu.%02lu %lu.%02lu", &fsinfo->uptime.uptime.tv_sec,
	       &fsinfo->uptime.uptime.tv_usec, &fsinfo->uptime.idle.tv_sec,
	       &fsinfo->uptime.idle.tv_usec);

	fclose(file);

	return 0;
}

static void *procfs_init(struct fuse_conn_info *conn)
{
	struct procfs_info *fsinfo;

	fsinfo = malloc(sizeof(*fsinfo));
	if (!fsinfo)
		return NULL;

	memset(fsinfo, 0, sizeof(*fsinfo));

	if (procfs_init_uptime(fsinfo))
		goto out_free_fsinfo;

	fsinfo->procdir = opendir("/proc");
	if (!fsinfo->procdir)
		goto out_free_fsinfo;

	fsinfo->subdir = NULL;

	if (procfs_init_hash(&fsinfo->shadow_hash, SHADOW_HASH_SIZE,
			     shadow_entries, ARRAY_SIZE(shadow_entries)))
		goto out_free_fsinfo;

	if (procfs_init_hash(&fsinfo->mirror_hash, MIRROR_HASH_SIZE,
			     mirror_entries, ARRAY_SIZE(mirror_entries)))
		goto out_destroy_shadow_hash;

out:
	return fsinfo;

out_destroy_shadow_hash:
	hdestroy_r(&fsinfo->shadow_hash);
out_free_fsinfo:
	free(fsinfo);
	fsinfo = NULL;
	goto out;
}

static void procfs_destroy(void *private_data)
{
	struct procfs_info *fsinfo = private_data;

	closedir(fsinfo->procdir);
	hdestroy_r(&fsinfo->shadow_hash);
	hdestroy_r(&fsinfo->mirror_hash);
	free(fsinfo);
}

static struct fuse_operations procfs_ops = {
	.readlink   = procfs_readlink,
	.getattr    = procfs_getattr,
	.open       = procfs_open,
	.read       = procfs_read,
	.write      = procfs_write,
	.opendir    = procfs_opendir,
	.releasedir = procfs_releasedir,
	.readdir    = procfs_readdir,
	.release    = procfs_release,
 	.init       = procfs_init,
 	.destroy    = procfs_destroy,
};

int main(int argc, char *argv[])
{
	return fuse_main(argc, argv, &procfs_ops, NULL);
}

/*
 * Mirroring specific functions
 */

static int get_cgroup_mount(const char *mtab, char *mnt)
{
        struct mntent *mntent;
        FILE *file = NULL;
        int err = -1;

        file = setmntent(mtab, "r");
        if (!file)
                goto out;

        while ((mntent = getmntent(file))) {

		/* there is a cgroup mounted named "lxc" */
		if (!strcmp(mntent->mnt_fsname, "lxc") &&
		    !strcmp(mntent->mnt_type, "cgroup")) {
			strcpy(mnt, mntent->mnt_dir);
			err = 0;
			break;
		}

		/* fallback to the first non-lxc cgroup found */
                if (!strcmp(mntent->mnt_type, "cgroup") && err) {
			strcpy(mnt, mntent->mnt_dir);
			err = 0;
		}
        };

        fclose(file);
out:
        return err;
}

static char *cgroup_name(void)
{
	char *path = "/proc/self/cgroup", *name;
        char line[MAXPATHLEN];
        FILE *file;

        file = fopen(path, "r");
        if (!file)
                return NULL;
        fscanf(file, "%s", line);
	fclose(file);

        strtok(line, ":");
        strtok(NULL, ":");
        name = strtok(NULL, ":");
        name = strtok(name, "/");

        return strdup(name);
}

struct meminfo {
	FILE *memlimit;
	FILE *memusage;
	FILE *swaplimit;
	FILE *swapusage;
};

static int meminfo_open(const char *path, struct fuse_file_info *fi)
{
	struct procfs_file *pfile = (typeof(pfile))fi->fh;
	char cgmntpath[MAXPATHLEN];
	char cgpath[MAXPATHLEN];
	char *cgname;
	struct meminfo *meminfo;
	int ret;

	if (get_cgroup_mount("/etc/mtab", cgmntpath))
		if (get_cgroup_mount("/proc/mounts", cgmntpath))
			return -ENOENT;

	cgname = cgroup_name();
	if (!cgname)
		return -errno;

	meminfo = malloc(sizeof(*meminfo));
	if (!meminfo) {
		ret = -ENOMEM;
		goto out;
	}
	pfile->file.mirror.data = meminfo;

	ret = -ENOENT;

	sprintf(cgpath, "%s/%s/memory.limit_in_bytes", cgmntpath, cgname);
	meminfo->memlimit = fopen(cgpath, "r");
	if (!meminfo->memlimit)
		goto out_free_meminfo;

	sprintf(cgpath, "%s/%s/memory.usage_in_bytes", cgmntpath, cgname);
	meminfo->memusage = fopen(cgpath, "r");
	if (!meminfo->memusage)
		goto out_close_memlimit;

	sprintf(cgpath, "%s/%s/memory.memsw.limit_in_bytes", cgmntpath, cgname);
	meminfo->swaplimit = fopen(cgpath, "r");
	if (!meminfo->swaplimit)
		goto out_close_memusage;

	sprintf(cgpath, "%s/%s/memory.memsw.limit_in_bytes", cgmntpath, cgname);
	meminfo->swapusage = fopen(cgpath, "r");
	if (!meminfo->swapusage)
		goto out_close_swaplimit;

	ret = 0;
out:
	free(cgname);
	return ret;

out_close_swaplimit:
	fclose(meminfo->swaplimit);
out_close_memusage:
	fclose(meminfo->memusage);
out_close_memlimit:
	fclose(meminfo->memlimit);
out_free_meminfo:
	free(meminfo);
	goto out;
}

static int meminfo_read(const char *path, char *buf, size_t size,
			off_t offset, struct fuse_file_info *fi)
{
	struct procfs_file *pfile = (typeof(pfile))fi->fh;
	struct meminfo *meminfo = pfile->file.mirror.data;
	long long memlimit, memusage, swaplimit, swapusage;
	size_t len;

	if (offset)
		return 0;

	fscanf(meminfo->memlimit, "%lld", &memlimit);
	fscanf(meminfo->memusage, "%lld", &memusage);
	fscanf(meminfo->swaplimit, "%lld", &swaplimit);
	fscanf(meminfo->swapusage, "%lld", &swapusage);

	len = sprintf(buf, "MemTotal:       %8lld kB\n",
		      memlimit >> 10);
	len += sprintf(buf + len, "MemFree:        %8lld kB\n",
		       (memlimit - memusage) >> 10);
	len += sprintf(buf + len, "SwapTotal:      %8lld kB\n",
		       swaplimit >> 10);
	len += sprintf(buf + len, "SwapFree:       %8lld kB\n\n",
		       (swaplimit - swapusage) >> 10);

	return len;
}

static int meminfo_release(const char *path, struct fuse_file_info *fi)
{
	struct procfs_file *pfile = (typeof(pfile))fi->fh;
	struct meminfo *meminfo = pfile->file.mirror.data;

	fclose(meminfo->memlimit);
	fclose(meminfo->memusage);
	fclose(meminfo->swaplimit);
	fclose(meminfo->swapusage);
	free(meminfo);

	return 0;
}

static int uptime_open(const char *path, struct fuse_file_info *fi)
{
	struct procfs_file *pfile = (typeof(pfile))fi->fh;
	FILE *file;

	file = fopen("/proc/uptime", "r");
	if (!file)
		return -errno;

	pfile->file.mirror.data = file;

	return 0;
}

static int uptime_read(const char *path, char *buf, size_t size, off_t offset,
		       struct fuse_file_info *fi)
{
	struct fuse_context *context = fuse_get_context();
	struct procfs_info *fsinfo = context->private_data;
	struct procfs_file *pfile = (typeof(pfile))fi->fh;
	struct timeval uptime, idle;
	FILE *file  = pfile->file.mirror.data;

	if (offset)
		return 0;

	fscanf(file, "%lu.%02lu %lu.%02lu", &uptime.tv_sec,
	       &uptime.tv_usec, &idle.tv_sec, &idle.tv_usec);

	return sprintf(buf, "%lu.%02lu %lu.%02lu\n",
		       uptime.tv_sec - fsinfo->uptime.uptime.tv_sec,
		       uptime.tv_usec - fsinfo->uptime.uptime.tv_usec,
		       idle.tv_sec - fsinfo->uptime.idle.tv_sec,
		       idle.tv_usec - fsinfo->uptime.idle.tv_usec);
}

static int uptime_release(const char *path, struct fuse_file_info *fi)
{
	struct procfs_file *pfile = (typeof(pfile))fi->fh;
	FILE *file  = pfile->file.mirror.data;

	if (fclose(file))
		return -errno;
	return 0;
}
