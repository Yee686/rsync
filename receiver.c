/*
 * Routines only used by the receiving process.
 *
 * Copyright (C) 1996-2000 Andrew Tridgell
 * Copyright (C) 1996 Paul Mackerras
 * Copyright (C) 2003-2023 Wayne Davison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, visit the http://fsf.org website.
 */

#include "rsync.h"
#include "inums.h"

#define BACKUP_WRITE_VERSION

extern int dry_run;
extern int do_xfers;
extern int am_root;
extern int am_server;
extern int inc_recurse;
extern int log_before_transfer;
extern int stdout_format_has_i;
extern int logfile_format_has_i;
extern int want_xattr_optim;
extern int csum_length;
extern int read_batch;
extern int write_batch;
extern int batch_gen_fd;
extern int protocol_version;
extern int relative_paths;
extern int preserve_hard_links;
extern int preserve_perms;
extern int write_devices;
extern int preserve_xattrs;
extern int do_fsync;
extern int basis_dir_cnt;
extern int make_backups;
extern int cleanup_got_literal;
extern int remove_source_files;
extern int append_mode;
extern int sparse_files;
extern int preallocate_files;
extern int keep_partial;
extern int checksum_seed;
extern int whole_file;
extern int inplace;
extern int inplace_partial;
extern int allowed_lull;
extern int delay_updates;
extern BOOL want_progress_now;
extern mode_t orig_umask;
extern struct stats stats;
extern char *tmpdir;
extern char *partial_dir;
extern char *basis_dir[MAX_BASIS_DIRS+1];
extern char sender_file_sum[MAX_DIGEST_LEN];
extern struct file_list *cur_flist, *first_flist, *dir_flist;
extern filter_rule_list daemon_filter_list;
extern OFF_T preallocated_len;

extern char *recovery_version; // 用户要恢复的版本号 YYYY-mm-dd-HH:MM:SS 需要传给sender模块恢复至指定版本
extern char *backup_version;   // 用户指定的的备份版本号 YYYY-mm-dd-HH:MM:SS 需要传给receiver模块恢复至指定版本

extern char *backup_type;		 // 备份类型 0:增量备份 1:差量备份
extern char *backup_version_num; // 存储端保留的备份版本数目

extern int is_backup;	// 是否是备份操作
extern int is_recovery; // 是否是恢复操作

int backup_type_flag = -1;		  // 备份类型标志 0:增量备份 1:差量备份
int backup_version_num_flag = -1; // 存储端保留的备份版本数目

char delta_backup_fpath[MAXPATHLEN]; // 存放备份数据的文件夹
char delta_backup_fname[MAXPATHLEN]; // 存放对应版本备份数据的文件名

int first_backup = -1; // 是否是第一次备份

extern struct name_num_item *xfer_sum_nni;
extern int xfer_sum_len;

static struct bitbag *delayed_bits = NULL;
static int phase = 0, redoing = 0;
static flist_ndx_list batch_redo_list;
/* This is non-0 when we are updating the basis file or an identical copy: */
static int updating_basis_or_equiv;

#define TMPNAME_SUFFIX ".XXXXXX"
#define TMPNAME_SUFFIX_LEN ((int)sizeof TMPNAME_SUFFIX - 1)
#define MAX_UNIQUE_NUMBER 999999
#define MAX_UNIQUE_LOOP 100

/* get_tmpname() - create a tmp filename for a given filename
 *
 * If a tmpdir is defined, use that as the directory to put it in.  Otherwise,
 * the tmp filename is in the same directory as the given name.  Note that
 * there may be no directory at all in the given name!
 *
 * The tmp filename is basically the given filename with a dot prepended, and
 * .XXXXXX appended (for mkstemp() to put its unique gunk in).  We take care
 * to not exceed either the MAXPATHLEN or NAME_MAX, especially the last, as
 * the basename basically becomes 8 characters longer.  In such a case, the
 * original name is shortened sufficiently to make it all fit.
 *
 * If the make_unique arg is True, the XXXXXX string is replaced with a unique
 * string that doesn't exist at the time of the check.  This is intended to be
 * used for creating hard links, symlinks, devices, and special files, since
 * normal files should be handled by mkstemp() for safety.
 *
 * Of course, the only reason the file is based on the original name is to
 * make it easier to figure out what purpose a temp file is serving when a
 * transfer is in progress. */
int get_tmpname(char *fnametmp, const char *fname, BOOL make_unique)
{
	int maxname, length = 0;
	const char *f;
	char *suf;

	if (tmpdir) {
		/* Note: this can't overflow, so the return value is safe */
		length = strlcpy(fnametmp, tmpdir, MAXPATHLEN - 2);
		fnametmp[length++] = '/';
	}

	if ((f = strrchr(fname, '/')) != NULL) {
		++f;
		if (!tmpdir) {
			length = f - fname;
			/* copy up to and including the slash */
			strlcpy(fnametmp, fname, length + 1);
		}
	} else
		f = fname;

	if (!tmpdir) { /* using a tmpdir avoids the leading dot on our temp names */
		if (*f == '.') /* avoid an extra leading dot for OS X's sake */
			f++;
		fnametmp[length++] = '.';
	}

	/* The maxname value is bufsize, and includes space for the '\0'.
	 * NAME_MAX needs an extra -1 for the name's leading dot. */
	maxname = MIN(MAXPATHLEN - length - TMPNAME_SUFFIX_LEN,
		      NAME_MAX - 1 - TMPNAME_SUFFIX_LEN);

	if (maxname < 0) {
		rprintf(FERROR_XFER, "temporary filename too long: %s\n", fname);
		fnametmp[0] = '\0';
		return 0;
	}

	if (maxname) {
		int added = strlcpy(fnametmp + length, f, maxname);
		if (added >= maxname)
			added = maxname - 1;
		suf = fnametmp + length + added;

		/* Trim any dangling high-bit chars if the first-trimmed char (if any) is
		 * also a high-bit char, just in case we cut into a multi-byte sequence.
		 * We are guaranteed to stop because of the leading '.' we added. */
		if ((int)f[added] & 0x80) {
			while ((int)suf[-1] & 0x80)
				suf--;
		}
		/* trim one trailing dot before our suffix's dot */
		if (suf[-1] == '.')
			suf--;
	} else
		suf = fnametmp + length - 1; /* overwrite the leading dot with suffix's dot */

	if (make_unique) {
		static unsigned counter_limit;
		unsigned counter;

		if (!counter_limit) {
			counter_limit = (unsigned)getpid() + MAX_UNIQUE_LOOP;
			if (counter_limit > MAX_UNIQUE_NUMBER || counter_limit < MAX_UNIQUE_LOOP)
				counter_limit = MAX_UNIQUE_LOOP;
		}
		counter = counter_limit - MAX_UNIQUE_LOOP;

		/* This doesn't have to be very good because we don't need
		 * to worry about someone trying to guess the values:  all
		 * a conflict will do is cause a device, special file, hard
		 * link, or symlink to fail to be created.  Also: avoid
		 * using mktemp() due to gcc's annoying warning. */
		while (1) {
			snprintf(suf, TMPNAME_SUFFIX_LEN+1, ".%d", counter);
			if (access(fnametmp, 0) < 0)
				break;
			if (++counter >= counter_limit)
				return 0;
		}
	} else
		memcpy(suf, TMPNAME_SUFFIX, TMPNAME_SUFFIX_LEN+1);

	return 1;
}

/* Opens a temporary file for writing.
 * Success: Writes name into fnametmp, returns fd.
 * Failure: Clobbers fnametmp, returns -1.
 * Calling cleanup_set() is the caller's job. */
int open_tmpfile(char *fnametmp, const char *fname, struct file_struct *file)
{
	int fd;
	mode_t added_perms;

	if (!get_tmpname(fnametmp, fname, False))
		return -1;

	if (am_root < 0) {
		/* For --fake-super, the file must be useable by the copying
		 * user, just like it would be for root. */
		added_perms = S_IRUSR|S_IWUSR;
	} else {
		/* For a normal copy, we need to be able to tweak things like xattrs. */
		added_perms = S_IWUSR;
	}

	/* We initially set the perms without the setuid/setgid bits or group
	 * access to ensure that there is no race condition.  They will be
	 * correctly updated after the right owner and group info is set.
	 * (Thanks to snabb@epipe.fi for pointing this out.) */
	fd = do_mkstemp(fnametmp, (file->mode|added_perms) & INITACCESSPERMS);

#if 0
	/* In most cases parent directories will already exist because their
	 * information should have been previously transferred, but that may
	 * not be the case with -R */
	if (fd == -1 && relative_paths && errno == ENOENT
	 && make_path(fnametmp, MKP_SKIP_SLASH | MKP_DROP_NAME) == 0) {
		/* Get back to name with XXXXXX in it. */
		get_tmpname(fnametmp, fname, False);
		fd = do_mkstemp(fnametmp, (file->mode|added_perms) & INITACCESSPERMS);
	}
#endif

	if (fd == -1) {
		rsyserr(FERROR_XFER, errno, "mkstemp %s failed",
			full_fname(fnametmp));
		return -1;
	}

	return fd;
}

static int receive_data(int f_in, char *fname_r, int fd_r, OFF_T size_r,
			const char *fname, int fd, struct file_struct *file, int inplace_sizing)
{
	if (is_backup)
	{
		rprintf(FINFO, "[debug-yee](%s)(%s->%s[%d]) is_backup = %d, first_backup = %d, delta_backup_fpath = %s, delta_backup_fname = %s\n",
				who_am_i(), __FILE__, __FUNCTION__, __LINE__, is_backup, first_backup, delta_backup_fpath, delta_backup_fname);
	}
	else if (is_recovery)
	{
		rprintf(FINFO, "[debug-yee](%s)(%s->%s[%d]) recovery_version = %s, fname_r = %s, fname = %s\n",
				who_am_i(), __FILE__, __FUNCTION__, __LINE__, recovery_version, fname_r, fname);
	}
	static char file_sum1[MAX_DIGEST_LEN];
	struct map_struct *mapbuf;
	struct sum_struct sum;
	int32 len;
	OFF_T total_size = F_LENGTH(file);
	OFF_T offset = 0;
	OFF_T offset2;
	char *data;
	int32 i;
	char *map = NULL;

#ifdef SUPPORT_PREALLOCATION
	if (preallocate_files && fd != -1 && total_size > 0 && (!inplace_sizing || total_size > size_r)) {
		/* Try to preallocate enough space for file's eventual length.  Can
		 * reduce fragmentation on filesystems like ext4, xfs, and NTFS. */
		if ((preallocated_len = do_fallocate(fd, 0, total_size)) < 0)
			rsyserr(FWARNING, errno, "do_fallocate %s", full_fname(fname));
	} else
#endif
	if (inplace_sizing) {
#ifdef HAVE_FTRUNCATE
		/* The most compatible way to create a sparse file is to start with no length. */
		if (sparse_files > 0 && whole_file && fd >= 0 && do_ftruncate(fd, 0) == 0)
			preallocated_len = 0;
		else
#endif
			preallocated_len = size_r;
	} else
		preallocated_len = 0;

	read_sum_head(f_in, &sum);

	if (fd_r >= 0 && size_r > 0) {
		int32 read_size = MAX(sum.blength * 2, 16*1024);
		mapbuf = map_file(fd_r, size_r, read_size, sum.blength);
		if (DEBUG_GTE(DELTASUM, 2)) {
			rprintf(FINFO, "recv mapped %s of size %s\n",
				fname_r, big_num(size_r));
		}
	} else
		mapbuf = NULL;

	sum_init(xfer_sum_nni, checksum_seed);

	if (append_mode > 0) {
		OFF_T j;
		sum.flength = (OFF_T)sum.count * sum.blength;
		if (sum.remainder)
			sum.flength -= sum.blength - sum.remainder;
		if (append_mode == 2 && mapbuf) {
			for (j = CHUNK_SIZE; j < sum.flength; j += CHUNK_SIZE) {
				if (INFO_GTE(PROGRESS, 1))
					show_progress(offset, total_size);
				sum_update(map_ptr(mapbuf, offset, CHUNK_SIZE),
					   CHUNK_SIZE);
				offset = j;
			}
			if (offset < sum.flength) {
				int32 len = (int32)(sum.flength - offset);
				if (INFO_GTE(PROGRESS, 1))
					show_progress(offset, total_size);
				sum_update(map_ptr(mapbuf, offset, len), len);
			}
		}
		offset = sum.flength;
		if (fd != -1 && (j = do_lseek(fd, offset, SEEK_SET)) != offset) {
			rsyserr(FERROR_XFER, errno, "lseek of %s returned %s, not %s",
				full_fname(fname), big_num(j), big_num(offset));
			exit_cleanup(RERR_FILEIO);
		}
	}
#ifdef BACKUP_WRITE_VERSION
	FILE *delta_fp = NULL;
	if (is_backup && !first_backup)
	{
		delta_fp = fopen(delta_backup_fname, "wb");
		if (!delta_fp)
		{
			rprintf(FINFO, "[debug-yee](%s)(%s->%s[%d]) open %s failed...",
					who_am_i(), __FILE__, __FUNCTION__, __LINE__, delta_backup_fpath);
		}
		char file_metadata[2048];
		sprintf(file_metadata, "[delta file metadata] file_size = %ld, content_size = %ld, block_size = %d, block_count = %d, remainder_block = %d\n",
				total_size, size_r, sum.blength, sum.count, sum.remainder);
		rprintf(FINFO, "[debug-yee](%s)(%s->%s[%d]) file_metadata = %s\n",
				who_am_i(), __FILE__, __FUNCTION__, __LINE__, file_metadata);
		fwrite(file_metadata, sizeof(char) * strlen(file_metadata), 1, delta_fp);
	}
#endif

	rprintf(FINFO, "[debug-yee](%s)(%s->%s[%d]) start while \n",
			who_am_i(), __FILE__, __FUNCTION__, __LINE__);
	while ((i = recv_token(f_in, &data)) != 0) {
		if (INFO_GTE(PROGRESS, 1))
			show_progress(offset, total_size);

		if (allowed_lull)
			maybe_send_keepalive(time(NULL), MSK_ALLOW_FLUSH | MSK_ACTIVE_RECEIVER);

		// i为不匹配的数据长度
		if (i > 0) {
			if (DEBUG_GTE(DELTASUM, 3)) {
				rprintf(FINFO,"data recv %d at %s\n",
					i, big_num(offset));
			}

			stats.literal_data += i;
			cleanup_got_literal = 1;

			sum_update(data, i);

			if (fd != -1 && write_file(fd, 0, offset, data, i) != i)
				goto report_write_error;
		#ifdef BACKUP_WRITE_VERSION
			// 对于backup任务 记录增量信息 -- 写入不匹配的字面量数据
			if (is_backup && !first_backup && delta_fp != NULL && data != NULL)
			{
				char unmatch_info[512];
				int write_len = -1;

				sprintf(unmatch_info, "unmatch data length = %d, offset = %ld\n", i, offset);
				// rprintf(FINFO, "[debug-yee](%s)(%s->%s[%d]) unmatch_info =*%s*\n",
				// 		who_am_i(), __FILE__, __FUNCTION__, __LINE__, unmatch_info);
				write_len = fwrite(unmatch_info, sizeof(char) * strlen(unmatch_info), 1, delta_fp);
				if (write_len < 1)
				{
					rsyserr(FERROR_XFER, errno, "write unmatched length and offset on %s, i am %s\n", full_fname(delta_backup_fname), who_am_i());
					goto report_write_error;
				}

				write_len = fwrite(data, 1, i, delta_fp);
				// rprintf(FINFO, "[debug-yee](%s)(%s->%s[%d]) write_len = %d, data = %d\n",
				// 		who_am_i(), __FILE__, __FUNCTION__, __LINE__, write_len, data);
				if (write_len != i)
				{
					rsyserr(FERROR_XFER, errno, "write unmatched chunk failed on %s", full_fname(delta_backup_fname));
					goto report_write_error;
				}
			}
		#endif
			offset += i;
			continue;
		}

		// i为匹配块号
		i = -(i+1);
		offset2 = i * (OFF_T)sum.blength;
		len = sum.blength;
		if (i == (int)sum.count-1 && sum.remainder != 0)
			len = sum.remainder;

		stats.matched_data += len;

		// rprintf(FINFO, "[debug-yee](%s)(%s->%s[%d]) i = %d, offset = %ld, offset2 = %ld, len = %d\n",
		// 		who_am_i(), __FILE__, __FUNCTION__, __LINE__, i, offset, offset2, len);

		if (DEBUG_GTE(DELTASUM, 3)) {
			rprintf(FINFO,
				"chunk[%d] of size %ld at %s offset=%s%s\n",
				i, (long)len, big_num(offset2), big_num(offset),
				updating_basis_or_equiv && offset == offset2 ? " (seek)" : "");
		}

		if (mapbuf) {
			map = map_ptr(mapbuf,offset2,len);

			see_token(map, len);
			sum_update(map, len);
		}

		if (updating_basis_or_equiv) {
			if (offset == offset2 && fd != -1) {
				if (skip_matched(fd, offset, map, len) < 0)
					goto report_write_error;
				offset += len;
				continue;
			}
		}
		if (fd != -1 && map && write_file(fd, 0, offset, map, len) != (int)len)
			goto report_write_error;

		/**
		 * 匹配的数据,直接记录块号
		 */
		// rprintf(FINFO, "[debug-yee](%s)(%s->%s[%d]) map = %d\n",
		// 			who_am_i(), __FILE__, __FUNCTION__, __LINE__, strlen(map));
	#ifdef BACKUP_WRITE_VERSION
		if (is_backup && !first_backup && delta_fp != NULL && map != NULL)
		{
			int write_len = -1;
			char match_chunk_id[512];

			sprintf(match_chunk_id, "match token = %d, offset = %ld, offset2 = %ld \n", i, offset, offset2);
			// rprintf(FINFO, "[debug-yee](%s)(%s->%s[%d]) match_info =*%s*\n",
			// 		who_am_i(), __FILE__, __FUNCTION__, __LINE__, match_chunk_id);
			write_len = fwrite(match_chunk_id, sizeof(char) * strlen(match_chunk_id), 1, delta_fp);

			if (write_len != 1)
			{
				rsyserr(FERROR_XFER, errno, "write matched token failed on %s", full_fname(fname));
				goto report_write_error;
			}
		}
	#endif
		offset += len;
	}

	#ifdef BACKUP_WRITE_VERSION
	/*读取结束*/
	if (is_backup && delta_fp != NULL) {
		fclose(delta_fp);
		delta_fp = NULL;
	}
	#endif

	/*刷入文件*/
	if (fd != -1 && offset > 0) {
		if (sparse_files > 0) {
			if (sparse_end(fd, offset, updating_basis_or_equiv) != 0)
				goto report_write_error;
		} else if (flush_write_file(fd) < 0) {
		    report_write_error:
			rsyserr(FERROR_XFER, errno, "write failed on %s", full_fname(fname));
			exit_cleanup(RERR_FILEIO);
		}
	}

#ifdef HAVE_FTRUNCATE
	/* inplace: New data could be shorter than old data.
	 * preallocate_files: total_size could have been an overestimate.
	 *     Cut off any extra preallocated zeros from dest file. */
	if ((inplace_sizing || preallocated_len > offset) && fd != -1 && !IS_DEVICE(file->mode)) {
		if (do_ftruncate(fd, offset) < 0)
			rsyserr(FERROR_XFER, errno, "ftruncate failed on %s", full_fname(fname));
	}
#endif

	if (INFO_GTE(PROGRESS, 1))
		end_progress(total_size);

	sum_end(file_sum1);

	if (do_fsync && fd != -1 && fsync(fd) != 0) {
		rsyserr(FERROR, errno, "fsync failed on %s", full_fname(fname));
		exit_cleanup(RERR_FILEIO);
	}

	if (mapbuf)
		unmap_file(mapbuf);

	read_buf(f_in, sender_file_sum, xfer_sum_len);

	if (DEBUG_GTE(DELTASUM, 2))
		rprintf(FINFO,"got file_sum\n");
	if (fd != -1 && memcmp(file_sum1, sender_file_sum, xfer_sum_len) != 0)
		return 0;
	return 1;
}

// 递归创建目录
int mkdir_recursive(const char* path, mode_t mode)
{
    char tmp[MAXPATHLEN];
    char* p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            int ret = mkdir(tmp, mode);
            if (ret != 0 && errno != EEXIST) {
				rprintf(FWARNING, "[yee-%s] receiver.c: mkdir_recursive mkdir %s failed\n", who_am_i(), tmp);
                perror("mkdir error");
                return -1;
            }
            *p = '/';
        }
    }
    int ret = mkdir(tmp, mode);
    if (ret != 0 && errno != EEXIST) {
		rprintf(FWARNING, "[yee-%s] receiver.c: mkdir_recursive mkdir %s failed\n", who_am_i(), tmp);
        perror("mkdir error");
        return -1;
    }

	rprintf(FINFO, "[debug-yee](%s)(receiver.c->mkdir_recursive) mkdir %s success\n", who_am_i(), tmp);
    return 0;
}

static void discard_receive_data(int f_in, struct file_struct *file)
{
	receive_data(f_in, NULL, -1, 0, NULL, -1, file, 0);
}

static void handle_delayed_updates(char *local_name)
{
	char *fname, *partialptr;
	int ndx;

	for (ndx = -1; (ndx = bitbag_next_bit(delayed_bits, ndx)) >= 0; ) {
		struct file_struct *file = cur_flist->files[ndx];
		fname = local_name ? local_name : f_name(file, NULL);
		if ((partialptr = partial_dir_fname(fname)) != NULL) {
			if (make_backups > 0 && !make_backup(fname, False))
				continue;
			if (DEBUG_GTE(RECV, 1)) {
				rprintf(FINFO, "renaming %s to %s\n",
					partialptr, fname);
			}
			/* We don't use robust_rename() here because the
			 * partial-dir must be on the same drive. */
			if (do_rename(partialptr, fname) < 0) {
				rsyserr(FERROR_XFER, errno,
					"rename failed for %s (from %s)",
					full_fname(fname), partialptr);
			} else {
				if (remove_source_files || (preserve_hard_links && F_IS_HLINKED(file)))
					send_msg_success(fname, ndx);
				handle_partial_dir(partialptr, PDIR_DELETE);
			}
		}
	}
}

static void no_batched_update(int ndx, BOOL is_redo)
{
	struct file_list *flist = flist_for_ndx(ndx, "no_batched_update");
	struct file_struct *file = flist->files[ndx - flist->ndx_start];

	rprintf(FERROR_XFER, "(No batched update for%s \"%s\")\n",
		is_redo ? " resend of" : "", f_name(file, NULL));

	if (inc_recurse && !dry_run)
		send_msg_int(MSG_NO_SEND, ndx);
}

static int we_want_redo(int desired_ndx)
{
	static int redo_ndx = -1;

	while (redo_ndx < desired_ndx) {
		if (redo_ndx >= 0)
			no_batched_update(redo_ndx, True);
		if ((redo_ndx = flist_ndx_pop(&batch_redo_list)) < 0)
			return 0;
	}

	if (redo_ndx == desired_ndx) {
		redo_ndx = -1;
		return 1;
	}

	return 0;
}

static int gen_wants_ndx(int desired_ndx, int flist_num)
{
	static int next_ndx = -1;
	static int done_cnt = 0;
	static BOOL got_eof = False;

	if (got_eof)
		return 0;

	/* TODO: integrate gen-reading I/O into perform_io() so this is not needed? */
	io_flush(FULL_FLUSH);

	while (next_ndx < desired_ndx) {
		if (inc_recurse && flist_num <= done_cnt)
			return 0;
		if (next_ndx >= 0)
			no_batched_update(next_ndx, False);
		if ((next_ndx = read_int(batch_gen_fd)) < 0) {
			if (inc_recurse) {
				done_cnt++;
				continue;
			}
			got_eof = True;
			return 0;
		}
	}

	if (next_ndx == desired_ndx) {
		next_ndx = -1;
		return 1;
	}

	return 0;
}

// 更新全量版本文件, 即一次拼接, full_file_path 待更新的全量备份文件 delta_file_path 更新使用的增量部分文件
int update_incre_full_backup(const char* full_file_path, const char* delta_file_path)
{
	char updated_full_file_path[MAXPATHLEN];	// 新的全量文件路径
	char new_timestamp[MAXPATHLEN];				// 新的全量文件的时间戳

	
	extract_file_name_timestamp(delta_file_path, new_timestamp);
	rprintf(FWARNING, "[yee-%s] delta_file_path = %s, new_timestamp = %s\n",who_am_i(), delta_file_path, new_timestamp);
	
	// 分离目录和文件名
	char *ptr = strrchr(full_file_path, '/');
	char dir_name[MAXPATHLEN];				// 目录名 /path/to/fold
	char file_name[MAXPATHLEN];				// 文件名 filename.delta.timestamp
	char file_name_row[MAXPATHLEN];			// 文件名 filename
	if(ptr != NULL)
	{
		strncpy(dir_name, full_file_path, ptr - full_file_path);
		dir_name[ptr - full_file_path] = '\0';
		strcpy(file_name, ptr + 1);
	}
	else
	{
		strcpy(dir_name, ".");
		strcpy(file_name, full_file_path);
	}
	// rprintf(FWARNING, "[yee-%s] dir_name = %s, file_name = %s\n",who_am_i(), dir_name, file_name);
	
	// 截取.delta.timestamp部分, 获取原始文件名
	char *dot_pos = strchr(file_name, '.');
	strlcpy(file_name_row, file_name, dot_pos - file_name + 1);
	// rprintf(FWARNING, "[yee-%s] dir_name = %s, file_name = %s\n",who_am_i(), dir_name, file_name_row);

	// 构建新的全量文件名
	sprintf(updated_full_file_path, "%s/%s.full.%s", dir_name, file_name_row, new_timestamp);

	rprintf(FWARNING, "[yee-%s] update backup version: %s -> %s\n", who_am_i(), full_file_path, updated_full_file_path);
	
	FILE *delta_file = fopen(delta_file_path, "rb");
	FILE *updated_full_file = fopen(updated_full_file_path, "wb");
	int full_fd = do_open(full_file_path, O_RDONLY, 0);

	if(delta_file == NULL || updated_full_file == NULL || full_fd < 0)
	{
		rprintf(FWARNING, "[yee-%s] receiver.c: updata_incre_full_backup open file failed\n", who_am_i());
		rprintf(FWARNING, "[yee-%s] delta_file = %p, updated_full_file = %p, full_fd = %d\n", who_am_i(), delta_file, updated_full_file, full_fd);
		return -1;
	}

	char line[1024*100];																	// delta行读取缓冲区
	int delta_block_length = -1, delta_block_count = -1, delta_remainder_block_length = -1; // delta文件元数据 块大小 块数量 剩余块大小
	OFF_T total_size = -1, content_size = -1;	// delta文件元数据 偏移量 总大小 内容大小

	// delta 文件元数据解析
	if(fgets(line, sizeof(line), delta_file) != NULL)	
	{
		sscanf(line, "[delta file metadata] file_size = %ld, content_size = %ld, block_size = %d, block_count = %d, remainder_block = %d\n", 
			&total_size, &content_size, &delta_block_length, &delta_block_count, &delta_remainder_block_length);
	}	
	else
	{
		rprintf(FWARNING, "[yee-%s] sender.c: make_d2f fgets delta metadata error\n", who_am_i());
	}

	int32 read_size = MAX(delta_block_length*2, 16*1024);
	struct map_struct *mapbuf = map_file(full_fd, content_size, read_size, delta_block_length);	// 构建map_struct 以供map_ptr使用
	// delta 增量信息解析
	while (fgets(line, sizeof(line), delta_file) != NULL)
	{ 
		int token = -1;
		OFF_T offset = -1, offset2 = -1;

		if(strcmp(line, "\n") == 0 || strcmp(line, "\r\n") == 0)
		{
			continue;
		}
		else if(strncmp(line, "match token\0", strlen("match token\0")) == 0)	// 解析delta文件中匹配的部分 token
		{
			char *map_data = NULL;
			size_t map_len = -1;
			sscanf(line, "match token = %d, offset = %ld, offset2 = %ld\n", &token, &offset, &offset2);
			
			map_len = delta_block_length;
			if( token == delta_block_count - 1 && delta_remainder_block_length != 0)
			{
				map_len = delta_remainder_block_length;
			}
						
			map_data = map_ptr(mapbuf, offset2, map_len);	// 使用offset2

			if( map_data != NULL && fwrite(map_data, 1, map_len, updated_full_file) != map_len )
			{
				rprintf(FWARNING, "[yee-%s] sender.c: make_d2f fwrite match data error\n", who_am_i());
			}
		}
		else if(strncmp(line, "unmatch data length\0", strlen("unmatch data length\0")) == 0) // 解析delta文件中不匹配的部分
		{

			char unmatch_data[1024*1000];	// 不匹配数据缓冲区
			size_t unmatch_len = 0;			// 读取长度
			sscanf(line, "unmatch data length = %ld, offset = %ld\n", &unmatch_len, &offset);

			if( fread(unmatch_data, 1, unmatch_len, delta_file) != unmatch_len )
			{
				rprintf(FWARNING, "[yee-%s] sender.c: make_d2f fread unmatch data length error\n", who_am_i());
			}

			if( fwrite(unmatch_data, 1, unmatch_len, updated_full_file) != unmatch_len ) // 直接将不匹配数据写入
			{
				rprintf(FWARNING, "[yee-%s] sender.c: make_d2f fwrite unmatch data length error\n", who_am_i());
			}
		}
		else
		{
			rprintf(FWARNING, "[yee-%s] sender.c: make_d2f line: %s is illegal\n", who_am_i(), line);
		}
	}
	fclose(delta_file);
	fclose(updated_full_file);
	close(full_fd);

	return 0;
}


/**管理备份版本 
 * 函数的参数：backup_path 指定到对应类型的备份路径[dir_name/file.backup/incremental(differential)/]
 * 所使用的全局变量： backup_type, backup_version_num_flag
 * */ 
int manage_backup_version(const char* backup_path)
{
	char backup_full_path[MAXPATHLEN];
	char backup_delta_path[MAXPATHLEN];

	strcpy(backup_full_path, backup_path);
	strlcat(backup_full_path, "full/", MAXPATHLEN);

	strcpy(backup_delta_path, backup_path);
	strlcat(backup_delta_path, "delta/", MAXPATHLEN);

	backup_files_list *backup_files_list_full = (backup_files_list*)malloc(sizeof(backup_files_list));
	backup_files_list *backup_files_list_delta = (backup_files_list*)malloc(sizeof(backup_files_list));

	// rprintf(FWARNING, "[yee-%s] receiver.c: manage_backup_version backup_full_path = %s, backup_delta_path = %s\n", who_am_i(), backup_full_path, backup_delta_path);

	backup_files_list_full->num = read_sort_dir_files(backup_full_path, backup_files_list_full->file_path);
	backup_files_list_delta->num = read_sort_dir_files(backup_delta_path, backup_files_list_delta->file_path);

	// rprintf(FWARNING, "[yee-%s] receiver.c: full_num = %d, delta_num = %d\n", who_am_i(), backup_files_list_full->num, backup_files_list_delta->num);

	if(backup_files_list_full->num <= backup_version_num_flag && backup_files_list_delta->num <= backup_version_num_flag)
	{
		// 版本数目符合要求，不需要其他操作
		return 0;
	}

	if(backup_type_flag == 1) // 管理差量备份文件
	{
		int i = 0;

		if(backup_files_list_full->num > backup_version_num_flag) 	// 如果全量备份数超过最大值, 删除最旧的全量版本
		{
			char full_timestamp_0[MAXPATHLEN], full_timestamp_1[MAXPATHLEN];

			extract_file_name_timestamp(backup_files_list_full->file_path[0], full_timestamp_0);
			extract_file_name_timestamp(backup_files_list_full->file_path[1], full_timestamp_1);

			remove(backup_files_list_full->file_path[0]);

			for( ; i < backup_files_list_delta->num; i++)	// 删除差量备份文件中对应的全量备份文件, i同时计数
			{
				char delta_timestamp[MAXPATHLEN];
				extract_file_name_timestamp(backup_files_list_delta->file_path[i], delta_timestamp);

				if(strcmp(full_timestamp_1, delta_timestamp) >= 0)
				{
					remove(backup_files_list_delta->file_path[i]);
				}
				else
					break;
			}
		}

		if(backup_files_list_delta->num - i > backup_version_num_flag)	// 如果差量备份数超过最大值, 删除最旧的差量版本
		{
			remove(backup_files_list_delta->file_path[i]);
		}
	}
	else if(backup_type_flag == 0)	// 管理增量备份文件
	{
		int i = 0;		// i计数增量备份文件
		int j = 0;		// j计数全量备份文件

		if(backup_files_list_full->num > backup_version_num_flag) 	// 如果全量备份数超过最大值, 删除最旧的全量版本, 不涉及拼接操作
		{
			char full_timestamp_0[MAXPATHLEN], full_timestamp_1[MAXPATHLEN];

			extract_file_name_timestamp(backup_files_list_full->file_path[0], full_timestamp_0);
			extract_file_name_timestamp(backup_files_list_full->file_path[1], full_timestamp_1);

			remove(backup_files_list_full->file_path[0]);	// 删除最旧的全量版本
			j = 1;

			for( ; i < backup_files_list_delta->num; i++)	// 删除增量量备份文件无效的增量备份文件, i同时计数
			{
				char delta_timestamp[MAXPATHLEN];
				extract_file_name_timestamp(backup_files_list_delta->file_path[i], delta_timestamp);

				if(strcmp(full_timestamp_1, delta_timestamp) >= 0)
				{
					remove(backup_files_list_delta->file_path[i]);
				}
				else
					break;
			}
		}

		if((backup_files_list_delta->num) - i > backup_version_num_flag)	// 如果差量备份数超过最大值, 删除最旧的差量版本, 涉及拼接操作
		{
			rprintf(FWARNING, "[yee-%s] receiver.c: j = %d, i = %d\n", who_am_i(), j, i);
			print_backup_files_list(backup_files_list_full);
			print_backup_files_list(backup_files_list_delta);
			update_incre_full_backup(backup_files_list_full->file_path[j], backup_files_list_delta->file_path[i]);	// 更新用于比较的上一次全量备份文件
			remove(backup_files_list_delta->file_path[i]);			// 删除最旧的增量版本
			remove(backup_files_list_full->file_path[j]);			// 全量版本更新完毕, 删除最旧的全量版本
		}

	}

	free(backup_files_list_full);
	free(backup_files_list_delta);
	return 0;
}


/**
 * main routine for receiver process.
 *
 * Receiver process runs on the same host as the generator process. */
int recv_files(int f_in, int f_out, char *local_name)
{
	if(is_backup)
	{
		sscanf(backup_type, "%d", &backup_type_flag);
		sscanf(backup_version_num, "%d", &backup_version_num_flag);
	}
	

	rprintf(FINFO, "[debug-yee](%s)(%s->%s[%d]) is_backup = %d, is_recovery = %d\n",
			who_am_i(), __FILE__, __FUNCTION__, __LINE__, is_backup, is_recovery);
	rprintf(FINFO, "[debug-yee](%s)(%s->%s[%d]) backup_version = %s, backup_type = %s, backup_version_num = %s\n",
			who_am_i(), __FILE__, __FUNCTION__, __LINE__, backup_version, backup_type, backup_version_num);
	rprintf(FINFO, "[debug-yee](%s)(%s->%s[%d]) backup_type_flag = %d, backup_version_num_flag = %d\n",
			who_am_i(), __FILE__, __FUNCTION__, __LINE__, backup_type_flag, backup_version_num_flag);
	rprintf(FINFO, "[debug-yee](%s)(%s-%s[%d]) recovery_version = %s\n",
			who_am_i(), __FILE__, __FUNCTION__, __LINE__, recovery_version);

	int fd1,fd2;
	STRUCT_STAT st;
	int iflags, xlen;
	char *fname, fbuf[MAXPATHLEN];
	char xname[MAXPATHLEN];
	char *fnametmp, fnametmpbuf[MAXPATHLEN];
	char *fnamecmp, *partialptr;
	char fnamecmpbuf[MAXPATHLEN];
	uchar fnamecmp_type;
	struct file_struct *file;
	int itemizing = am_server ? logfile_format_has_i : stdout_format_has_i;
	enum logcode log_code = log_before_transfer ? FLOG : FINFO;
	int max_phase = protocol_version >= 29 ? 2 : 1;
	int dflt_perms = (ACCESSPERMS & ~orig_umask);
#ifdef SUPPORT_ACLS
	const char *parent_dirname = "";
#endif
	int ndx, recv_ok, one_inplace;

	if (DEBUG_GTE(RECV, 1))
		rprintf(FINFO, "recv_files(%d) starting\n", cur_flist->used);

	if (delay_updates)
		delayed_bits = bitbag_create(cur_flist->used + 1);

	if (whole_file < 0)
		whole_file = 0;

	progress_init();

	while (1) {
		cleanup_disable();

		/* This call also sets cur_flist. */
		ndx = read_ndx_and_attrs(f_in, f_out, &iflags, &fnamecmp_type,
					 xname, &xlen);
		// rprintf(FINFO, "[debug-yee](%s)(%s->%s[%d]) read ndx = %d\n",
		// 		who_am_i(), __FILE__, __FUNCTION__, __LINE__, ndx);
		if (ndx == NDX_DONE) {
			if (!am_server && cur_flist) {
				set_current_file_index(NULL, 0);
				if (INFO_GTE(PROGRESS, 2))
					end_progress(0);
			}
			if (inc_recurse && first_flist) {
				if (read_batch) {
					ndx = first_flist->used + first_flist->ndx_start;
					gen_wants_ndx(ndx, first_flist->flist_num);
				}
				flist_free(first_flist);
				if (first_flist)
					continue;
			} else if (read_batch && first_flist) {
				ndx = first_flist->used;
				gen_wants_ndx(ndx, first_flist->flist_num);
			}
			if (++phase > max_phase)
				break;
			if (DEBUG_GTE(RECV, 1))
				rprintf(FINFO, "recv_files phase=%d\n", phase);
			if (phase == 2 && delay_updates)
				handle_delayed_updates(local_name);
			write_int(f_out, NDX_DONE);
			continue;
		}

		if (ndx - cur_flist->ndx_start >= 0)
			file = cur_flist->files[ndx - cur_flist->ndx_start];
		else
			file = dir_flist->files[cur_flist->parent_ndx];
		fname = local_name ? local_name : f_name(file, fbuf);

		if (DEBUG_GTE(RECV, 1))
			rprintf(FINFO, "recv_files(%s)\n", fname);

		if (daemon_filter_list.head && (*fname != '.' || fname[1] != '\0')) {
			int filt_flags = S_ISDIR(file->mode) ? NAME_IS_DIR : NAME_IS_FILE;
			if (check_filter(&daemon_filter_list, FLOG, fname, filt_flags) < 0) {
				rprintf(FERROR, "ERROR: rejecting file transfer request for daemon excluded file: %s\n",
					fname);
				exit_cleanup(RERR_PROTOCOL);
			}
		}

#ifdef SUPPORT_XATTRS
		if (preserve_xattrs && iflags & ITEM_REPORT_XATTR && do_xfers
		 && !(want_xattr_optim && BITS_SET(iflags, ITEM_XNAME_FOLLOWS|ITEM_LOCAL_CHANGE)))
			recv_xattr_request(file, f_in);
#endif

		if (!(iflags & ITEM_TRANSFER)) {
			maybe_log_item(file, iflags, itemizing, xname);
#ifdef SUPPORT_XATTRS
			if (preserve_xattrs && iflags & ITEM_REPORT_XATTR && do_xfers
			 && !BITS_SET(iflags, ITEM_XNAME_FOLLOWS|ITEM_LOCAL_CHANGE))
				set_file_attrs(fname, file, NULL, fname, 0);
#endif
			if (iflags & ITEM_IS_NEW) {
				stats.created_files++;
				if (S_ISREG(file->mode)) {
					/* Nothing further to count. */
				} else if (S_ISDIR(file->mode))
					stats.created_dirs++;
#ifdef SUPPORT_LINKS
				else if (S_ISLNK(file->mode))
					stats.created_symlinks++;
#endif
				else if (IS_DEVICE(file->mode))
					stats.created_devices++;
				else
					stats.created_specials++;
			}
			continue;
		}
		if (phase == 2) {
			rprintf(FERROR,
				"got transfer request in phase 2 [%s]\n",
				who_am_i());
			exit_cleanup(RERR_PROTOCOL);
		}

		if (file->flags & FLAG_FILE_SENT) {
			if (csum_length == SHORT_SUM_LENGTH) {
				if (keep_partial && !partial_dir)
					make_backups = -make_backups; /* prevents double backup */
				if (append_mode)
					sparse_files = -sparse_files;
				append_mode = -append_mode;
				csum_length = SUM_LENGTH;
				redoing = 1;
			}
		} else {
			if (csum_length != SHORT_SUM_LENGTH) {
				if (keep_partial && !partial_dir)
					make_backups = -make_backups;
				if (append_mode)
					sparse_files = -sparse_files;
				append_mode = -append_mode;
				csum_length = SHORT_SUM_LENGTH;
				redoing = 0;
			}
			if (iflags & ITEM_IS_NEW)
				stats.created_files++;
		}

		if (!am_server)
			set_current_file_index(file, ndx);
		stats.xferred_files++;
		stats.total_transferred_size += F_LENGTH(file);

		cleanup_got_literal = 0;

		if (read_batch) {
			int wanted = redoing
				   ? we_want_redo(ndx)
				   : gen_wants_ndx(ndx, cur_flist->flist_num);
			if (!wanted) {
				rprintf(FINFO,
					"(Skipping batched update for%s \"%s\")\n",
					redoing ? " resend of" : "",
					fname);
				discard_receive_data(f_in, file);
				file->flags |= FLAG_FILE_SENT;
				continue;
			}
		}

		remember_initial_stats();

		if (!do_xfers) { /* log the transfer */
			log_item(FCLIENT, file, iflags, NULL);
			if (read_batch)
				discard_receive_data(f_in, file);
			continue;
		}
		if (write_batch < 0) {
			log_item(FCLIENT, file, iflags, NULL);
			if (!am_server)
				discard_receive_data(f_in, file);
			if (inc_recurse)
				send_msg_success(fname, ndx);
			continue;
		}

		partialptr = partial_dir ? partial_dir_fname(fname) : fname;

		if (protocol_version >= 29) {
			switch (fnamecmp_type) {
			case FNAMECMP_FNAME:
				fnamecmp = fname;
				break;
			case FNAMECMP_PARTIAL_DIR:
				fnamecmp = partialptr;
				break;
			case FNAMECMP_BACKUP:
				fnamecmp = get_backup_name(fname);
				break;
			case FNAMECMP_FUZZY:
				if (file->dirname) {
					pathjoin(fnamecmpbuf, sizeof fnamecmpbuf, file->dirname, xname);
					fnamecmp = fnamecmpbuf;
				} else
					fnamecmp = xname;
				break;
			default:
				if (fnamecmp_type > FNAMECMP_FUZZY && fnamecmp_type-FNAMECMP_FUZZY <= basis_dir_cnt) {
					fnamecmp_type -= FNAMECMP_FUZZY + 1;
					if (file->dirname) {
						stringjoin(fnamecmpbuf, sizeof fnamecmpbuf,
							   basis_dir[fnamecmp_type], "/", file->dirname, "/", xname, NULL);
					} else
						pathjoin(fnamecmpbuf, sizeof fnamecmpbuf, basis_dir[fnamecmp_type], xname);
				} else if (fnamecmp_type >= basis_dir_cnt) {
					rprintf(FERROR,
						"invalid basis_dir index: %d.\n",
						fnamecmp_type);
					exit_cleanup(RERR_PROTOCOL);
				} else
					pathjoin(fnamecmpbuf, sizeof fnamecmpbuf, basis_dir[fnamecmp_type], fname);
				fnamecmp = fnamecmpbuf;
				break;
			}
			if (!fnamecmp || (daemon_filter_list.head
			  && check_filter(&daemon_filter_list, FLOG, fnamecmp, 0) < 0)) {
				fnamecmp = fname;
				fnamecmp_type = FNAMECMP_FNAME;
			}
		} else {
			/* Reminder: --inplace && --partial-dir are never
			 * enabled at the same time. */
			if (inplace && make_backups > 0) {
				if (!(fnamecmp = get_backup_name(fname)))
					fnamecmp = fname;
				else
					fnamecmp_type = FNAMECMP_BACKUP;
			} else if (partial_dir && partialptr)
				fnamecmp = partialptr;
			else
				fnamecmp = fname;
		}

		rprintf(FINFO, "[debug-yee](%s)((%s->%s[%d]) recv_files() fname = %s\n",
				who_am_i(), __FILE__, __FUNCTION__, __LINE__, fname);
		rprintf(FINFO, "[debug-yee](%s)((%s->%s[%d]) recv_files() fnamecmp = %s\n",
				who_am_i(), __FILE__, __FUNCTION__, __LINE__, fnamecmp);
		rprintf(FINFO, "[debug-yee](%s)((%s->%s[%d]) recv_files() partialptr = %s\n",
				who_am_i(), __FILE__, __FUNCTION__, __LINE__, partialptr);
		
	
		first_backup = 1;							// 预设为是第一次备份,搜索文件夹存在同名.full.文件则不是第一次备份
		char full_backup_name_prefix[MAXPATHLEN];	// xxxx.full.
		char full_backup_fpath[MAXPATHLEN];			// ./path/to/xxxx.backup/incremental(differental)/full/									全量备份完整路径
		char full_backup_fname[MAXPATHLEN];			// ./path/to/xxxx.backup/incremental(differental)/full/xxxx.full.xxxx-xx-xx-xx:xx:xx	全量备份完整文件名

		strcpy(delta_backup_fpath,"");				// ./path/to/xxxx.backup/incremental(differental)/delta/								增量备份完整路径
		strcpy(delta_backup_fname,"");				// ./path/to/xxxx.backup/incremental(differental)/delta/xxxx.full.xxxx-xx-xx-xx:xx:xx	增量备份完整文件名

		char dir_name[MAXPATHLEN];					// ./path/to 文件夹名
		char file_name[MAXNAMLEN];					// xxxx 文件名
		// char backup_path[MAXPATHLEN];				// ./path/to/incremental(differental)/full/xxxx.backup/ 备份文件夹
	#ifdef BACKUP_WRITE_VERSION	
		// 备份任务 全量备份文件夹设置
		if (is_backup)
		{
			char *ptr = strrchr(fname, '/');

			if (ptr != NULL)
			{
				strncpy(dir_name, fname, ptr - fname);
				dir_name[ptr - fname] = '\0';
				strcpy(file_name, ptr + 1);
			}
			else
			{
				strcpy(dir_name, ".");
				strcpy(file_name, fname);
			}

			// xxxx.full.
			sprintf(full_backup_name_prefix, "%s.full.", file_name);

			// ./path/to/xxxx.backup/incremental(differental)/full/
			sprintf(full_backup_fpath, "%s/%s.backup/%s/full/", dir_name, file_name, backup_type_flag ? "differential" : "incremental");

			// ./path/to/xxxx.backup/incremental(differental)/delta/
			sprintf(delta_backup_fpath, "%s/%s.backup/%s/delta/", dir_name, file_name, backup_type_flag ? "differential" : "incremental");

			mkdir_recursive(full_backup_fpath, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
			mkdir_recursive(delta_backup_fpath, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

			sprintf(full_backup_fname, "%s%s.full.%s", full_backup_fpath, file_name, backup_version);
			sprintf(delta_backup_fname, "%s%s.delta.%s", delta_backup_fpath, file_name, backup_version);

			int full_prefix_len = strlen(full_backup_name_prefix);

			DIR *dir = opendir(full_backup_fpath);
			if (dir != NULL)
			{
				struct dirent *entry;
				while ((entry = readdir(dir)) != NULL)
				{

					if (strncmp(entry->d_name, full_backup_name_prefix, full_prefix_len) == 0)
					{
						first_backup = 0;
						break;
					}
				}
				closedir(dir);
			}
			else
			{
				rprintf(FWARNING, "[yee-%s] opendir failed\n", who_am_i());
			}
			rprintf(FINFO, "[debug-yee](%s)((%s->%s[%d]) full_backup_name_prefix = %s\n",
					who_am_i(), __FILE__, __FUNCTION__, __LINE__, full_backup_name_prefix);
			rprintf(FINFO, "[debug-yee](%s)((%s->%s[%d]) full_backup_fpath = %s\n",
					who_am_i(), __FILE__, __FUNCTION__, __LINE__, full_backup_fpath);
			rprintf(FINFO, "[debug-yee](%s)((%s->%s[%d]) full_backup_fname = %s\n",
					who_am_i(), __FILE__, __FUNCTION__, __LINE__, full_backup_fname);
			rprintf(FINFO, "[debug-yee](%s)((%s->%s[%d]) first_backup = %d\n",
					who_am_i(), __FILE__, __FUNCTION__, __LINE__, first_backup);
		}
#endif


		one_inplace = inplace_partial && fnamecmp_type == FNAMECMP_PARTIAL_DIR;
		updating_basis_or_equiv = one_inplace
		    || (inplace && (fnamecmp == fname || fnamecmp_type == FNAMECMP_BACKUP));

		/* open the file */
		fd1 = do_open(fnamecmp, O_RDONLY, 0);

		if (fd1 == -1 && protocol_version < 29) {
			if (fnamecmp != fname) {
				fnamecmp = fname;
				fnamecmp_type = FNAMECMP_FNAME;
				fd1 = do_open(fnamecmp, O_RDONLY, 0);
			}

			if (fd1 == -1 && basis_dir[0]) {
				/* pre-29 allowed only one alternate basis */
				pathjoin(fnamecmpbuf, sizeof fnamecmpbuf,
					 basis_dir[0], fname);
				fnamecmp = fnamecmpbuf;
				fnamecmp_type = FNAMECMP_BASIS_DIR_LOW;
				fd1 = do_open(fnamecmp, O_RDONLY, 0);
			}
		}

		if (fd1 == -1) {
			st.st_mode = 0;
			st.st_size = 0;
		} else if (do_fstat(fd1,&st) != 0) {
			rsyserr(FERROR_XFER, errno, "fstat %s failed",
				full_fname(fnamecmp));
			discard_receive_data(f_in, file);
			close(fd1);
			if (inc_recurse)
				send_msg_int(MSG_NO_SEND, ndx);
			continue;
		}

		if (fd1 != -1 && S_ISDIR(st.st_mode) && fnamecmp == fname) {
			/* this special handling for directories
			 * wouldn't be necessary if robust_rename()
			 * and the underlying robust_unlink could cope
			 * with directories
			 */
			rprintf(FERROR_XFER, "recv_files: %s is a directory\n",
				full_fname(fnamecmp));
			discard_receive_data(f_in, file);
			close(fd1);
			if (inc_recurse)
				send_msg_int(MSG_NO_SEND, ndx);
			continue;
		}

		if (write_devices && IS_DEVICE(st.st_mode)) {
			if (fd1 != -1 && st.st_size == 0)
				st.st_size = get_device_size(fd1, fname);
			/* Mark the file entry as a device so that we don't try to truncate it later on. */
			file->mode = S_IFBLK | (file->mode & ACCESSPERMS);
		} else if (fd1 != -1 && !(S_ISREG(st.st_mode))) {
			close(fd1);
			fd1 = -1;
		}

		/* If we're not preserving permissions, change the file-list's
		 * mode based on the local permissions and some heuristics. */
		if (!preserve_perms) {
			int exists = fd1 != -1;
#ifdef SUPPORT_ACLS
			const char *dn = file->dirname ? file->dirname : ".";
			if (parent_dirname != dn
			 && strcmp(parent_dirname, dn) != 0) {
				dflt_perms = default_perms_for_dir(dn);
				parent_dirname = dn;
			}
#endif
			file->mode = dest_mode(file->mode, st.st_mode, dflt_perms, exists);
		}

		/* We now check to see if we are writing the file "inplace" */
		if (inplace || one_inplace)  {
			fnametmp = one_inplace ? partialptr : fname;
			fd2 = do_open(fnametmp, O_WRONLY|O_CREAT, 0600);
#ifdef linux
			if (fd2 == -1 && errno == EACCES) {
				/* Maybe the error was due to protected_regular setting? */
				fd2 = do_open(fname, O_WRONLY, 0600);
			}
#endif
			if (fd2 == -1) {
				rsyserr(FERROR_XFER, errno, "open %s failed",
					full_fname(fnametmp));
			} else if (updating_basis_or_equiv)
				cleanup_set(NULL, NULL, file, fd1, fd2);
		} else {
			fnametmp = fnametmpbuf;
			fd2 = open_tmpfile(fnametmp, fname, file);
			if (fd2 != -1)
				cleanup_set(fnametmp, partialptr, file, fd1, fd2);
		}

		if (fd2 == -1) {
			discard_receive_data(f_in, file);
			if (fd1 != -1)
				close(fd1);
			if (inc_recurse)
				send_msg_int(MSG_NO_SEND, ndx);
			continue;
		}

		/* log the transfer */
		if (log_before_transfer)
			log_item(FCLIENT, file, iflags, NULL);
		else if (!am_server && INFO_GTE(NAME, 1) && INFO_EQ(PROGRESS, 1))
			rprintf(FINFO, "%s\n", fname);

		/* recv file data */
		recv_ok = receive_data(f_in, fnamecmp, fd1, st.st_size, fname, fd2, file, inplace || one_inplace);

		log_item(log_code, file, iflags, NULL);
		if (want_progress_now)
			instant_progress(fname);

		if (fd1 != -1)
			close(fd1);
		if (close(fd2) < 0) {
			rsyserr(FERROR, errno, "close failed on %s",
				full_fname(fnametmp));
			exit_cleanup(RERR_FILEIO);
		}

		if ((recv_ok && (!delay_updates || !partialptr)) || inplace) {
			if (partialptr == fname)
				partialptr = NULL;
			if (!finish_transfer(fname, fnametmp, fnamecmp, partialptr, file, recv_ok, 1))
				recv_ok = -1;
			else if (fnamecmp == partialptr) {
				if (!one_inplace)
					do_unlink(partialptr);
				handle_partial_dir(partialptr, PDIR_DELETE);
			}
		} else if (keep_partial && partialptr && (!one_inplace || delay_updates)) {
			if (!handle_partial_dir(partialptr, PDIR_CREATE)) {
				rprintf(FERROR,
					"Unable to create partial-dir for %s -- discarding %s.\n",
					local_name ? local_name : f_name(file, NULL),
					recv_ok ? "completed file" : "partial file");
				do_unlink(fnametmp);
				recv_ok = -1;
			} else if (!finish_transfer(partialptr, fnametmp, fnamecmp, NULL,
						    file, recv_ok, !partial_dir))
				recv_ok = -1;
			else if (delay_updates && recv_ok) {
				bitbag_set_bit(delayed_bits, ndx);
				recv_ok = 2;
			} else
				partialptr = NULL;
		} else if (!one_inplace)
			do_unlink(fnametmp);

		cleanup_disable();

		if (read_batch)
			file->flags |= FLAG_FILE_SENT;

		switch (recv_ok) {
		case 2:
			break;
		case 1:
			if (remove_source_files || inc_recurse || (preserve_hard_links && F_IS_HLINKED(file)))
				send_msg_success(fname, ndx);
			break;
		case 0: {
			enum logcode msgtype = redoing ? FERROR_XFER : FWARNING;
			if (msgtype == FERROR_XFER || INFO_GTE(NAME, 1) || stdout_format_has_i) {
				char *errstr, *redostr, *keptstr;
				if (!(keep_partial && partialptr) && !inplace)
					keptstr = "discarded";
				else if (partial_dir)
					keptstr = "put into partial-dir";
				else
					keptstr = "retained";
				if (msgtype == FERROR_XFER) {
					errstr = "ERROR";
					redostr = "";
				} else {
					errstr = "WARNING";
					redostr = read_batch ? " (may try again)"
							     : " (will try again)";
				}
				rprintf(msgtype,
					"%s: %s failed verification -- update %s%s.\n",
					errstr, local_name ? f_name(file, NULL) : fname,
					keptstr, redostr);
			}
			if (!redoing) {
				if (read_batch)
					flist_ndx_push(&batch_redo_list, ndx);
				send_msg_int(MSG_REDO, ndx);
				file->flags |= FLAG_FILE_SENT;
			} else if (inc_recurse)
				send_msg_int(MSG_NO_SEND, ndx);
			break;
		}
		case -1:
			if (inc_recurse)
				send_msg_int(MSG_NO_SEND, ndx);
			break;
		}

	#ifdef BACKUP_WRITE_VERSION
		if(is_backup && first_backup)
		{
			FILE *full_tmp = fopen(fname,"rb");
			FILE *full_backup = fopen(full_backup_fname,"wb");
			
			if(full_tmp == NULL || full_backup == NULL)
			{
				rprintf(FWARNING, "[debug-yee](%s)(receiver.c->recv_files)open %s or %s failed\n", who_am_i(), fname, full_backup_fname);
			}
			else
			{	
				char buf[1024*100];
				size_t read_len = 0;
				size_t buffer_size = sizeof(buf);
				while((read_len = fread(buf, sizeof(char), buffer_size, full_tmp)) > 0)
				{
					rprintf(FWARNING, "[debug-yee](%s)(receiver.c->recv_files)write_full_files write %ld chars to %s\n", who_am_i(), read_len, full_backup_fname);
					fwrite(buf, sizeof(char), read_len, full_backup);
					if(read_len < buffer_size)	// 读到了文件末尾
					{
						break;
					}	
				}
			}

			fclose(full_tmp);
			fclose(full_backup);

			full_tmp = NULL;
			full_backup = NULL;
		}

		if(is_backup && 0)
		{
			char manage_backup_path[MAXPATHLEN];
			sprintf(manage_backup_path, "%s/%s.backup/%s/", dir_name, file_name, backup_type_flag?"differential":"incremental");

			// rprintf(FWARNING, "[yee-%s] receiver.c: recv_files manage_backup_version %s\n", who_am_i(), manage_backup_path);
			if(manage_backup_version(manage_backup_path) != 0)
			{
				rprintf(FWARNING, "[yee-%s] receiver.c: recv_files manage_backup_version %s failed\n", who_am_i(), manage_backup_path);
			}
		}
	#endif

	}
	if (make_backups < 0)
		make_backups = -make_backups;

	if (phase == 2 && delay_updates) /* for protocol_version < 29 */
		handle_delayed_updates(local_name);

	if (DEBUG_GTE(RECV, 1))
		rprintf(FINFO,"recv_files finished\n");

	return 0;
}
