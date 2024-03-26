/*
 * Routines only used by the sending process.
 *
 * Copyright (C) 1996 Andrew Tridgell
 * Copyright (C) 1996 Paul Mackerras
 * Copyright (C) 2003-2022 Wayne Davison
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

#define RECOVERY_VERSION
// #define TRY_NEW
#define TRY_OLD

extern int do_xfers;
extern int am_server;
extern int am_daemon;
extern int local_server;
extern int inc_recurse;
extern int log_before_transfer;
extern int stdout_format_has_i;
extern int logfile_format_has_i;
extern int want_xattr_optim;
extern int csum_length;
extern int append_mode;
extern int copy_links;
extern int io_error;
extern int flist_eof;
extern int whole_file;
extern int allowed_lull;
extern int copy_devices;
extern int preserve_xattrs;
extern int protocol_version;
extern int remove_source_files;
extern int updating_basis_file;
extern int make_backups;
extern int inplace;
extern int inplace_partial;
extern int batch_fd;
extern int write_batch;
extern int file_old_total;
extern BOOL want_progress_now;
extern struct stats stats;
extern struct file_list *cur_flist, *first_flist, *dir_flist;
extern char num_dev_ino_buf[4 + 8 + 8];


extern char *recovery_version; // 用户要恢复的版本号 YYYY-mm-dd-HH:MM:SS 需要传给sender模块恢复至指定版本
extern char *backup_version;   // 用户指定的的备份版本号 YYYY-mm-dd-HH:MM:SS 需要传给receiver模块恢复至指定版本

extern char *backup_type;		 // 备份类型 0:增量备份 1:差量备份
extern char *backup_version_num; // 存储端保留的备份版本数目

extern int is_backup;	// 是否是备份操作
extern int is_recovery; // 是否是恢复操作

int recovery_type = -1;	// 0 使用增量备份文件, 1 使用差量备份文件


BOOL extra_flist_sending_enabled;

// 基于时间戳的比较器
int compare_delta_file_name(const void *a, const void *b)
{
	return strcmp(*(char **)a, *(char **)b);
}

// 从文件名中提取时间戳
void extract_file_name_timestamp(const char *file_name, char *timestamp)
{
	char *timestamp_start = strrchr(file_name, '.');	// xxxx.full(delta).xxxx-xx-xx-xx:xx:xx

	if (timestamp_start != NULL ) {
		// rprintf(FWARNING, "[yee-%s] sender.c: extract_file_name_timestamp {%s} time = {%s}\n", who_am_i(), file_name, timestamp_start+1);
		strcpy(timestamp, timestamp_start+1);
	}
	else 
	{
		rprintf(FWARNING, "[yee-%s] sender.c: extract_file_name_timestamp fname{%s} is illegal\n", who_am_i(), file_name);
	}
}

// 读取path下的所有文件,并按照时间戳排序, dir_name: 文件夹路径, files: 文件名数组
int read_sort_dir_files(const char* dir_name, char* files[])
{
    DIR *dirp = NULL;
    struct dirent *dp = NULL;
    int n = 0;

    // 打开目录
    if ((dirp = opendir(dir_name)) == NULL) {
		char cwd[4096];
		if (getcwd(cwd, sizeof(cwd)))
			rprintf(FWARNING, "[yee-%s] sender.c: read_sort_dir_files opendir() %s error, cwd=%s\n",
			who_am_i(), dir_name, cwd);
		else
			rprintf(FWARNING, "[yee-%s] sender.c: read_sort_dir_files opendir() %s error\n",
			who_am_i(), dir_name);
		return -1;
    }

    // 统计目录下的文件数
    while ((dp = readdir(dirp)) != NULL) {
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
            n++;
        }
    }

    // 重新设置目录位置
    rewinddir(dirp);

    // 分配动态内存，保存文件名
    for (int i = 0; i < n; i++) {
        files[i] = (char *)malloc(MAXPATHLEN * sizeof(char));
    }

    // 保存文件名到字符串指针数组中
    int i = 0;
    while ((dp = readdir(dirp)) != NULL) {
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
			strcpy(files[i], dir_name);
            strcat(files[i], dp->d_name);
            i++;
        }
    }

    // 关闭目录
    closedir(dirp);

    // 对文件名进行排序
    qsort(files, n, sizeof(char *), compare_delta_file_name);

    return n;
}

// 打印备份文件列表
void print_backup_files_list(const backup_files_list * backup_files)
{
	rprintf(FWARNING, "\n[yee-%s] sender.c: print_backup_files_list backup_files->num: %d\n", who_am_i(), backup_files->num);
	for(int i = 0; i < backup_files->num; i++)
	{
		rprintf(FWARNING, "[yee-%s] sender.c: print_backup_files_list backup_files[%d]: %s\n", who_am_i(), i, backup_files->file_path[i]);
	}
}

#ifdef TRY_NEW
// 恢复时,选用的备份文件类型  0: incremental 使用增量备份, 	 	1: differential 使用差量备份
int decide_recovery_type(const char *dir_name, const char *file_name,
								backup_files_list *incremental_full_files, backup_files_list *incremental_delta_files,
								backup_files_list *differential_full_files, backup_files_list *differential_delta_files,
								const char *recovery_timestamp)
{
	// 生成备份文件路径
	char incre_full_backup_path[MAXPATHLEN];
	char incre_delta_backup_path[MAXPATHLEN];
	char diffe_full_backup_path[MAXPATHLEN];
	char diffe_delta_backup_path[MAXPATHLEN];
	
	// if(dir_name != NULL && strlen(dir_name) > 0)
	// {
	// 	sprintf(incre_full_backup_path, "%s/%s.backup/incremental/full/", dir_name, file_name);
	// 	sprintf(incre_delta_backup_path, "%s/%s.backup/incremental/delta/", dir_name, file_name);
	// 	sprintf(diffe_full_backup_path, "%s/%s.backup/differential/full/", dir_name, file_name);
	// // 	sprintf(diffe_delta_backup_path, "%s/%s.backup/differential/delta/", dir_name, file_name);
	// // }
	// // else
	// {
		sprintf(incre_full_backup_path, "./%s.backup/incremental/full/", file_name);
		sprintf(incre_delta_backup_path, "./%s.backup/incremental/delta/", file_name);
		sprintf(diffe_full_backup_path, "./%s.backup/differential/full/", file_name);
		sprintf(diffe_delta_backup_path, "./%s.backup/differential/delta/", file_name);
	// }
	
	rprintf(FWARNING, "[yee-%s] sender.c: decide_recovery_type incre_full_backup_path: %s\n", who_am_i(), incre_full_backup_path);
	rprintf(FWARNING, "[yee-%s] sender.c: decide_recovery_type incre_delta_backup_path: %s\n", who_am_i(), incre_delta_backup_path);
	rprintf(FWARNING, "[yee-%s] sender.c: decide_recovery_type diffe_full_backup_path: %s\n", who_am_i(), diffe_full_backup_path);
	rprintf(FWARNING, "[yee-%s] sender.c: decide_recovery_type diffe_delta_backup_path: %s\n", who_am_i(), diffe_delta_backup_path);

	// 读取路径下文件并按时间排序
	int incre_delta_count = 0, incre_full_count = 0;
	int diffe_delta_count = 0, diffe_full_count = 0;

	if ((incre_full_count = read_sort_dir_files(incre_full_backup_path, incremental_full_files->file_path)) == -1)
		incre_full_count = 0;
	else
		incremental_full_files->num = incre_full_count;

	if ((incre_delta_count = read_sort_dir_files(incre_delta_backup_path, incremental_delta_files->file_path)) == -1)
		incre_delta_count = 0;
	else
		incremental_delta_files->num = incre_delta_count;

	if ((diffe_full_count = read_sort_dir_files(diffe_full_backup_path, differential_full_files->file_path)) == -1)
		diffe_full_count = 0;
	else
		differential_full_files->num = diffe_full_count;

	if ((diffe_delta_count = read_sort_dir_files(diffe_delta_backup_path, differential_delta_files->file_path)) == -1)
		diffe_delta_count = 0;
	else
		differential_delta_files->num = diffe_delta_count;

	rprintf(FWARNING, "[yee-%s] sender.c: decide_recovery_type incre_full_count: %d, incre_delta_count: %d, diffe_full_count: %d, diffe_delta_count: %d\n",
			who_am_i(), incre_full_count, incre_delta_count, diffe_full_count, diffe_delta_count);

	if (incre_full_count == 0 && diffe_full_count == 0) // 增量备份和差量备份都不存在
	{
		return -1;
	}
	else if (incre_full_count == 0 && diffe_full_count != 0) // 无增量备份,使用差量备份
	{
		rprintf(FWARNING, "[yee-%s] sender.c: decide_recovery_type incre_full_count == 0\n", who_am_i());
		return 1;
	}
	else if (incre_full_count != 0 && diffe_full_count == 0) // 无差量备份,使用增量备份
	{
		rprintf(FWARNING, "[yee-%s] sender.c: decide_recovery_type diffe_full_count == 0\n", who_am_i());
		return 0;
	}
	else // 增量备份和差量备份都存在
	{
		/*找delta文件的版本*/
		char incre_delta_timestamp[100] = "\0";
		char diffe_delta_timestamp[100] = "\0";
		int find_incre_delta = 0, find_diffe_delta = 0;

		// 找到增量备份和差量备份的delta文件中, 最新的时间戳小于等于恢复版本号的文件 delta_timestamp <= recovery_timestamp
		for (int i = incre_delta_count; i != 0; i--)
		{
			extract_file_name_timestamp(incremental_delta_files->file_path[i - 1], incre_delta_timestamp);
			if (strcmp(incre_delta_timestamp, recovery_timestamp) <= 0)
			{
				find_incre_delta = 1;
				break;
			}
		}

		for (int i = diffe_delta_count; i != 0; i--)
		{
			extract_file_name_timestamp(differential_delta_files->file_path[i - 1], diffe_delta_timestamp);
			if (strcmp(diffe_delta_timestamp, recovery_timestamp) <= 0)
			{
				find_diffe_delta = 1;
				break;
			}
		}

		/*找full文件的版本*/
		char incre_full_timestamp[100] = "\0";
		char diffe_full_timestamp[100] = "\0";
		int find_incre_full = 0, find_diffe_full = 0;

		for (int i = incre_full_count; i != 0; i--)
		{
			extract_file_name_timestamp(incremental_full_files->file_path[i - 1], incre_full_timestamp);
			if (strcmp(incre_full_timestamp, recovery_timestamp) <= 0)
			{
				find_incre_full = 1;
				break;
			}
		}

		for (int i = diffe_full_count; i != 0; i--)
		{
			extract_file_name_timestamp(differential_full_files->file_path[i - 1], diffe_full_timestamp);
			if (strcmp(diffe_full_timestamp, recovery_timestamp) <= 0)
			{
				find_diffe_full = 1;
				break;
			}
		}

		if (find_incre_delta == 0 && find_diffe_delta == 0)
		{
			if (find_incre_full == 1 && find_diffe_full == 1)
			{
				if (strcmp(incre_full_timestamp, diffe_full_timestamp) > 0) // 增量备份full最新 使用增量备份
					return 0;
				else // 差量备份full最新 使用差量备份
					return 1;
			}
			else if (find_incre_full == 1 && find_diffe_full == 0)
			{
				return 0;
			}
			else if (find_incre_full == 0 && find_diffe_full == 1)
			{
				return 1;
			}
			else
			{
				return -1;
			}
		}
		else if (find_incre_delta == 0 && find_diffe_delta == 1) // 无合规的增量备份delta
		{
			if (find_incre_full == 1)
				return 0;
			else
				return 1;
		}
		else if (find_incre_delta == 1 && find_diffe_delta == 0) // 无合规的差量备份delta
		{
			if (find_diffe_full == 1)
				return 1;
			else
				return 0;
		}
		else if (strcmp(incre_delta_timestamp, diffe_delta_timestamp) > 0) // 增量备份delta最新 使用增量备份
		{
			return 0;
		}
		else // 差量备份delta最新(或差量与增量delta版本一致) 使用差量备份
		{
			return 1;
		}
	}
}

// 将增量文件拼接为完整文件
int combine_incremental_files(const char *dir_name, const char *file_name,
									 const backup_files_list *full_files, const backup_files_list *delta_files,
									 const char *recovery_version, char *recovery_file_path)
{
	rprintf(FINFO, "[debug-yee](%s)(%s-%s[%d]) combine_incremental_files dir_name = %s, file_name = %s \n",
			who_am_i(), __FILE__, __func__, __LINE__, dir_name, file_name);
	char full_timestamp[128], delta_timestamp[128];
	int full_count = full_files->num;
	int delta_count = delta_files->num;

	int full_index = 0, delta_index = 0, find_full = 0;

	char cwd[4096];
	getcwd(cwd, 4096);
	rprintf(FWARNING, "[yee-%s] sender.c: combine_incremental_files cwd: %s\n", who_am_i(), cwd);

	// 确定full文件
	for (full_index = full_count; full_index; full_index--)
	{
		extract_file_name_timestamp(full_files->file_path[full_index - 1], full_timestamp);
		int cmp = strcmp(full_timestamp, recovery_version);
		if (cmp < 0) // 该full文件时间戳小于恢复版本号, 满足要求,用于后续拼接
		{
			find_full = 1;
			full_index = full_index - 1;
			break;
		}
		else if (cmp == 0) // 该full文件时间戳等于恢复版本号,直接发送
		{
			strcpy(recovery_file_path, full_files->file_path[full_index - 1]);
			return 0;
		}
	}
	rprintf(FWARNING, "[yee-%s] sender.c: combine_incremental_files full_index: %d, full_timestamp = %s\n", who_am_i(), full_index, full_timestamp);
	if (find_full == 0) // 没有找到满足要求的full文件
	{
		rprintf(FWARNING, "[yee-%s] sender.c: combine_incremental_files full file %s not find\n", who_am_i(), recovery_version);
		return -1;
	}

	int delta_index_start = -1, delta_index_end = -1;
	for (delta_index = delta_count; delta_index; delta_index--)
	{
		extract_file_name_timestamp(delta_files->file_path[delta_index - 1], delta_timestamp);
		rprintf(FWARNING, "[yee-%s] sender.c: combine_incremental_files delta_index: %d, delta_timestamp = %s, recovery_version = %s\n",
				who_am_i(), delta_index, delta_timestamp, recovery_version);
		if (delta_index_end == -1 && strcmp(delta_timestamp, recovery_version) <= 0) // 找到增量文件的结束位置
		{
			delta_index_end = delta_index - 1;
		}
		if (delta_index_end != -1 && strcmp(delta_timestamp, full_timestamp) > 0) // 找到增量文件的起始位置
		{
			delta_index_start = delta_index - 1;
		}
		else if (delta_index_end != -1)
		{
			break;
		}
	}
	rprintf(FWARNING, "[yee-%s] sender.c: combine_incremental_files delta_index_start: %d, delta_index_end: %d\n", who_am_i(), delta_index_start, delta_index_end);
	if (delta_index_start == -1 || delta_index_end == -1 || delta_index_start > delta_index_end) // 增量版本号不满足要求
	{
		strcpy(recovery_file_path, full_files->file_path[full_index]);
		return 0;
	}

	char tmp_file_path[MAXPATHLEN], full_file_path[MAXPATHLEN], delta_file_path[MAXPATHLEN];

	// if ( dir_name != NULL || strlen(dir_name) == 0)
	// {
		sprintf(recovery_file_path, "./%s.backup/%s.%s", file_name, file_name, "recovery");
		sprintf(tmp_file_path, "./%s.backup/%s.%s", file_name, file_name, "recovery.tmp");

		rprintf(FINFO, "[debug-yee](%s) sender.c: combine_incremental_files recovery_file_path: %s\n", who_am_i(), recovery_file_path);
		rprintf(FINFO, "[debug-yee](%s) sender.c: combine_incremental_files tmp_file_path: %s\n", who_am_i(), tmp_file_path);
	// }
	// else
	// {
	// 	sprintf(recovery_file_path, "%s/%s.backup/%s.%s", dir_name, file_name, file_name, "recovery");
	// 	sprintf(tmp_file_path, "%s/%s.backup/%s.%s", dir_name, file_name, file_name, "recovery.tmp");
	// }

	strcpy(full_file_path, full_files->file_path[full_index]);

	FILE *full_file = fopen(full_file_path, "rb");
	FILE *delta_file = NULL;
	FILE *recovery_file = fopen(recovery_file_path, "wb");

	if (full_file == NULL)
	{
		rprintf(FWARNING, "[yee-%s] sender.c: combine_incremental_files full file %s fopen failed\n", who_am_i(), full_file_path);
	}
	else
	{
		rprintf(FWARNING, "[yee-%s] sender.c: combine_incremental_files full file %s fopen success\n", who_am_i(), full_file_path);
	}

	// 开始拼接文件
	for (delta_index = delta_index_start; delta_index <= delta_index_end; delta_index++)
	{
		rprintf(FWARNING, "[yee-%s] sender.c: combine_incremental_files in loop delta_file[%d] %s\n", who_am_i(), delta_index, delta_files->file_path[delta_index]);

		strcpy(delta_file_path, delta_files->file_path[delta_index]);
		delta_file = fopen(delta_file_path, "rb");

		if (delta_file == NULL)
		{
			rprintf(FWARNING, "[yee-%s] sender.c: make_delta_to_full delta_file %s open failed\n", who_am_i(), delta_file_path);
			return -1;
		}

		char line[1024 * 100];																	// delta行读取缓冲区
		int delta_block_length = -1, delta_block_count = -1, delta_remainder_block_length = -1; // delta文件元数据 块大小 块数量 剩余块大小
		OFF_T total_size = -1, content_size = -1;												// delta文件元数据 偏移量 总大小 内容大小

		struct map_struct *mapbuf = NULL;					// map_struct 快速找到全量文件中匹配的内容
		int fd_full = do_open(full_file_path, O_RDONLY, 0); // 以文件描述符的方式打开全量文件
		if (fd_full < 0)
		{
			rprintf(FWARNING, "[yee-%s] sender.c: make_delta_to_full full_file %s open failed\n", who_am_i(), full_file_path);
			return -1;
		}
		else
		{
			rprintf(FWARNING, "[yee-%s] sender.c: make_delta_to_full full_file %s open success\n", who_am_i(), full_file_path);
		}

		// delta 文件元数据解析
		if (fgets(line, sizeof(line), delta_file) != NULL)
		{
			sscanf(line, "[delta file metadata] file_size = %ld, content_size = %ld, block_size = %d, block_count = %d, remainder_block = %d\n",
				   &total_size, &content_size, &delta_block_length, &delta_block_count, &delta_remainder_block_length);
		}
		else
		{
			rprintf(FWARNING, "[yee-%s] sender.c: make_d2f fgets delta metadata error\n", who_am_i());
		}

		// 构建map_struct 以供map_ptr使用 参见receiver->receive_data
		int32 read_size = MAX(delta_block_length * 2, 16 * 1024);
		mapbuf = map_file(fd_full, content_size, read_size, delta_block_length); // 构建map_struct 以供map_ptr使用

		// delta 增量信息解析
		while (fgets(line, sizeof(line), delta_file) != NULL)
		{
			int token = -1;
			OFF_T offset = -1, offset2 = -1;

			if (strcmp(line, "\n") == 0 || strcmp(line, "\r\n") == 0)
			{
				continue;
			}
			else if (strncmp(line, "match token\0", strlen("match token\0")) == 0) // 解析delta文件中匹配的部分 token
			{
				char *map_data = NULL;
				size_t map_len = -1;
				sscanf(line, "match token = %d, offset = %ld, offset2 = %ld\n", &token, &offset, &offset2);

				map_len = delta_block_length;
				if (token == delta_block_count - 1 && delta_remainder_block_length != 0)
				{
					map_len = delta_remainder_block_length;
				}

				map_data = map_ptr(mapbuf, offset2, map_len); // 使用offset2

				if (map_data != NULL && fwrite(map_data, 1, map_len, recovery_file) != map_len)
				{
					rprintf(FWARNING, "[yee-%s] sender.c: make_d2f fwrite match data error\n", who_am_i());
				}
			}
			else if (strncmp(line, "unmatch data length\0", strlen("unmatch data length\0")) == 0) // 解析delta文件中不匹配的部分
			{

				char unmatch_data[1024 * 1000]; // 不匹配数据缓冲区
				size_t unmatch_len = 0;			// 读取长度
				sscanf(line, "unmatch data length = %ld, offset = %ld\n", &unmatch_len, &offset);

				if (fread(unmatch_data, 1, unmatch_len, delta_file) != unmatch_len)
				{
					rprintf(FWARNING, "[yee-%s] sender.c: make_d2f fread unmatch data length error\n", who_am_i());
				}

				if (fwrite(unmatch_data, 1, unmatch_len, recovery_file) != unmatch_len) // 直接将不匹配数据写入
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
		fclose(full_file);
		fclose(recovery_file);
		close(fd_full);

		if (delta_index != delta_index_end)
		{
			copy_file(recovery_file_path, tmp_file_path, -1, 0666);

			full_file = fopen(tmp_file_path, "rb");
			recovery_file = fopen(recovery_file_path, "wb");

			strcpy(full_file_path, tmp_file_path);
		}
		else
		{
			remove(tmp_file_path);
		}
	}
	rprintf(FWARNING, "[yee-%s] sender.c: combine_incremental_files finish!\n", who_am_i());
	return 0;
}

// 将差量文件拼接为完整文件
int combine_differental_files(const char *dir_name, const char *file_name,
									 const backup_files_list *full_files, const backup_files_list *delta_files,
									 const char *recovery_version, char *recovery_file_path)
{
	rprintf(FINFO, "[debug-yee](%s)(%s-%s[%d]) combine_incremental_files dir_name = %s, file_name = %s \n",
			who_am_i(), __FILE__, __func__, __LINE__, dir_name, file_name);
	char full_timestamp[128], delta_timestamp[128];
	int full_count = full_files->num;
	int delta_count = delta_files->num;

	int full_index = 0, delta_index = 0, find_full = 0, find_delta = 0;

	// 确定full文件
	for (full_index = full_count; full_index; full_index--)
	{
		extract_file_name_timestamp(full_files->file_path[full_index - 1], full_timestamp);
		int cmp = strcmp(full_timestamp, recovery_version);
		if (cmp < 0) // 该full文件时间戳小于恢复版本号, 满足要求,用于后续拼接
		{
			find_full = 1;
			full_index = full_index - 1;
			break;
		}
		else if (cmp == 0) // 该full文件时间戳等于恢复版本号,直接发送
		{
			strcpy(recovery_file_path, full_files->file_path[full_index - 1]);
			return 0;
		}
	}
	if (find_full == 0) // 没有找到满足要求的full文件
	{
		rprintf(FWARNING, "[yee-%s] sender.c: combine_differental_files full file %s not find\n", who_am_i(), recovery_version);
		return -1;
	}

	for (delta_index = delta_count; delta_index; delta_index--)
	{
		extract_file_name_timestamp(delta_files->file_path[delta_index - 1], delta_timestamp);
		if (strcmp(delta_timestamp, recovery_version) <= 0 && strcmp(delta_timestamp, full_timestamp) > 0) // 找到增量文件的结束位置
		{
			find_delta = 1;
			delta_index = delta_index - 1;
			break;
		}
	}
	if (find_delta == 0) // 增量版本号不满足要求
	{
		rprintf(FWARNING, "[yee-%s] sender.c: combine_differental_files delta file [%s -- %s] not find\n", who_am_i(), full_timestamp, recovery_version);
		return -1;
	}

	char full_file_path[MAXPATHLEN], delta_file_path[MAXPATHLEN];

	// if(dir_name == NULL || strlen(dir_name) == 0)
	// 	sprintf(recovery_file_path, "%s/%s.backup/%s.%s", dir_name, file_name, file_name, "recovery");
	// else
		sprintf(recovery_file_path, "./%s.backup/%s.%s", file_name, file_name, "recovery");

	strcpy(full_file_path, full_files->file_path[full_index]);

	FILE *full_file = fopen(full_file_path, "rb");
	FILE *delta_file = NULL;
	FILE *recovery_file = fopen(recovery_file_path, "wb");

	// 开始拼接文件

	char cwd[MAXPATHLEN];

	if (getcwd(cwd, sizeof(cwd)) != NULL)
	{
		rprintf(FWARNING, "[yee-%s] sender.c: make_delta_to_full current working directory: %s\n", who_am_i(), cwd);
	}
	else
	{
		rprintf(FWARNING, "[yee-%s] sender.c: make_delta_to_full getcwd() error\n", who_am_i());
	}

	strcpy(delta_file_path, delta_files->file_path[delta_index]);
	rprintf(FWARNING, "[yee-%s] sender.c: combine_differental_files delta_file_path: %s\n", who_am_i(), delta_file_path);
	delta_file = fopen(delta_file_path, "rb");
	if (delta_file == NULL)
	{
		rprintf(FWARNING, "[yee-%s] sender.c: combine_differental_files delta_file open failed\n", who_am_i());
		if (errno == ENOENT)
		{
			rprintf(FWARNING, "[yee-%s] sender.c:Error: file %s does not exist\n", who_am_i(), delta_file_path);
		}
		else if (errno == EACCES)
		{
			rprintf(FWARNING, "[yee-%s] sender.c:Error: file %s cannot be accessed\n", who_am_i(), delta_file_path);
		}
		else
		{
			rprintf(FWARNING, "[yee-%s] sender.c:Error: failed to open file %s, errno = %d\n", who_am_i(), delta_file_path, errno);
		}
		return -1;
	}

	char line[1024 * 100];																	// delta行读取缓冲区
	int delta_block_length = -1, delta_block_count = -1, delta_remainder_block_length = -1; // delta文件元数据 块大小 块数量 剩余块大小
	OFF_T total_size = -1, content_size = -1;												// delta文件元数据 偏移量 总大小 内容大小

	struct map_struct *mapbuf = NULL;					// map_struct 快速找到全量文件中匹配的内容
	int fd_full = do_open(full_file_path, O_RDONLY, 0); // 以文件描述符的方式打开全量文件
	if (fd_full < 0)
	{
		rprintf(FWARNING, "[yee-%s] sender.c: make_delta_to_full full_file %s open failed\n", who_am_i(), full_file_path);
		return -1;
	}

	// delta 文件元数据解析
	if (fgets(line, sizeof(line), delta_file) != NULL)
	{
		sscanf(line, "[delta file metadata] file_size = %ld, content_size = %ld, block_size = %d, block_count = %d, remainder_block = %d\n",
			   &total_size, &content_size, &delta_block_length, &delta_block_count, &delta_remainder_block_length);
	}
	else
	{
		rprintf(FWARNING, "[yee-%s] sender.c: make_d2f fgets delta metadata error\n", who_am_i());
	}

	// 构建map_struct 以供map_ptr使用 参见receiver->receive_data
	int32 read_size = MAX(delta_block_length * 2, 16 * 1024);
	mapbuf = map_file(fd_full, content_size, read_size, delta_block_length); // 构建map_struct 以供map_ptr使用

	// delta 增量信息解析
	while (fgets(line, sizeof(line), delta_file) != NULL)
	{
		int token = -1;
		OFF_T offset = -1, offset2 = -1;

		// rprintf(FWARNING, "[yee-%s] sender.c: make_d2f line: %s\n", who_am_i(), line);
		if (strcmp(line, "\n") == 0 || strcmp(line, "\r\n") == 0)
		{
			continue;
		}
		else if (strncmp(line, "match token\0", strlen("match token\0")) == 0) // 解析delta文件中匹配的部分 token
		{
			char *map_data = NULL;
			size_t map_len = -1;
			sscanf(line, "match token = %d, offset = %ld, offset2 = %ld\n", &token, &offset, &offset2);

			map_len = delta_block_length;
			if (token == delta_block_count - 1 && delta_remainder_block_length != 0)
			{
				map_len = delta_remainder_block_length;
			}

			map_data = map_ptr(mapbuf, offset2, map_len); // 使用offset2

			if (map_data != NULL && fwrite(map_data, 1, map_len, recovery_file) != map_len)
			{
				rprintf(FWARNING, "[yee-%s] sender.c: make_d2f fwrite match data error\n", who_am_i());
			}
		}
		else if (strncmp(line, "unmatch data length\0", strlen("unmatch data length\0")) == 0) // 解析delta文件中不匹配的部分
		{

			char unmatch_data[1024 * 1000]; // 不匹配数据缓冲区
			size_t unmatch_len = 0;			// 读取长度
			sscanf(line, "unmatch data length = %ld, offset = %ld\n", &unmatch_len, &offset);

			if (fread(unmatch_data, 1, unmatch_len, delta_file) != unmatch_len)
			{
				rprintf(FWARNING, "[yee-%s] sender.c: make_d2f fread unmatch data length error\n", who_am_i());
			}

			if (fwrite(unmatch_data, 1, unmatch_len, recovery_file) != unmatch_len) // 直接将不匹配数据写入
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
	fclose(full_file);
	fclose(recovery_file);
	close(fd_full);

	return 0;
}

# endif

# ifdef TRY_OLD
// 恢复时,选用的备份文件类型  0: incremental 使用增量备份, 	 	1: differential 使用差量备份
int decide_recovery_type(const char* dir_name, const char* file_name, 
						backup_files_list * incremental_full_files, backup_files_list * incremental_delta_files, 
						backup_files_list * differential_full_files, backup_files_list * differential_delta_files, 
						const char* recovery_timestamp )
{
	// 生成备份文件路径
	char incre_full_backup_path[MAXPATHLEN];
	char incre_delta_backup_path[MAXPATHLEN];
	char diffe_full_backup_path[MAXPATHLEN];
	char diffe_delta_backup_path[MAXPATHLEN];

	sprintf(incre_full_backup_path, "%s/%s.backup/incremental/full/", dir_name, file_name);
	sprintf(incre_delta_backup_path, "%s/%s.backup/incremental/delta/", dir_name, file_name);
	sprintf(diffe_full_backup_path, "%s/%s.backup/differential/full/", dir_name, file_name);
	sprintf(diffe_delta_backup_path, "%s/%s.backup/differential/delta/", dir_name, file_name);

	// 读取路径下文件并按时间排序
	int incre_delta_count = 0, incre_full_count = 0;
	int diffe_delta_count = 0, diffe_full_count = 0;

	if((incre_full_count = read_sort_dir_files(incre_full_backup_path, incremental_full_files->file_path)) == -1)
		incre_full_count = 0;
	else
		incremental_full_files->num = incre_full_count;

	if((incre_delta_count = read_sort_dir_files(incre_delta_backup_path, incremental_delta_files->file_path)) == -1)
		incre_delta_count = 0;
	else
		incremental_delta_files->num = incre_delta_count;

	if((diffe_full_count = read_sort_dir_files(diffe_full_backup_path, differential_full_files->file_path)) == -1)
		diffe_full_count = 0;
	else
		differential_full_files->num = diffe_full_count;

	if((diffe_delta_count = read_sort_dir_files(diffe_delta_backup_path, differential_delta_files->file_path)) == -1)
		diffe_delta_count = 0;
	else
		differential_delta_files->num = diffe_delta_count;

	rprintf(FWARNING, "[yee-%s] sender.c: decide_recovery_type incre_full_count: %d, incre_delta_count: %d, diffe_full_count: %d, diffe_delta_count: %d\n", 
			who_am_i(), incre_full_count, incre_delta_count, diffe_full_count, diffe_delta_count);

	if(incre_full_count == 0 && diffe_full_count == 0)		// 增量备份和差量备份都不存在
	{
		return -1;
	}
	else if(incre_full_count == 0 && diffe_full_count != 0) // 无增量备份,使用差量备份
	{
		rprintf(FWARNING, "[yee-%s] sender.c: decide_recovery_type incre_full_count == 0\n", who_am_i());
		return 1;
	}
	else if(incre_full_count != 0 && diffe_full_count == 0) // 无差量备份,使用增量备份
	{
		rprintf(FWARNING, "[yee-%s] sender.c: decide_recovery_type diffe_full_count == 0\n", who_am_i());
		return 0;
	}
	else	// 增量备份和差量备份都存在
	{
		/*找delta文件的版本*/
		char incre_delta_timestamp[100] = "\0";
		char diffe_delta_timestamp[100] = "\0";
		int find_incre_delta = 0, find_diffe_delta = 0;


		// 找到增量备份和差量备份的delta文件中, 最新的时间戳小于等于恢复版本号的文件 delta_timestamp <= recovery_timestamp
		for(int i = incre_delta_count; i != 0; i--)
		{
			extract_file_name_timestamp(incremental_delta_files->file_path[i - 1], incre_delta_timestamp);
			if(strcmp(incre_delta_timestamp, recovery_timestamp) <= 0)
			{
				find_incre_delta = 1;
				break;
			}
		}

		for(int i = diffe_delta_count; i != 0; i--)
		{
			extract_file_name_timestamp(differential_delta_files->file_path[i - 1], diffe_delta_timestamp);
			if(strcmp(diffe_delta_timestamp, recovery_timestamp) <= 0)
			{
				find_diffe_delta = 1;
				break;
			}
		}

		/*找full文件的版本*/
		char incre_full_timestamp[100] = "\0";
		char diffe_full_timestamp[100] = "\0";
		int find_incre_full = 0, find_diffe_full = 0;

		for(int i = incre_full_count; i != 0; i--)
		{
			extract_file_name_timestamp(incremental_full_files->file_path[i - 1], incre_full_timestamp);
			if(strcmp(incre_full_timestamp, recovery_timestamp) <= 0)
			{
				find_incre_full = 1;
				break;
			}
		}

		for(int i = diffe_full_count; i != 0; i--)
		{
			extract_file_name_timestamp(differential_full_files->file_path[i - 1], diffe_full_timestamp);
			if(strcmp(diffe_full_timestamp, recovery_timestamp) <= 0)
			{
				find_diffe_full = 1;
				break;
			}
		}


		if(find_incre_delta == 0 && find_diffe_delta == 0)
		{
			if(find_incre_full == 1 && find_diffe_full == 1)
			{
				if(strcmp(incre_full_timestamp, diffe_full_timestamp) > 0)	// 增量备份full最新 使用增量备份
					return 0;
				else														// 差量备份full最新 使用差量备份
					return 1;
			}
			else if(find_incre_full == 1 && find_diffe_full == 0)
			{
				return 0;
			}
			else if(find_incre_full == 0 && find_diffe_full == 1)
			{
				return 1;
			}
			else
			{	
				return -1;
			}
		}
		else if(find_incre_delta == 0 && find_diffe_delta == 1)				// 无合规的增量备份delta
		{
			if(find_incre_full == 1)
				return 0;
			else
				return 1;
		}
		else if(find_incre_delta == 1 && find_diffe_delta == 0)				// 无合规的差量备份delta
		{
			if(find_diffe_full == 1)
				return 1;
			else
				return 0;
		}
		else if(strcmp(incre_delta_timestamp, diffe_delta_timestamp) > 0)	// 增量备份delta最新 使用增量备份
		{
			return 0;
		}	
		else																// 差量备份delta最新(或差量与增量delta版本一致) 使用差量备份
		{
			return 1;
		}

	}
}

// 将增量文件拼接为完整文件
int combine_incremental_files(const char* dir_name, const char* file_name,
							const backup_files_list * full_files, const backup_files_list * delta_files, 
							const char* recovery_version, char* recovery_file_path)	
{
	char full_timestamp[128], delta_timestamp[128];
	int full_count = full_files->num;
	int delta_count = delta_files->num;

	int full_index = 0, delta_index = 0, find_full = 0;

	char cwd[4096];
	getcwd(cwd, 4096);
	rprintf(FWARNING, "[yee-%s] sender.c: combine_incremental_files cwd: %s\n", who_am_i(), cwd);

	// 确定full文件
	for(full_index = full_count; full_index; full_index--)
	{
		extract_file_name_timestamp(full_files->file_path[full_index - 1], full_timestamp);
		int cmp = strcmp(full_timestamp, recovery_version);
		if(cmp < 0)	// 该full文件时间戳小于恢复版本号, 满足要求,用于后续拼接
		{	
			find_full = 1;
			full_index = full_index - 1;
			break;
		}
		else if(cmp == 0)	// 该full文件时间戳等于恢复版本号,直接发送
		{
			strcpy(recovery_file_path, full_files->file_path[full_index - 1]);
			return 0;
		}

	}
	rprintf(FWARNING, "[yee-%s] sender.c: combine_incremental_files full_index: %d, full_timestamp = %s\n", who_am_i(), full_index, full_timestamp);
	if( find_full == 0 )	// 没有找到满足要求的full文件
	{
		rprintf(FWARNING, "[yee-%s] sender.c: combine_incremental_files full file %s not find\n", who_am_i(), recovery_version);
		return -1;
	}

	int delta_index_start = -1, delta_index_end = -1;
	for(delta_index = delta_count; delta_index; delta_index--)
	{
		extract_file_name_timestamp(delta_files->file_path[delta_index - 1], delta_timestamp);
		rprintf(FWARNING, "[yee-%s] sender.c: combine_incremental_files delta_index: %d, delta_timestamp = %s, recovery_version = %s\n", 
			who_am_i(), delta_index, delta_timestamp, recovery_version);
		if(delta_index_end == -1 && strcmp(delta_timestamp, recovery_version) <= 0)	// 找到增量文件的结束位置
		{
			delta_index_end = delta_index - 1;
		}
		if(delta_index_end != -1 && strcmp(delta_timestamp, full_timestamp) > 0)	// 找到增量文件的起始位置
		{
			delta_index_start = delta_index - 1;
		}
		else if(delta_index_end != -1)
		{
			break;
		}
	}
	rprintf(FWARNING, "[yee-%s] sender.c: combine_incremental_files delta_index_start: %d, delta_index_end: %d\n", who_am_i(), delta_index_start, delta_index_end);
	if(delta_index_start == -1 || delta_index_end == -1 || delta_index_start > delta_index_end)	// 增量版本号不满足要求
	{
		strcpy(recovery_file_path, full_files->file_path[full_index]);
		return 0;
	}

	char tmp_file_path[MAXPATHLEN], full_file_path[MAXPATHLEN], delta_file_path[MAXPATHLEN];

	sprintf(recovery_file_path, "%s/%s.backup/%s.%s", dir_name, file_name, file_name, "recovery");
	sprintf(tmp_file_path,"%s/%s.backup/%s.%s", dir_name, file_name, file_name, "recovery.tmp");
	
	strcpy(full_file_path, full_files->file_path[full_index]);
 
	FILE *full_file = fopen(full_file_path, "rb");
	FILE *delta_file = NULL;
	FILE *recovery_file = fopen(recovery_file_path, "wb");

	if(full_file == NULL)
	{
		rprintf(FWARNING, "[yee-%s] sender.c: combine_incremental_files full file %s fopen failed\n", who_am_i(), full_file_path);
	}
	else
	{
		rprintf(FWARNING, "[yee-%s] sender.c: combine_incremental_files full file %s fopen success\n", who_am_i(), full_file_path);
	}

	// 开始拼接文件
	for(delta_index = delta_index_start; delta_index <= delta_index_end; delta_index++)
	{	
		rprintf(FWARNING,"[yee-%s] sender.c: combine_incremental_files in loop delta_file[%d] %s\n", who_am_i(), delta_index, delta_files->file_path[delta_index]);
		
		strcpy(delta_file_path, delta_files->file_path[delta_index]);
		delta_file = fopen(delta_file_path, "rb");

		if( delta_file == NULL )
		{
			rprintf(FWARNING, "[yee-%s] sender.c: make_delta_to_full delta_file %s open failed\n", who_am_i(), delta_file_path);
			return -1;
		}

		char line[1024*100];																	// delta行读取缓冲区
		int delta_block_length = -1, delta_block_count = -1, delta_remainder_block_length = -1; // delta文件元数据 块大小 块数量 剩余块大小
		OFF_T total_size = -1, content_size = -1;	// delta文件元数据 偏移量 总大小 内容大小
		
		struct map_struct *mapbuf = NULL;	// map_struct 快速找到全量文件中匹配的内容
		int fd_full = do_open(full_file_path, O_RDONLY, 0);	// 以文件描述符的方式打开全量文件
		if( fd_full < 0 )
		{
			rprintf(FWARNING, "[yee-%s] sender.c: make_delta_to_full full_file %s open failed\n", who_am_i(), full_file_path);
			return -1;
		}
		else
		{
			rprintf(FWARNING, "[yee-%s] sender.c: make_delta_to_full full_file %s open success\n", who_am_i(), full_file_path);
		}

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

		// 构建map_struct 以供map_ptr使用 参见receiver->receive_data
		int32 read_size = MAX(delta_block_length*2, 16*1024);
		mapbuf = map_file(fd_full, content_size, read_size, delta_block_length);	// 构建map_struct 以供map_ptr使用

		// delta 增量信息解析
		while ( fgets(line, sizeof(line), delta_file) != NULL)
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

				if( map_data != NULL && fwrite(map_data, 1, map_len, recovery_file) != map_len )
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

				if( fwrite(unmatch_data, 1, unmatch_len, recovery_file) != unmatch_len ) // 直接将不匹配数据写入
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
		fclose(full_file);
		fclose(recovery_file);
		close(fd_full);

		if(delta_index != delta_index_end)
		{
			copy_file(recovery_file_path, tmp_file_path, -1, 0666);

			full_file = fopen(tmp_file_path, "rb");
			recovery_file = fopen(recovery_file_path, "wb");

			strcpy(full_file_path, tmp_file_path);
		}
		else
		{
			remove(tmp_file_path);
		}
	}
	return 0;
}

// 将差量文件拼接为完整文件
int combine_differental_files(const char* dir_name, const char* file_name,
							const backup_files_list * full_files, const backup_files_list * delta_files, 
							const char* recovery_version, char* recovery_file_path)	
{
	char full_timestamp[128], delta_timestamp[128];
	int full_count = full_files->num;
	int delta_count = delta_files->num;

	int full_index = 0, delta_index = 0, find_full = 0, find_delta = 0;
	

	// 确定full文件
	for(full_index = full_count; full_index; full_index--)
	{
		extract_file_name_timestamp(full_files->file_path[full_index - 1], full_timestamp);
		int cmp = strcmp(full_timestamp, recovery_version);
		if(cmp < 0)	// 该full文件时间戳小于恢复版本号, 满足要求,用于后续拼接
		{
			find_full = 1;
			full_index = full_index - 1;
			break;
		}
		else if(cmp == 0)	// 该full文件时间戳等于恢复版本号,直接发送
		{
			strcpy(recovery_file_path, full_files->file_path[full_index - 1]);
			return 0;
		}
	}
	if( find_full == 0 )	// 没有找到满足要求的full文件
	{
		rprintf(FWARNING, "[yee-%s] sender.c: combine_differental_files full file %s not find\n", who_am_i(), recovery_version);
		return -1;
	}



	for(delta_index = delta_count; delta_index; delta_index--)
	{
		extract_file_name_timestamp(delta_files->file_path[delta_index - 1], delta_timestamp);
		if(strcmp(delta_timestamp, recovery_version) <= 0 && strcmp(delta_timestamp, full_timestamp) > 0)	// 找到增量文件的结束位置
		{
			find_delta = 1;
			delta_index = delta_index - 1;
			break;
		}
	}
	if(find_delta == 0)	// 增量版本号不满足要求
	{
		rprintf(FWARNING, "[yee-%s] sender.c: combine_differental_files delta file [%s -- %s] not find\n", who_am_i(), full_timestamp, recovery_version);
		return -1;
	}

	char full_file_path[MAXPATHLEN], delta_file_path[MAXPATHLEN];

	sprintf(recovery_file_path, "%s/%s.backup/%s.%s", dir_name, file_name, file_name, "recovery");
	
	strcpy(full_file_path, full_files->file_path[full_index]);

	FILE *full_file = fopen(full_file_path, "rb");
	FILE *delta_file = NULL;
	FILE *recovery_file = fopen(recovery_file_path, "wb");

	// 开始拼接文件

	char cwd[MAXPATHLEN];

	if (getcwd(cwd, sizeof(cwd)) != NULL) {
		rprintf(FWARNING, "[yee-%s] sender.c: make_delta_to_full current working directory: %s\n", who_am_i(), cwd);
	} else {
		rprintf(FWARNING, "[yee-%s] sender.c: make_delta_to_full getcwd() error\n", who_am_i());
	}

	strcpy(delta_file_path, delta_files->file_path[delta_index]);
	rprintf(FWARNING, "[yee-%s] sender.c: combine_differental_files delta_file_path: %s\n", who_am_i(), delta_file_path);
	delta_file = fopen(delta_file_path, "rb");
	if( delta_file == NULL )
	{
		rprintf(FWARNING, "[yee-%s] sender.c: combine_differental_files delta_file open failed\n", who_am_i());
		if (errno == ENOENT) {
            rprintf(FWARNING, "[yee-%s] sender.c:Error: file %s does not exist\n", who_am_i(), delta_file_path);
        } else if (errno == EACCES) {
            rprintf(FWARNING, "[yee-%s] sender.c:Error: file %s cannot be accessed\n", who_am_i(), delta_file_path);
        } else {
            rprintf(FWARNING, "[yee-%s] sender.c:Error: failed to open file %s, errno = %d\n", who_am_i(), delta_file_path, errno);
        }
		return -1;
	}

	char line[1024*100];																	// delta行读取缓冲区
	int delta_block_length = -1, delta_block_count = -1, delta_remainder_block_length = -1; // delta文件元数据 块大小 块数量 剩余块大小
	OFF_T total_size = -1, content_size = -1;	// delta文件元数据 偏移量 总大小 内容大小
	
	struct map_struct *mapbuf = NULL;	// map_struct 快速找到全量文件中匹配的内容
	int fd_full = do_open(full_file_path, O_RDONLY, 0);	// 以文件描述符的方式打开全量文件
	if( fd_full < 0 )
	{
		rprintf(FWARNING, "[yee-%s] sender.c: make_delta_to_full full_file %s open failed\n", who_am_i(), full_file_path);
		return -1;
	}

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

	// 构建map_struct 以供map_ptr使用 参见receiver->receive_data
	int32 read_size = MAX(delta_block_length*2, 16*1024);
	mapbuf = map_file(fd_full, content_size, read_size, delta_block_length);	// 构建map_struct 以供map_ptr使用

	// delta 增量信息解析
	while ( fgets(line, sizeof(line), delta_file) != NULL)
	{ 
		int token = -1;
		OFF_T offset = -1, offset2 = -1;

		// rprintf(FWARNING, "[yee-%s] sender.c: make_d2f line: %s\n", who_am_i(), line);
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

			if( map_data != NULL && fwrite(map_data, 1, map_len, recovery_file) != map_len )
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

			if( fwrite(unmatch_data, 1, unmatch_len, recovery_file) != unmatch_len ) // 直接将不匹配数据写入
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
	fclose(full_file);
	fclose(recovery_file);
	close(fd_full);

	
	return 0;
}

# endif

/**
 * @file
 *
 * The sender gets checksums from the generator, calculates deltas,
 * and transmits them to the receiver.  The sender process runs on the
 * machine holding the source files.
 **/

/**
 * Receive the checksums for a buffer
 **/
static struct sum_struct *receive_sums(int f)
{
	struct sum_struct *s = new(struct sum_struct);
	int lull_mod = protocol_version >= 31 ? 0 : allowed_lull * 5;
	OFF_T offset = 0;
	int32 i;

	read_sum_head(f, s);

	s->sums = NULL;

	if (DEBUG_GTE(DELTASUM, 3)) {
		rprintf(FINFO, "count=%s n=%ld rem=%ld\n",
			big_num(s->count), (long)s->blength, (long)s->remainder);
	}

	if (append_mode > 0) {
		s->flength = (OFF_T)s->count * s->blength;
		if (s->remainder)
			s->flength -= s->blength - s->remainder;
		return s;
	}

	if (s->count == 0)
		return(s);

	if (!(s->sums = new_array(struct sum_buf, s->count)))
		out_of_memory("receive_sums");

	// s->sums = new_array(struct sum_buf, s->count);

	for (i = 0; i < s->count; i++) {
		s->sums[i].sum1 = read_int(f);
		read_buf(f, s->sums[i].sum2, s->s2length);

		s->sums[i].offset = offset;
		s->sums[i].flags = 0;

		if (i == s->count-1 && s->remainder != 0)
			s->sums[i].len = s->remainder;
		else
			s->sums[i].len = s->blength;
		offset += s->sums[i].len;

		if (lull_mod && !(i % lull_mod))
			maybe_send_keepalive(time(NULL), True);

		if (DEBUG_GTE(DELTASUM, 3)) {
			rprintf(FINFO,
				"chunk[%d] len=%d offset=%s sum1=%08x\n",
				i, s->sums[i].len, big_num(s->sums[i].offset),
				s->sums[i].sum1);
		}
	}

	s->flength = offset;

	return s;
}

void successful_send(int ndx)
{
	char fname[MAXPATHLEN];
	char *failed_op;
	struct file_struct *file;
	struct file_list *flist;
	STRUCT_STAT st;

	if (!remove_source_files)
		return;

	flist = flist_for_ndx(ndx, "successful_send");
	file = flist->files[ndx - flist->ndx_start];
	if (!change_pathname(file, NULL, 0))
		return;
	f_name(file, fname);

	if ((copy_links ? do_stat(fname, &st) : do_lstat(fname, &st)) < 0) {
		failed_op = "re-lstat";
		goto failed;
	}

	if (local_server
	 && (int64)st.st_dev == IVAL64(num_dev_ino_buf, 4)
	 && (int64)st.st_ino == IVAL64(num_dev_ino_buf, 4 + 8)) {
		rprintf(FERROR_XFER, "ERROR: Skipping sender remove of destination file: %s\n", fname);
		return;
	}

	if (st.st_size != F_LENGTH(file) || st.st_mtime != file->modtime
#ifdef ST_MTIME_NSEC
	 || (NSEC_BUMP(file) && (uint32)st.ST_MTIME_NSEC != F_MOD_NSEC(file))
#endif
	) {
		rprintf(FERROR_XFER, "ERROR: Skipping sender remove for changed file: %s\n", fname);
		return;
	}

	if (do_unlink(fname) < 0) {
		failed_op = "remove";
	  failed:
		if (errno == ENOENT)
			rprintf(FINFO, "sender file already removed: %s\n", fname);
		else
			rsyserr(FERROR_XFER, errno, "sender failed to %s %s", failed_op, fname);
	} else {
		if (INFO_GTE(REMOVE, 1))
			rprintf(FINFO, "sender removed %s\n", fname);
	}
}

static void write_ndx_and_attrs(int f_out, int ndx, int iflags,
				const char *fname, struct file_struct *file,
				uchar fnamecmp_type, char *buf, int len)
{
	write_ndx(f_out, ndx);
	if (protocol_version < 29)
		return;
	write_shortint(f_out, iflags);
	if (iflags & ITEM_BASIS_TYPE_FOLLOWS)
		write_byte(f_out, fnamecmp_type);
	if (iflags & ITEM_XNAME_FOLLOWS)
		write_vstring(f_out, buf, len);
#ifdef SUPPORT_XATTRS
	if (preserve_xattrs && iflags & ITEM_REPORT_XATTR && do_xfers
	 && !(want_xattr_optim && BITS_SET(iflags, ITEM_XNAME_FOLLOWS|ITEM_LOCAL_CHANGE)))
		send_xattr_request(fname, file, f_out);
#endif
}

void send_files(int f_in, int f_out)
{
	int fd = -1;
	struct sum_struct *s;
	struct map_struct *mbuf = NULL;
	STRUCT_STAT st;
	char fname[MAXPATHLEN], xname[MAXPATHLEN];
	const char *path, *slash;
	uchar fnamecmp_type;
	int iflags, xlen;
	struct file_struct *file;
	int phase = 0, max_phase = protocol_version >= 29 ? 2 : 1;
	int itemizing = am_server ? logfile_format_has_i : stdout_format_has_i;
	enum logcode log_code = log_before_transfer ? FLOG : FINFO;
	int f_xfer = write_batch < 0 ? batch_fd : f_out;
	int save_io_error = io_error;
	int ndx, j;

	if (DEBUG_GTE(SEND, 1))
		rprintf(FINFO, "send_files starting\n");

	if (whole_file < 0)
		whole_file = 0;

	progress_init();

	while (1) {
		if (inc_recurse) {
			send_extra_file_list(f_out, MIN_FILECNT_LOOKAHEAD);
			extra_flist_sending_enabled = !flist_eof;
		}

		/* This call also sets cur_flist. */
		ndx = read_ndx_and_attrs(f_in, f_out, &iflags, &fnamecmp_type,
					 xname, &xlen);
		extra_flist_sending_enabled = False;

		if (ndx == NDX_DONE) {
			if (!am_server && INFO_GTE(PROGRESS, 2) && cur_flist) {
				set_current_file_index(NULL, 0);
				if (INFO_GTE(PROGRESS, 2))
					end_progress(0);
			}
			if (inc_recurse && first_flist) {
				file_old_total -= first_flist->used;
				flist_free(first_flist);
				if (first_flist) {
					if (first_flist == cur_flist)
						file_old_total = cur_flist->used;
					write_ndx(f_out, NDX_DONE);
					continue;
				}
			}
			if (++phase > max_phase)
				break;
			if (DEBUG_GTE(SEND, 1))
				rprintf(FINFO, "send_files phase=%d\n", phase);
			write_ndx(f_out, NDX_DONE);
			continue;
		}

		if (inc_recurse)
			send_extra_file_list(f_out, MIN_FILECNT_LOOKAHEAD);

		if (ndx - cur_flist->ndx_start >= 0)
			file = cur_flist->files[ndx - cur_flist->ndx_start];
		else
			file = dir_flist->files[cur_flist->parent_ndx];
		if (F_PATHNAME(file)) {
			path = F_PATHNAME(file);
			slash = "/";
		} else {
			path = slash = "";
		}
		if (!change_pathname(file, NULL, 0))
			continue;
		f_name(file, fname);

		/**
		 * 以上完成待备份文件的路径解析
		 * @param path 路径名
		 * @param slash 斜杠号
		 * @param fname 文件名
		*/
		// if (DEBUG_GTE(SEND, 1))
			rprintf(FINFO, "send_files(%d, %s|%s|%s)\n", ndx, path,slash,fname);

	#ifdef RECOVERY_VERSION


	#ifdef TRY_NEW
		recovery_type = -1;

		backup_files_list *incremental_full_files = (backup_files_list *)malloc(sizeof(backup_files_list));
		backup_files_list *incremental_delta_files = (backup_files_list *)malloc(sizeof(backup_files_list));
		backup_files_list *differential_full_files = (backup_files_list *)malloc(sizeof(backup_files_list));
		backup_files_list *differential_delta_files = (backup_files_list *)malloc(sizeof(backup_files_list));

		char recovery_path[MAXPATHLEN] = "";	
		if (is_recovery && strcmp(fname, ".") != 0 && strcmp(fname, "..") != 0)
		{
			rprintf(FINFO, "[debug-yee](%s)(%s-%s[%d]): recovery fname=%s\n",
					who_am_i(), __FILE__, __FUNCTION__, __LINE__, fname);
			struct stat path_stat;
			if (stat(fname, &path_stat) == 0)
			{
				if (!S_ISDIR(path_stat.st_mode))
				{
					recovery_type = decide_recovery_type(path, fname, incremental_full_files, incremental_delta_files,
														 differential_full_files, differential_delta_files, recovery_version);
					rprintf(FINFO, "[debug-yee](%s)(%s-%s[%d]): send_files recovery_type=%s\n",
							who_am_i(), __FILE__, __FUNCTION__, __LINE__, recovery_type?"differential":"incremental");
				}
				if (recovery_type == 0)
				{
					rprintf(FINFO, "[debug-yee](%s)(%s-%s[%d]):start incremental combine\n",
							who_am_i(), __FILE__, __FUNCTION__, __LINE__);
					if (combine_incremental_files(path, fname, incremental_full_files, incremental_delta_files, recovery_version, recovery_path) != 0)
					{
						rprintf(FERROR, "[debug-yee](%s)(%s-%s[%d]): send_files combine_incremental_files error\n",
								who_am_i(), __FILE__, __FUNCTION__, __LINE__);
					}
				}
				else if (recovery_type == 1)
				{
					rprintf(FINFO, "[debug-yee](%s)(%s-%s[%d]):start differential combine\n",
							who_am_i(), __FILE__, __FUNCTION__, __LINE__);
					if (combine_differental_files(path, fname, differential_full_files, differential_delta_files, recovery_version, recovery_path) != 0)
					{
						rprintf(FERROR, "[debug-yee](%s)(%s-%s[%d]): send_files combine_differental_files error\n",
								who_am_i(), __FILE__, __FUNCTION__, __LINE__);
					}
				}
				else
				{
					rprintf(FERROR, "[debug-yee](%s)(%s-%s[%d]): send_files recovery_type error!\n",
							who_am_i(), __FILE__, __FUNCTION__, __LINE__);
					perror("decide recovery type error");
				}
			}
			else
			{
				rprintf(FERROR, "[debug-yee](%s)(%s-%s[%d]): send_files stat %s error\n",
						who_am_i(), __FILE__, __FUNCTION__, __LINE__, fname);
			}

		}
	#endif

	#ifdef TRY_OLD
			// 分离出目录名和文件名
			char *ptr = strrchr(fname, '/');
			char dir_name[MAXPATHLEN];
			char file_name[MAXNAMLEN];

			if(ptr != NULL)
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

			recovery_type = -1;

			backup_files_list *incremental_full_files = (backup_files_list*)malloc(sizeof(backup_files_list));
			backup_files_list *incremental_delta_files = (backup_files_list*)malloc(sizeof(backup_files_list));
			backup_files_list *differential_full_files = (backup_files_list*)malloc(sizeof(backup_files_list));
			backup_files_list *differential_delta_files = (backup_files_list*)malloc(sizeof(backup_files_list));

			char recovery_path[MAXPATHLEN] = "";

			
			if(is_recovery == 1 && strcmp(fname, ".") != 0 && strcmp(fname, "..") != 0 )
			{	
				struct stat path_stat;
				if (stat(fname, &path_stat) == 0) 
				{
					if (!S_ISDIR(path_stat.st_mode)) 
					{
						rprintf(FWARNING, "[yee-%s] sender.c: send_files make d2f dir_name = %s, file_name = %s\n", who_am_i(), dir_name, file_name);
						rprintf(FWARNING, "[yee-%s] sender.c: send_files make d2f version = %s, iflags = %d\n", who_am_i(), recovery_version, iflags);
						recovery_type =  decide_recovery_type(dir_name, file_name, incremental_full_files, incremental_delta_files, 
																differential_full_files, differential_delta_files, recovery_version);
						rprintf(FWARNING, "[yee-%s] sender.c: send_files recovery_type = *%s*\n", who_am_i(), recovery_type?"diffe 差量备份":"incre 增量备份");
						// print_backup_files_list(incremental_full_files);
						// print_backup_files_list(incremental_delta_files);
						// print_backup_files_list(differential_full_files);
						// print_backup_files_list(differential_delta_files);
						if(recovery_type == 0)		// 使用增量备份
						{
							if(combine_incremental_files(dir_name, file_name, incremental_full_files, incremental_delta_files, recovery_version, recovery_path) != 0)
							{
								rprintf(FWARNING, "[yee-%s] sender.c: send_files combine_incremental_files error\n", who_am_i());
							}
						}
						else if(recovery_type == 1)	// 使用差量备份
						{
							if(combine_differental_files(dir_name, file_name, differential_full_files, differential_delta_files, recovery_version, recovery_path) != 0)
							{
								rprintf(FWARNING, "[yee-%s] sender.c: send_files combine_differental_files error\n", who_am_i());
							}
						}
						else
						{
							rprintf(FWARNING, "[yee-%s] sender.c: send_files decide_recovery_type error\n", who_am_i());
						}
					}
				// make_delta_to_full(fname, recovery_version);
				}
			}
	#endif

	#endif

#ifdef SUPPORT_XATTRS
		if (preserve_xattrs && iflags & ITEM_REPORT_XATTR && do_xfers
		 && !(want_xattr_optim && BITS_SET(iflags, ITEM_XNAME_FOLLOWS|ITEM_LOCAL_CHANGE)))
			recv_xattr_request(file, f_in);
#endif

		if (!(iflags & ITEM_TRANSFER)) {
			maybe_log_item(file, iflags, itemizing, xname);
			write_ndx_and_attrs(f_out, ndx, iflags, fname, file, fnamecmp_type, xname, xlen);
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
				/* For inplace: redo phase turns off the backup
				 * flag so that we do a regular inplace send. */
				make_backups = -make_backups;
				append_mode = -append_mode;
				csum_length = SUM_LENGTH;
			}
		} else {
			if (csum_length != SHORT_SUM_LENGTH) {
				make_backups = -make_backups;
				append_mode = -append_mode;
				csum_length = SHORT_SUM_LENGTH;
			}
			if (iflags & ITEM_IS_NEW)
				stats.created_files++;
		}

		updating_basis_file = (inplace_partial && fnamecmp_type == FNAMECMP_PARTIAL_DIR)
		    || (inplace && (protocol_version >= 29 ? fnamecmp_type == FNAMECMP_FNAME : make_backups <= 0));

		if (!am_server)
			set_current_file_index(file, ndx);
		stats.xferred_files++;
		stats.total_transferred_size += F_LENGTH(file);

		remember_initial_stats();
		
		if (!do_xfers) { /* log the transfer */
			log_item(FCLIENT, file, iflags, NULL);
			write_ndx_and_attrs(f_out, ndx, iflags, fname, file, fnamecmp_type, xname, xlen);
			continue;
		}

		if (!(s = receive_sums(f_in))) {
			io_error |= IOERR_GENERAL;
			rprintf(FERROR_XFER, "receive_sums failed\n");
			exit_cleanup(RERR_PROTOCOL);
		}

	#ifdef RECOVERY_VERSION
		if (is_recovery)
		{
			rprintf(FINFO, "[debug-yee](%s)(%s->%s[%d]) do_open recovery_path=%s\n", 
					who_am_i(), __FILE__, __FUNCTION__, __LINE__, recovery_path);
			fd = do_open(recovery_path, O_RDONLY, 0);
		}
		else
	#endif
			fd = do_open(fname, O_RDONLY, 0);
		if (fd == -1) {
			if (errno == ENOENT) {
				enum logcode c = am_daemon && protocol_version < 28 ? FERROR : FWARNING;
				io_error |= IOERR_VANISHED;
				rprintf(c, "file has vanished: %s\n",
					full_fname(fname));
			} else {
				io_error |= IOERR_GENERAL;
				rsyserr(FERROR_XFER, errno,
					"send_files failed to open %s",
					full_fname(fname));
			}
			free_sums(s);
			if (protocol_version >= 30)
				send_msg_int(MSG_NO_SEND, ndx);
			continue;
		}


		/* map the local file */
		if (do_fstat(fd, &st) != 0) {
			io_error |= IOERR_GENERAL;
			rsyserr(FERROR_XFER, errno, "fstat failed");
			free_sums(s);
			close(fd);
			exit_cleanup(RERR_FILEIO);
		}

		if (IS_DEVICE(st.st_mode)) {
			if (!copy_devices) {
				rprintf(FERROR, "attempt to copy device contents without --copy-devices\n");
				exit_cleanup(RERR_PROTOCOL);
			}
			if (st.st_size == 0)
				st.st_size = get_device_size(fd, fname);
		}

		if (append_mode > 0 && st.st_size < F_LENGTH(file)) {
			rprintf(FWARNING, "skipped diminished file: %s\n",
				full_fname(fname));
			free_sums(s);
			close(fd);
			if (protocol_version >= 30)
				send_msg_int(MSG_NO_SEND, ndx);
			continue;
		}

		if (st.st_size) {
			int32 read_size = MAX(s->blength * 3, MAX_MAP_SIZE);
			mbuf = map_file(fd, st.st_size, read_size, s->blength);
		} else
			mbuf = NULL;

		if (DEBUG_GTE(DELTASUM, 2)) {
			rprintf(FINFO, "send_files mapped %s%s%s of size %s\n",
				path,slash,fname, big_num(st.st_size));
		}
				

		write_ndx_and_attrs(f_out, ndx, iflags, fname, file, 
							fnamecmp_type, xname, xlen);
		write_sum_head(f_xfer, s);

		if (DEBUG_GTE(DELTASUM, 2))
			rprintf(FINFO, "calling match_sums %s%s%s\n", path,slash,fname);

		if (log_before_transfer)
			log_item(FCLIENT, file, iflags, NULL);
		else if (!am_server && INFO_GTE(NAME, 1) && INFO_EQ(PROGRESS, 1))
			rprintf(FCLIENT, "%s\n", fname);

		set_compression(fname);

		match_sums(f_xfer, s, mbuf, st.st_size);
		if (INFO_GTE(PROGRESS, 1))
			end_progress(st.st_size);
		else if (want_progress_now)
			instant_progress(fname);

		log_item(log_code, file, iflags, NULL);

		if (mbuf) {
			j = unmap_file(mbuf);
			if (j) {
				io_error |= IOERR_GENERAL;
				rsyserr(FERROR_XFER, j,
					"read errors mapping %s",
					full_fname(fname));
			}
		}
		close(fd);

		free_sums(s);

	#ifdef RECOVERY_VERSION
		free(incremental_full_files);
		free(incremental_delta_files);
		free(differential_full_files);
		free(differential_delta_files);
	#endif

		if (DEBUG_GTE(SEND, 1))
			rprintf(FINFO, "sender finished %s|%s|%s\n", path,slash,fname);

		/* Flag that we actually sent this entry. */
		file->flags |= FLAG_FILE_SENT;
	}
	if (make_backups < 0)
		make_backups = -make_backups;

	if (io_error != save_io_error && protocol_version >= 30)
		send_msg_int(MSG_IO_ERROR, io_error);

	if (DEBUG_GTE(SEND, 1))
		rprintf(FINFO, "send files finished\n");

	match_report();

	write_ndx(f_out, NDX_DONE);
}