/*
 * pkgmgr-info
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>,
 * Jaeho Lee <jaeho81.lee@samsung.com>, Shobhit Srivastava <shobhit.s@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/smack.h>
#include <linux/limits.h>
#include <libgen.h>
#include <sys/stat.h>

#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlschemas.h>
#include <sqlite3.h>
#include <glib.h>

#include "pkgmgr_parser.h"
#include "pkgmgrinfo_basic.h"
#include "pkgmgrinfo_private.h"
#include "pkgmgrinfo_debug.h"
#include "pkgmgr-info.h"
#include "pkgmgr_parser_db.h"
#include "pkgmgr_parser_internal.h"

static int _pkginfo_get_pkginfo(const char *pkgid, uid_t uid,
		pkgmgr_pkginfo_x **pkginfo);
static char *_get_filtered_query(const char *query_raw,
		pkgmgrinfo_filter_x *filter);

static bool _get_bool_value(const char *str)
{
	if (str == NULL)
		return false;
	else if (!strcasecmp(str, "true"))
		return true;
	else
		return false;
}

static gint __compare_func(gconstpointer data1, gconstpointer data2)
{
	pkgmgrinfo_node_x *node1 = (pkgmgrinfo_node_x*)data1;
	pkgmgrinfo_node_x *node2 = (pkgmgrinfo_node_x*)data2;
	if (node1->prop == node2->prop)
		return 0;
	else if (node1->prop > node2->prop)
		return 1;
	else
		return -1;
}

static void __destroy_each_node(gpointer data, gpointer user_data)
{
	ret_if(data == NULL);
	pkgmgrinfo_node_x *node = (pkgmgrinfo_node_x*)data;
	if (node->value) {
		free(node->value);
		node->value = NULL;
	}
	if (node->key) {
		free(node->key);
		node->key = NULL;
	}
	free(node);
	node = NULL;
}

static void __cleanup_pkginfo(pkgmgr_pkginfo_x *data)
{
	ret_if(data == NULL);
	if (data->locale){
		free((void *)data->locale);
		data->locale = NULL;
	}

	pkgmgrinfo_basic_free_package(data->pkg_info);
	free((void *)data);
	data = NULL;
	return;
}

static int __child_element(xmlTextReaderPtr reader, int depth)
{
	int ret = xmlTextReaderRead(reader);
	int cur = xmlTextReaderDepth(reader);
	while (ret == 1) {

		switch (xmlTextReaderNodeType(reader)) {
		case XML_READER_TYPE_ELEMENT:
			if (cur == depth + 1)
				return 1;
			break;
		case XML_READER_TYPE_TEXT:
			/*text is handled by each function separately*/
			if (cur == depth + 1)
				return 0;
			break;
		case XML_READER_TYPE_END_ELEMENT:
			if (cur == depth)
				return 0;
			break;
		default:
			if (cur <= depth)
				return 0;
			break;
		}
		ret = xmlTextReaderRead(reader);
		cur = xmlTextReaderDepth(reader);
	}
	return ret;
}

long long _pkgmgr_calculate_dir_size(char *dirname)
{
	long long total = 0;
	long long ret = 0;
	int q = 0; /*quotient*/
	int r = 0; /*remainder*/
	DIR *dp = NULL;
	struct dirent ep, *result;
	struct stat fileinfo;
	char abs_filename[FILENAME_MAX] = { 0, };
	retvm_if(dirname == NULL, PMINFO_R_ERROR, "dirname is NULL");

	dp = opendir(dirname);
	if (dp == NULL) {
		_LOGE("Couldn't open the directory\n");
		return -1;
	}

	for (ret = readdir_r(dp, &ep, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dp, &ep, &result)) {
		if (!strcmp(ep.d_name, ".") ||
			!strcmp(ep.d_name, "..")) {
			continue;
		}
		snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname,
			 ep.d_name);
		if (lstat(abs_filename, &fileinfo) < 0)
			perror(abs_filename);
		else {
			if (S_ISDIR(fileinfo.st_mode)) {
				total += fileinfo.st_size;
				if (strcmp(ep.d_name, ".")
				    && strcmp(ep.d_name, "..")) {
					ret = _pkgmgr_calculate_dir_size
					    (abs_filename);
					total = total + ret;
				}
			} else if (S_ISLNK(fileinfo.st_mode)) {
				continue;
			} else {
				/*It is a file. Calculate the actual
				size occupied (in terms of 4096 blocks)*/
			q = (fileinfo.st_size / BLOCK_SIZE);
			r = (fileinfo.st_size % BLOCK_SIZE);
			if (r) {
				q = q + 1;
			}
			total += q * BLOCK_SIZE;
			}
		}
	}
	(void)closedir(dp);
	return total;

}

static int _pkginfo_get_author(sqlite3 *db, const char *pkgid,
		GList **author)
{
	static const char query_raw[] =
		"SELECT author_name, author_email, author_href "
		"FROM package_info WHERE package=%Q";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	int idx = 0;
	author_x *info;

	query = sqlite3_mprintf(query_raw, pkgid);
	if (query == NULL) {
		LOGE("out of memory");
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_prepare_v2(db, query, strlen(query),
			&stmt, NULL);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	if (sqlite3_step(stmt) == SQLITE_ERROR) {
		LOGE("step error: %s", sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return PMINFO_R_ERROR;
	}

	/* one author per one package */
	info = calloc(1, sizeof(author_x));
	if (info == NULL) {
		LOGE("out of memory");
		sqlite3_finalize(stmt);
		return PMINFO_R_ERROR;
	}

	_save_column_str(stmt, idx++, &info->text);
	_save_column_str(stmt, idx++, &info->email);
	_save_column_str(stmt, idx++, &info->href);

	/* TODO: revised */
	*author = g_list_append(*author, info);

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

static int _pkginfo_get_label(sqlite3 *db, const char *pkgid,
		const char *locale, GList **label)
{
	static const char query_raw[] =
		"SELECT package_label, package_locale "
		"FROM package_localized_info "
		"WHERE package=%Q AND package_locale IN (%Q, %Q)";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	int idx;
	label_x *info;

	query = sqlite3_mprintf(query_raw, pkgid, locale, DEFAULT_LOCALE);
	if (query == NULL) {
		LOGE("out of memory");
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_prepare_v2(db, query, strlen(query),
			&stmt, NULL);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		info = calloc(1, sizeof(label_x));
		if (info == NULL) {
			LOGE("out of memory");
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}
		idx = 0;
		_save_column_str(stmt, idx++, &info->text);
		_save_column_str(stmt, idx++, &info->lang);
		*label = g_list_append(*label, info);
	}

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

static int _pkginfo_get_icon(sqlite3 *db, const char *pkgid, const char *locale,
		GList **icon)
{
	static const char query_raw[] =
		"SELECT package_icon, package_locale "
		"FROM package_localized_info "
		"WHERE package=%Q AND package_locale IN (%Q, %Q)";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	int idx;
	icon_x *info;

	query = sqlite3_mprintf(query_raw, pkgid, locale, DEFAULT_LOCALE);
	if (query == NULL) {
		LOGE("out of memory");
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_prepare_v2(db, query, strlen(query),
			&stmt, NULL);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		info = calloc(1, sizeof(icon_x));
		if (info == NULL) {
			LOGE("out of memory");
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}
		idx = 0;
		_save_column_str(stmt, idx++, &info->text);
		_save_column_str(stmt, idx++, &info->lang);
		*icon = g_list_append(*icon, info);
	}

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

static int _pkginfo_get_description(sqlite3 *db, const char *pkgid,
		const char *locale, GList **description)
{
	static const char query_raw[] =
		"SELECT package_description, package_locale "
		"FROM package_localized_info "
		"WHERE package=%Q AND package_locale IN (%Q, %Q)";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	int idx;
	description_x *info;

	query = sqlite3_mprintf(query_raw, pkgid, locale, DEFAULT_LOCALE);
	if (query == NULL) {
		LOGE("out of memory");
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_prepare_v2(db, query, strlen(query),
			&stmt, NULL);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		info = calloc(1, sizeof(description_x));
		if (info == NULL) {
			LOGE("out of memory");
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}
		idx = 0;
		_save_column_str(stmt, idx++, &info->text);
		_save_column_str(stmt, idx++, &info->lang);
		*description = g_list_append(*description, info);
	}

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

static int _pkginfo_get_privilege(sqlite3 *db, const char *pkgid,
		GList **privileges)
{
	static const char query_raw[] =
		"SELECT privilege FROM package_privilege_info WHERE package=%Q";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	char *privilege;

	query = sqlite3_mprintf(query_raw, pkgid);
	if (query == NULL) {
		LOGE("out of memory");
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_prepare_v2(db, query, strlen(query),
			&stmt, NULL);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		privilege = NULL;
		_save_column_str(stmt, 0, &privilege);
		if (privilege)
			*privileges = g_list_append(*privileges,
					(gpointer)privilege);
	}

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

static char *_get_filtered_query(const char *query_raw,
		pkgmgrinfo_filter_x *filter)
{
	char buf[MAX_QUERY_LEN] = { 0, };
	char *condition;
	size_t len;
	GSList *list;
	GSList *head = NULL;

	if (filter)
		head = filter->list;

	strncat(buf, query_raw, MAX_QUERY_LEN - 1);
	len = strlen(buf);
	for (list = head; list; list = list->next) {
		/* TODO: revise condition getter function */
		__get_filter_condition(list->data, &condition);
		if (condition == NULL)
			continue;
		if (buf[strlen(query_raw)] == '\0') {
			len += strlen(" WHERE ");
			strncat(buf, " WHERE ", MAX_QUERY_LEN - len - 1);
		} else {
			len += strlen(" AND ");
			strncat(buf, " AND ", MAX_QUERY_LEN -len - 1);
		}
		len += strlen(condition);
		strncat(buf, condition, sizeof(buf) - len - 1);
		free(condition);
		condition = NULL;
	}

	return strdup(buf);
}

static void __free_packages(gpointer data)
{
	pkgmgrinfo_basic_free_package((package_x *)data);
}

static gint __list_comp(gconstpointer a, gconstpointer b)
{
	package_x *pkg_a = (package_x *)a;
	package_x *pkg_b = (package_x *)b;

	return strcmp(pkg_a->package, pkg_b->package);
}

static int _pkginfo_get_packages(uid_t uid, const char *locale,
		pkgmgrinfo_filter_x *filter, int flag, GList **packages)
{
	static const char query_raw[] =
		"SELECT DISTINCT pi.package, pi.package_version, "
		"pi.install_location, pi.package_removable, "
		"pi.package_preload, pi.package_readonly, pi.package_update, "
		"pi.package_appsetting, pi.package_system, pi.package_type, "
		"pi.package_size, pi.installed_time, pi.installed_storage, "
		"pi.storeclient_id, pi.mainapp_id, pi.package_url, "
		"pi.root_path, pi.csc_path, pi.package_nodisplay, "
		"pi.package_api_version, pi.package_support_disable, "
		"pi.package_tep_name, pi.package_zip_mount_file "
		"FROM package_info as pi";
	int ret;
	char *query;
	const char *dbpath;
	sqlite3 *db;
	sqlite3_stmt *stmt;
	int idx;
	package_x *info;

	dbpath = getUserPkgParserDBPathUID(uid);
	if (dbpath == NULL)
		return PMINFO_R_ERROR;

	ret = sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("failed to open db: %d", ret);
		return PMINFO_R_ERROR;
	}

	query = _get_filtered_query(query_raw, filter);
	if (query == NULL) {
		LOGE("out of memory");
		sqlite3_close_v2(db);
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(db));
		sqlite3_close_v2(db);
		return PMINFO_R_ERROR;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		info = calloc(1, sizeof(package_x));
		if (info == NULL) {
			LOGE("out of memory");
			sqlite3_finalize(stmt);
			sqlite3_close_v2(db);
			return PMINFO_R_ERROR;
		}
		idx = 0;
		_save_column_str(stmt, idx++, &info->package);
		_save_column_str(stmt, idx++, &info->version);
		_save_column_str(stmt, idx++, &info->installlocation);
		_save_column_str(stmt, idx++, &info->removable);
		_save_column_str(stmt, idx++, &info->preload);
		_save_column_str(stmt, idx++, &info->readonly);
		_save_column_str(stmt, idx++, &info->update);
		_save_column_str(stmt, idx++, &info->appsetting);
		_save_column_str(stmt, idx++, &info->system);
		_save_column_str(stmt, idx++, &info->type);
		_save_column_str(stmt, idx++, &info->package_size);
		_save_column_str(stmt, idx++, &info->installed_time);
		_save_column_str(stmt, idx++, &info->installed_storage);
		_save_column_str(stmt, idx++, &info->storeclient_id);
		_save_column_str(stmt, idx++, &info->mainapp_id);
		_save_column_str(stmt, idx++, &info->package_url);
		_save_column_str(stmt, idx++, &info->root_path);
		_save_column_str(stmt, idx++, &info->csc_path);
		_save_column_str(stmt, idx++, &info->nodisplay_setting);
		_save_column_str(stmt, idx++, &info->api_version);
		_save_column_str(stmt, idx++, &info->support_disable);
		_save_column_str(stmt, idx++, &info->tep_name);
		_save_column_str(stmt, idx++, &info->zip_mount_file);
		info->for_all_users =
			strdup((uid != GLOBAL_USER) ? "false" : "true");

		if (flag & PMINFO_PKGINFO_GET_AUTHOR) {
			if (_pkginfo_get_author(db, info->package,
						&info->author)) {
				pkgmgrinfo_basic_free_package(info);
				sqlite3_finalize(stmt);
				sqlite3_close_v2(db);
				return PMINFO_R_ERROR;
			}
		}

		if (flag & PMINFO_PKGINFO_GET_LABEL) {
			if (_pkginfo_get_label(db, info->package, locale,
						&info->label)) {
				pkgmgrinfo_basic_free_package(info);
				g_list_free_full(*packages, __free_packages);
				sqlite3_finalize(stmt);
				sqlite3_close_v2(db);
				return PMINFO_R_ERROR;
			}
		}

		if (flag & PMINFO_PKGINFO_GET_ICON) {
			if (_pkginfo_get_icon(db, info->package, locale,
						&info->icon)) {
				pkgmgrinfo_basic_free_package(info);
				g_list_free_full(*packages, __free_packages);
				sqlite3_finalize(stmt);
				sqlite3_close_v2(db);
				return PMINFO_R_ERROR;
			}
		}

		if (flag & PMINFO_PKGINFO_GET_DESCRIPTION) {
			if (_pkginfo_get_description(db, info->package, locale,
						&info->description)) {
				pkgmgrinfo_basic_free_package(info);
				g_list_free_full(*packages, __free_packages);
				sqlite3_finalize(stmt);
				sqlite3_close_v2(db);
				return PMINFO_R_ERROR;
			}
		}

		if (flag & PMINFO_PKGINFO_GET_PRIVILEGE) {
			if (_pkginfo_get_privilege(db, info->package,
						&info->privileges)) {
				pkgmgrinfo_basic_free_package(info);
				g_list_free_full(*packages, __free_packages);
				sqlite3_finalize(stmt);
				sqlite3_close_v2(db);
				return PMINFO_R_ERROR;
			}
		}

		*packages = g_list_insert_sorted(*packages, info, __list_comp);
	}

	sqlite3_finalize(stmt);
	sqlite3_close_v2(db);

	return PMINFO_R_OK;
}

static void __remove_duplicates(GList **list)
{
	GList *l = *list;
	GList *next;
	package_x *pkg_a;
	package_x *pkg_b;

	while (l != NULL && l->next != NULL) {
		next = l->next;
		pkg_a = (package_x *)l->data;
		pkg_b = (package_x *)next->data;
		if (!strcmp(pkg_a->package, pkg_b->package)) {
			pkgmgrinfo_basic_free_package(pkg_a);
			*list = g_list_delete_link(*list, l);
		}
		l = next;
	}
}

static int _pkginfo_get_filtered_foreach_pkginfo(uid_t uid,
		pkgmgrinfo_filter_x *filter, int flag,
		pkgmgrinfo_pkg_list_cb pkg_list_cb, void *user_data)
{
	int ret;
	char *locale;
	package_x *pkg;
	pkgmgr_pkginfo_x info;
	GList *list = NULL;
	GList *tmp;

	locale = _get_system_locale();
	if (locale == NULL)
		return PMINFO_R_ERROR;

	ret = _pkginfo_get_packages(uid, locale, filter, flag, &list);
	if (ret == PMINFO_R_OK && uid != GLOBAL_USER)
		ret = _pkginfo_get_packages(GLOBAL_USER, locale, filter,
				flag, &list);

	if (ret != PMINFO_R_OK) {
		free(locale);
		return PMINFO_R_ERROR;
	}

	__remove_duplicates(&list);

	for (tmp = list; tmp; tmp = tmp->next) {
		pkg = (package_x *)tmp->data;
		info.pkg_info = pkg;
		info.locale = locale;
		info.uid = uid;
		if (pkg_list_cb(&info, user_data) < 0)
			break;
	}

	g_list_free_full(list, __free_packages);
	free(locale);

	return PMINFO_R_OK;
}

static int _pkginfo_get_pkginfo(const char *pkgid, uid_t uid,
		pkgmgr_pkginfo_x **pkginfo)
{
	int ret;
	char *locale;
	GList *list = NULL;
	pkgmgrinfo_pkginfo_filter_h filter;
	pkgmgr_pkginfo_x *info;

	locale = _get_system_locale();
	if (locale == NULL)
		return PMINFO_R_ERROR;

	ret = pkgmgrinfo_pkginfo_filter_create(&filter);
	if (ret != PMINFO_R_OK) {
		free(locale);
		return PMINFO_R_ERROR;
	}

	ret = pkgmgrinfo_appinfo_filter_add_string(filter,
			PMINFO_PKGINFO_PROP_PACKAGE_ID, pkgid);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_pkginfo_filter_destroy(filter);
		free(locale);
		return PMINFO_R_ERROR;
	}

	info = calloc(1, sizeof(pkgmgr_pkginfo_x));
	if (info == NULL) {
		_LOGE("out of memory");
		free(locale);
		return PMINFO_R_ERROR;
	}

	ret = _pkginfo_get_packages(uid, locale, filter,
			PMINFO_PKGINFO_GET_ALL, &list);
	if (!g_list_length(list) && uid != GLOBAL_USER)
		ret = _pkginfo_get_packages(GLOBAL_USER, locale, filter,
				PMINFO_PKGINFO_GET_ALL, &list);

	pkgmgrinfo_pkginfo_filter_destroy(filter);
	if (ret != PMINFO_R_OK) {
		free(info);
		free(locale);
		return ret;
	}

	__remove_duplicates(&list);

	if (!g_list_length(list)) {
		free(info);
		free(locale);
		return PMINFO_R_ENOENT;
	}

	info->pkg_info = (package_x *)list->data;
	info->pkg_info->for_all_users = strdup(
			uid != GLOBAL_USER ? "false" : "true");
	info->locale = locale;
	info->uid = uid;

	/* just free list only */
	g_list_free(list);

	*pkginfo = info;

	return ret;
}

API int pkgmgrinfo_pkginfo_get_usr_pkginfo(const char *pkgid, uid_t uid,
		pkgmgrinfo_pkginfo_h *handle)
{
	int ret;

	if (pkgid == NULL || handle == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	ret = _pkginfo_get_pkginfo(pkgid, uid, (pkgmgr_pkginfo_x **)handle);
	if (ret == PMINFO_R_ENOENT && uid != GLOBAL_USER)
		ret = _pkginfo_get_pkginfo(pkgid, GLOBAL_USER,
				(pkgmgr_pkginfo_x **)handle);

	if (ret != PMINFO_R_OK)
		_LOGI("pkginfo for [%s] is not existed for user [%d]", pkgid, uid);

	return ret;
}

API int pkgmgrinfo_pkginfo_get_pkginfo(const char *pkgid,
		pkgmgrinfo_pkginfo_h *handle)
{
	return pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, _getuid(), handle);
}

API int pkgmgrinfo_pkginfo_get_usr_list_full(pkgmgrinfo_pkg_list_cb pkg_list_cb,
		int flag, void *user_data, uid_t uid)
{
	if (pkg_list_cb == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	return _pkginfo_get_filtered_foreach_pkginfo(uid, NULL, flag,
			pkg_list_cb, user_data);
}

API int pkgmgrinfo_pkginfo_get_list_full(pkgmgrinfo_pkg_list_cb pkg_list_cb,
		int flag, void *user_data)
{
	return pkgmgrinfo_pkginfo_get_usr_list_full(pkg_list_cb, flag,
			user_data, _getuid());
}

API int pkgmgrinfo_pkginfo_get_usr_list(pkgmgrinfo_pkg_list_cb pkg_list_cb,
		void *user_data, uid_t uid)
{
	if (pkg_list_cb == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	return _pkginfo_get_filtered_foreach_pkginfo(uid, NULL,
			PMINFO_PKGINFO_GET_ALL, pkg_list_cb, user_data);
}

API int pkgmgrinfo_pkginfo_get_list(pkgmgrinfo_pkg_list_cb pkg_list_cb,
		void *user_data)
{
	return pkgmgrinfo_pkginfo_get_usr_list(pkg_list_cb, user_data,
			_getuid());
}

API int pkgmgrinfo_pkginfo_get_pkgname(pkgmgrinfo_pkginfo_h handle, char **pkg_name)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(pkg_name == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->package == NULL)
		return PMINFO_R_ERROR;

	*pkg_name = (char *)info->pkg_info->package;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_pkgid(pkgmgrinfo_pkginfo_h handle, char **pkgid)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->package == NULL)
		return PMINFO_R_ERROR;

	*pkgid = (char *)info->pkg_info->package;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_type(pkgmgrinfo_pkginfo_h handle, char **type)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(type == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->type == NULL)
		return PMINFO_R_ERROR;

	*type = (char *)info->pkg_info->type;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_version(pkgmgrinfo_pkginfo_h handle, char **version)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(version == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->version == NULL)
		return PMINFO_R_ERROR;

	*version = (char *)info->pkg_info->version;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_api_version(pkgmgrinfo_pkginfo_h handle, char **api_version)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(api_version == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->api_version == NULL)
		return PMINFO_R_ERROR;

	*api_version = (char *)info->pkg_info->api_version;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_tep_name(pkgmgrinfo_pkginfo_h handle, char **tep_name)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(tep_name == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->tep_name == NULL)
		return PMINFO_R_ERROR;

	if (strlen(info->pkg_info->tep_name) == 0)
		return PMINFO_R_ERROR;

	*tep_name = (char *)info->pkg_info->tep_name;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_zip_mount_file(pkgmgrinfo_pkginfo_h handle, char **zip_mount_file)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(zip_mount_file == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL)
		return PMINFO_R_ERROR;

	if (strlen(info->pkg_info->zip_mount_file) > 0)
		*zip_mount_file = (char *)info->pkg_info->zip_mount_file;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_install_location(pkgmgrinfo_pkginfo_h handle, pkgmgrinfo_install_location *location)
{
	char *val;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(location == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->installlocation == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->pkg_info->installlocation;
	if (strcmp(val, "internal-only") == 0)
		*location = PMINFO_INSTALL_LOCATION_INTERNAL_ONLY;
	else if (strcmp(val, "prefer-external") == 0)
		*location = PMINFO_INSTALL_LOCATION_PREFER_EXTERNAL;
	else
		*location = PMINFO_INSTALL_LOCATION_AUTO;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_package_size(pkgmgrinfo_pkginfo_h handle, int *size)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(size == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->package_size == NULL)
		return PMINFO_R_ERROR;

	*size = atoi((char *)info->pkg_info->package_size);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_total_size(pkgmgrinfo_pkginfo_h handle, int *size)
{
	char *pkgid;
	char device_path[PKG_STRING_LEN_MAX] = { '\0', };
	long long rw_size = 0;
	long long ro_size = 0;
	long long tmp_size = 0;
	long long total_size = 0;
	struct stat fileinfo;
	int ret;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(size == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if (ret < 0)
		return PMINFO_R_ERROR;

	/* RW area */
	snprintf(device_path, PKG_STRING_LEN_MAX, "%s%s/bin", PKG_RW_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = _pkgmgr_calculate_dir_size(device_path);
			if (tmp_size > 0)
				rw_size += tmp_size;
		}
	}

	snprintf(device_path, PKG_STRING_LEN_MAX, "%s%s/info", PKG_RW_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = _pkgmgr_calculate_dir_size(device_path);
			if (tmp_size > 0)
			rw_size += tmp_size;
		}
	}

	snprintf(device_path, PKG_STRING_LEN_MAX, "%s%s/res", PKG_RW_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = _pkgmgr_calculate_dir_size(device_path);
			if (tmp_size > 0)
			rw_size += tmp_size;
		}
	}

	snprintf(device_path, PKG_STRING_LEN_MAX, "%s%s/data", PKG_RW_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = _pkgmgr_calculate_dir_size(device_path);
			if (tmp_size > 0)
				rw_size += tmp_size;
		}
	}

	snprintf(device_path, PKG_STRING_LEN_MAX, "%s%s/shared", PKG_RW_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = _pkgmgr_calculate_dir_size(device_path);
			if (tmp_size > 0)
				rw_size += tmp_size;
	}
	}

	snprintf(device_path, PKG_STRING_LEN_MAX, "%s%s/setting", PKG_RW_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = _pkgmgr_calculate_dir_size(device_path);
			if (tmp_size > 0)
				rw_size += tmp_size;
		}
	}

	/* RO area */
	snprintf(device_path, PKG_STRING_LEN_MAX, "%s%s/bin", PKG_RO_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = _pkgmgr_calculate_dir_size(device_path);
			if (tmp_size > 0)
				ro_size += tmp_size;
		}
	}

	snprintf(device_path, PKG_STRING_LEN_MAX, "%s%s/info", PKG_RO_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = _pkgmgr_calculate_dir_size(device_path);
			if (tmp_size > 0)
				ro_size += tmp_size;
		}
	}

	snprintf(device_path, PKG_STRING_LEN_MAX, "%s%s/res", PKG_RO_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = _pkgmgr_calculate_dir_size(device_path);
			if (tmp_size > 0)
				ro_size += tmp_size;
		}
	}

	snprintf(device_path, PKG_STRING_LEN_MAX, "%s%s/data", PKG_RO_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = _pkgmgr_calculate_dir_size(device_path);
			if (tmp_size > 0)
				ro_size += tmp_size;
		}
	}

	snprintf(device_path, PKG_STRING_LEN_MAX, "%s%s/shared", PKG_RO_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = _pkgmgr_calculate_dir_size(device_path);
			if (tmp_size > 0)
				ro_size += tmp_size;
		}
	}

	snprintf(device_path, PKG_STRING_LEN_MAX, "%s%s/setting", PKG_RO_PATH, pkgid);
	if (lstat(device_path, &fileinfo) == 0) {
		if (!S_ISLNK(fileinfo.st_mode)) {
			tmp_size = _pkgmgr_calculate_dir_size(device_path);
			if (tmp_size > 0)
				ro_size += tmp_size;
		}
	}

	/* Total size */
	total_size = rw_size + ro_size;
	*size = (int)total_size;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_data_size(pkgmgrinfo_pkginfo_h handle, int *size)
{
	char *pkgid;
	char device_path[PKG_STRING_LEN_MAX] = { '\0', };
	long long total_size = 0;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(size == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid) < 0)
		return PMINFO_R_ERROR;

	snprintf(device_path, PKG_STRING_LEN_MAX, "%s%s/data", PKG_RW_PATH, pkgid);
	if (access(device_path, R_OK) == 0)
		total_size = _pkgmgr_calculate_dir_size(device_path);
	if (total_size < 0)
		return PMINFO_R_ERROR;

	*size = (int)total_size;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_icon(pkgmgrinfo_pkginfo_h handle, char **icon)
{
	const char *locale;
	icon_x *ptr;
	GList *tmp;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL");
	retvm_if(icon == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	locale = info->locale;
	retvm_if(locale == NULL, PMINFO_R_ERROR, "manifest locale is NULL");

	if (info->pkg_info == NULL)
		return PMINFO_R_ERROR;

	for (tmp = info->pkg_info->icon; tmp; tmp = tmp->next) {
		ptr = (icon_x *)tmp->data;
		if (ptr == NULL || ptr->text == NULL || ptr->lang == NULL ||
				!strcasecmp(ptr->text, "(null)") ||
				strcmp(ptr->lang, locale))
			continue;
		*icon = (char *)ptr->text;
		return PMINFO_R_OK;
	}

	locale = DEFAULT_LOCALE;
	for (tmp = info->pkg_info->icon; tmp; tmp = tmp->next) {
		ptr = (icon_x *)tmp->data;
		if (ptr == NULL || ptr->text == NULL || ptr->lang == NULL ||
				strcmp(ptr->lang, locale))
			continue;
		*icon = (char *)ptr->text;
		return PMINFO_R_OK;
	}

	return PMINFO_R_ERROR;
}

API int pkgmgrinfo_pkginfo_get_label(pkgmgrinfo_pkginfo_h handle, char **label)
{
	const char *locale;
	label_x *ptr;
	GList *tmp;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL");
	retvm_if(label == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	locale = info->locale;
	retvm_if(locale == NULL, PMINFO_R_ERROR, "manifest locale is NULL");

	for (tmp = info->pkg_info->label; tmp != NULL; tmp = tmp->next) {
		ptr = (label_x *)tmp->data;
		if (ptr == NULL || ptr->text == NULL || ptr->lang == NULL ||
				strcmp(ptr->lang, locale))
			continue;
		*label = (char *)ptr->text;
		return PMINFO_R_OK;
	}

	locale = DEFAULT_LOCALE;
	for (tmp = info->pkg_info->label; tmp != NULL; tmp = tmp->next) {
		ptr = (label_x *)tmp->data;
		if (ptr == NULL || ptr->text == NULL || ptr->lang == NULL ||
				strcmp(ptr->lang, locale))
			continue;
		*label = (char *)ptr->text;
		return PMINFO_R_OK;
	}

	return PMINFO_R_ERROR;
}

API int pkgmgrinfo_pkginfo_get_description(pkgmgrinfo_pkginfo_h handle, char **description)
{
	const char *locale;
	description_x *ptr;
	GList *tmp;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(description == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	locale = info->locale;
	retvm_if(locale == NULL, PMINFO_R_ERROR, "manifest locale is NULL");

	for (tmp = info->pkg_info->description; tmp; tmp = tmp->next) {
		ptr = (description_x *)tmp->data;
		if (ptr == NULL || ptr->text == NULL || ptr->lang == NULL ||
				strcmp(ptr->lang, locale))
			continue;
		*description = (char *)ptr->text;
		return PMINFO_R_OK;
	}

	locale = DEFAULT_LOCALE;
	for (tmp = info->pkg_info->description; tmp; tmp = tmp->next) {
		ptr = (description_x *)tmp->data;
		if (ptr == NULL || ptr->text == NULL || ptr->lang == NULL ||
				strcmp(ptr->lang, locale))
			continue;
		*description = (char *)ptr->text;
		return PMINFO_R_OK;
	}

	return PMINFO_R_ERROR;
}

API int pkgmgrinfo_pkginfo_get_author_name(pkgmgrinfo_pkginfo_h handle, char **author_name)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	author_x *author;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(author_name == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->author == NULL)
		return PMINFO_R_ERROR;

	author = (author_x *)info->pkg_info->author->data;
	if (author == NULL || author->text == NULL)
		return PMINFO_R_ERROR;

	*author_name = (char *)author->text;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_author_email(pkgmgrinfo_pkginfo_h handle, char **author_email)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	author_x *author;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(author_email == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->author == NULL)
		return PMINFO_R_ERROR;

	author = (author_x *)info->pkg_info->author->data;
	if (author == NULL || author->email == NULL)
		return PMINFO_R_ERROR;

	*author_email = (char *)author->email;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_author_href(pkgmgrinfo_pkginfo_h handle, char **author_href)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	author_x *author;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(author_href == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->author == NULL)
		return PMINFO_R_ERROR;

	author = (author_x *)info->pkg_info->author->data;
	if (author == NULL || author->href == NULL)
		return PMINFO_R_ERROR;

	*author_href = (char *)author->href;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_installed_storage(pkgmgrinfo_pkginfo_h handle, pkgmgrinfo_installed_storage *storage)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(storage == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->installed_storage == NULL)
		return PMINFO_R_ERROR;

	if (strcmp(info->pkg_info->installed_storage,"installed_internal") == 0)
		*storage = PMINFO_INTERNAL_STORAGE;
	else if (strcmp(info->pkg_info->installed_storage,"installed_external") == 0)
		*storage = PMINFO_EXTERNAL_STORAGE;
	else
		return PMINFO_R_ERROR;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_installed_time(pkgmgrinfo_pkginfo_h handle, int *installed_time)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(installed_time == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->installed_time == NULL)
		return PMINFO_R_ERROR;

	*installed_time = atoi(info->pkg_info->installed_time);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_storeclientid(pkgmgrinfo_pkginfo_h handle, char **storeclientid)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(storeclientid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->storeclient_id == NULL)
		return PMINFO_R_ERROR;

	*storeclientid = (char *)info->pkg_info->storeclient_id;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_mainappid(pkgmgrinfo_pkginfo_h handle, char **mainappid)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(mainappid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->mainapp_id == NULL)
		return PMINFO_R_ERROR;

	*mainappid = (char *)info->pkg_info->mainapp_id;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_url(pkgmgrinfo_pkginfo_h handle, char **url)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(url == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->package_url == NULL)
		return PMINFO_R_ERROR;

	*url = (char *)info->pkg_info->package_url;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_size_from_xml(const char *manifest, int *size)
{
	const char *val = NULL;
	const xmlChar *node;
	xmlTextReaderPtr reader;
	retvm_if(manifest == NULL, PMINFO_R_EINVAL, "Input argument is NULL\n");
	retvm_if(size == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	xmlInitParser();
	reader = xmlReaderForFile(manifest, NULL, 0);

	if (reader){
		if (__child_element(reader, -1)) {
			node = xmlTextReaderConstName(reader);
			if (!node) {
				_LOGE("xmlTextReaderConstName value is NULL\n");
				xmlFreeTextReader(reader);
				xmlCleanupParser();
				return PMINFO_R_ERROR;
			}

			if (!strcmp(ASC_CHAR(node), "manifest")) {
				if (xmlTextReaderGetAttribute(reader, XML_CHAR("size")))
					val = ASC_CHAR(xmlTextReaderGetAttribute(reader, XML_CHAR("size")));

				if (val) {
					*size = atoi(val);
				} else {
					*size = 0;
					_LOGE("package size is not specified\n");
					xmlFreeTextReader(reader);
					xmlCleanupParser();
					return PMINFO_R_ERROR;
				}
			} else {
				_LOGE("Unable to create xml reader\n");
				xmlFreeTextReader(reader);
				xmlCleanupParser();
				return PMINFO_R_ERROR;
			}
		}
	} else {
		_LOGE("xmlReaderForFile value is NULL\n");
		xmlCleanupParser();
		return PMINFO_R_ERROR;
	}

	xmlFreeTextReader(reader);
	xmlCleanupParser();

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_location_from_xml(const char *manifest, pkgmgrinfo_install_location *location)
{
	const char *val = NULL;
	const xmlChar *node;
	xmlTextReaderPtr reader;
	retvm_if(manifest == NULL, PMINFO_R_EINVAL, "Input argument is NULL\n");
	retvm_if(location == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	xmlInitParser();
	reader = xmlReaderForFile(manifest, NULL, 0);

	if (reader) {
		if ( __child_element(reader, -1)) {
			node = xmlTextReaderConstName(reader);
			if (!node) {
				_LOGE("xmlTextReaderConstName value is NULL\n");
				xmlFreeTextReader(reader);
				xmlCleanupParser();
				return PMINFO_R_ERROR;
			}

			if (!strcmp(ASC_CHAR(node), "manifest")) {
				if (xmlTextReaderGetAttribute(reader, XML_CHAR("install-location")))
					val = ASC_CHAR(xmlTextReaderGetAttribute(reader, XML_CHAR("install-location")));

				if (val) {
					if (strcmp(val, "internal-only") == 0)
						*location = PMINFO_INSTALL_LOCATION_INTERNAL_ONLY;
					else if (strcmp(val, "prefer-external") == 0)
						*location = PMINFO_INSTALL_LOCATION_PREFER_EXTERNAL;
					else
						*location = PMINFO_INSTALL_LOCATION_AUTO;
				}
			} else {
				_LOGE("Unable to create xml reader\n");
				xmlFreeTextReader(reader);
				xmlCleanupParser();
				return PMINFO_R_ERROR;
			}
		}
	} else {
		_LOGE("xmlReaderForFile value is NULL\n");
		xmlCleanupParser();
		return PMINFO_R_ERROR;
	}

	xmlFreeTextReader(reader);
	xmlCleanupParser();

	return PMINFO_R_OK;
}


API int pkgmgrinfo_pkginfo_get_root_path(pkgmgrinfo_pkginfo_h handle, char **path)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(path == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->root_path == NULL)
		return PMINFO_R_ERROR;

	*path = (char *)info->pkg_info->root_path;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_csc_path(pkgmgrinfo_pkginfo_h handle, char **path)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(path == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->csc_path == NULL)
		return PMINFO_R_ERROR;

	*path = (char *)info->pkg_info->csc_path;

	return PMINFO_R_OK;
}


API int pkgmgrinfo_pkginfo_is_accessible(pkgmgrinfo_pkginfo_h handle, bool *accessible)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(accessible == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

#if 0 //smack issue occured, check later
	char *pkgid = NULL;
	pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if (pkgid == NULL){
		 _LOGD("invalid func parameters\n");
		 return PMINFO_R_ERROR;
	}
	 _LOGD("pkgmgr_get_pkg_external_validation() called\n");

	FILE *fp = NULL;
	char app_mmc_path[FILENAME_MAX] = { 0, };
	char app_dir_path[FILENAME_MAX] = { 0, };
	char app_mmc_internal_path[FILENAME_MAX] = { 0, };
	snprintf(app_dir_path, FILENAME_MAX,"%s%s", PKG_INSTALLATION_PATH, pkgid);
	snprintf(app_mmc_path, FILENAME_MAX,"%s%s", PKG_SD_PATH, pkgid);
	snprintf(app_mmc_internal_path, FILENAME_MAX,"%s%s/.mmc", PKG_INSTALLATION_PATH, pkgid);

	/*check whether application is in external memory or not */
	fp = fopen(app_mmc_path, "r");
	if (fp == NULL){
		_LOGD(" app path in external memory not accesible\n");
	} else {
		fclose(fp);
		fp = NULL;
		*accessible = 1;
		_LOGD("pkgmgr_get_pkg_external_validation() : SD_CARD \n");
		return PMINFO_R_OK;
	}

	/*check whether application is in internal or not */
	fp = fopen(app_dir_path, "r");
	if (fp == NULL) {
		_LOGD(" app path in internal memory not accesible\n");
		*accessible = 0;
		return PMINFO_R_ERROR;
	} else {
		fclose(fp);
		/*check whether the application is installed in SD card
		but SD card is not present*/
		fp = fopen(app_mmc_internal_path, "r");
		if (fp == NULL){
			*accessible = 1;
			_LOGD("pkgmgr_get_pkg_external_validation() : INTERNAL_MEM \n");
			return PMINFO_R_OK;
		}
		else{
			*accessible = 0;
			_LOGD("pkgmgr_get_pkg_external_validation() : ERROR_MMC_STATUS \n");
		}
		fclose(fp);
	}

	_LOGD("pkgmgr_get_pkg_external_validation() end\n");
#endif

	*accessible = 1;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_removable(pkgmgrinfo_pkginfo_h handle, bool *removable)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(removable == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->removable == NULL)
		return PMINFO_R_ERROR;

	*removable = _get_bool_value(info->pkg_info->removable);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_movable(pkgmgrinfo_pkginfo_h handle, bool *movable)
{
	char *val;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(movable == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->installlocation == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->pkg_info->installlocation;
	if (strcmp(val, "internal-only") == 0)
		*movable = 0;
	else if (strcmp(val, "prefer-external") == 0)
		*movable = 1;
	else
		*movable = 1;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_preload(pkgmgrinfo_pkginfo_h handle, bool *preload)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(preload == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->preload == NULL)
		return PMINFO_R_ERROR;

	*preload = _get_bool_value(info->pkg_info->preload);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_system(pkgmgrinfo_pkginfo_h handle, bool *system)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(system == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->system == NULL)
		return PMINFO_R_ERROR;

	*system = _get_bool_value(info->pkg_info->system);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_readonly(pkgmgrinfo_pkginfo_h handle, bool *readonly)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(readonly == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->readonly == NULL)
		return PMINFO_R_ERROR;

	*readonly = _get_bool_value(info->pkg_info->readonly);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_update(pkgmgrinfo_pkginfo_h handle, bool *update)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(update == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->update == NULL)
		return PMINFO_R_ERROR;

	*update = _get_bool_value(info->pkg_info->update);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_support_disable(pkgmgrinfo_pkginfo_h handle, bool *support_disable)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(support_disable == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->support_disable == NULL)
		return PMINFO_R_ERROR;

	*support_disable = _get_bool_value(info->pkg_info->support_disable);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_global(pkgmgrinfo_pkginfo_h handle, bool *global)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(global == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->for_all_users == NULL)
		return PMINFO_R_ERROR;

	*global = _get_bool_value(info->pkg_info->for_all_users);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_for_all_users(pkgmgrinfo_pkginfo_h handle, bool *for_all_users)
{
	return pkgmgrinfo_pkginfo_is_global(handle, for_all_users);
}

API int pkgmgrinfo_pkginfo_destroy_pkginfo(pkgmgrinfo_pkginfo_h handle)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");

	__cleanup_pkginfo(info);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_filter_create(pkgmgrinfo_pkginfo_filter_h *handle)
{
	pkgmgrinfo_filter_x *filter;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle output parameter is NULL\n");

	filter = (pkgmgrinfo_filter_x*)calloc(1, sizeof(pkgmgrinfo_filter_x));
	if (filter == NULL) {
		_LOGE("Out of Memory!!!");
		return PMINFO_R_ERROR;
	}

	*handle = filter;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_filter_destroy(pkgmgrinfo_pkginfo_filter_h handle)
{
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");

	if (filter->list) {
		g_slist_foreach(filter->list, __destroy_each_node, NULL);
		g_slist_free(filter->list);
	}

	free(filter);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_filter_add_int(pkgmgrinfo_pkginfo_filter_h handle,
				const char *property, const int value)
{
	char buf[PKG_VALUE_STRING_LEN_MAX] = {'\0'};
	char *val;
	GSList *link;
	int prop;
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x *)handle;
	pkgmgrinfo_node_x *node;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(property == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");

	prop = _pminfo_pkginfo_convert_to_prop_int(property);
	if (prop < E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_INT ||
		prop > E_PMINFO_PKGINFO_PROP_PACKAGE_MAX_INT) {
		_LOGE("Invalid Integer Property\n");
		return PMINFO_R_EINVAL;
	}
	node = (pkgmgrinfo_node_x *)calloc(1, sizeof(pkgmgrinfo_node_x));
	if (node == NULL) {
		_LOGE("Out of Memory!!!\n");
		return PMINFO_R_ERROR;
	}
	snprintf(buf, PKG_VALUE_STRING_LEN_MAX - 1, "%d", value);
	val = strndup(buf, PKG_VALUE_STRING_LEN_MAX - 1);
	if (val == NULL) {
		_LOGE("Out of Memory\n");
		free(node);
		return PMINFO_R_ERROR;
	}
	node->prop = prop;
	node->value = val;
	/*If API is called multiple times for same property, we should override the previous values.
	Last value set will be used for filtering.*/
	link = g_slist_find_custom(filter->list, (gconstpointer)node, __compare_func);
	if (link)
		filter->list = g_slist_delete_link(filter->list, link);
	filter->list = g_slist_append(filter->list, (gpointer)node);
	return PMINFO_R_OK;

}

API int pkgmgrinfo_pkginfo_filter_add_bool(pkgmgrinfo_pkginfo_filter_h handle,
				const char *property, const bool value)
{
	char *val;
	GSList *link;
	int prop;
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x *)handle;
	pkgmgrinfo_node_x *node;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(property == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");

	prop = _pminfo_pkginfo_convert_to_prop_bool(property);
	if (prop < E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_BOOL ||
		prop > E_PMINFO_PKGINFO_PROP_PACKAGE_MAX_BOOL) {
		_LOGE("Invalid Boolean Property\n");
		return PMINFO_R_EINVAL;
	}
	node = (pkgmgrinfo_node_x *)calloc(1, sizeof(pkgmgrinfo_node_x));
	if (node == NULL) {
		_LOGE("Out of Memory!!!\n");
		return PMINFO_R_ERROR;
	}
	if (value)
		val = strndup("('true','True')", 15);
	else
		val = strndup("('false','False')", 17);
	if (val == NULL) {
		_LOGE("Out of Memory\n");
		free(node);
		return PMINFO_R_ERROR;
	}
	node->prop = prop;
	node->value = val;
	/*If API is called multiple times for same property, we should override the previous values.
	Last value set will be used for filtering.*/
	link = g_slist_find_custom(filter->list, (gconstpointer)node, __compare_func);
	if (link)
		filter->list = g_slist_delete_link(filter->list, link);
	filter->list = g_slist_append(filter->list, (gpointer)node);
	return PMINFO_R_OK;

}

API int pkgmgrinfo_pkginfo_filter_add_string(pkgmgrinfo_pkginfo_filter_h handle,
				const char *property, const char *value)
{
	char *val;
	GSList *link;
	int prop;
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x *)handle;
	pkgmgrinfo_node_x *node;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(property == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(value == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");

	prop = _pminfo_pkginfo_convert_to_prop_str(property);
	if (prop < E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_STR ||
		prop > E_PMINFO_PKGINFO_PROP_PACKAGE_MAX_STR) {
		_LOGE("Invalid String Property\n");
		return PMINFO_R_EINVAL;
	}
	node = (pkgmgrinfo_node_x *)calloc(1, sizeof(pkgmgrinfo_node_x));
	if (node == NULL) {
		_LOGE("Out of Memory!!!\n");
		return PMINFO_R_ERROR;
	}
	if (strcmp(value, PMINFO_PKGINFO_INSTALL_LOCATION_AUTO) == 0)
		val = strndup("auto", PKG_STRING_LEN_MAX - 1);
	else if (strcmp(value, PMINFO_PKGINFO_INSTALL_LOCATION_INTERNAL) == 0)
		val = strndup("internal-only", PKG_STRING_LEN_MAX - 1);
	else if (strcmp(value, PMINFO_PKGINFO_INSTALL_LOCATION_EXTERNAL) == 0)
		val = strndup("prefer-external", PKG_STRING_LEN_MAX - 1);
	else if (strcmp(value, "installed_internal") == 0)
		val = strndup("installed_internal", PKG_STRING_LEN_MAX - 1);
	else if (strcmp(value, "installed_external") == 0)
		val = strndup("installed_external", PKG_STRING_LEN_MAX - 1);
	else
		val = strndup(value, PKG_STRING_LEN_MAX - 1);
	if (val == NULL) {
		_LOGE("Out of Memory\n");
		free(node);
		return PMINFO_R_ERROR;
	}
	node->prop = prop;
	node->value = val;
	/*If API is called multiple times for same property, we should override the previous values.
	Last value set will be used for filtering.*/
	link = g_slist_find_custom(filter->list, (gconstpointer)node, __compare_func);
	if (link)
		filter->list = g_slist_delete_link(filter->list, link);
	filter->list = g_slist_append(filter->list, (gpointer)node);
	return PMINFO_R_OK;

}

API int pkgmgrinfo_pkginfo_usr_filter_count(pkgmgrinfo_pkginfo_filter_h handle, int *count, uid_t uid)
{
	int ret;
	char *locale;
	GList *list = NULL;

	if (handle == NULL || count == NULL) {
		_LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	locale = _get_system_locale();
	if (locale == NULL)
		return PMINFO_R_ERROR;

	ret = _pkginfo_get_packages(uid, locale,
			(pkgmgrinfo_filter_x *)handle, 0, &list);
	if (ret == PMINFO_R_OK && uid != GLOBAL_USER)
		ret = _pkginfo_get_packages(GLOBAL_USER, locale, handle, 0,
				&list);

	if (ret != PMINFO_R_OK) {
		free(locale);
		return PMINFO_R_ERROR;
	}

	__remove_duplicates(&list);

	*count = g_list_length(list);

	g_list_free_full(list, free);
	free(locale);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_filter_count(pkgmgrinfo_pkginfo_filter_h handle, int *count)
{
	return pkgmgrinfo_pkginfo_usr_filter_count(handle, count, _getuid());
}

API int pkgmgrinfo_pkginfo_usr_filter_foreach_pkginfo(
		pkgmgrinfo_pkginfo_filter_h handle,
		pkgmgrinfo_pkg_list_cb pkg_cb, void *user_data, uid_t uid)
{
	if (handle == NULL || pkg_cb == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	return _pkginfo_get_filtered_foreach_pkginfo(uid, handle,
			PMINFO_PKGINFO_GET_ALL, pkg_cb, user_data);
}

API int pkgmgrinfo_pkginfo_filter_foreach_pkginfo(pkgmgrinfo_pkginfo_filter_h handle,
				pkgmgrinfo_pkg_list_cb pkg_cb, void *user_data)
{
	return pkgmgrinfo_pkginfo_usr_filter_foreach_pkginfo(handle, pkg_cb, user_data, _getuid());
}

API int pkgmgrinfo_pkginfo_foreach_privilege(pkgmgrinfo_pkginfo_h handle,
			pkgmgrinfo_pkg_privilege_list_cb privilege_func, void *user_data)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL");
	retvm_if(privilege_func == NULL, PMINFO_R_EINVAL, "Callback function is NULL");
	int ret;
	const char *privilege;
	GList *tmp;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	if (info->pkg_info == NULL)
		return PMINFO_R_ERROR;

	for (tmp = info->pkg_info->privileges; tmp; tmp = tmp->next) {
		privilege = (const char *)tmp->data;
		if (privilege == NULL)
			continue;
		ret = privilege_func(privilege, user_data);
		if (ret < 0)
			break;
	}
	return PMINFO_R_OK;
}
