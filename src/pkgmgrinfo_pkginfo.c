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

#define FILTER_QUERY_COUNT_PACKAGE	"select count(DISTINCT package_info.package) " \
				"from package_info LEFT OUTER JOIN package_localized_info " \
				"ON package_info.package=package_localized_info.package " \
				"and package_localized_info.package_locale='%s' where "


static int _pkginfo_get_pkg(const char *pkgid, const char *locale,
		pkgmgr_pkginfo_x **pkginfo);
static char *_get_filtered_query(const char *query_raw,
		pkgmgrinfo_filter_x *filter);

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

static int __count_cb(void *data, int ncols, char **coltxt, char **colname)
{
	int *p = (int*)data;
	*p = atoi(coltxt[0]);
	_LOGE("count value is %d\n", *p);
	return 0;
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
	struct dirent *ep = NULL;
	struct stat fileinfo;
	char abs_filename[FILENAME_MAX] = { 0, };
	retvm_if(dirname == NULL, PMINFO_R_ERROR, "dirname is NULL");

	dp = opendir(dirname);
	if (dp != NULL) {
		while ((ep = readdir(dp)) != NULL) {
			if (!strcmp(ep->d_name, ".") ||
				!strcmp(ep->d_name, "..")) {
				continue;
			}
			snprintf(abs_filename, FILENAME_MAX, "%s/%s", dirname,
				 ep->d_name);
			if (lstat(abs_filename, &fileinfo) < 0)
				perror(abs_filename);
			else {
				if (S_ISDIR(fileinfo.st_mode)) {
					total += fileinfo.st_size;
					if (strcmp(ep->d_name, ".")
					    && strcmp(ep->d_name, "..")) {
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
	} else {
		_LOGE("Couldn't open the directory\n");
		return -1;
	}
	return total;

}

static GSList *_pkginfo_get_filtered_list(const char *locale,
		pkgmgrinfo_filter_x *filter)
{
	static const char query_raw[] =
		"SELECT DISTINCT package_info.package FROM package_info"
		" LEFT OUTER JOIN package_localized_info"
		"  ON package_info.package=package_localized_info.package"
		"  AND package_localized_info.package_locale=%Q "
		" LEFT OUTER JOIN package_privilege_info"
		"  ON package_info.package=package_privilege_info.package";
	int ret;
	char *query;
	char *query_localized;
	sqlite3_stmt *stmt;
	GSList *list = NULL;
	char *pkgid;

	query = _get_filtered_query(query_raw, filter);
	if (query == NULL)
		return NULL;
	query_localized = sqlite3_mprintf(query, locale);
	free(query);
	if (query_localized == NULL)
		return NULL;

	ret = sqlite3_prepare_v2(GET_DB(manifest_db), query_localized,
			strlen(query_localized), &stmt, NULL);
	sqlite3_free(query_localized);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(GET_DB(manifest_db)));
		return NULL;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		_save_column_str(stmt, 0, (const char **)&pkgid);
		list = g_slist_append(list, pkgid);
	}

	sqlite3_finalize(stmt);

	return list;
}

static int _pkginfo_get_filtered_foreach_pkginfo(pkgmgrinfo_filter_x *filter,
		pkgmgrinfo_pkg_list_cb pkg_list_cb, void *user_data, uid_t uid)
{
	pkgmgr_pkginfo_x *info;
	GSList *list;
	GSList *tmp;
	char *pkgid;
	char *locale;
	int stop = 0;

	if (__open_manifest_db(uid, true) < 0)
		return PMINFO_R_ERROR;

	locale = _get_system_locale();
	if (locale == NULL) {
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}

	list = _pkginfo_get_filtered_list(locale, filter);
	if (list == NULL) {
		free(locale);
		__close_manifest_db();
		return PMINFO_R_OK;
	}

	for (tmp = list; tmp; tmp = tmp->next) {
		pkgid = (char *)tmp->data;
		if (stop == 0) {
			if (_pkginfo_get_pkg(pkgid, locale, &info)) {
				free(pkgid);
				continue;
			}
			info->uid = uid;
			if (pkg_list_cb(info, user_data) < 0)
				stop = 1;
			pkgmgrinfo_pkginfo_destroy_pkginfo(info);
		}
		free(pkgid);
	}

	free(locale);
	g_slist_free(list);
	__close_manifest_db();

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_usr_list(pkgmgrinfo_pkg_list_cb pkg_list_cb,
		void *user_data, uid_t uid)
{
	if (pkg_list_cb == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	return _pkginfo_get_filtered_foreach_pkginfo(NULL, pkg_list_cb,
			user_data, uid);
}

API int pkgmgrinfo_pkginfo_get_list(pkgmgrinfo_pkg_list_cb pkg_list_cb, void *user_data)
{
	return pkgmgrinfo_pkginfo_get_usr_list(pkg_list_cb, user_data, GLOBAL_USER);
}

static int _pkginfo_get_author(const char *pkgid, author_x **author)
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

	ret = sqlite3_prepare_v2(GET_DB(manifest_db), query, strlen(query),
			&stmt, NULL);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(GET_DB(manifest_db)));
		return PMINFO_R_ERROR;
	}

	if (sqlite3_step(stmt) == SQLITE_ERROR) {
		LOGE("step error: %s", sqlite3_errmsg(GET_DB(manifest_db)));
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

	*author = info;

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

static int _pkginfo_get_label(const char *pkgid, const char *locale,
		label_x **label)
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

	ret = sqlite3_prepare_v2(GET_DB(manifest_db), query, strlen(query),
			&stmt, NULL);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(GET_DB(manifest_db)));
		return PMINFO_R_ERROR;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		info = calloc(1, sizeof(label_x));
		if (info == NULL) {
			LOGE("out of memory");
			sqlite3_finalize(stmt);
			if (*label) {
				LISTHEAD(*label, info);
				*label = info;
			}
			return PMINFO_R_ERROR;
		}
		idx = 0;
		_save_column_str(stmt, idx++, &info->text);
		_save_column_str(stmt, idx++, &info->lang);
		LISTADD(*label, info);
	}

	if (*label) {
		LISTHEAD(*label, info);
		*label = info;
	}

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

static int _pkginfo_get_icon(const char *pkgid, const char *locale,
		icon_x **icon)
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

	ret = sqlite3_prepare_v2(GET_DB(manifest_db), query, strlen(query),
			&stmt, NULL);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(GET_DB(manifest_db)));
		return PMINFO_R_ERROR;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		info = calloc(1, sizeof(icon_x));
		if (info == NULL) {
			LOGE("out of memory");
			sqlite3_finalize(stmt);
			if (*icon) {
				LISTHEAD(*icon, info);
				*icon = info;
			}
			return PMINFO_R_ERROR;
		}
		idx = 0;
		_save_column_str(stmt, idx++, &info->text);
		_save_column_str(stmt, idx++, &info->lang);
		LISTADD(*icon, info);
	}

	if (*icon) {
		LISTHEAD(*icon, info);
		*icon = info;
	}

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

static int _pkginfo_get_description(const char *pkgid, const char *locale,
		description_x **description)
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

	ret = sqlite3_prepare_v2(GET_DB(manifest_db), query, strlen(query),
			&stmt, NULL);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(GET_DB(manifest_db)));
		return PMINFO_R_ERROR;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		info = calloc(1, sizeof(description_x));
		if (info == NULL) {
			LOGE("out of memory");
			sqlite3_finalize(stmt);
			if (*description) {
				LISTHEAD(*description, info);
				*description = info;
			}
			return PMINFO_R_ERROR;
		}
		idx = 0;
		_save_column_str(stmt, idx++, &info->text);
		_save_column_str(stmt, idx++, &info->lang);
		LISTADD(*description, info);
	}

	if (*description) {
		LISTHEAD(*description, info);
		*description = info;
	}

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

static int _pkginfo_get_privilege(const char *pkgid, privileges_x **privileges)
{
	static const char query_raw[] =
		"SELECT privilege FROM package_privilege_info WHERE package=%Q";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	privileges_x *p;
	privilege_x *info;

	/* privilege list should stored in privileges_x... */
	p = calloc(1, sizeof(privileges_x));
	if (p == NULL) {
		LOGE("out of memory");
		return PMINFO_R_ERROR;
	}
	*privileges = p;

	query = sqlite3_mprintf(query_raw, pkgid);
	if (query == NULL) {
		LOGE("out of memory");
		free(p);
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_prepare_v2(GET_DB(manifest_db), query, strlen(query),
			&stmt, NULL);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(GET_DB(manifest_db)));
		free(p);
		return PMINFO_R_ERROR;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		info = calloc(1, sizeof(privilege_x));
		if (info == NULL) {
			LOGE("out of memory");
			sqlite3_finalize(stmt);
			if (p->privilege) {
				LISTHEAD(p->privilege, info);
				p->privilege = info;
			}
			return PMINFO_R_ERROR;
		}
		_save_column_str(stmt, 0, &info->text);
		LISTADD(p->privilege, info);
	}

	if (p->privilege) {
		LISTHEAD(p->privilege, info);
		p->privilege = info;
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

static int _pkginfo_get_pkg(const char *pkgid, const char *locale,
		pkgmgr_pkginfo_x **pkginfo)
{
	static const char query_raw[] =
		"SELECT for_all_users, package, package_version, "
		"install_location, package_removable, package_preload, "
		"package_readonly, package_update, package_appsetting, "
		"package_system, package_type, package_size, installed_time, "
		"installed_storage, storeclient_id, mainapp_id, package_url, "
		"root_path, csc_path, package_nodisplay, package_api_version "
		"FROM package_info WHERE package=%Q order by for_all_users";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	int idx;
	pkgmgr_pkginfo_x *info;
	package_x *pkg;

	query = sqlite3_mprintf(query_raw, pkgid);
	if (query == NULL) {
		LOGE("out of memory");
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_prepare_v2(GET_DB(manifest_db), query, strlen(query),
			&stmt, NULL);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(GET_DB(manifest_db)));
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_step(stmt);
	if (ret == SQLITE_DONE) {
		LOGE("cannot find pkg");
		sqlite3_finalize(stmt);
		return PMINFO_R_ENOENT;
	} else if (ret != SQLITE_ROW) {
		LOGE("step failed: %s", sqlite3_errmsg(GET_DB(manifest_db)));
		sqlite3_finalize(stmt);
		return PMINFO_R_ERROR;
	}

	pkg = calloc(1, sizeof(package_x));
	if (pkg == NULL) {
		LOGE("out of memory");
		sqlite3_finalize(stmt);
		return PMINFO_R_ERROR;
	}
	idx = 0;
	_save_column_str(stmt, idx++, &pkg->for_all_users);
	_save_column_str(stmt, idx++, &pkg->package);
	_save_column_str(stmt, idx++, &pkg->version);
	_save_column_str(stmt, idx++, &pkg->installlocation);
	_save_column_str(stmt, idx++, &pkg->removable);
	_save_column_str(stmt, idx++, &pkg->preload);
	_save_column_str(stmt, idx++, &pkg->readonly);
	_save_column_str(stmt, idx++, &pkg->update);
	_save_column_str(stmt, idx++, &pkg->appsetting);
	_save_column_str(stmt, idx++, &pkg->system);
	_save_column_str(stmt, idx++, &pkg->type);
	_save_column_str(stmt, idx++, &pkg->package_size);
	_save_column_str(stmt, idx++, &pkg->installed_time);
	_save_column_str(stmt, idx++, &pkg->installed_storage);
	_save_column_str(stmt, idx++, &pkg->storeclient_id);
	_save_column_str(stmt, idx++, &pkg->mainapp_id);
	_save_column_str(stmt, idx++, &pkg->package_url);
	_save_column_str(stmt, idx++, &pkg->root_path);
	_save_column_str(stmt, idx++, &pkg->csc_path);
	_save_column_str(stmt, idx++, &pkg->nodisplay_setting);
	_save_column_str(stmt, idx++, &pkg->api_version);

	if (_pkginfo_get_author(pkg->package, &pkg->author)) {
		pkgmgrinfo_basic_free_package(pkg);
		sqlite3_finalize(stmt);
		return PMINFO_R_ERROR;
	}

	if (_pkginfo_get_label(pkg->package, locale, &pkg->label)) {
		pkgmgrinfo_basic_free_package(pkg);
		sqlite3_finalize(stmt);
		return PMINFO_R_ERROR;
	}

	if (_pkginfo_get_icon(pkg->package, locale, &pkg->icon)) {
		pkgmgrinfo_basic_free_package(pkg);
		sqlite3_finalize(stmt);
		return PMINFO_R_ERROR;
	}

	if (_pkginfo_get_description(pkg->package, locale,
				&pkg->description)) {
		pkgmgrinfo_basic_free_package(pkg);
		sqlite3_finalize(stmt);
		return PMINFO_R_ERROR;
	}

	if (_pkginfo_get_privilege(pkg->package, &pkg->privileges)) {
		pkgmgrinfo_basic_free_package(pkg);
		sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
	}

	info = calloc(1, sizeof(pkgmgr_pkginfo_x));
	if (info == NULL) {
		LOGE("out of memory");
		pkgmgrinfo_basic_free_package(pkg);
		sqlite3_finalize(stmt);
		return PMINFO_R_ERROR;
	}

	info->pkg_info = pkg;
	info->locale = strdup(locale);
	*pkginfo = info;

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_usr_pkginfo(const char *pkgid, uid_t uid,
		pkgmgrinfo_pkginfo_h *handle)
{
	pkgmgr_pkginfo_x *pkginfo = NULL;
	char *locale;

	if (pkgid == NULL || handle == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	if (__open_manifest_db(uid, true) < 0)
		return PMINFO_R_ERROR;


	locale = _get_system_locale();
	if (locale == NULL) {
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}

	if (_pkginfo_get_pkg(pkgid, locale, &pkginfo)) {
		LOGE("failed to get pkginfo of %s for user %d", pkgid, uid);
		free(locale);
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}

	free(locale);
	pkginfo->uid = uid;
	*handle = pkginfo;

	__close_manifest_db();

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_pkginfo(const char *pkgid, pkgmgrinfo_pkginfo_h *handle)
{
	return pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, GLOBAL_USER, handle);
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
	char *locale;
	icon_x *ptr;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL");
	retvm_if(icon == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	locale = info->locale;
	retvm_if(locale == NULL, PMINFO_R_ERROR, "manifest locale is NULL");

	for (ptr = info->pkg_info->icon; ptr != NULL; ptr = ptr->next) {
		if (ptr->lang == NULL)
			continue;

		if (strcmp(ptr->lang, locale) == 0) {
			*icon = (char *)ptr->text;
			if (strcasecmp(*icon, "(null)") == 0) {
				locale = DEFAULT_LOCALE;
				continue;
			} else {
				return PMINFO_R_OK;
			}
		} else if (strcmp(ptr->lang, DEFAULT_LOCALE) == 0) {
			*icon = (char *)ptr->text;
			return PMINFO_R_OK;
		}
	}

	return PMINFO_R_ERROR;
}

API int pkgmgrinfo_pkginfo_get_label(pkgmgrinfo_pkginfo_h handle, char **label)
{
	char *locale;
	label_x *ptr;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL");
	retvm_if(label == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	locale = info->locale;
	retvm_if(locale == NULL, PMINFO_R_ERROR, "manifest locale is NULL");

	for (ptr = info->pkg_info->label; ptr != NULL; ptr = ptr->next) {
		if (ptr->lang == NULL)
			continue;

		if (strcmp(ptr->lang, locale) == 0) {
			*label = (char *)ptr->text;
			if (strcasecmp(*label, "(null)") == 0) {
				locale = DEFAULT_LOCALE;
				continue;
			} else {
				return PMINFO_R_OK;
			}
		} else if (strcmp(ptr->lang, DEFAULT_LOCALE) == 0) {
			*label = (char *)ptr->text;
			return PMINFO_R_OK;
		}
	}

	return PMINFO_R_ERROR;
}

API int pkgmgrinfo_pkginfo_get_description(pkgmgrinfo_pkginfo_h handle, char **description)
{
	char *locale;
	description_x *ptr;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(description == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	locale = info->locale;
	retvm_if(locale == NULL, PMINFO_R_ERROR, "manifest locale is NULL");

	for (ptr = info->pkg_info->description; ptr != NULL; ptr = ptr->next) {
		if (ptr->lang == NULL)
			continue;

		if (strcmp(ptr->lang, locale) == 0) {
			*description = (char *)ptr->text;
			if (strcasecmp(*description, PKGMGR_PARSER_EMPTY_STR) == 0) {
				locale = DEFAULT_LOCALE;
				continue;
			} else {
				return PMINFO_R_OK;
			}
		} else if (strcmp(ptr->lang, DEFAULT_LOCALE) == 0) {
			*description = (char *)ptr->text;
			return PMINFO_R_OK;
		}
	}

	return PMINFO_R_ERROR;
}

API int pkgmgrinfo_pkginfo_get_author_name(pkgmgrinfo_pkginfo_h handle, char **author_name)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(author_name == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->author == NULL ||
			info->pkg_info->author->text == NULL)
		return PMINFO_R_ERROR;

	*author_name = (char *)info->pkg_info->author->text;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_author_email(pkgmgrinfo_pkginfo_h handle, char **author_email)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(author_email == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->author == NULL ||
			info->pkg_info->author->email == NULL)
		return PMINFO_R_ERROR;

	*author_email = (char *)info->pkg_info->author->email;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_author_href(pkgmgrinfo_pkginfo_h handle, char **author_href)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(author_href == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->author == NULL ||
			info->pkg_info->author->href == NULL)
		return PMINFO_R_ERROR;

	*author_href = (char *)info->pkg_info->author->href;

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
	char *val;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(removable == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->removable == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->pkg_info->removable;
	if (strcasecmp(val, "true") == 0)
		*removable = 1;
	else if (strcasecmp(val, "false") == 0)
		*removable = 0;
	else
		*removable = 1;

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
	char *val;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(preload == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->preload == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->pkg_info->preload;
	if (strcasecmp(val, "true") == 0)
		*preload = 1;
	else if (strcasecmp(val, "false") == 0)
		*preload = 0;
	else
		*preload = 0;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_system(pkgmgrinfo_pkginfo_h handle, bool *system)
{
	char *val;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(system == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->system == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->pkg_info->system;
	if (strcasecmp(val, "true") == 0)
		*system = 1;
	else if (strcasecmp(val, "false") == 0)
		*system = 0;
	else
		*system = 0;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_readonly(pkgmgrinfo_pkginfo_h handle, bool *readonly)
{
	char *val;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(readonly == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->readonly == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->pkg_info->readonly;
	if (strcasecmp(val, "true") == 0)
		*readonly = 1;
	else if (strcasecmp(val, "false") == 0)
		*readonly = 0;
	else
		*readonly = 0;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_update(pkgmgrinfo_pkginfo_h handle, bool *update)
{
	char *val;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(update == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->update == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->pkg_info->update;
	if (strcasecmp(val, "true") == 0)
		*update = 1;
	else if (strcasecmp(val, "false") == 0)
		*update = 0;
	else
		*update = 1;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_for_all_users(pkgmgrinfo_pkginfo_h handle, bool *for_all_users)
{
	char *val;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(for_all_users == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->pkg_info == NULL || info->pkg_info->for_all_users == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->pkg_info->for_all_users;
	if (strcasecmp(val, "1") == 0)
		*for_all_users = 1;
	else if (strcasecmp(val, "0") == 0)
		*for_all_users = 0;
	else
		*for_all_users = 1;

	return PMINFO_R_OK;
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
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(count == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	char *locale = NULL;
	char *condition = NULL;
	char *error_message = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	char where[MAX_QUERY_LEN] = {'\0'};
	GSList *list;
	int ret = 0;

	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)handle;
	filter->uid = uid;
	/*Get current locale*/
	locale = _get_system_locale();
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		return PMINFO_R_ERROR;
	}

	ret = __open_manifest_db(uid, true);
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		free(locale);
		return PMINFO_R_ERROR;
	}

	/*Start constructing query*/
	snprintf(query, MAX_QUERY_LEN - 1, FILTER_QUERY_COUNT_PACKAGE, locale);

	/*Get where clause*/
	for (list = filter->list; list; list = g_slist_next(list)) {
		__get_filter_condition(list->data, &condition);
		if (condition) {
			strncat(where, condition, sizeof(where) - strlen(where) -1);
			where[sizeof(where) - 1] = '\0';
			free(condition);
			condition = NULL;
		}
		if (g_slist_next(list)) {
			strncat(where, " and ", sizeof(where) - strlen(where) - 1);
			where[sizeof(where) - 1] = '\0';
		}
	}
	if (strlen(where) > 0) {
		strncat(query, where, sizeof(query) - strlen(query) - 1);
		query[sizeof(query) - 1] = '\0';
	}

	/*Execute Query*/
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(manifest_db), query, __count_cb, (void *)count, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		ret = PMINFO_R_ERROR;
		*count = 0;
		goto err;
	}
	ret = PMINFO_R_OK;
err:
	if (locale) {
		free(locale);
		locale = NULL;
	}
	__close_manifest_db();
	return ret;
}

API int pkgmgrinfo_pkginfo_filter_count(pkgmgrinfo_pkginfo_filter_h handle, int *count)
{
	return pkgmgrinfo_pkginfo_usr_filter_count(handle, count, GLOBAL_USER);
}

API int pkgmgrinfo_pkginfo_usr_filter_foreach_pkginfo(
		pkgmgrinfo_pkginfo_filter_h handle,
		pkgmgrinfo_pkg_list_cb pkg_cb, void *user_data, uid_t uid)
{
	if (handle == NULL || pkg_cb == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	return _pkginfo_get_filtered_foreach_pkginfo(handle, pkg_cb, user_data,
			uid);
}

API int pkgmgrinfo_pkginfo_filter_foreach_pkginfo(pkgmgrinfo_pkginfo_filter_h handle,
				pkgmgrinfo_pkg_list_cb pkg_cb, void *user_data)
{
	return pkgmgrinfo_pkginfo_usr_filter_foreach_pkginfo(handle, pkg_cb, user_data, GLOBAL_USER);
}

API int pkgmgrinfo_pkginfo_foreach_privilege(pkgmgrinfo_pkginfo_h handle,
			pkgmgrinfo_pkg_privilege_list_cb privilege_func, void *user_data)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL");
	retvm_if(privilege_func == NULL, PMINFO_R_EINVAL, "Callback function is NULL");
	int ret = -1;
	privilege_x *ptr = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	ptr = info->pkg_info->privileges->privilege;
	for (; ptr; ptr = ptr->next) {
		if (ptr->text){
			ret = privilege_func(ptr->text, user_data);
			if (ret < 0)
				break;
		}
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_create_pkgusrdbinfo(const char *pkgid, uid_t uid, pkgmgrinfo_pkgdbinfo_h *handle)
{
	retvm_if(!pkgid, PMINFO_R_EINVAL, "pkgid is NULL");
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");

	char *manifest = NULL;
	manifest_x *mfx = NULL;
	*handle = NULL;
	manifest = pkgmgr_parser_get_usr_manifest_file(pkgid, uid);
	retvm_if(manifest == NULL, PMINFO_R_EINVAL, "pkg[%s] dont have manifest file", pkgid);

	mfx = pkgmgr_parser_usr_process_manifest_xml(manifest, uid);
	if (manifest) {
		free(manifest);
		manifest = NULL;
	}
	retvm_if(mfx == NULL, PMINFO_R_EINVAL, "pkg[%s] parsing fail", pkgid);

	*handle = (void *)mfx;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_create_pkgdbinfo(const char *pkgid, pkgmgrinfo_pkgdbinfo_h *handle)
{
	retvm_if(!pkgid, PMINFO_R_EINVAL, "pkgid is NULL");
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");

	char *manifest = NULL;
	manifest_x *mfx = NULL;
	*handle = NULL;
	manifest = pkgmgr_parser_get_manifest_file(pkgid);
	retvm_if(manifest == NULL, PMINFO_R_EINVAL, "pkg[%s] dont have manifest file", pkgid);

	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	if (manifest) {
		free(manifest);
		manifest = NULL;
	}
	retvm_if(mfx == NULL, PMINFO_R_EINVAL, "pkg[%s] parsing fail", pkgid);

	*handle = (void *)mfx;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_type_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, const char *type)
{
	int len;
	manifest_x *mfx = (manifest_x *)handle;

	retvm_if(!type, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");

	len = strlen(type);
	retvm_if(len > PKG_TYPE_STRING_LEN_MAX, PMINFO_R_EINVAL, "pkg type length exceeds the max limit");

	if (mfx->type)
		free((void *)mfx->type);

	mfx->type = strndup(type, PKG_TYPE_STRING_LEN_MAX);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_version_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, const char *version)
{
	int len;
	manifest_x *mfx = (manifest_x *)handle;

	retvm_if(!version, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");

	len = strlen(version);
	retvm_if(len > PKG_TYPE_STRING_LEN_MAX, PMINFO_R_EINVAL, "pkg type length exceeds the max limit");

	if (mfx->version)
		free((void *)mfx->version);

	mfx->version = strndup(version, PKG_VERSION_STRING_LEN_MAX);
	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_install_location_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, INSTALL_LOCATION location)
{
	manifest_x *mfx = (manifest_x *)handle;

	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if((location < 0) || (location > 1), PMINFO_R_EINVAL, "Argument supplied is NULL");

	if (mfx->installlocation)
		free((void *)mfx->installlocation);

	if (location == INSTALL_INTERNAL)
		mfx->installlocation = strdup("internal-only");
	else if (location == INSTALL_EXTERNAL)
		mfx->installlocation = strdup("prefer-external");

	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_size_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, const char *size)
{
	manifest_x *mfx = (manifest_x *)handle;

	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if(size == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL");

	if (mfx->package_size)
		free((void *)mfx->package_size);

	mfx->package_size = strdup(size);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_label_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, const char *label_txt, const char *locale)
{
	int len;
	manifest_x *mfx = (manifest_x *)handle;
	label_x *label;

	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if(!label_txt, PMINFO_R_EINVAL, "Argument supplied is NULL");

	len = strlen(label_txt);
	retvm_if(len > PKG_TYPE_STRING_LEN_MAX, PMINFO_R_EINVAL, "pkg type length exceeds the max limit");

	label = calloc(1, sizeof(label_x));
	retvm_if(label == NULL, PMINFO_R_EINVAL, "Malloc Failed");

	LISTADD(mfx->label, label);
	if (locale)
		mfx->label->lang = strdup(locale);
	else
		mfx->label->lang = strdup(DEFAULT_LOCALE);
	mfx->label->text = strdup(label_txt);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_icon_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, const char *icon_txt, const char *locale)
{
	int len;
	manifest_x *mfx = (manifest_x *)handle;
	icon_x *icon;

	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if(!icon_txt, PMINFO_R_EINVAL, "Argument supplied is NULL");

	len = strlen(icon_txt);
	retvm_if(len > PKG_TYPE_STRING_LEN_MAX, PMINFO_R_EINVAL, "pkg type length exceeds the max limit");

	icon = calloc(1, sizeof(icon_x));
	retvm_if(icon == NULL, PMINFO_R_EINVAL, "Malloc Failed");

	LISTADD(mfx->icon, icon);
	if (locale)
		mfx->icon->lang = strdup(locale);
	else
		mfx->icon->lang = strdup(DEFAULT_LOCALE);
	mfx->icon->text = strdup(icon_txt);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_description_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, const char *desc_txt, const char *locale)
{
	int len = strlen(desc_txt);
	manifest_x *mfx = (manifest_x *)handle;
	description_x *description;

	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if(!desc_txt, PMINFO_R_EINVAL, "Argument supplied is NULL");

	len = strlen(desc_txt);
	retvm_if(len > PKG_TYPE_STRING_LEN_MAX, PMINFO_R_EINVAL, "pkg type length exceeds the max limit");

	description = calloc(1, sizeof(description_x));
	retvm_if(description == NULL, PMINFO_R_EINVAL, "Malloc Failed");

	LISTADD(mfx->description, description);
	if (locale)
		mfx->description->lang = strdup(locale);
	else
		mfx->description->lang = strdup(DEFAULT_LOCALE);
	mfx->description->text = strdup(desc_txt);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_author_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, const char *author_name,
		const char *author_email, const char *author_href, const char *locale)
{
	manifest_x *mfx = (manifest_x *)handle;
	author_x *author;

	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");

	author = calloc(1, sizeof(author_x));
	retvm_if(author == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL");

	LISTADD(mfx->author, author);
	if (author_name)
		mfx->author->text = strdup(author_name);
	if (author_email)
		mfx->author->email = strdup(author_email);
	if (author_href)
		mfx->author->href = strdup(author_href);
	if (locale)
		mfx->author->lang = strdup(locale);
	else
		mfx->author->lang = strdup(DEFAULT_LOCALE);
	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_removable_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, int removable)
{
	manifest_x *mfx = (manifest_x *)handle;

	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if((removable < 0) || (removable > 1), PMINFO_R_EINVAL, "Argument supplied is NULL");

	if (mfx->removable)
		free((void *)mfx->removable);

	if (removable == 0)
		mfx->removable = strdup("false");
	else if (removable == 1)
		mfx->removable = strdup("true");

	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_preload_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, int preload)
{
	manifest_x *mfx = (manifest_x *)handle;

	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if((preload < 0) || (preload > 1), PMINFO_R_EINVAL, "Argument supplied is NULL");

	if (mfx->preload)
		free((void *)mfx->preload);

	if (preload == 0)
		mfx->preload = strdup("false");
	else if (preload == 1)
		mfx->preload = strdup("true");

	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_installed_storage_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, INSTALL_LOCATION location)
{
	manifest_x *mfx = (manifest_x *)handle;

	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if((location < 0) || (location > 1), PMINFO_R_EINVAL, "Argument supplied is NULL");

	if (mfx->installed_storage)
		free((void *)mfx->installed_storage);

	if (location == INSTALL_INTERNAL)
		mfx->installed_storage = strdup("installed_internal");
	else if (location == INSTALL_EXTERNAL)
		mfx->installed_storage = strdup("installed_external");

	return PMINFO_R_OK;
}

API int pkgmgrinfo_save_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle)
{
	int ret;
	manifest_x *mfx = (manifest_x *)handle;
	mfx = (manifest_x *)handle;

	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");

	ret = pkgmgr_parser_update_manifest_info_in_db(mfx);
	if (ret == 0) {
		_LOGE("Successfully stored info in DB\n");
		return PMINFO_R_OK;
	} else {
		_LOGE("Failed to store info in DB\n");
		return PMINFO_R_ERROR;
	}
}

API int pkgmgrinfo_save_pkgusrdbinfo(pkgmgrinfo_pkgdbinfo_h handle, uid_t uid)
{
	int ret;
	manifest_x *mfx = (manifest_x *)handle;

	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");

	ret = pkgmgr_parser_update_manifest_info_in_usr_db(mfx, uid);
	if (ret == 0) {
		_LOGE("Successfully stored info in DB\n");
		return PMINFO_R_OK;
	} else {
		_LOGE("Failed to store info in DB\n");
		return PMINFO_R_ERROR;
	}
}

API int pkgmgrinfo_destroy_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle)
{
	manifest_x *mfx = (manifest_x *)handle;

	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");

	pkgmgrinfo_basic_free_package(mfx);

	return PMINFO_R_OK;
}
