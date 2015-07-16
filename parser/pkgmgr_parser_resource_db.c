/*
 * pkgmgr-info
 *
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <db-util.h>
#include <glib.h>
#include <dlfcn.h>
#include <bundle.h>

#include "pkgmgr-info.h"
#include "pkgmgr-info-debug.h"
#include "pkgmgr_parser_db.h"
#include "pkgmgr_parser_internal.h"
#include "pkgmgr_parser_resource.h"
#include "pkgmgr_parser_resource_db.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "PKGMGR_PARSER"

#define BUF_SIZE 1024
#define PKGMGR_PARSER_DB_FILE tzplatform_mkpath(TZ_USER_DB, ".pkgmgr_parser.db")

enum {
	NODE_ATTR_MIN = 0,
	NODE_ATTR_SCREEN_DPI,
	NODE_ATTR_SCREEN_DPI_RANGE,
	NODE_ATTR_SCREEN_WIDTH_RANGE,
	NODE_ATTR_SCREEN_LARGE,
	NODE_ATTR_SCREEN_BPP,
	NODE_ATTR_PLATFORM_VER,
	NODE_ATTR_LANGUAGE,
	NODE_ATTR_MAX,
};

static int _get_attr_val(bundle *b, char **attr_name, const char **attr_val, int attr_index)
{
	char *buf = NULL;
	if (b == NULL) {
		_LOGE("bundle is null");
		return PMINFO_R_EINVAL;
	}

	buf = malloc(BUF_SIZE);
	if (buf == NULL) {
		_LOGE("malloc failed");
		return PMINFO_R_ERROR;
	}
	memset(buf, '\0', BUF_SIZE);
	switch (attr_index) {
	case NODE_ATTR_SCREEN_DPI:
		snprintf(buf, BUF_SIZE, "%s", RSC_NODE_ATTR_SCREEN_DPI);
		*attr_val = bundle_get_val(b, RSC_NODE_ATTR_SCREEN_DPI);
		break;
	case NODE_ATTR_SCREEN_DPI_RANGE:
		snprintf(buf, BUF_SIZE, "%s", RSC_NODE_ATTR_SCREEN_DPI_RANGE);
		*attr_val = bundle_get_val(b, RSC_NODE_ATTR_SCREEN_DPI_RANGE);
		break;
	case NODE_ATTR_SCREEN_WIDTH_RANGE:
		snprintf(buf, BUF_SIZE, "%s", RSC_NODE_ATTR_SCREEN_WIDTH_RANGE);
		*attr_val = bundle_get_val(b, RSC_NODE_ATTR_SCREEN_WIDTH_RANGE);
		break;
	case NODE_ATTR_SCREEN_LARGE:
		snprintf(buf, BUF_SIZE, "%s", RSC_NODE_ATTR_SCREEN_LARGE);
		*attr_val = bundle_get_val(b, RSC_NODE_ATTR_SCREEN_LARGE);
		break;
	case NODE_ATTR_SCREEN_BPP:
		snprintf(buf, BUF_SIZE, "%s", RSC_NODE_ATTR_SCREEN_BPP);
		*attr_val = bundle_get_val(b, RSC_NODE_ATTR_SCREEN_BPP);
		break;
	case NODE_ATTR_PLATFORM_VER:
		snprintf(buf, BUF_SIZE, "%s", RSC_NODE_ATTR_PLATFORM_VER);
		*attr_val = bundle_get_val(b, RSC_NODE_ATTR_PLATFORM_VER);
		break;
	case NODE_ATTR_LANGUAGE:
		snprintf(buf, BUF_SIZE, "%s", RSC_NODE_ATTR_LANGUAGE);
		*attr_val = bundle_get_val(b, RSC_NODE_ATTR_LANGUAGE);
		break;
	default:
		_LOGE("unidentified index[%d]", attr_index);
		free(buf);
		buf = NULL;
		return PMINFO_R_ERROR;
	}

	if (buf != NULL && strlen(buf) != 0)
		*attr_name = buf;

	return PMINFO_R_OK;
}

static int _insert_node_data_into_db(sqlite3 *pkginfo, const char *package, char *group_type, GList *node_list)
{
	char *query = NULL;
	resource_node_t *rsc_node = NULL;
	GList *tmp_node_list = NULL;
	bundle *b = NULL;
	const char *attr_val = NULL;
	char *attr_name = NULL;
	int i;
	int ret = -1;

	if (pkginfo == NULL || package == NULL || strlen(package) == 0 || group_type == NULL || strlen(group_type) == 0 || node_list == NULL)
		return PMINFO_R_EINVAL;

	tmp_node_list = g_list_first(node_list);

	if (tmp_node_list == NULL) {
		_LOGE("list is null");
		return PMINFO_R_ERROR;
	}

	while (tmp_node_list != NULL) {
		rsc_node = (resource_node_t *)tmp_node_list->data;
		if (rsc_node == NULL) {
			_LOGE("node is null");
			return PMINFO_R_ERROR;
		}

		/*get bundle for each nodes*/
		b = rsc_node->attr;
		if (b == NULL) {
			_LOGE("bundle is null");
			return PMINFO_R_ERROR;
		}

		for (i = NODE_ATTR_MIN + 1; i < NODE_ATTR_MAX; i++) {
			ret = _get_attr_val(b, &attr_name, &attr_val, i);
			if (ret != 0) {
				_LOGE("get attribute from bundle failed");
				return ret;
			}

			if (attr_name == NULL || attr_val == NULL)
				continue;
			query = sqlite3_mprintf("insert into package_resource_data(id, node_folder, attr_name, attr_value) VALUES(" \
				"(select rowid from package_resource_info where pkg_id=%Q and group_type=%Q), %Q, %Q, %Q)", package, group_type, rsc_node->folder, attr_name, attr_val);

			/*Begin transaction*/
			ret = sqlite3_exec(pkginfo, query, NULL, NULL, NULL);
			if (ret != SQLITE_OK)
				_LOGE("Failed to insert into package_resource_data, attr_name[%s], attr_val[%s]", attr_name, attr_val);
			sqlite3_free(query);
			query = NULL;
			free(attr_name);
			attr_name = NULL;
			attr_val = NULL;
		}
		tmp_node_list = g_list_next(tmp_node_list);
	}

	return ret;
}

int pkgmgr_parser_resource_db_remove(const char *package)
{
	sqlite3 *pkginfo = NULL;
	char *query = NULL;
	int ret = -1;

	if (package == NULL) {
		_LOGE("parameter is NULL");
		return PMINFO_R_EINVAL;
	}

	/*db open*/
	ret = db_util_open(PKGMGR_PARSER_DB_FILE, &pkginfo, 0);
	retvm_if(ret != SQLITE_OK, PMINFO_R_ERROR, "connect db [%s] failed!", PKGMGR_PARSER_DB_FILE);

	/*Begin transaction*/
	ret = sqlite3_exec(pkginfo, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Failed to begin transaction\n");
	_LOGD("Transaction Begin\n");

	/*delete data from package_resource_data*/
	query = sqlite3_mprintf("delete from package_resource_data where id in (select rowid from package_resource_info where pkg_id=%Q)", package);
	ret = sqlite3_exec(pkginfo, query, NULL, NULL, NULL);
	tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Failed to delete from package_resource_info");
	sqlite3_free(query);
	query = NULL;

	/*delete data from package_resource_info*/
	query = sqlite3_mprintf("delete from package_resource_info where pkg_id=%Q", package);
	ret = sqlite3_exec(pkginfo, query, NULL, NULL, NULL);
	tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Failed to delete from package_resource_info");

	/*Commit transaction*/
	ret = sqlite3_exec(pkginfo, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to commit transaction. Rollback now\n");
		ret = sqlite3_exec(pkginfo, "ROLLBACK", NULL, NULL, NULL);
		tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Don't execute query = %s\n", query);
	}
	_LOGD("Transaction Commit and End\n");

	ret = PMINFO_R_OK;
catch:
	sqlite3_close(pkginfo);
	sqlite3_free(query);

	return ret;
}

int pkgmgr_parser_resource_db_save(const char *package, resource_data_t *data)
{
	sqlite3 *pkginfo = NULL;
	char *query = NULL;
	int ret = -1;
	GList *group_list = NULL;
	GList *node_list = NULL;
	resource_group_t *rsc_group = NULL;

	if (package == NULL || strlen(package) == 0 || data == NULL) {
		_LOGE("invalid parameter");
		return -1;
	}

	ret = pkgmgr_parser_check_and_create_db(getuid());
	if (ret == 0)
		ret = pkgmgr_parser_initialize_db(getuid());
	if (ret < 0) {
		_LOGE("db initialization failed");
		goto catch;
	}


	group_list = g_list_first(data->group_list);
	/*db open*/
	ret = db_util_open(PKGMGR_PARSER_DB_FILE, &pkginfo, 0);
	retvm_if(ret != SQLITE_OK, PMINFO_R_ERROR, "connect db [%s] failed!", PKGMGR_PARSER_DB_FILE);

	/*Begin transaction*/
	ret = sqlite3_exec(pkginfo, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Failed to begin transaction\n");
	_LOGD("Transaction Begin\n");

	while (group_list != NULL) {
		rsc_group = NULL;
		node_list = NULL;

		rsc_group = (resource_group_t *)group_list->data;
		node_list = g_list_first(rsc_group->node_list);

		if (rsc_group == NULL || node_list == NULL) {
			_LOGE("value is null");
			ret = -1;
			goto catch;
		}

		query = sqlite3_mprintf("insert into package_resource_info(pkg_id, group_folder, group_type) VALUES(%Q, %Q, %Q)", \
			package, rsc_group->folder, rsc_group->type);

		/*Begin transaction*/
		ret = sqlite3_exec(pkginfo, query, NULL, NULL, NULL);
		tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Failed to insert into package_resource_info");
		sqlite3_free(query);
		query = NULL;

		ret = _insert_node_data_into_db(pkginfo, package, rsc_group->type, node_list);

		group_list = g_list_next(group_list);
	}

	/*Commit transaction*/
	ret = sqlite3_exec(pkginfo, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to commit transaction. Rollback now\n");
		ret = sqlite3_exec(pkginfo, "ROLLBACK", NULL, NULL, NULL);
		tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Don't execute query = %s\n", query);
	}
	_LOGD("Transaction Commit and End\n");

	ret = PMINFO_R_OK;


catch:
	pkgmgr_parser_close_db();
	sqlite3_close(pkginfo);
	sqlite3_free(query);

	return ret;

}

static gint _find_group_type(void *group, void *data)
{
	resource_group_t *rsc_group = (resource_group_t *)group;

	return strcmp(rsc_group->type, (char *)data);
}

static gint _find_node_folder(void *node, void *data)
{
	resource_node_t *rsc_node = (resource_node_t *)node;
	char *str = (char *)data;

	return strcmp(rsc_node->folder, str);
}

static int _init_node(char *node_folder, resource_node_t **rsc_node)
{
	resource_node_t *tmp_node = NULL;

	if (node_folder == NULL) {
		_LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	tmp_node = malloc(sizeof(resource_node_t));
	if (tmp_node == NULL) {
		_LOGE("malloc failed");
		return PMINFO_R_ERROR;
	}

	tmp_node->folder = strdup(node_folder);
	tmp_node->attr = bundle_create();
	*rsc_node = tmp_node;

	return PMINFO_R_OK;
}

static int _init_group(char *group_type, resource_group_t **rsc_group)
{
	resource_group_t *tmp_group = NULL;

	if (group_type == NULL) {
		_LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	tmp_group = malloc(sizeof(resource_group_t));
	if (tmp_group == NULL) {
		_LOGE("malloc failed");
		return PMINFO_R_ERROR;
	}

	tmp_group->type = strdup(group_type);
	tmp_group->node_list = NULL;
	*rsc_group = tmp_group;

	return PMINFO_R_OK;
}

int pkgmgr_parser_resource_db_load(const char *package, resource_data_t **data)
{
	sqlite3 *pkginfo = NULL;
	sqlite3_stmt *stmt = NULL;
	char *query = NULL;
	char *colname = NULL;
	char *group_type = NULL;
	char *group_folder = NULL;
	char *node_folder = NULL;
	char *attr_name = NULL;
	char *attr_value = NULL;
	int ret = -1;
	int cols = 0;
	int i;
	resource_data_t *rsc_data = NULL;
	resource_group_t *rsc_group = NULL;
	resource_node_t *rsc_node = NULL;
	GList *group_list = NULL;
	GList *node_list = NULL;
	GList *tmp_group_list = NULL;
	GList *tmp_node_list = NULL;

	ret = db_util_open(PKGMGR_PARSER_DB_FILE, &pkginfo, 0);
	retvm_if(ret != SQLITE_OK, PMINFO_R_ERROR, "connect db [%s] failed!", PKGMGR_PARSER_DB_FILE);
	query = sqlite3_mprintf("select " \
		"package_resource_info.group_type, package_resource_info.group_folder, package_resource_data.node_folder, package_resource_data.attr_name, package_resource_data.attr_value " \
		"from package_resource_info, package_resource_data where " \
		"package_resource_info.rowid=package_resource_data.id and " \
		"package_resource_info.pkg_id=%Q order by package_resource_data.rowid asc", \
		package);
	ret = sqlite3_prepare_v2(pkginfo, query, strlen(query), &stmt, NULL);
	tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "sqlite3_prepare_v2 query = %s\n", query);
	cols = sqlite3_column_count(stmt);

	while (1) {
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_ROW)
			break;
		tmp_group_list = NULL;
		tmp_node_list = NULL;
		rsc_group = NULL;
		rsc_node = NULL;

		for (i = 0; i < cols; i++) {
			colname = (char *)sqlite3_column_name(stmt, i);
			if (strcmp(colname, "group_type") == 0) {
				/*group_type*/
				group_type = (char *)sqlite3_column_text(stmt, i);
				tmp_group_list = g_list_find_custom(group_list, group_type, (GCompareFunc)_find_group_type);
				if (tmp_group_list == NULL) {
					ret = _init_group(group_type, &rsc_group);
					if (ret != PMINFO_R_OK) {
						_LOGE("group initialization failed[%d]", ret);
						goto catch;
					}
					group_list = g_list_append(group_list, rsc_group);
					node_list = NULL;
				} else {
					rsc_group = (resource_group_t *)tmp_group_list->data;
					node_list = rsc_group->node_list;
				}
			} else if (strcmp(colname, "group_folder") == 0) {
				/*group_folder*/
				group_folder = (char *)sqlite3_column_text(stmt, i);
				if (rsc_group->folder != NULL && strcmp(rsc_group->folder, group_folder) == 0)
					continue;
				else if (rsc_group != NULL && group_folder != NULL)
					rsc_group->folder = strdup(group_folder);
				else {
					_LOGE("rsc_group and group_folder should not be null");
					ret = PMINFO_R_ERROR;
					goto catch;
				}
			} else if (strcmp(colname, "node_folder") == 0) {
				/*node_folder*/
				node_folder = (char *)sqlite3_column_text(stmt, i);
				tmp_node_list = g_list_find_custom(node_list, node_folder, (GCompareFunc)_find_node_folder);
				if (tmp_node_list == NULL) {
					ret = _init_node(node_folder, &rsc_node);
					/*initialize new node*/
					if (ret != PMINFO_R_OK) {
						_LOGE("node initialization failed[%d]", ret);
						goto catch;
					}
					node_list = g_list_append(node_list, rsc_node);
					if (rsc_group->node_list == NULL)
						rsc_group->node_list = node_list;
				} else
					rsc_node = (resource_node_t *)tmp_node_list->data;
			} else if (strcmp(colname, "attr_name") == 0) {
				/*attr_name*/
				attr_name = (char *)sqlite3_column_text(stmt, i);
			} else if (strcmp(colname, "attr_value") == 0) {
				/*attr_value*/
				attr_value = (char *)sqlite3_column_text(stmt, i);
				if (rsc_node != NULL && attr_name != NULL && attr_value != NULL) {
					if (rsc_node->attr != NULL)
						bundle_add(rsc_node->attr, attr_name, attr_value);
					else {
						_LOGE("bundle is not initialized");
						ret = PMINFO_R_ERROR;
						goto catch;
					}
				} else {
					_LOGE("error happened");
					ret = PMINFO_R_ERROR;
					goto catch;
				}
			} else {
				/*error handling*/
				_LOGE("unexpected column name detected:[%s]", colname);
				ret = PMINFO_R_ERROR;
				goto catch;
			}
		}
	}
	if (ret == SQLITE_DONE)
		ret = PMINFO_R_OK;

	rsc_data = malloc(sizeof(resource_data_t));
	if (rsc_data == NULL) {
		_LOGD("malloc failed");
		ret = PMINFO_R_ERROR;
		goto catch;
	}
	rsc_data->group_list = group_list;
	rsc_data->package = strdup(package);
	/*set return data*/
	*data = rsc_data;
catch:
	sqlite3_close(pkginfo);
	sqlite3_free(query);

	return ret;
}
