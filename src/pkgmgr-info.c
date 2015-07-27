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
#include <unistd.h>
#include <ctype.h>
#include <assert.h>
#include <dlfcn.h>
#include <sys/smack.h>
#include <linux/limits.h>
#include <libgen.h>
#include <grp.h>
#include <dirent.h>
#include <sys/stat.h>

#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlschemas.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <sqlite3.h>
#include <glib.h>

#include <db-util.h>
#include <vconf.h>
/* For multi-user support */
#include <tzplatform_config.h>

#include "pkgmgr_parser.h"
#include "pkgmgr-info-basic.h"
#include "pkgmgr-info-internal.h"
#include "pkgmgr-info-debug.h"
#include "pkgmgr-info.h"
#include "pkgmgr_parser_db.h"
#include "pkgmgr_parser_internal.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "PKGMGR_INFO"

#define ASC_CHAR(s) (const char *)s
#define XML_CHAR(s) (const xmlChar *)s

#define MANIFEST_DB	tzplatform_mkpath(TZ_SYS_DB, ".pkgmgr_parser.db")
#define MAX_QUERY_LEN	4096
#define MAX_CERT_TYPE	9
#define CERT_DB		tzplatform_mkpath(TZ_SYS_DB, ".pkgmgr_cert.db")
#define DATACONTROL_DB	tzplatform_mkpath(TZ_USER_DB, ".app-package.db")
#define PKG_TYPE_STRING_LEN_MAX		128
#define PKG_VERSION_STRING_LEN_MAX	128
#define PKG_VALUE_STRING_LEN_MAX		512
#define PKG_LOCALE_STRING_LEN_MAX		8
#define PKG_RW_PATH tzplatform_mkpath(TZ_USER_APP, "")
#define PKG_RO_PATH tzplatform_mkpath(TZ_SYS_RO_APP, "")
#define BLOCK_SIZE      4096 /*in bytes*/
#define BUFSIZE 4096
#define ROOT_UID 0

#define MMC_PATH tzplatform_mkpath(TZ_SYS_STORAGE, "sdcard")
#define PKG_SD_PATH tzplatform_mkpath3(TZ_SYS_STORAGE, "sdcard", "app2sd/")
#define PKG_INSTALLATION_PATH tzplatform_mkpath(TZ_USER_APP, "")

#define FILTER_QUERY_COUNT_PACKAGE	"select count(DISTINCT package_info.package) " \
				"from package_info LEFT OUTER JOIN package_localized_info " \
				"ON package_info.package=package_localized_info.package " \
				"and package_localized_info.package_locale='%s' where "

#define FILTER_QUERY_LIST_PACKAGE	"select DISTINCT package_info.package " \
				"from package_info LEFT OUTER JOIN package_localized_info " \
				"ON package_info.package=package_localized_info.package " \
				"and package_localized_info.package_locale='%s' where "

#define FILTER_QUERY_COUNT_APP	"select count(DISTINCT package_app_info.app_id) " \
				"from package_app_info LEFT OUTER JOIN package_app_localized_info " \
				"ON package_app_info.app_id=package_app_localized_info.app_id " \
				"and package_app_localized_info.app_locale='%s' " \
				"LEFT OUTER JOIN package_app_app_svc " \
				"ON package_app_info.app_id=package_app_app_svc.app_id " \
				"LEFT OUTER JOIN package_app_app_category " \
				"ON package_app_info.app_id=package_app_app_category.app_id where "

#define FILTER_QUERY_LIST_APP	"select DISTINCT package_app_info.app_id, package_app_info.app_component " \
				"from package_app_info LEFT OUTER JOIN package_app_localized_info " \
				"ON package_app_info.app_id=package_app_localized_info.app_id " \
				"and package_app_localized_info.app_locale='%s' " \
				"LEFT OUTER JOIN package_app_app_svc " \
				"ON package_app_info.app_id=package_app_app_svc.app_id " \
				"LEFT OUTER JOIN package_app_app_category " \
				"ON package_app_info.app_id=package_app_app_category.app_id where "

#define METADATA_FILTER_QUERY_SELECT_CLAUSE	"select DISTINCT package_app_info.app_id, package_app_info.app_component " \
				"from package_app_info LEFT OUTER JOIN package_app_app_metadata " \
				"ON package_app_info.app_id=package_app_app_metadata.app_id where "

#define METADATA_FILTER_QUERY_UNION_CLAUSE	" UNION "METADATA_FILTER_QUERY_SELECT_CLAUSE

#define LANGUAGE_LENGTH 2

#define SERVICE_NAME "org.tizen.system.deviced"
#define PATH_NAME "/Org/Tizen/System/DeviceD/Mmc"
#define INTERFACE_NAME "org.tizen.system.deviced.Mmc"
#define METHOD_NAME "RequestMountApp2ext"



typedef struct _pkgmgr_instcertinfo_x {
	char *pkgid;
	char *cert_info[MAX_CERT_TYPE];	/*certificate data*/
	int is_new[MAX_CERT_TYPE];		/*whether already exist in table or not*/
	int ref_count[MAX_CERT_TYPE];		/*reference count of certificate data*/
	int cert_id[MAX_CERT_TYPE];		/*certificate ID in index table*/
} pkgmgr_instcertinfo_x;

typedef struct _pkgmgr_certindexinfo_x {
	int cert_id;
	int cert_ref_count;
} pkgmgr_certindexinfo_x;

typedef struct _pkgmgr_pkginfo_x {
	uid_t uid;
	package_x *pkg_info;
	char *locale;

	struct _pkgmgr_pkginfo_x *prev;
	struct _pkgmgr_pkginfo_x *next;
} pkgmgr_pkginfo_x;

typedef struct _pkgmgr_cert_x {
	char *pkgid;
	int cert_id;
} pkgmgr_cert_x;

typedef struct _pkgmgr_datacontrol_x {
	char *appid;
	char *access;
} pkgmgr_datacontrol_x;

typedef struct _pkgmgr_iconpath_x {
	char *appid;
	char *iconpath;
} pkgmgr_iconpath_x;

typedef struct _pkgmgr_image_x {
	char *imagepath;
} pkgmgr_image_x;

typedef struct _pkgmgr_locale_x {
	char *locale;
} pkgmgr_locale_x;

typedef struct _pkgmgr_appinfo_x {
	const char *package;
	char *locale;
	pkgmgrinfo_app_component app_component;
	union {
		uiapplication_x *uiapp_info;
		serviceapplication_x *svcapp_info;
		application_x *app_info;
	};
	struct _pkgmgr_appinfo_x *prev;
	struct _pkgmgr_appinfo_x *next;
} pkgmgr_appinfo_x;

typedef struct _pkgmgr_certinfo_x {
	int for_all_users;
	char *pkgid;
	char *cert_value;
	char *cert_info[MAX_CERT_TYPE];	/*certificate info*/
	int cert_id[MAX_CERT_TYPE];		/*certificate ID in index table*/
} pkgmgr_certinfo_x;

/*For filter APIs*/
typedef struct _pkgmgrinfo_filter_x {
	uid_t uid;
	GSList *list;
} pkgmgrinfo_filter_x;

typedef struct _pkgmgrinfo_node_x {
	int prop;
	char *key;
	char *value;
} pkgmgrinfo_node_x;

typedef struct _pkgmgrinfo_appcontrol_x {
	int operation_count;
	int uri_count;
	int mime_count;
	int subapp_count;
	char **operation;
	char **uri;
	char **mime;
	char **subapp;
} pkgmgrinfo_appcontrol_x;


typedef struct _db_handle {
	sqlite3 *dbHandle;
	int ref;
} db_handle;


typedef int (*sqlite_query_callback)(void *data, int ncols, char **coltxt, char **colname);

typedef int (*pkgmgr_handler)(int req_id, const char *pkg_type,
				const char *pkgid, const char *key,
				const char *val, const void *pmsg, void *data);

typedef void pkgmgr_client;
typedef void pkgmgr_info;

typedef enum {
	PM_REQUEST_CSC = 0,
	PM_REQUEST_MOVE = 1,
	PM_REQUEST_GET_SIZE = 2,
	PM_REQUEST_KILL_APP = 3,
	PM_REQUEST_CHECK_APP = 4,
	PM_REQUEST_MAX
}pkgmgr_request_service_type;

typedef enum {
	PM_GET_TOTAL_SIZE= 0,
	PM_GET_DATA_SIZE = 1,
	PM_GET_ALL_PKGS = 2,
	PM_GET_SIZE_INFO = 3,
	PM_GET_TOTAL_AND_DATA = 4,
	PM_GET_SIZE_FILE = 5,
	PM_GET_MAX
}pkgmgr_getsize_type;

typedef enum {
	PC_REQUEST = 0,
	PC_LISTENING,
	PC_BROADCAST,
}client_type;

#define PKG_SIZE_INFO_FILE "/tmp/pkgmgr_size_info.txt"
#define MAX_PKG_BUF_LEN		1024
#define MAX_PKG_INFO_LEN	10

#define QUERY_CREATE_TABLE_PACKAGE_CERT_INDEX_INFO "create table if not exists package_cert_index_info " \
						"(cert_info text not null, " \
						"cert_id integer, " \
						"cert_ref_count integer, " \
						"PRIMARY KEY(cert_id)) "

#define QUERY_CREATE_TABLE_PACKAGE_CERT_INFO "create table if not exists package_cert_info " \
						"(package text not null, " \
						"author_root_cert integer, " \
						"author_im_cert integer, " \
						"author_signer_cert integer, " \
						"dist_root_cert integer, " \
						"dist_im_cert integer, " \
						"dist_signer_cert integer, " \
						"dist2_root_cert integer, " \
						"dist2_im_cert integer, " \
						"dist2_signer_cert integer, " \
						"PRIMARY KEY(package)) "

#define GET_DB(X)  (X).dbHandle
char *pkgtype = "rpm";
__thread db_handle manifest_db;
__thread db_handle datacontrol_db;
__thread db_handle cert_db;

static int __open_manifest_db(uid_t uid);
static int __close_manifest_db(void);
static int __open_cert_db(uid_t uid, char* mode);
static int __close_cert_db(void);
static int __exec_certinfo_query(char *query, void *data);
static int __exec_certindexinfo_query(char *query, void *data);
static int __certinfo_cb(void *data, int ncols, char **coltxt, char **colname);
static int __certindexinfo_cb(void *data, int ncols, char **coltxt, char **colname);
static int __validate_cb(void *data, int ncols, char **coltxt, char **colname);
static int __maxid_cb(void *data, int ncols, char **coltxt, char **colname);
static int __count_cb(void *data, int ncols, char **coltxt, char **colname);
static int __uiapp_list_cb(void *data, int ncols, char **coltxt, char **colname);
static int __svcapp_list_cb(void *data, int ncols, char **coltxt, char **colname);
static int __app_list_cb(void *data, int ncols, char **coltxt, char **colname);
static void __cleanup_pkginfo(pkgmgr_pkginfo_x *data);
static void __cleanup_appinfo(pkgmgr_appinfo_x *data);
static char* __convert_system_locale_to_manifest_locale(char *syslocale);
static void __destroy_each_node(gpointer data, gpointer user_data);
static void __get_filter_condition(gpointer data, char **condition);
static void __get_metadata_filter_condition(gpointer data, char **condition);
static gint __compare_func(gconstpointer data1, gconstpointer data2);
static int __delete_certinfo(const char *pkgid, uid_t uid);
static int _check_create_Cert_db( sqlite3 *certdb);
static int __exec_db_query(sqlite3 *db, char *query, sqlite_query_callback callback, void *data);
static char *_get_system_locale(void);
static int _pkginfo_get_pkg(const char *locale, pkgmgrinfo_filter_x *filter,
		pkgmgr_pkginfo_x **pkginfo);
static int _appinfo_get_app(const char *locale, pkgmgrinfo_filter_x *filter,
		pkgmgr_appinfo_x **appinfo);

static int _mkdir_for_user(const char* dir, uid_t uid, gid_t gid)
{
	int ret;
	char *fullpath;
	char *subpath;

	fullpath = strdup(dir);
	subpath = dirname(fullpath);
	if (strlen(subpath) > 1 && strcmp(subpath, fullpath) != 0) {
		ret = _mkdir_for_user(fullpath, uid, gid);
		if (ret == -1) {
			free(fullpath);
			return ret;
		}
	}

	ret = mkdir(dir, S_IRWXU | S_IRGRP | S_IXGRP | S_IXOTH);
	if (ret && errno != EEXIST) {
		free(fullpath);
		return ret;
	} else if (ret && errno == EEXIST) {
		free(fullpath);
		return 0;
	}

	if (getuid() == ROOT_UID) {
		ret = chown(dir, uid, gid);
		if (ret == -1)
			_LOGE("FAIL : chown %s %d.%d, because %s", dir, uid,
					gid, strerror(errno));
	}

	free(fullpath);

	return 0;
}

static const char *_get_db_path(uid_t uid) {
	const char *db_path = NULL;
	if (uid != GLOBAL_USER && uid != ROOT_UID) {
		tzplatform_set_user(uid);
		db_path = tzplatform_getenv(TZ_USER_DB);
		tzplatform_reset_user();
	} else {
		db_path = tzplatform_getenv(TZ_SYS_DB);
	}
	return db_path;
}

static int __attach_and_create_view(sqlite3 *handle, const char *db, const char *tables[], uid_t uid)
{
	int i;
	char *err;
	char query[MAX_QUERY_LEN];

	if (uid != GLOBAL_USER && uid != ROOT_UID) {
		snprintf(query, sizeof(query), "ATTACH DATABASE '%s' AS Global", db);
		if (SQLITE_OK != sqlite3_exec(handle, query, NULL, NULL, &err)) {
			_LOGD("Don't execute query = %s error message = %s\n", query, err);
			sqlite3_free(err);
			return SQLITE_ERROR;
		}
	}

	for (i = 0; tables[i]; i++) {
		if (uid != GLOBAL_USER && uid != ROOT_UID)
			snprintf(query, sizeof(query), "CREATE TEMP VIEW '%s' AS SELECT * \
					FROM (SELECT *,0 AS for_all_users FROM main.'%s' UNION \
					SELECT *,1 AS for_all_users FROM Global.'%s')",
					tables[i], tables[i], tables[i]);
		else
			snprintf(query, sizeof(query), "CREATE TEMP VIEW '%s' AS SELECT * \
					FROM (SELECT *,1 AS for_all_users FROM main.'%s')",
					tables[i], tables[i]);
		if (SQLITE_OK != sqlite3_exec(handle, query, NULL, NULL, &err)) {
			_LOGD("Don't execute query = %s error message = %s\n", query, err);
			sqlite3_free(err);
		}
	}

	return SQLITE_OK;
}

static int _check_create_Cert_db( sqlite3 *certdb)
{
	int ret = 0;
	ret = __exec_db_query(certdb, QUERY_CREATE_TABLE_PACKAGE_CERT_INDEX_INFO, NULL, NULL);
	if(ret < 0)
		return ret;
	ret = __exec_db_query(certdb, QUERY_CREATE_TABLE_PACKAGE_CERT_INFO, NULL, NULL);
	return ret;
}

static gid_t _get_gid(const char *name)
{
	char buf[BUFSIZE];
	struct group entry;
	struct group *ge;
	int ret;

	ret = getgrnam_r(name, &entry, buf, sizeof(buf), &ge);
	if (ret || ge == NULL) {
		_LOGE("fail to get gid of %s", name);
		return -1;
	}

	return entry.gr_gid;
}

API const char *getIconPath(uid_t uid)
{
	const char *path = NULL;
	uid_t uid_caller = getuid();
	gid_t gid = ROOT_UID;

	if (uid != GLOBAL_USER && uid != ROOT_UID) {
		tzplatform_set_user(uid);
		path = tzplatform_mkpath(TZ_USER_ICONS, "/");
		gid = _get_gid(tzplatform_getenv(TZ_SYS_USER_GROUP));
		tzplatform_reset_user();
	} else {
		path = tzplatform_mkpath(TZ_SYS_RW_ICONS, "/");
	}

	// just allow certain users to create the icon directory if needed.
	if (uid_caller == ROOT_UID || uid_caller == uid)
		_mkdir_for_user(path, uid, gid);

	return path;
}

API const char *getUserPkgParserDBPath(void)
{
	return getUserPkgParserDBPathUID(GLOBAL_USER);
}

API const char *getUserPkgParserDBPathUID(uid_t uid)
{
	const char *pkgmgr_parser_db = NULL;
	uid_t uid_caller = getuid();
	gid_t gid = ROOT_UID;

	if (uid != GLOBAL_USER && uid != ROOT_UID) {
		tzplatform_set_user(uid);
		pkgmgr_parser_db = tzplatform_mkpath(TZ_USER_DB, ".pkgmgr_parser.db");
		gid = _get_gid(tzplatform_getenv(TZ_SYS_USER_GROUP));
		tzplatform_reset_user();
	} else {
		pkgmgr_parser_db = tzplatform_mkpath(TZ_SYS_DB, ".pkgmgr_parser.db");
	}

	// just allow certain users to create the dbspace directory if needed.
	if (uid_caller == ROOT_UID || uid_caller == uid) {
		const char *db_path = _get_db_path(uid);
		_mkdir_for_user(db_path, uid, gid);
	}

	return pkgmgr_parser_db;
}

API const char *getUserPkgCertDBPath(void)
{
	 return getUserPkgCertDBPathUID(GLOBAL_USER);
}

API const char *getUserPkgCertDBPathUID(uid_t uid)
{
	const char *pkgmgr_cert_db = NULL;
	uid_t uid_caller = getuid();
	gid_t gid = ROOT_UID;

	if (uid != GLOBAL_USER && uid != ROOT_UID) {
		tzplatform_set_user(uid);
		pkgmgr_cert_db = tzplatform_mkpath(TZ_USER_DB, ".pkgmgr_cert.db");
		gid = _get_gid(tzplatform_getenv(TZ_SYS_USER_GROUP));
		tzplatform_reset_user();
	} else {
		pkgmgr_cert_db = tzplatform_mkpath(TZ_SYS_DB, ".pkgmgr_cert.db");
	}

	// just allow certain users to create the dbspace directory if needed.
	if (uid_caller == ROOT_UID || uid_caller == uid) {
		const char *db_path = _get_db_path(uid);
		_mkdir_for_user(db_path, uid, gid);
	}

	return pkgmgr_cert_db;
}

API const char *getUserDesktopPath(uid_t uid)
{
	const char *path = NULL;
	uid_t uid_caller = getuid();
	gid_t gid = ROOT_UID;

	if (uid != GLOBAL_USER && uid != ROOT_UID) {
		tzplatform_set_user(uid);
		path = tzplatform_mkpath(TZ_USER_DESKTOP, "/");
		gid = _get_gid(tzplatform_getenv(TZ_SYS_USER_GROUP));
		tzplatform_reset_user();
	} else {
		path = tzplatform_mkpath(TZ_SYS_RW_DESKTOP_APP, "/");
	}

	// just allow certain users to create the icon directory if needed.
	if (uid_caller == ROOT_UID || uid_caller == uid)
		_mkdir_for_user(path, uid, gid);

	return path;
}

API const char *getUserManifestPath(uid_t uid)
{
	const char *path = NULL;
	uid_t uid_caller = getuid();
	gid_t gid = ROOT_UID;

	if (uid != GLOBAL_USER && uid != ROOT_UID) {
		tzplatform_set_user(uid);
		path = tzplatform_mkpath(TZ_USER_PACKAGES, "/");
		gid = _get_gid(tzplatform_getenv(TZ_SYS_USER_GROUP));
		tzplatform_reset_user();
	} else {
		path = tzplatform_mkpath(TZ_SYS_RW_PACKAGES, "/");
	}

	// just allow certain users to create the icon directory if needed.
	if (uid_caller == ROOT_UID || uid_caller == uid)
		_mkdir_for_user(path, uid, gid);

	return path;
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

static void __get_metadata_filter_condition(gpointer data, char **condition)
{
	pkgmgrinfo_node_x *node = (pkgmgrinfo_node_x*)data;
	char key[MAX_QUERY_LEN] = {'\0'};
	char value[MAX_QUERY_LEN] = {'\0'};
	if (node->key) {
		snprintf(key, MAX_QUERY_LEN, "(package_app_app_metadata.md_key='%s'", node->key);
	}
	if (node->value) {
		snprintf(value, MAX_QUERY_LEN, " AND package_app_app_metadata.md_value='%s')", node->value);
		strcat(key, value);
	} else {
		strcat(key, ")");
	}
	*condition = strdup(key);
	return;
}

static void __get_filter_condition(gpointer data, char **condition)
{
	pkgmgrinfo_node_x *node = (pkgmgrinfo_node_x*)data;
	char buf[MAX_QUERY_LEN + 1] = {'\0'};
	char temp[PKG_STRING_LEN_MAX] = {'\0'};
	switch (node->prop) {
	case E_PMINFO_PKGINFO_PROP_PACKAGE_ID:
		snprintf(buf, MAX_QUERY_LEN, "package_info.package='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_TYPE:
		snprintf(buf, MAX_QUERY_LEN, "package_info.package_type='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_VERSION:
		snprintf(buf, MAX_QUERY_LEN, "package_info.package_version='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_INSTALL_LOCATION:
		snprintf(buf, MAX_QUERY_LEN, "package_info.install_location='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_INSTALLED_STORAGE:
		snprintf(buf, MAX_QUERY_LEN, "package_info.installed_storage='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_NAME:
		snprintf(buf, MAX_QUERY_LEN, "package_info.author_name='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_HREF:
		snprintf(buf, MAX_QUERY_LEN, "package_info.author_href='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_EMAIL:
		snprintf(buf, MAX_QUERY_LEN, "package_info.author_email='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_SIZE:
		snprintf(buf, MAX_QUERY_LEN, "package_info.package_size='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_REMOVABLE:
		snprintf(buf, MAX_QUERY_LEN, "package_info.package_removable IN %s", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_PRELOAD:
		snprintf(buf, MAX_QUERY_LEN, "package_info.package_preload IN %s", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_READONLY:
		snprintf(buf, MAX_QUERY_LEN, "package_info.package_readonly IN %s", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_UPDATE:
		snprintf(buf, MAX_QUERY_LEN, "package_info.package_update IN %s", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_APPSETTING:
		snprintf(buf, MAX_QUERY_LEN, "package_info.package_appsetting IN %s", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_NODISPLAY_SETTING:
		snprintf(buf, MAX_QUERY_LEN, "package_info.package_nodisplay IN %s", node->value);
		break;

	case E_PMINFO_APPINFO_PROP_APP_ID:
		snprintf(buf, MAX_QUERY_LEN, "package_app_info.app_id='%s'", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_COMPONENT:
		snprintf(buf, MAX_QUERY_LEN, "package_app_info.app_component='%s'", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_EXEC:
		snprintf(buf, MAX_QUERY_LEN, "package_app_info.app_exec='%s'", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_ICON:
		snprintf(buf, MAX_QUERY_LEN, "package_app_localized_info.app_icon='%s'", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_TYPE:
		snprintf(buf, MAX_QUERY_LEN, "package_app_info.app_type='%s'", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_OPERATION:
		snprintf(temp, PKG_STRING_LEN_MAX, "(%s)", node->value);
		snprintf(buf, MAX_QUERY_LEN, "package_app_app_svc.operation IN %s", temp);
		break;
	case E_PMINFO_APPINFO_PROP_APP_URI:
		snprintf(temp, PKG_STRING_LEN_MAX, "(%s)", node->value);
		snprintf(buf, MAX_QUERY_LEN, "package_app_app_svc.uri_scheme IN %s", temp);
		break;
	case E_PMINFO_APPINFO_PROP_APP_MIME:
		snprintf(temp, PKG_STRING_LEN_MAX, "(%s)", node->value);
		snprintf(buf, MAX_QUERY_LEN, "package_app_app_svc.mime_type IN %s", temp);
		break;
	case E_PMINFO_APPINFO_PROP_APP_CATEGORY:
		snprintf(temp, PKG_STRING_LEN_MAX, "(%s)", node->value);
		snprintf(buf, MAX_QUERY_LEN, "package_app_app_category.category IN %s", temp);
		break;
	case E_PMINFO_APPINFO_PROP_APP_NODISPLAY:
		snprintf(buf, MAX_QUERY_LEN, "package_app_info.app_nodisplay IN %s", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_MULTIPLE:
		snprintf(buf, MAX_QUERY_LEN, "package_app_info.app_multiple IN %s", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_ONBOOT:
		snprintf(buf, MAX_QUERY_LEN, "package_app_info.app_onboot IN %s", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_AUTORESTART:
		snprintf(buf, MAX_QUERY_LEN, "package_app_info.app_autorestart IN %s", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_TASKMANAGE:
		snprintf(buf, MAX_QUERY_LEN, "package_app_info.app_taskmanage IN %s", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_HWACCELERATION:
		snprintf(buf, MAX_QUERY_LEN, "package_app_info.app_hwacceleration='%s'", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_SCREENREADER:
		snprintf(buf, MAX_QUERY_LEN, "package_app_info.app_screenreader='%s'", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_LAUNCHCONDITION:
		snprintf(buf, MAX_QUERY_LEN, "package_app_info.app_launchcondition IN %s", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_PACKAGE:
		snprintf(buf, MAX_QUERY_LEN, "package_app_info.package='%s'", node->value);
		break;
	default:
		_LOGE("Invalid Property Type\n");
		*condition = NULL;
		return;
	}
	*condition = strdup(buf);
	return;
}

static char* __convert_system_locale_to_manifest_locale(char *syslocale)
{
	if (syslocale == NULL)
		return strdup(DEFAULT_LOCALE);
	char *locale = NULL;
	locale = (char *)calloc(1, 6);
	retvm_if(!locale, NULL, "Malloc Failed\n");

	strncpy(locale, syslocale, 2);
	strncat(locale, "-", 1);
	locale[3] = syslocale[3] + 32;
	locale[4] = syslocale[4] + 32;
	return locale;
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

static void __cleanup_appinfo(pkgmgr_appinfo_x *data)
{
	ret_if(data == NULL);
	if (data->package){
		free((void *)data->package);
		data->package = NULL;
	}
	if (data->locale){
		free((void *)data->locale);
		data->locale = NULL;
	}

	pkgmgrinfo_basic_free_application(data->app_info);
	free((void *)data);
	data = NULL;
	return;
}

static int __close_manifest_db(void)
{
	if(manifest_db.ref) {
		if(--manifest_db.ref == 0)
			sqlite3_close(GET_DB(manifest_db));
		return 0;
	}
	return -1;
}

static const char *parserdb_tables[] = {
	"package_app_app_category",
	"package_app_info",
	"package_app_app_control",
	"package_app_localized_info",
	"package_app_app_metadata",
	"package_app_share_allowed",
	"package_app_app_permission",
	"package_app_share_request",
	"package_app_app_svc",
	"package_info",
	"package_app_data_control",
	"package_localized_info",
	"package_app_icon_section_info",
	"package_privilege_info",
	"package_app_image_info",
	NULL
};

static int __open_manifest_db(uid_t uid)
{
	int ret = -1;
	if(manifest_db.ref) {
		manifest_db.ref ++;
		return 0;
	}
	const char* user_pkg_parser = getUserPkgParserDBPathUID(uid);
	if (access(user_pkg_parser, F_OK) != 0) {
		_LOGE("Manifest DB does not exists !! try to create\n");

		if (pkgmgr_parser_check_and_create_db(uid)) {
			_LOGE("create db failed");
			return -1;
		}

		if (pkgmgr_parser_initialize_db(uid)) {
			_LOGE("initialize db failed");
			return -1;
		}
	}

	ret = db_util_open_with_options(user_pkg_parser, &GET_DB(manifest_db),
			SQLITE_OPEN_READONLY, NULL);
	retvm_if(ret != SQLITE_OK, -1, "connect db [%s] failed!\n", user_pkg_parser);
	manifest_db.ref ++;
	ret = __attach_and_create_view(GET_DB(manifest_db), MANIFEST_DB, parserdb_tables, uid);
	retvm_if(ret != SQLITE_OK, -1, "attach db [%s] failed!\n", user_pkg_parser);

	return 0;
}

static int __close_cert_db(void)
{
	if(cert_db.ref) {
		if(--cert_db.ref == 0)
			sqlite3_close(GET_DB(cert_db));
			return 0;
	}
	_LOGE("Certificate DB is already closed !!\n");
	return -1;
}

static const char *certdb_tables[] = {
	"package_cert_index_info",
	"package_cert_info",
	NULL
};

static int __open_cert_db(uid_t uid, char* mode)
{
	int ret = -1;
	if(cert_db.ref) {
		cert_db.ref ++;
		return 0;
	}

	const char* user_cert_parser = getUserPkgCertDBPathUID(uid);
	if (access(user_cert_parser, F_OK) == 0) {
		ret = db_util_open_with_options(user_cert_parser, &GET_DB(cert_db),
				 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
		retvm_if(ret != SQLITE_OK, -1, "connect db [%s] failed!\n", user_cert_parser);
		cert_db.ref ++;
		if ((strcmp(mode, "w") != 0)) {
			ret = __attach_and_create_view(GET_DB(cert_db), CERT_DB, certdb_tables, uid);
			retvm_if(ret != SQLITE_OK, -1, "attach db [%s] failed!\n", user_cert_parser);
		}
		return 0;
	}
	_LOGE("Cert DB does not exists !!\n");
	return -1;
}

static int __close_datacontrol_db(void)
{
	if(datacontrol_db.ref) {
		if(--datacontrol_db.ref == 0)
			sqlite3_close(GET_DB(datacontrol_db));
			return 0;
	}
	_LOGE("Certificate DB is already closed !!\n");
	return -1;
}

static int __open_datacontrol_db()
{
	int ret = -1;
	if(datacontrol_db.ref) {
		datacontrol_db.ref ++;
		return 0;
	}
	if (access(DATACONTROL_DB, F_OK) == 0) {
		ret = db_util_open_with_options(DATACONTROL_DB, &GET_DB(datacontrol_db),
				 SQLITE_OPEN_READONLY, NULL);
		retvm_if(ret != SQLITE_OK, -1, "connect db [%s] failed!\n", DATACONTROL_DB);
		datacontrol_db.ref ++;
		return 0;
	}
	_LOGE("Datacontrol DB does not exists !!\n");
	return -1;
}

static int __app_list_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)data;
	int i = 0;
	int j = 0;
	uiapplication_x *uiapp = NULL;
	serviceapplication_x *svcapp = NULL;
	for(i = 0; i < ncols; i++)
	{
		if ((strcmp(colname[i], "app_component") == 0) ||
			(strcmp(colname[i], "package_app_info.app_component") == 0)) {
			if (coltxt[i]) {
				if (strcmp(coltxt[i], "uiapp") == 0) {
					uiapp = calloc(1, sizeof(uiapplication_x));
					if (uiapp == NULL) {
						_LOGE("Out of Memory!!!\n");
						return -1;
					}
					LISTADD(info->pkg_info->uiapplication, uiapp);
					for(j = 0; j < ncols; j++)
					{
						if ((strcmp(colname[j], "app_id") == 0) ||
							(strcmp(colname[j], "package_app_info.app_id") == 0)) {
							if (coltxt[j])
								info->pkg_info->uiapplication->appid = strdup(coltxt[j]);
						} else if (strcmp(colname[j], "package") == 0) {
							if (coltxt[j])
								info->pkg_info->uiapplication->package = strdup(coltxt[j]);
						} else
							continue;
					}
				} else {
					svcapp = calloc(1, sizeof(serviceapplication_x));
					if (svcapp == NULL) {
						_LOGE("Out of Memory!!!\n");
						return -1;
					}
					LISTADD(info->pkg_info->serviceapplication, svcapp);
					for(j = 0; j < ncols; j++)
					{
						if ((strcmp(colname[j], "app_id") == 0) ||
							(strcmp(colname[j], "package_app_info.app_id") == 0)) {
							if (coltxt[j])
								info->pkg_info->serviceapplication->appid = strdup(coltxt[j]);
						} else if (strcmp(colname[j], "package") == 0) {
							if (coltxt[j])
								info->pkg_info->serviceapplication->package = strdup(coltxt[j]);
						} else
							continue;
					}
				}
			}
		} else
			continue;
	}

	return 0;
}


static int __uiapp_list_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)data;
	int i = 0;
	uiapplication_x *uiapp = NULL;
	icon_x *icon = NULL;
	label_x *label = NULL;

	uiapp = calloc(1, sizeof(uiapplication_x));
	LISTADD(info->pkg_info->uiapplication, uiapp);
	icon = calloc(1, sizeof(icon_x));
	LISTADD(info->pkg_info->uiapplication->icon, icon);
	label = calloc(1, sizeof(label_x));
	LISTADD(info->pkg_info->uiapplication->label, label);

	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "app_id") == 0) {
			if (coltxt[i])
				info->pkg_info->uiapplication->appid = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->appid = NULL;
		} else if (strcmp(colname[i], "app_exec") == 0) {
			if (coltxt[i])
				info->pkg_info->uiapplication->exec = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->exec = NULL;
		} else if (strcmp(colname[i], "app_type") == 0 ){
			if (coltxt[i])
				info->pkg_info->uiapplication->type = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->type = NULL;
		} else if (strcmp(colname[i], "app_nodisplay") == 0 ){
			if (coltxt[i])
				info->pkg_info->uiapplication->nodisplay = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->nodisplay = NULL;
		} else if (strcmp(colname[i], "app_multiple") == 0 ){
			if (coltxt[i])
				info->pkg_info->uiapplication->multiple = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->multiple = NULL;
		} else if (strcmp(colname[i], "app_taskmanage") == 0 ){
			if (coltxt[i])
				info->pkg_info->uiapplication->taskmanage = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->taskmanage = NULL;
		} else if (strcmp(colname[i], "app_hwacceleration") == 0 ){
			if (coltxt[i])
				info->pkg_info->uiapplication->hwacceleration = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->hwacceleration = NULL;
		} else if (strcmp(colname[i], "app_screenreader") == 0 ){
			if (coltxt[i])
				info->pkg_info->uiapplication->screenreader = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->screenreader = NULL;
		} else if (strcmp(colname[i], "app_indicatordisplay") == 0 ){
			if (coltxt[i])
				info->pkg_info->uiapplication->indicatordisplay = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->indicatordisplay = NULL;
		} else if (strcmp(colname[i], "app_portraitimg") == 0 ){
			if (coltxt[i])
				info->pkg_info->uiapplication->portraitimg = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->portraitimg = NULL;
		} else if (strcmp(colname[i], "app_landscapeimg") == 0 ){
			if (coltxt[i])
				info->pkg_info->uiapplication->landscapeimg = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->landscapeimg = NULL;
		} else if (strcmp(colname[i], "app_guestmodevisibility") == 0 ){
			if (coltxt[i])
				info->pkg_info->uiapplication->guestmode_visibility = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->guestmode_visibility = NULL;
		} else if (strcmp(colname[i], "package") == 0 ){
			if (coltxt[i])
				info->pkg_info->uiapplication->package = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->package = NULL;
		} else if (strcmp(colname[i], "app_icon") == 0) {
			if (coltxt[i])
				info->pkg_info->uiapplication->icon->text = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->icon->text = NULL;
		} else if (strcmp(colname[i], "app_enabled") == 0 ) {
			if (coltxt[i])
				info->pkg_info->uiapplication->enabled= strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->enabled = NULL;
		} else if (strcmp(colname[i], "app_label") == 0 ) {
			if (coltxt[i])
				info->pkg_info->uiapplication->label->text = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->label->text = NULL;
		} else if (strcmp(colname[i], "app_recentimage") == 0 ) {
			if (coltxt[i])
				info->pkg_info->uiapplication->recentimage = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->recentimage = NULL;
		} else if (strcmp(colname[i], "app_mainapp") == 0 ) {
			if (coltxt[i])
				info->pkg_info->uiapplication->mainapp = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->mainapp = NULL;
		} else if (strcmp(colname[i], "app_locale") == 0 ) {
			if (coltxt[i]) {
				info->pkg_info->uiapplication->icon->lang = strdup(coltxt[i]);
				info->pkg_info->uiapplication->label->lang = strdup(coltxt[i]);
			}
			else {
				info->pkg_info->uiapplication->icon->lang = NULL;
				info->pkg_info->uiapplication->label->lang = NULL;
			}
		} else if (strcmp(colname[i], "app_permissiontype") == 0 ) {
			if (coltxt[i])
				info->pkg_info->uiapplication->permission_type = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->permission_type = NULL;
		} else if (strcmp(colname[i], "component_type") == 0 ) {
			if (coltxt[i])
				info->pkg_info->uiapplication->component_type = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->component_type = NULL;
		} else if (strcmp(colname[i], "app_preload") == 0 ) {
			if (coltxt[i])
				info->pkg_info->uiapplication->preload = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->preload = NULL;
		} else if (strcmp(colname[i], "app_submode") == 0 ) {
			if (coltxt[i])
				info->pkg_info->uiapplication->submode = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->submode = NULL;
		} else if (strcmp(colname[i], "app_submode_mainid") == 0 ) {
			if (coltxt[i])
				info->pkg_info->uiapplication->submode_mainid = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->submode_mainid = NULL;
		} else if (strcmp(colname[i], "app_launch_mode") == 0 ) {
			if (coltxt[i])
				info->pkg_info->uiapplication->launch_mode = strdup(coltxt[i]);
			else
				info->pkg_info->uiapplication->launch_mode = NULL;
		} else
			continue;
	}
	return 0;
}

static int __svcapp_list_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)data;
	int i = 0;
	serviceapplication_x *svcapp = NULL;
	icon_x *icon = NULL;
	label_x *label = NULL;

	svcapp = calloc(1, sizeof(serviceapplication_x));
	LISTADD(info->pkg_info->serviceapplication, svcapp);
	icon = calloc(1, sizeof(icon_x));
	LISTADD(info->pkg_info->serviceapplication->icon, icon);
	label = calloc(1, sizeof(label_x));
	LISTADD(info->pkg_info->serviceapplication->label, label);
	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "app_id") == 0) {
			if (coltxt[i])
				info->pkg_info->serviceapplication->appid = strdup(coltxt[i]);
			else
				info->pkg_info->serviceapplication->appid = NULL;
		} else if (strcmp(colname[i], "app_exec") == 0) {
			if (coltxt[i])
				info->pkg_info->serviceapplication->exec = strdup(coltxt[i]);
			else
				info->pkg_info->serviceapplication->exec = NULL;
		} else if (strcmp(colname[i], "app_type") == 0 ){
			if (coltxt[i])
				info->pkg_info->serviceapplication->type = strdup(coltxt[i]);
			else
				info->pkg_info->serviceapplication->type = NULL;
		} else if (strcmp(colname[i], "app_onboot") == 0 ){
			if (coltxt[i])
				info->pkg_info->serviceapplication->onboot = strdup(coltxt[i]);
			else
				info->pkg_info->serviceapplication->onboot = NULL;
		} else if (strcmp(colname[i], "app_autorestart") == 0 ){
			if (coltxt[i])
				info->pkg_info->serviceapplication->autorestart = strdup(coltxt[i]);
			else
				info->pkg_info->serviceapplication->autorestart = NULL;
		} else if (strcmp(colname[i], "package") == 0 ){
			if (coltxt[i])
				info->pkg_info->serviceapplication->package = strdup(coltxt[i]);
			else
				info->pkg_info->serviceapplication->package = NULL;
		} else if (strcmp(colname[i], "app_icon") == 0) {
			if (coltxt[i])
				info->pkg_info->serviceapplication->icon->text = strdup(coltxt[i]);
			else
				info->pkg_info->serviceapplication->icon->text = NULL;
		} else if (strcmp(colname[i], "app_label") == 0 ) {
			if (coltxt[i])
				info->pkg_info->serviceapplication->label->text = strdup(coltxt[i]);
			else
				info->pkg_info->serviceapplication->label->text = NULL;
		} else if (strcmp(colname[i], "app_locale") == 0 ) {
			if (coltxt[i]) {
				info->pkg_info->serviceapplication->icon->lang = strdup(coltxt[i]);
				info->pkg_info->serviceapplication->label->lang = strdup(coltxt[i]);
			}
			else {
				info->pkg_info->serviceapplication->icon->lang = NULL;
				info->pkg_info->serviceapplication->label->lang = NULL;
			}
		} else if (strcmp(colname[i], "app_permissiontype") == 0 ) {
			if (coltxt[i])
				info->pkg_info->serviceapplication->permission_type = strdup(coltxt[i]);
			else
				info->pkg_info->serviceapplication->permission_type = NULL;
		} else
			continue;
	}
	return 0;
}

static int __validate_cb(void *data, int ncols, char **coltxt, char **colname)
{
	int *p = (int*)data;
	*p = atoi(coltxt[0]);
	return 0;
}

static int __maxid_cb(void *data, int ncols, char **coltxt, char **colname)
{
	int *p = (int*)data;
	if (coltxt[0])
		*p = atoi(coltxt[0]);
	return 0;
}

static pkgmgrinfo_app_component __appcomponent_convert(const char *comp)
{
	if ( strcasecmp(comp, "uiapp") == 0)
		return PMINFO_UI_APP;
	else if ( strcasecmp(comp, "svcapp") == 0)
		return PMINFO_SVC_APP;
	else
		return -1;
}

static int __certindexinfo_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_certindexinfo_x *info = (pkgmgr_certindexinfo_x *)data;
	int i = 0;
	for(i = 0; i < ncols; i++) {
		if (strcmp(colname[i], "cert_id") == 0) {
			if (coltxt[i])
				info->cert_id = atoi(coltxt[i]);
			else
				info->cert_id = 0;
		} else if (strcmp(colname[i], "cert_ref_count") == 0) {
			if (coltxt[i])
				info->cert_ref_count = atoi(coltxt[i]);
			else
				info->cert_ref_count = 0;
		} else
			continue;
	}
	return 0;
}
static int __certinfo_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_certinfo_x *info = (pkgmgr_certinfo_x *)data;
	int i = 0;
	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "package") == 0) {
			if (coltxt[i])
				info->pkgid = strdup(coltxt[i]);
			else
				info->pkgid = NULL;
		} else if (strcmp(colname[i], "author_signer_cert") == 0) {
			if (coltxt[i])
				(info->cert_id)[PMINFO_AUTHOR_SIGNER_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_AUTHOR_SIGNER_CERT] = 0;
		} else if (strcmp(colname[i], "author_im_cert") == 0) {
			if (coltxt[i])
				(info->cert_id)[PMINFO_AUTHOR_INTERMEDIATE_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_AUTHOR_INTERMEDIATE_CERT] = 0;
		} else if (strcmp(colname[i], "author_root_cert") == 0) {
			if (coltxt[i])
				(info->cert_id)[PMINFO_AUTHOR_ROOT_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_AUTHOR_ROOT_CERT] = 0;
		} else if (strcmp(colname[i], "dist_signer_cert") == 0 ){
			if (coltxt[i])
				(info->cert_id)[PMINFO_DISTRIBUTOR_SIGNER_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_DISTRIBUTOR_SIGNER_CERT] = 0;
		} else if (strcmp(colname[i], "dist_im_cert") == 0 ){
			if (coltxt[i])
				(info->cert_id)[PMINFO_DISTRIBUTOR_INTERMEDIATE_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_DISTRIBUTOR_INTERMEDIATE_CERT] = 0;
		} else if (strcmp(colname[i], "dist_root_cert") == 0 ){
			if (coltxt[i])
				(info->cert_id)[PMINFO_DISTRIBUTOR_ROOT_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_DISTRIBUTOR_ROOT_CERT] = 0;
		} else if (strcmp(colname[i], "dist2_signer_cert") == 0 ){
			if (coltxt[i])
				(info->cert_id)[PMINFO_DISTRIBUTOR2_SIGNER_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_DISTRIBUTOR2_SIGNER_CERT] = 0;
		} else if (strcmp(colname[i], "dist2_im_cert") == 0 ){
			if (coltxt[i])
				(info->cert_id)[PMINFO_DISTRIBUTOR2_INTERMEDIATE_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_DISTRIBUTOR2_INTERMEDIATE_CERT] = 0;
		} else if (strcmp(colname[i], "dist2_root_cert") == 0 ){
			if (coltxt[i])
				(info->cert_id)[PMINFO_DISTRIBUTOR2_ROOT_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_DISTRIBUTOR2_ROOT_CERT] = 0;
		} else if (strcmp(colname[i], "cert_info") == 0 ){
			if (coltxt[i])
				info->cert_value = strdup(coltxt[i]);
			else
				info->cert_value = NULL;
		} else if (strcmp(colname[i], "for_all_users") == 0 ){
			if (coltxt[i])
				info->for_all_users = atoi(coltxt[i]);
			else
				info->for_all_users = 0;
		} else
			continue;
	}
	return 0;
}

static void __parse_appcontrol(appcontrol_x **appcontrol, char *appcontrol_str)
{
	char *dup;
	char *token;
	char *ptr = NULL;
	appcontrol_x *ac;

	if (appcontrol_str == NULL)
		return;

	dup = strdup(appcontrol_str);
	do {
		ac = calloc(1, sizeof(appcontrol_x));
		token = strtok_r(dup, "|", &ptr);
		if (strcmp(token, "NULL"))
			ac->operation = strdup(token);
		token = strtok_r(NULL, "|", &ptr);
		if (strcmp(token, "NULL"))
			ac->uri = strdup(token);
		token = strtok_r(NULL, "|", &ptr);
		if (strcmp(token, "NULL"))
			ac->mime = strdup(token);
		LISTADD(*appcontrol, ac);
	} while ((token = strtok_r(NULL, ";", &ptr)));

	free(dup);
}

static int __datacontrol_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_datacontrol_x *info = (pkgmgr_datacontrol_x *)data;
	int i = 0;
	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "PACKAGE_NAME") == 0) {
			if (coltxt[i])
				info->appid = strdup(coltxt[i]);
			else
				info->appid = NULL;
		} else if (strcmp(colname[i], "ACCESS") == 0 ){
			if (coltxt[i])
				info->access = strdup(coltxt[i]);
			else
				info->access = NULL;
		} else
			continue;
	}
	return 0;
}

static int __cert_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_cert_x *info = (pkgmgr_cert_x *)data;
	int i = 0;

	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "author_signer_cert") == 0) {
			if (coltxt[i])
				info->cert_id = atoi(coltxt[i]);
			else
				info->cert_id = 0;
		} else if (strcmp(colname[i], "package") == 0) {
			if (coltxt[i])
				info->pkgid= strdup(coltxt[i]);
			else
				info->pkgid = NULL;
		} else
			continue;
	}
	return 0;
}

static int __exec_certinfo_query(char *query, void *data)
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(cert_db), query, __certinfo_cb, data, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __exec_certindexinfo_query(char *query, void *data)
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(cert_db), query, __certindexinfo_cb, data, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __exec_db_query(sqlite3 *db, char *query, sqlite_query_callback callback, void *data)
{
	char *error_message = NULL;
	int ret = sqlite3_exec(db, query, callback, data, &error_message);
	if (SQLITE_OK != ret) {
		_LOGE("Don't execute query = %s error message = %s   ret = %d\n", query,
		       error_message, ret);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
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

static int __delete_certinfo(const char *pkgid, uid_t uid)
{
	int ret = -1;
	int i = 0;
	int j = 0;
	int c = 0;
	int unique_id[MAX_CERT_TYPE] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
	char *error_message = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	pkgmgr_certinfo_x *certinfo = NULL;
	pkgmgr_certindexinfo_x *indexinfo = NULL;
	certinfo = calloc(1, sizeof(pkgmgr_certinfo_x));
	retvm_if(certinfo == NULL, PMINFO_R_ERROR, "Malloc Failed\n");
	indexinfo = calloc(1, sizeof(pkgmgr_certindexinfo_x));
	if (indexinfo == NULL) {
		_LOGE("Out of Memory!!!");
		ret = PMINFO_R_ERROR;
		goto err;
	}

	__open_cert_db(uid, "w");
	/*populate certinfo from DB*/
	snprintf(query, MAX_QUERY_LEN, "select * from package_cert_info where package='%s' ", pkgid);
	ret = __exec_certinfo_query(query, (void *)certinfo);
	if (ret == -1) {
		_LOGE("Package Cert Info DB Information retrieval failed\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	/*Update cert index table*/
	for (i = 0; i < MAX_CERT_TYPE; i++) {
		if ((certinfo->cert_id)[i]) {
			for (j = 0; j < MAX_CERT_TYPE; j++) {
				if ((certinfo->cert_id)[i] == unique_id[j]) {
					/*Ref count has already been updated. Just continue*/
					break;
				}
			}
			if (j == MAX_CERT_TYPE)
				unique_id[c++] = (certinfo->cert_id)[i];
			else
				continue;
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_cert_index_info where cert_id=%d ", (certinfo->cert_id)[i]);
			ret = __exec_certindexinfo_query(query, (void *)indexinfo);
			if (ret == -1) {
				_LOGE("Cert Info DB Information retrieval failed\n");
				ret = PMINFO_R_ERROR;
				goto err;
			}
			memset(query, '\0', MAX_QUERY_LEN);
			if (indexinfo->cert_ref_count > 1) {
				/*decrease ref count*/
				snprintf(query, MAX_QUERY_LEN, "update package_cert_index_info set cert_ref_count=%d where cert_id=%d ",
				indexinfo->cert_ref_count - 1, (certinfo->cert_id)[i]);
			} else {
				/*delete this certificate as ref count is 1 and it will become 0*/
				snprintf(query, MAX_QUERY_LEN, "delete from  package_cert_index_info where cert_id=%d ", (certinfo->cert_id)[i]);
			}
		        if (SQLITE_OK !=
		            sqlite3_exec(GET_DB(cert_db), query, NULL, NULL, &error_message)) {
		                _LOGE("Don't execute query = %s error message = %s\n", query,
		                       error_message);
				sqlite3_free(error_message);
				ret = PMINFO_R_ERROR;
				goto err;
		        }
		}
	}
	/*Now delete the entry from db*/
	snprintf(query, MAX_QUERY_LEN, "delete from package_cert_info where package='%s'", pkgid);
        if (SQLITE_OK !=
            sqlite3_exec(GET_DB(cert_db), query, NULL, NULL, &error_message)) {
                _LOGE("Don't execute query = %s error message = %s\n", query,
                       error_message);
		sqlite3_free(error_message);
		ret = PMINFO_R_ERROR;
		goto err;
        }
	ret = PMINFO_R_OK;
err:
	if (indexinfo) {
		free(indexinfo);
		indexinfo = NULL;
	}
	if (certinfo->pkgid) {
		free(certinfo->pkgid);
		certinfo->pkgid = NULL;
	}
	for (i = 0; i < MAX_CERT_TYPE; i++) {
		if ((certinfo->cert_info)[i]) {
			free((certinfo->cert_info)[i]);
			(certinfo->cert_info)[i] = NULL;
		}
	}
	__close_cert_db();
	free(certinfo);
	certinfo = NULL;
	return ret;
}

static int __get_pkg_location(const char *pkgid)
{
	retvm_if(pkgid == NULL, PMINFO_R_OK, "pkginfo handle is NULL");

	FILE *fp = NULL;
	char pkg_mmc_path[FILENAME_MAX] = { 0, };
	snprintf(pkg_mmc_path, FILENAME_MAX, "%s%s", PKG_SD_PATH, pkgid);

	/*check whether application is in external memory or not */
	fp = fopen(pkg_mmc_path, "r");
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;
		return PMINFO_EXTERNAL_STORAGE;
	}

	return PMINFO_INTERNAL_STORAGE;
}

static int _pkginfo_get_filtered_foreach_pkginfo(pkgmgrinfo_filter_x *filter,
		pkgmgrinfo_pkg_list_cb pkg_list_cb, void *user_data, uid_t uid)
{
	pkgmgr_pkginfo_x *pkginfo = NULL;
	pkgmgr_pkginfo_x *next;
	pkgmgr_pkginfo_x *tmp;
	char *locale;
	int stop = 0;

	if (__open_manifest_db(uid) < 0)
		return PMINFO_R_ERROR;

	locale = _get_system_locale();
	if (locale == NULL) {
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}

	if (_pkginfo_get_pkg(locale, filter, &pkginfo)) {
		free(locale);
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}

	tmp = pkginfo;
	while (tmp) {
		next = tmp->next;
		tmp->uid = uid;
		tmp->locale = locale;
		if (stop == 0) {
			if (pkg_list_cb(tmp, user_data) < 0)
				stop = 1;
		}
		pkgmgrinfo_basic_free_package(tmp->pkg_info);
		free(tmp);
		tmp = next;
	}

	free(locale);
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

static void _save_column_str(sqlite3_stmt *stmt, int idx, const char **str)
{
	const char *val;

	val = (const char *)sqlite3_column_text(stmt, idx);
	if (val)
		*str = strdup(val);
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

static int _pkginfo_get_pkg(const char *locale, pkgmgrinfo_filter_x *filter,
		pkgmgr_pkginfo_x **pkginfo)
{
	static const char query_raw[] =
		"SELECT for_all_users, package, package_version, "
		"install_location, package_removable, package_preload, "
		"package_readonly, package_update, package_appsetting, "
		"package_system, package_type, package_size, installed_time, "
		"installed_storage, storeclient_id, mainapp_id, package_url, "
		"root_path, csc_path, package_nodisplay, package_api_version "
		"FROM package_info";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	int idx;
	pkgmgr_pkginfo_x *info;
	package_x *pkg;

	query = _get_filtered_query(query_raw, filter);
	if (query == NULL) {
		LOGE("out of memory");
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_prepare_v2(GET_DB(manifest_db), query, strlen(query),
			&stmt, NULL);
	free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(GET_DB(manifest_db)));
		return PMINFO_R_ERROR;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
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
		LISTADD(*pkginfo, info);
	}

	if (*pkginfo) {
		LISTHEAD(*pkginfo, info);
		*pkginfo = info;
	}

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

static char *_get_system_locale(void)
{
	char *lang;
	char *locale;

	lang = vconf_get_str(VCONFKEY_LANGSET);
	if (lang == NULL) {
		locale = strdup(DEFAULT_LOCALE);
		if (locale == NULL) {
			LOGE("out of memory");
			return NULL;
		}
		return locale;
	}

	locale = malloc(sizeof(char *) * 6);
	if (locale == NULL) {
		LOGE("out of memory");
		free(lang);
		return NULL;
	}

	strncpy(locale, lang, 2);
	locale[2] = '-';
	locale[3] = tolower(lang[3]);
	locale[4] = tolower(lang[4]);
	locale[5] = '\0';

	free(lang);

	return locale;
}

API int pkgmgrinfo_pkginfo_get_usr_pkginfo(const char *pkgid, uid_t uid,
		pkgmgrinfo_pkginfo_h *handle)
{
	pkgmgr_pkginfo_x *pkginfo = NULL;
	pkgmgrinfo_pkginfo_filter_h filter;
	char *locale;

	if (pkgid == NULL || handle == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	if (__open_manifest_db(uid) < 0)
		return PMINFO_R_ERROR;


	locale = _get_system_locale();
	if (locale == NULL) {
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}

	if (pkgmgrinfo_pkginfo_filter_create(&filter)) {
		free(locale);
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}

	if (pkgmgrinfo_pkginfo_filter_add_string(filter,
			PMINFO_PKGINFO_PROP_PACKAGE_ID, pkgid)) {
		pkgmgrinfo_pkginfo_filter_destroy(filter);
		free(locale);
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}

	if (_pkginfo_get_pkg(locale, filter, &pkginfo)) {
		LOGE("failed to get pkginfo of %s for user %d", pkgid, uid);
		pkgmgrinfo_pkginfo_filter_destroy(filter);
		free(locale);
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}

	pkginfo->uid = uid;
	pkginfo->locale = locale;
	*handle = pkginfo;

	pkgmgrinfo_pkginfo_filter_destroy(filter);
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
	char *locale;
	author_x *ptr;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(author_name == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	locale = info->locale;
	retvm_if(locale == NULL, PMINFO_R_ERROR, "manifest locale is NULL");

	for (ptr = info->pkg_info->author; ptr != NULL; ptr = ptr->next) {
		if (ptr->lang == NULL)
			continue;

		if (strcmp(ptr->lang, locale) == 0) {
			*author_name = (char *)ptr->text;
			if (strcasecmp(*author_name, PKGMGR_PARSER_EMPTY_STR) == 0) {
				locale = DEFAULT_LOCALE;
				continue;
			} else {
				return PMINFO_R_OK;
			}
		} else if (strcmp(ptr->lang, DEFAULT_LOCALE) == 0) {
			*author_name = (char *)ptr->text;
			return PMINFO_R_OK;
		}
	}

	return PMINFO_R_ERROR;
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

API int pkgmgrinfo_pkginfo_compare_usr_pkg_cert_info(const char *lhs_package_id, const char *rhs_package_id, uid_t uid, pkgmgrinfo_cert_compare_result_type_e *compare_result)
{
	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message;
	sqlite3_stmt *stmt = NULL;
	char *lhs_certinfo = NULL;
	char *rhs_certinfo = NULL;
	int lcert;
	int rcert;
	int exist;
	int i;
	int is_global = 0;
	*compare_result = PMINFO_CERT_COMPARE_ERROR;

	retvm_if(lhs_package_id == NULL, PMINFO_R_EINVAL, "lhs package ID is NULL");
	retvm_if(rhs_package_id == NULL, PMINFO_R_EINVAL, "rhs package ID is NULL");
	retvm_if(compare_result == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	ret = __open_cert_db(uid, "r");
	if (ret != 0) {
		ret = PMINFO_R_ERROR;
		goto err;
	}
	_check_create_Cert_db(GET_DB(cert_db));
	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", lhs_package_id);
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(cert_db), query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}
	lcert = exist;

	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", rhs_package_id);
	if (SQLITE_OK !=
		sqlite3_exec(GET_DB(cert_db), query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
			   error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}
	rcert = exist;

	if (uid == GLOBAL_USER || uid == ROOT_UID) {
		snprintf(query, MAX_QUERY_LEN, "select cert_info from package_cert_index_info where cert_id=(select author_signer_cert from package_cert_info where package=?)");
		is_global = 1;
	} else
		snprintf(query, MAX_QUERY_LEN, "select cert_info from package_cert_index_info where cert_id=(select author_signer_cert from package_cert_info where package=?) and for_all_users=(select for_all_users from package_cert_info where package=?)");
	if (SQLITE_OK != sqlite3_prepare_v2(GET_DB(cert_db), query, strlen(query), &stmt, NULL)) {
		_LOGE("sqlite3_prepare_v2 error: %s", sqlite3_errmsg(GET_DB(cert_db)));
		ret = PMINFO_R_ERROR;
		goto err;
	}

	for (i = 1; i <= 2 - is_global; i++) {
		if (SQLITE_OK != sqlite3_bind_text(stmt, i, lhs_package_id, -1, SQLITE_STATIC)) {
			_LOGE("sqlite3_bind_text error: %s", sqlite3_errmsg(GET_DB(cert_db)));
			ret = PMINFO_R_ERROR;
			goto err;
		}
	}
	if (SQLITE_ROW != sqlite3_step(stmt) || sqlite3_column_text(stmt, 0) == NULL) {
		_LOGE("sqlite3_step error: %s", sqlite3_errmsg(GET_DB(cert_db)));
		ret = PMINFO_R_ERROR;
		goto err;
	}

	lhs_certinfo = strdup((const char *)sqlite3_column_text(stmt, 0));
	sqlite3_reset(stmt);
	sqlite3_clear_bindings(stmt);

	for (i = 1; i <= 2 - is_global; i++) {
		if (SQLITE_OK != sqlite3_bind_text(stmt, i, rhs_package_id, -1, SQLITE_STATIC)) {
			_LOGE("sqlite3_bind_text error: %s", sqlite3_errmsg(GET_DB(cert_db)));
			ret = PMINFO_R_ERROR;
			goto err;
		}
	}
	if (SQLITE_ROW != sqlite3_step(stmt) || sqlite3_column_text(stmt, 0) == NULL) {
		_LOGE("sqlite3_step error: %s", sqlite3_errmsg(GET_DB(cert_db)));
		ret = PMINFO_R_ERROR;
		goto err;
	}

	rhs_certinfo = strdup((const char *)sqlite3_column_text(stmt, 0));

	if ((lcert == 0) || (rcert == 0)) {
		if ((lcert == 0) && (rcert == 0))
			*compare_result = PMINFO_CERT_COMPARE_BOTH_NO_CERT;
		else if (lcert == 0)
			*compare_result = PMINFO_CERT_COMPARE_LHS_NO_CERT;
		else if (rcert == 0)
			*compare_result = PMINFO_CERT_COMPARE_RHS_NO_CERT;
	} else {
		if (!strcmp(lhs_certinfo, rhs_certinfo))
			*compare_result = PMINFO_CERT_COMPARE_MATCH;
		else
			*compare_result = PMINFO_CERT_COMPARE_MISMATCH;
	}

err:
	if (stmt)
		sqlite3_finalize(stmt);
	if (lhs_certinfo)
		free(lhs_certinfo);
	if (rhs_certinfo)
		free(rhs_certinfo);
	sqlite3_free(error_message);
	__close_cert_db();

	return ret;
}

API int pkgmgrinfo_pkginfo_compare_pkg_cert_info(const char *lhs_package_id, const char *rhs_package_id, pkgmgrinfo_cert_compare_result_type_e *compare_result)
{
	return pkgmgrinfo_pkginfo_compare_usr_pkg_cert_info(lhs_package_id, rhs_package_id, GLOBAL_USER, compare_result);
}

API int pkgmgrinfo_pkginfo_compare_app_cert_info(const char *lhs_app_id, const char *rhs_app_id, pkgmgrinfo_cert_compare_result_type_e *compare_result)
{
	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message;
	pkgmgr_cert_x *info;
 	int exist;
	char *lpkgid = NULL;
	char *rpkgid = NULL;
	const char* user_pkg_parser = getUserPkgParserDBPath();

	retvm_if(lhs_app_id == NULL, PMINFO_R_EINVAL, "lhs app ID is NULL");
	retvm_if(rhs_app_id == NULL, PMINFO_R_EINVAL, "rhs app ID is NULL");
	retvm_if(compare_result == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	info = (pkgmgr_cert_x *)calloc(1, sizeof(pkgmgr_cert_x));
	retvm_if(info == NULL, PMINFO_R_ERROR, "Out of Memory!!!");

	ret = db_util_open_with_options(user_pkg_parser, &GET_DB(manifest_db),
					SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n", user_pkg_parser);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_app_info where app_id='%s')", lhs_app_id);
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(manifest_db), query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	if (exist == 0) {
		lpkgid = NULL;
	} else {
		snprintf(query, MAX_QUERY_LEN, "select package from package_app_info where app_id='%s' ", lhs_app_id);
		if (SQLITE_OK !=
			sqlite3_exec(GET_DB(manifest_db), query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto err;
		}
		lpkgid = strdup(info->pkgid);
		if (lpkgid == NULL) {
			_LOGE("Out of Memory\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		free(info->pkgid);
		info->pkgid = NULL;
	}

	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_app_info where app_id='%s')", rhs_app_id);
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(manifest_db), query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	if (exist == 0) {
		rpkgid = NULL;
	} else {
		snprintf(query, MAX_QUERY_LEN, "select package from package_app_info where app_id='%s' ", rhs_app_id);
		if (SQLITE_OK !=
			sqlite3_exec(GET_DB(manifest_db), query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto err;
		}
		rpkgid = strdup(info->pkgid);
		if (rpkgid == NULL) {
			_LOGE("Out of Memory\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		free(info->pkgid);
		info->pkgid = NULL;
	}
	ret = pkgmgrinfo_pkginfo_compare_pkg_cert_info(lpkgid, rpkgid, compare_result);
 err:
	sqlite3_free(error_message);
	__close_manifest_db();
	if (info) {
		if (info->pkgid) {
			free(info->pkgid);
			info->pkgid = NULL;
		}
		free(info);
		info = NULL;
	}
	if (lpkgid) {
		free(lpkgid);
		lpkgid = NULL;
	}
	if (rpkgid) {
		free(rpkgid);
		rpkgid = NULL;
	}
	return ret;
}

API int pkgmgrinfo_pkginfo_compare_usr_app_cert_info(const char *lhs_app_id, const char *rhs_app_id, uid_t uid, pkgmgrinfo_cert_compare_result_type_e *compare_result)
{
	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message;
	pkgmgr_cert_x *info;
 	int exist;
	char *lpkgid = NULL;
	char *rpkgid = NULL;

	retvm_if(lhs_app_id == NULL, PMINFO_R_EINVAL, "lhs app ID is NULL");
	retvm_if(rhs_app_id == NULL, PMINFO_R_EINVAL, "rhs app ID is NULL");
	retvm_if(compare_result == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	info = (pkgmgr_cert_x *)calloc(1, sizeof(pkgmgr_cert_x));
	retvm_if(info == NULL, PMINFO_R_ERROR, "Out of Memory!!!");

	ret = __open_manifest_db(uid);
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n", getUserPkgParserDBPathUID(uid));
		ret = PMINFO_R_ERROR;
		goto err;
	}

	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_app_info where app_id='%s')", lhs_app_id);
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(manifest_db), query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	if (exist == 0) {
		lpkgid = NULL;
	} else {
		snprintf(query, MAX_QUERY_LEN, "select package from package_app_info where app_id='%s' ", lhs_app_id);
		if (SQLITE_OK !=
			sqlite3_exec(GET_DB(manifest_db), query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto err;
		}
		lpkgid = strdup(info->pkgid);
		if (lpkgid == NULL) {
			_LOGE("Out of Memory\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		free(info->pkgid);
		info->pkgid = NULL;
	}

	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_app_info where app_id='%s')", rhs_app_id);
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(manifest_db), query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	if (exist == 0) {
		rpkgid = NULL;
	} else {
		snprintf(query, MAX_QUERY_LEN, "select package from package_app_info where app_id='%s' ", rhs_app_id);
		if (SQLITE_OK !=
			sqlite3_exec(GET_DB(manifest_db), query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto err;
		}
		rpkgid = strdup(info->pkgid);
		if (rpkgid == NULL) {
			_LOGE("Out of Memory\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		free(info->pkgid);
		info->pkgid = NULL;
	}
	ret = pkgmgrinfo_pkginfo_compare_usr_pkg_cert_info(lpkgid, rpkgid, uid, compare_result);
 err:
	sqlite3_free(error_message);
	__close_manifest_db();
	if (info) {
		if (info->pkgid) {
			free(info->pkgid);
			info->pkgid = NULL;
		}
		free(info);
		info = NULL;
	}
	if (lpkgid) {
		free(lpkgid);
		lpkgid = NULL;
	}
	if (rpkgid) {
		free(rpkgid);
		rpkgid = NULL;
	}
	return ret;
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
	char *syslocale = NULL;
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
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	if (syslocale == NULL) {
		_LOGE("current locale is NULL\n");
		return PMINFO_R_ERROR;
	}
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		free(syslocale);
		return PMINFO_R_ERROR;
	}

	ret = __open_manifest_db(uid);
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		free(syslocale);
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
	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
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

static int _appinfo_get_filtered_foreach_appinfo(uid_t uid,
		pkgmgrinfo_filter_x *filter, pkgmgrinfo_app_list_cb app_list_cb,
		void *user_data)
{
	pkgmgr_appinfo_x *appinfo = NULL;
	pkgmgr_appinfo_x *next;
	pkgmgr_appinfo_x *tmp;
	char *locale;
	int stop = 0;

	if (__open_manifest_db(uid) < 0)
		return PMINFO_R_ERROR;

	locale = _get_system_locale();
	if (locale == NULL) {
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}

	if (_appinfo_get_app(locale, filter, &appinfo)) {
		free(locale);
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}

	tmp = appinfo;
	while (tmp) {
		next = tmp->next;
		tmp->locale = strdup(locale);
		if (stop == 0) {
			if (app_list_cb(tmp, user_data) < 0)
				stop = 1;
		}
		__cleanup_appinfo(tmp);
		tmp = next;
	}

	free(locale);
	__close_manifest_db();

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_usr_list(pkgmgrinfo_pkginfo_h handle,
		pkgmgrinfo_app_component component,
		pkgmgrinfo_app_list_cb app_func, void *user_data, uid_t uid)
{
	int ret;
	pkgmgrinfo_appinfo_filter_h filter;
	char *pkgid;
	const char *comp_str = NULL;

	if (handle == NULL || app_func == NULL) {
		LOGE("invalied parameter");
		return PMINFO_R_EINVAL;
	}

	if (pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid)) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	if (pkgmgrinfo_appinfo_filter_create(&filter))
		return PMINFO_R_ERROR;

	if (pkgmgrinfo_appinfo_filter_add_string(filter,
				PMINFO_APPINFO_PROP_APP_PACKAGE, pkgid))
		return PMINFO_R_ERROR;


	switch (component) {
	case PMINFO_UI_APP:
		comp_str = PMINFO_APPINFO_UI_APP;
		break;
	case PMINFO_SVC_APP:
		comp_str = PMINFO_APPINFO_SVC_APP;
		break;
	default:
		break;
	}

	if (comp_str) {
		if (pkgmgrinfo_appinfo_filter_add_string(filter,
					PMINFO_APPINFO_PROP_APP_COMPONENT,
					comp_str)) {
			pkgmgrinfo_appinfo_filter_destroy(filter);
			return PMINFO_R_ERROR;
		}
	}

	ret = _appinfo_get_filtered_foreach_appinfo(uid, filter, app_func,
			user_data);

	pkgmgrinfo_appinfo_filter_destroy(filter);

	return ret;
}

API int pkgmgrinfo_appinfo_get_list(pkgmgrinfo_pkginfo_h handle, pkgmgrinfo_app_component component,
						pkgmgrinfo_app_list_cb app_func, void *user_data)
{
	return pkgmgrinfo_appinfo_get_usr_list(handle, component, app_func, user_data, GLOBAL_USER);
}

API int pkgmgrinfo_appinfo_get_usr_install_list(pkgmgrinfo_app_list_cb app_func, uid_t uid, void *user_data)
{
	if (app_func == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	return _appinfo_get_filtered_foreach_appinfo(uid, NULL, app_func,
			user_data);
}

API int pkgmgrinfo_appinfo_get_install_list(pkgmgrinfo_app_list_cb app_func, void *user_data)
{
	return pkgmgrinfo_appinfo_get_usr_install_list(app_func, GLOBAL_USER, user_data);
}

API int pkgmgrinfo_appinfo_get_usr_installed_list(pkgmgrinfo_app_list_cb app_func, uid_t uid, void *user_data)
{
	if (app_func == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	return _appinfo_get_filtered_foreach_appinfo(uid, NULL, app_func,
			user_data);
}

API int pkgmgrinfo_appinfo_get_installed_list(pkgmgrinfo_app_list_cb app_func, void *user_data)
{
	return pkgmgrinfo_appinfo_get_usr_installed_list(app_func, GLOBAL_USER, user_data);
}

static int _appinfo_get_label(const char *appid, const char *locale,
		label_x **label)
{
	static const char query_raw[] =
		"SELECT app_label, app_locale "
		"FROM package_app_localized_info "
		"WHERE app_id=%Q AND app_locale IN (%Q, %Q)";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	int idx;
	label_x *info;

	query = sqlite3_mprintf(query_raw, appid, locale, DEFAULT_LOCALE);
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

	return PMINFO_R_OK;
}

static int _appinfo_get_icon(const char *appid, const char *locale,
		icon_x **icon)
{
	static const char query_raw[] =
		"SELECT app_icon, app_locale "
		"FROM package_app_localized_info "
		"WHERE app_id=%Q AND app_locale IN (%Q, %Q)";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	int idx;
	icon_x *info;

	query = sqlite3_mprintf(query_raw, appid, locale, DEFAULT_LOCALE);
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

	return PMINFO_R_OK;
}

static int _appinfo_get_category(const char *appid, category_x **category)
{
	static const char query_raw[] =
		"SELECT category FROM package_app_app_category WHERE app_id=%Q";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	category_x *info;

	query = sqlite3_mprintf(query_raw, appid);
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
		info = calloc(1, sizeof(category_x));
		if (info == NULL) {
			LOGE("out of memory");
			sqlite3_finalize(stmt);
			if (*category) {
				LISTHEAD(*category, info);
				*category = info;
			}
			return PMINFO_R_ERROR;
		}
		_save_column_str(stmt, 0, &info->name);
		LISTADD(*category, info);
	}

	if (*category) {
		LISTHEAD(*category, info);
		*category = info;
	}

	return PMINFO_R_OK;
}

static int _appinfo_get_app_control(const char *appid,
		appcontrol_x **appcontrol)
{
	static const char query_raw[] =
		"SELECT app_control FROM package_app_app_control "
		"WHERE app_id=%Q";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	appcontrol_x *info = NULL;
	char *str;

	query = sqlite3_mprintf(query_raw, appid);
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
		_save_column_str(stmt, 0, (const char **)&str);
		/* TODO: revise */
		__parse_appcontrol(&info, str);
		free(str);
	}

	if (*appcontrol) {
		LISTHEAD(*appcontrol, info);
		*appcontrol = info;
	}

	return PMINFO_R_OK;
}

static int _appinfo_get_data_control(const char *appid,
		datacontrol_x **datacontrol)
{
	static const char query_raw[] =
		"SELECT providerid, access, type "
		"FROM package_app_data_control WHERE app_id=%Q";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	int idx;
	datacontrol_x *info;

	query = sqlite3_mprintf(query_raw, appid);
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
		info = calloc(1, sizeof(datacontrol_x));
		if (info == NULL) {
			LOGE("out of memory");
			sqlite3_finalize(stmt);
			if (*datacontrol) {
				LISTHEAD(*datacontrol, info);
				*datacontrol = info;
			}
			return PMINFO_R_ERROR;
		}
		idx = 0;
		_save_column_str(stmt, idx++, &info->providerid);
		_save_column_str(stmt, idx++, &info->access);
		_save_column_str(stmt, idx++, &info->type);
		LISTADD(*datacontrol, info);
	}

	if (*datacontrol) {
		LISTHEAD(*datacontrol, info);
		*datacontrol = info;
	}

	return PMINFO_R_OK;
}

static int _appinfo_get_app(const char *locale, pkgmgrinfo_filter_x *filter,
		pkgmgr_appinfo_x **appinfo)
{
	static const char query_raw[] =
		"SELECT app_id, app_component, app_exec, app_nodisplay, "
		"app_type, app_onboot, app_multiple, app_autorestart, "
		"app_taskmanage, app_enabled, app_hwacceleration, "
		"app_screenreader, app_mainapp, app_recentimage, "
		"app_launchcondition, app_indicatordisplay, app_portraitimg, "
		"app_landscapeimg, app_guestmodevisibility, "
		"app_permissiontype, app_preload, app_submode, "
		"app_submode_mainid, app_launch_mode, component_type, package "
		"FROM package_app_info";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	int idx;
	pkgmgr_appinfo_x *info;
	application_x *app;

	query = _get_filtered_query(query_raw, filter);
	if (query == NULL) {
		LOGE("out of memory");
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_prepare_v2(GET_DB(manifest_db), query, strlen(query),
			&stmt, NULL);
	free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(GET_DB(manifest_db)));
		return PMINFO_R_ERROR;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		app = calloc(1, sizeof(application_x));
		if (app == NULL) {
			LOGE("out of memory");
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}
		idx = 0;
		_save_column_str(stmt, idx++, &app->appid);
		_save_column_str(stmt, idx++, &app->component);
		_save_column_str(stmt, idx++, &app->exec);
		_save_column_str(stmt, idx++, &app->nodisplay);
		_save_column_str(stmt, idx++, &app->type);
		_save_column_str(stmt, idx++, &app->onboot);
		_save_column_str(stmt, idx++, &app->multiple);
		_save_column_str(stmt, idx++, &app->autorestart);
		_save_column_str(stmt, idx++, &app->taskmanage);
		_save_column_str(stmt, idx++, &app->enabled);
		_save_column_str(stmt, idx++, &app->hwacceleration);
		_save_column_str(stmt, idx++, &app->screenreader);
		_save_column_str(stmt, idx++, &app->mainapp);
		_save_column_str(stmt, idx++, &app->recentimage);
		_save_column_str(stmt, idx++, &app->launchcondition);
		_save_column_str(stmt, idx++, &app->indicatordisplay);
		_save_column_str(stmt, idx++, &app->portraitimg);
		_save_column_str(stmt, idx++, &app->landscapeimg);
		_save_column_str(stmt, idx++, &app->guestmode_visibility);
		_save_column_str(stmt, idx++, &app->permission_type);
		_save_column_str(stmt, idx++, &app->preload);
		_save_column_str(stmt, idx++, &app->submode);
		_save_column_str(stmt, idx++, &app->submode_mainid);
		_save_column_str(stmt, idx++, &app->launch_mode);
		_save_column_str(stmt, idx++, &app->component_type);
		_save_column_str(stmt, idx++, &app->package);

		if (_appinfo_get_label(app->appid, locale, &app->label)) {
			pkgmgrinfo_basic_free_application(app);
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}

		if (_appinfo_get_icon(app->appid, locale, &app->icon)) {
			pkgmgrinfo_basic_free_application(app);
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}

		if (_appinfo_get_category(app->appid, &app->category)) {
			pkgmgrinfo_basic_free_application(app);
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}

		if (_appinfo_get_app_control(app->appid, &app->appcontrol)) {
			pkgmgrinfo_basic_free_application(app);
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}

		if (_appinfo_get_data_control(app->appid, &app->datacontrol)) {
			pkgmgrinfo_basic_free_application(app);
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}

		info = calloc(1, sizeof(pkgmgr_appinfo_x));
		if (info == NULL) {
			LOGE("out of memory");
			pkgmgrinfo_basic_free_application(app);
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}

		info->package = strdup(app->package);
		info->app_info = app;
		info->locale = strdup(locale);
		LISTADD(*appinfo, info);
	}

	if (*appinfo) {
		LISTHEAD(*appinfo, info);
		*appinfo = info;
	}

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_usr_appinfo(const char *appid, uid_t uid,
		pkgmgrinfo_appinfo_h *handle)
{
	pkgmgr_appinfo_x *appinfo = NULL;
	pkgmgrinfo_appinfo_filter_h filter;
	char *locale;

	if (appid == NULL || handle == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	if (__open_manifest_db(uid) < 0)
		return PMINFO_R_ERROR;

	locale = _get_system_locale();
	if (locale == NULL) {
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}

	if (pkgmgrinfo_appinfo_filter_create(&filter)) {
		free(locale);
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}

	if (pkgmgrinfo_appinfo_filter_add_string(filter,
				PMINFO_APPINFO_PROP_APP_ID, appid)) {
		pkgmgrinfo_appinfo_filter_destroy(filter);
		free(locale);
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}

	if (_appinfo_get_app(locale, filter, &appinfo)) {
		free(locale);
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}

	*handle = appinfo;

	pkgmgrinfo_appinfo_filter_destroy(filter);
	__close_manifest_db();

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_appinfo(const char *appid, pkgmgrinfo_appinfo_h *handle)
{
	return pkgmgrinfo_appinfo_get_usr_appinfo(appid, GLOBAL_USER, handle);
}

API int pkgmgrinfo_appinfo_get_appid(pkgmgrinfo_appinfo_h handle, char **appid)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(appid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL || info->app_info->appid == NULL)
		return PMINFO_R_ERROR;
	*appid = (char *)info->app_info->appid;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_pkgname(pkgmgrinfo_appinfo_h handle, char **pkg_name)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(pkg_name == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->package == NULL)
		return PMINFO_R_ERROR;

	*pkg_name = (char *)info->package;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_pkgid(pkgmgrinfo_appinfo_h handle, char **pkgid)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->package == NULL)
		return PMINFO_R_ERROR;

	*pkgid = (char *)info->package;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_exec(pkgmgrinfo_appinfo_h handle, char **exec)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(exec == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL || info->app_info->exec == NULL)
		return PMINFO_R_ERROR;
	*exec = (char *)info->app_info->exec;

	return PMINFO_R_OK;
}


API int pkgmgrinfo_appinfo_get_icon(pkgmgrinfo_appinfo_h handle, char **icon)
{
        char *locale;
        icon_x *ptr;
        icon_x *start;
        pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(icon == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	locale = info->locale;
	retvm_if(locale == NULL, PMINFO_R_ERROR, "manifest locale is NULL");

	start = info->app_info->icon;
	for (ptr = start; ptr != NULL; ptr = ptr->next) {
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


API int pkgmgrinfo_appinfo_get_label(pkgmgrinfo_appinfo_h handle, char **label)
{
	char *locale;
	label_x *ptr;
	label_x *start;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(label == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	locale = info->locale;
	retvm_if(locale == NULL, PMINFO_R_ERROR, "manifest locale is NULL");

	start = info->app_info->label;
	for (ptr = start; ptr != NULL; ptr = ptr->next) {
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

static char *_get_localed_label(const char *appid, const char *locale, uid_t uid)
{
	char *result = NULL;
	char *query = NULL;
	sqlite3_stmt *stmt = NULL;
	sqlite3 *db = NULL;
	char *val;
	const char *manifest_db;

	manifest_db = getUserPkgParserDBPathUID(uid);
	if (manifest_db == NULL) {
		_LOGE("Failed to get manifest db path");
		goto err;
	}

	if (sqlite3_open_v2(manifest_db, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
		_LOGE("DB open fail\n");
		goto err;
	}

	query = sqlite3_mprintf("select app_label from package_app_localized_info where app_id=%Q and app_locale=%Q", appid, locale);
	if (query == NULL) {
		_LOGE("Out of memory");
		goto err;
	}

	if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
		_LOGE("prepare_v2 fail\n");
		goto err;
	}

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		val = (char *)sqlite3_column_text(stmt, 0);
		if (val != NULL)
			result = strdup(val);
	}

err:
	sqlite3_finalize(stmt);
	sqlite3_free(query);
	sqlite3_close(db);

	return result;
}

API int pkgmgrinfo_appinfo_usr_get_localed_label(const char *appid, const char *locale, uid_t uid, char **label)
{
	char *val;

	retvm_if(appid == NULL || locale == NULL || label == NULL, PMINFO_R_EINVAL, "Argument is NULL");

	val = _get_localed_label(appid, locale, uid);
	if (val == NULL)
		val = _get_localed_label(appid, DEFAULT_LOCALE, uid);

	if (val == NULL)
		return PMINFO_R_ERROR;

	*label = val;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_localed_label(const char *appid, const char *locale, char **label)
{
	return pkgmgrinfo_appinfo_usr_get_localed_label(appid, locale, GLOBAL_USER, label);
}

API int pkgmgrinfo_appinfo_get_component(pkgmgrinfo_appinfo_h handle, pkgmgrinfo_app_component *component)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	int comp;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(component == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	comp = __appcomponent_convert(info->app_info->component);
	if (comp < 0)
		return PMINFO_R_ERROR;

	*component = comp;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_apptype(pkgmgrinfo_appinfo_h handle, char **app_type)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(app_type == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL || info->app_info->type == NULL)
		return PMINFO_R_ERROR;
	*app_type = (char *)info->app_info->type;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_operation(pkgmgrinfo_appcontrol_h  handle,
					int *operation_count, char ***operation)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(operation == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	retvm_if(operation_count == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgrinfo_appcontrol_x *data = (pkgmgrinfo_appcontrol_x *)handle;
	*operation_count = data->operation_count;
	*operation = data->operation;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_uri(pkgmgrinfo_appcontrol_h  handle,
					int *uri_count, char ***uri)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(uri == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	retvm_if(uri_count == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgrinfo_appcontrol_x *data = (pkgmgrinfo_appcontrol_x *)handle;
	*uri_count = data->uri_count;
	*uri = data->uri;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_mime(pkgmgrinfo_appcontrol_h  handle,
					int *mime_count, char ***mime)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(mime == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	retvm_if(mime_count == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgrinfo_appcontrol_x *data = (pkgmgrinfo_appcontrol_x *)handle;
	*mime_count = data->mime_count;
	*mime = data->mime;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_subapp(pkgmgrinfo_appcontrol_h  handle,
					int *subapp_count, char ***subapp)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(subapp == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	retvm_if(subapp_count == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgrinfo_appcontrol_x *data = (pkgmgrinfo_appcontrol_x *)handle;
	*subapp_count = data->subapp_count;
	*subapp = data->subapp;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_setting_icon(pkgmgrinfo_appinfo_h handle, char **icon)
{
	char *val;
	icon_x *ptr;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(icon == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	for (ptr = info->app_info->icon; ptr != NULL; ptr = ptr->next) {
		if (ptr->section == NULL)
			continue;

		val = (char *)ptr->section;
		if (val && strcmp(val, "setting") == 0) {
			*icon = (char *)ptr->text;
			return PMINFO_R_OK;
		}
	}

	return PMINFO_R_ERROR;
}


API int pkgmgrinfo_appinfo_get_notification_icon(pkgmgrinfo_appinfo_h handle, char **icon)
{
	char *val;
	icon_x *ptr;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(icon == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	for (ptr = info->app_info->icon; ptr != NULL; ptr = ptr->next) {
		if (ptr->section == NULL)
			continue;

		val = (char *)ptr->section;
		if (val && strcmp(val, "notification") == 0){
			*icon = (char *)ptr->text;
			return PMINFO_R_OK;
		}
	}

	return PMINFO_R_ERROR;
}

API int pkgmgrinfo_appinfo_get_recent_image_type(pkgmgrinfo_appinfo_h handle, pkgmgrinfo_app_recentimage *type)
{
	char *val;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(type == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL || info->app_info->recentimage == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->app_info->recentimage;
	if (strcasecmp(val, "capture") == 0)
		*type = PMINFO_RECENTIMAGE_USE_CAPTURE;
	else if (strcasecmp(val, "icon") == 0)
		*type = PMINFO_RECENTIMAGE_USE_ICON;
	else
		*type = PMINFO_RECENTIMAGE_USE_NOTHING;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_preview_image(pkgmgrinfo_appinfo_h handle, char **preview_img)
{
	char *val;
	image_x *ptr;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(preview_img == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	for (ptr = info->app_info->image; ptr != NULL; ptr = ptr->next) {
		if (ptr->section == NULL)
			continue;

		val = (char *)ptr->section;
		if (val && strcmp(val, "preview") == 0) {
			*preview_img = (char *)ptr->text;
			return PMINFO_R_OK;
		}
	}

	return PMINFO_R_ERROR;
}

API int pkgmgrinfo_appinfo_get_permission_type(pkgmgrinfo_appinfo_h handle, pkgmgrinfo_permission_type *permission)
{
	const char *val;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(permission == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	val = info->app_info->permission_type;
	if (val == NULL)
		return PMINFO_R_ERROR;

	if (strcmp(val, "signature") == 0)
		*permission = PMINFO_PERMISSION_SIGNATURE;
	else if (strcmp(val, "privilege") == 0)
		*permission = PMINFO_PERMISSION_PRIVILEGE;
	else
		*permission = PMINFO_PERMISSION_NORMAL;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_component_type(pkgmgrinfo_appinfo_h handle, char **component_type)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(component_type == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL || info->app_info->component_type == NULL)
		return PMINFO_R_ERROR;

	*component_type = (char *)info->app_info->component_type;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_hwacceleration(pkgmgrinfo_appinfo_h handle, pkgmgrinfo_app_hwacceleration *hwacceleration)
{
	char *val;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(hwacceleration == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL || info->app_info->hwacceleration == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->app_info->hwacceleration;
	if (strcasecmp(val, "not-use-GL") == 0)
		*hwacceleration = PMINFO_HWACCELERATION_NOT_USE_GL;
	else if (strcasecmp(val, "use-GL") == 0)
		*hwacceleration = PMINFO_HWACCELERATION_USE_GL;
	else
		*hwacceleration = PMINFO_HWACCELERATION_USE_SYSTEM_SETTING;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_screenreader(pkgmgrinfo_appinfo_h handle, pkgmgrinfo_app_screenreader *screenreader)
{
	char *val;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(screenreader == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL || info->app_info->screenreader == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->app_info->screenreader;
	if (strcasecmp(val, "screenreader-off") == 0)
		*screenreader = PMINFO_SCREENREADER_OFF;
	else if (strcasecmp(val, "screenreader-on") == 0)
		*screenreader = PMINFO_SCREENREADER_ON;
	else
		*screenreader = PMINFO_SCREENREADER_USE_SYSTEM_SETTING;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_effectimage(pkgmgrinfo_appinfo_h handle, char **portrait_img, char **landscape_img)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(portrait_img == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	retvm_if(landscape_img == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL || info->app_info->portraitimg ||
			info->app_info->landscapeimg == NULL)
		return PMINFO_R_ERROR;

	*portrait_img = (char *)info->app_info->portraitimg;
	*landscape_img = (char *)info->app_info->landscapeimg;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_submode_mainid(pkgmgrinfo_appinfo_h  handle, char **submode_mainid)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(submode_mainid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL || info->app_info->submode_mainid == NULL)
		return PMINFO_R_ERROR;

	*submode_mainid = (char *)info->app_info->submode_mainid;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_launch_mode(pkgmgrinfo_appinfo_h handle, char **mode)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(mode == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->app_info->launch_mode == NULL)
		return PMINFO_R_ERROR;

	*mode = (char *)(info->app_info->launch_mode);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_usr_get_datacontrol_info(const char *providerid, const char *type, uid_t uid, char **appid, char **access)
{
	retvm_if(providerid == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(type == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(appid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	retvm_if(access == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	int ret = PMINFO_R_OK;
	char *query = NULL;
	sqlite3_stmt *stmt = NULL;

	/*open db*/
	ret = __open_manifest_db(uid);
	retvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	/*Start constructing query*/
	query = sqlite3_mprintf("select * from package_app_data_control where providerid=%Q and type=%Q", providerid, type);

	/*prepare query*/
	ret = sqlite3_prepare_v2(GET_DB(manifest_db), query, strlen(query), &stmt, NULL);
	tryvm_if(ret != PMINFO_R_OK, ret = PMINFO_R_ERROR, "sqlite3_prepare_v2 failed[%s]\n", query);

	/*step query*/
	ret = sqlite3_step(stmt);
	tryvm_if((ret != SQLITE_ROW) || (ret == SQLITE_DONE), ret = PMINFO_R_ERROR, "No records found");

	*appid = strdup((char *)sqlite3_column_text(stmt, 0));
	*access = strdup((char *)sqlite3_column_text(stmt, 2));

	ret = PMINFO_R_OK;

catch:
	sqlite3_free(query);
	sqlite3_finalize(stmt);
	__close_manifest_db();
	return ret;
}

API int pkgmgrinfo_appinfo_get_datacontrol_info(const char *providerid, const char *type, char **appid, char **access)
{
	return pkgmgrinfo_appinfo_usr_get_datacontrol_info(providerid, type, GLOBAL_USER, appid, access);
}

API int pkgmgrinfo_appinfo_usr_get_datacontrol_appid(const char *providerid, uid_t uid, char **appid)
{
	retvm_if(providerid == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(appid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	int ret = PMINFO_R_OK;
	char *query = NULL;
	sqlite3_stmt *stmt = NULL;

	/*open db*/
	ret = __open_manifest_db(uid);
	retvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	/*Start constructing query*/
	query = sqlite3_mprintf("select * from package_app_data_control where providerid=%Q", providerid);

	/*prepare query*/
	ret = sqlite3_prepare_v2(GET_DB(manifest_db), query, strlen(query), &stmt, NULL);
	tryvm_if(ret != PMINFO_R_OK, ret = PMINFO_R_ERROR, "sqlite3_prepare_v2 failed[%s]\n", query);

	/*step query*/
	ret = sqlite3_step(stmt);
	tryvm_if((ret != SQLITE_ROW) || (ret == SQLITE_DONE), ret = PMINFO_R_ERROR, "No records found");

	*appid = strdup((char *)sqlite3_column_text(stmt, 0));

	ret = PMINFO_R_OK;

catch:
	sqlite3_free(query);
	sqlite3_finalize(stmt);
	__close_manifest_db();
	return ret;
}

API int pkgmgrinfo_appinfo_get_datacontrol_appid(const char *providerid, char **appid)
{
	return pkgmgrinfo_appinfo_usr_get_datacontrol_appid(providerid, GLOBAL_USER, appid);
}

API int pkgmgrinfo_appinfo_foreach_permission(pkgmgrinfo_appinfo_h handle,
			pkgmgrinfo_app_permission_list_cb permission_func, void *user_data)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(permission_func == NULL, PMINFO_R_EINVAL, "Callback function is NULL");
	int ret = -1;
	permission_x *ptr = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	for (ptr = info->app_info->permission; ptr; ptr = ptr->next) {
		if (ptr->value) {
			ret = permission_func(ptr->value, user_data);
			if (ret < 0)
				break;
		}
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_foreach_category(pkgmgrinfo_appinfo_h handle,
			pkgmgrinfo_app_category_list_cb category_func, void *user_data)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(category_func == NULL, PMINFO_R_EINVAL, "Callback function is NULL");
	int ret = -1;
	category_x *ptr = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	for (ptr = info->app_info->category; ptr; ptr = ptr->next) {
		if (ptr->name) {
			ret = category_func(ptr->name, user_data);
			if (ret < 0)
				break;
		}
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_foreach_metadata(pkgmgrinfo_appinfo_h handle,
			pkgmgrinfo_app_metadata_list_cb metadata_func, void *user_data)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(metadata_func == NULL, PMINFO_R_EINVAL, "Callback function is NULL");
	int ret = -1;
	metadata_x *ptr = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	for (ptr = info->app_info->metadata; ptr; ptr = ptr->next) {
		if (ptr->key) {
			ret = metadata_func(ptr->key, ptr->value, user_data);
			if (ret < 0)
				break;
		}
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_foreach_appcontrol(pkgmgrinfo_appinfo_h handle,
			pkgmgrinfo_app_control_list_cb appcontrol_func, void *user_data)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(appcontrol_func == NULL, PMINFO_R_EINVAL, "Callback function is NULL");
	int ret;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	appcontrol_x *appcontrol;

	if (info->uiapp_info == NULL)
		return PMINFO_R_ERROR;

	for (appcontrol = info->app_info->appcontrol; appcontrol; appcontrol = appcontrol->next) {
		ret = appcontrol_func(appcontrol->operation, appcontrol->uri, appcontrol->mime, user_data);
		if (ret < 0)
			break;
	}

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_nodisplay(pkgmgrinfo_appinfo_h handle, bool *nodisplay)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(nodisplay == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->app_info->nodisplay;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*nodisplay = 1;
		else if (strcasecmp(val, "false") == 0)
			*nodisplay = 0;
		else
			*nodisplay = 0;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_multiple(pkgmgrinfo_appinfo_h handle, bool *multiple)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(multiple == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->app_info->multiple;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*multiple = 1;
		else if (strcasecmp(val, "false") == 0)
			*multiple = 0;
		else
			*multiple = 0;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_indicator_display_allowed(pkgmgrinfo_appinfo_h handle, bool *indicator_disp)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(indicator_disp == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->app_info->indicatordisplay;
	if (val) {
		if (strcasecmp(val, "true") == 0){
			*indicator_disp = 1;
		}else if (strcasecmp(val, "false") == 0){
			*indicator_disp = 0;
		}else{
			*indicator_disp = 0;
		}
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_taskmanage(pkgmgrinfo_appinfo_h  handle, bool *taskmanage)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(taskmanage == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->app_info->taskmanage;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*taskmanage = 1;
		else if (strcasecmp(val, "false") == 0)
			*taskmanage = 0;
		else
			*taskmanage = 0;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_enabled(pkgmgrinfo_appinfo_h  handle, bool *enabled)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(enabled == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->app_info->enabled;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*enabled = 1;
		else if (strcasecmp(val, "false") == 0)
			*enabled = 0;
		else
			*enabled = 1;
	}
	return PMINFO_R_OK;

}

API int pkgmgrinfo_appinfo_is_onboot(pkgmgrinfo_appinfo_h  handle, bool *onboot)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(onboot == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->app_info->onboot;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*onboot = 1;
		else if (strcasecmp(val, "false") == 0)
			*onboot = 0;
		else
			*onboot = 0;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_autorestart(pkgmgrinfo_appinfo_h  handle, bool *autorestart)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(autorestart == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->app_info->autorestart;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*autorestart = 1;
		else if (strcasecmp(val, "false") == 0)
			*autorestart = 0;
		else
			*autorestart = 0;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_mainapp(pkgmgrinfo_appinfo_h  handle, bool *mainapp)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(mainapp == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->app_info->mainapp;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*mainapp = 1;
		else if (strcasecmp(val, "false") == 0)
			*mainapp = 0;
		else
			*mainapp = 0;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_preload(pkgmgrinfo_appinfo_h handle, bool *preload)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(preload == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->app_info->preload;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*preload = 1;
		else if (strcasecmp(val, "false") == 0)
			*preload = 0;
		else
			*preload = 0;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_submode(pkgmgrinfo_appinfo_h handle, bool *submode)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(submode == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->app_info->submode;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*submode = 1;
		else if (strcasecmp(val, "false") == 0)
			*submode = 0;
		else
			*submode = 0;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_category_exist(pkgmgrinfo_appinfo_h handle, const char *category, bool *exist)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(category == NULL, PMINFO_R_EINVAL, "category is NULL");
	retvm_if(exist == NULL, PMINFO_R_EINVAL, "exist is NULL");

	category_x *ptr = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	*exist = 0;
	for (ptr = info->app_info->category; ptr; ptr = ptr->next) {
		if (ptr->name) {
			if (strcasecmp(ptr->name, category) == 0) {
				*exist = 1;
				break;
			}
		}
	}

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_destroy_appinfo(pkgmgrinfo_appinfo_h  handle)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	__cleanup_appinfo(info);
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_filter_create(pkgmgrinfo_appinfo_filter_h *handle)
{
	return (pkgmgrinfo_pkginfo_filter_create(handle));
}

API int pkgmgrinfo_appinfo_filter_destroy(pkgmgrinfo_appinfo_filter_h handle)
{
	return (pkgmgrinfo_pkginfo_filter_destroy(handle));
}

API int pkgmgrinfo_appinfo_filter_add_int(pkgmgrinfo_appinfo_filter_h handle,
				const char *property, const int value)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(property == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	char buf[PKG_VALUE_STRING_LEN_MAX] = {'\0'};
	char *val = NULL;
	GSList *link = NULL;
	int prop = -1;
	prop = _pminfo_appinfo_convert_to_prop_int(property);
	if (prop < E_PMINFO_APPINFO_PROP_APP_MIN_INT ||
		prop > E_PMINFO_APPINFO_PROP_APP_MAX_INT) {
		_LOGE("Invalid Integer Property\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)handle;
	pkgmgrinfo_node_x *node = (pkgmgrinfo_node_x*)calloc(1, sizeof(pkgmgrinfo_node_x));
	if (node == NULL) {
		_LOGE("Out of Memory!!!\n");
		return PMINFO_R_ERROR;
	}
	snprintf(buf, PKG_VALUE_STRING_LEN_MAX - 1, "%d", value);
	val = strndup(buf, PKG_VALUE_STRING_LEN_MAX - 1);
	if (val == NULL) {
		_LOGE("Out of Memory\n");
		free(node);
		node = NULL;
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

API int pkgmgrinfo_appinfo_filter_add_bool(pkgmgrinfo_appinfo_filter_h handle,
				const char *property, const bool value)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(property == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	char *val = NULL;
	GSList *link = NULL;
	int prop = -1;
	prop = _pminfo_appinfo_convert_to_prop_bool(property);
	if (prop < E_PMINFO_APPINFO_PROP_APP_MIN_BOOL ||
		prop > E_PMINFO_APPINFO_PROP_APP_MAX_BOOL) {
		_LOGE("Invalid Boolean Property\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)handle;
	pkgmgrinfo_node_x *node = (pkgmgrinfo_node_x*)calloc(1, sizeof(pkgmgrinfo_node_x));
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
		node = NULL;
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

API int pkgmgrinfo_appinfo_filter_add_string(pkgmgrinfo_appinfo_filter_h handle,
				const char *property, const char *value)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(property == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(value == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	char *val = NULL;
	pkgmgrinfo_node_x *ptr = NULL;
	char prev[PKG_STRING_LEN_MAX] = {'\0'};
	char temp[PKG_STRING_LEN_MAX] = {'\0'};
	GSList *link = NULL;
	int prop = -1;
	prop = _pminfo_appinfo_convert_to_prop_str(property);
	if (prop < E_PMINFO_APPINFO_PROP_APP_MIN_STR ||
		prop > E_PMINFO_APPINFO_PROP_APP_MAX_STR) {
		_LOGE("Invalid String Property\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)handle;
	pkgmgrinfo_node_x *node = (pkgmgrinfo_node_x*)calloc(1, sizeof(pkgmgrinfo_node_x));
	if (node == NULL) {
		_LOGE("Out of Memory!!!\n");
		return PMINFO_R_ERROR;
	}
	node->prop = prop;
	switch (prop) {
	case E_PMINFO_APPINFO_PROP_APP_COMPONENT:
		if (strcmp(value, PMINFO_APPINFO_UI_APP) == 0)
			val = strndup("uiapp", PKG_STRING_LEN_MAX - 1);
		else
			val = strndup("svcapp", PKG_STRING_LEN_MAX - 1);
		node->value = val;
		link = g_slist_find_custom(filter->list, (gconstpointer)node, __compare_func);
		if (link)
			filter->list = g_slist_delete_link(filter->list, link);
		filter->list = g_slist_append(filter->list, (gpointer)node);
		break;
	case E_PMINFO_APPINFO_PROP_APP_CATEGORY:
	case E_PMINFO_APPINFO_PROP_APP_OPERATION:
	case E_PMINFO_APPINFO_PROP_APP_URI:
	case E_PMINFO_APPINFO_PROP_APP_MIME:
		val = (char *)calloc(1, PKG_STRING_LEN_MAX);
		if (val == NULL) {
			_LOGE("Out of Memory\n");
			free(node);
			node = NULL;
			return PMINFO_R_ERROR;
		}
		link = g_slist_find_custom(filter->list, (gconstpointer)node, __compare_func);
		if (link) {
			ptr = (pkgmgrinfo_node_x *)link->data;
			strncpy(prev, ptr->value, PKG_STRING_LEN_MAX - 1);
			_LOGE("Previous value is %s\n", prev);
			filter->list = g_slist_delete_link(filter->list, link);
			snprintf(temp, PKG_STRING_LEN_MAX - 1, "%s , '%s'", prev, value);
			strncpy(val, temp, PKG_STRING_LEN_MAX - 1);
			_LOGE("New value is %s\n", val);
			node->value = val;
			filter->list = g_slist_append(filter->list, (gpointer)node);
			memset(temp, '\0', PKG_STRING_LEN_MAX);
		} else {
			snprintf(temp, PKG_STRING_LEN_MAX - 1, "'%s'", value);
			strncpy(val, temp, PKG_STRING_LEN_MAX - 1);
			_LOGE("First value is %s\n", val);
			node->value = val;
			filter->list = g_slist_append(filter->list, (gpointer)node);
			memset(temp, '\0', PKG_STRING_LEN_MAX);
		}
		break;
	default:
		node->value = strndup(value, PKG_STRING_LEN_MAX - 1);
		link = g_slist_find_custom(filter->list, (gconstpointer)node, __compare_func);
		if (link)
			filter->list = g_slist_delete_link(filter->list, link);
		filter->list = g_slist_append(filter->list, (gpointer)node);
		break;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_usr_filter_count(pkgmgrinfo_appinfo_filter_h handle, int *count, uid_t uid)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(count == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	char *syslocale = NULL;
	char *locale = NULL;
	char *condition = NULL;
	char *error_message = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	char where[MAX_QUERY_LEN] = {'\0'};
	GSList *list;
	int ret = 0;

	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)handle;
	/*Get current locale*/
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	if (syslocale == NULL) {
		_LOGE("current locale is NULL\n");
		return PMINFO_R_ERROR;
	}
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		free(syslocale);
		return PMINFO_R_ERROR;
	}

	ret = __open_manifest_db(uid);
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		free(syslocale);
		free(locale);
		return PMINFO_R_ERROR;
	}

	/*Start constructing query*/
	snprintf(query, MAX_QUERY_LEN - 1, FILTER_QUERY_COUNT_APP, locale);

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
	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	__close_manifest_db();
	return ret;
}

API int pkgmgrinfo_appinfo_filter_count(pkgmgrinfo_appinfo_filter_h handle, int *count)
{
	return pkgmgrinfo_appinfo_usr_filter_count(handle, count, GLOBAL_USER);
}

API int pkgmgrinfo_appinfo_usr_filter_foreach_appinfo(
		pkgmgrinfo_appinfo_filter_h handle,
		pkgmgrinfo_app_list_cb app_cb, void *user_data, uid_t uid)
{
	if (handle == NULL || app_cb == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	return _appinfo_get_filtered_foreach_appinfo(uid, handle, app_cb,
			user_data);
}

API int pkgmgrinfo_appinfo_filter_foreach_appinfo(pkgmgrinfo_appinfo_filter_h handle,
				pkgmgrinfo_app_list_cb app_cb, void * user_data)
{
	return pkgmgrinfo_appinfo_usr_filter_foreach_appinfo(handle, app_cb, user_data, GLOBAL_USER);
}

API int pkgmgrinfo_appinfo_metadata_filter_create(pkgmgrinfo_appinfo_metadata_filter_h *handle)
{
	return (pkgmgrinfo_pkginfo_filter_create(handle));
}

API int pkgmgrinfo_appinfo_metadata_filter_destroy(pkgmgrinfo_appinfo_metadata_filter_h handle)
{
	return (pkgmgrinfo_pkginfo_filter_destroy(handle));
}

API int pkgmgrinfo_appinfo_metadata_filter_add(pkgmgrinfo_appinfo_metadata_filter_h handle,
		const char *key, const char *value)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "filter handle is NULL\n");
	retvm_if(key == NULL, PMINFO_R_EINVAL, "metadata key supplied is NULL\n");
	/*value can be NULL. In that case all apps with specified key should be displayed*/
	int ret = 0;
	char *k = NULL;
	char *v = NULL;
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)handle;
	pkgmgrinfo_node_x *node = (pkgmgrinfo_node_x*)calloc(1, sizeof(pkgmgrinfo_node_x));
	retvm_if(node == NULL, PMINFO_R_ERROR, "Out of Memory!!!\n");
	k = strdup(key);
	tryvm_if(k == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");
	node->key = k;
	if (value) {
		v = strdup(value);
		tryvm_if(v == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");
	}
	node->value = v;
	/*If API is called multiple times, we should OR all conditions.*/
	filter->list = g_slist_append(filter->list, (gpointer)node);
	/*All memory will be freed in destroy API*/
	return PMINFO_R_OK;
catch:
	if (node) {
		if (node->key) {
			free(node->key);
			node->key = NULL;
		}
		if (node->value) {
			free(node->value);
			node->value = NULL;
		}
		free(node);
		node = NULL;
	}
	return ret;
}

API int pkgmgrinfo_appinfo_usr_metadata_filter_foreach(pkgmgrinfo_appinfo_metadata_filter_h handle,
		pkgmgrinfo_app_list_cb app_cb, void *user_data, uid_t uid)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "filter handle is NULL\n");
	retvm_if(app_cb == NULL, PMINFO_R_EINVAL, "Callback function supplied is NULL\n");
	char *syslocale = NULL;
	char *locale = NULL;
	char *condition = NULL;
	char *error_message = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	char where[MAX_QUERY_LEN] = {'\0'};
	GSList *list;
	int ret = 0;
	pkgmgr_pkginfo_x *info = NULL;
	pkgmgr_pkginfo_x *filtinfo = NULL;
	pkgmgr_appinfo_x *appinfo = NULL;
	uiapplication_x *ptr1 = NULL;
	serviceapplication_x *ptr2 = NULL;
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)handle;

	/*Get current locale*/
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	retvm_if(syslocale == NULL, PMINFO_R_ERROR, "current locale is NULL\n");
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	tryvm_if(locale == NULL, ret = PMINFO_R_ERROR, "manifest locale is NULL\n");

	ret = __open_manifest_db(uid);
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		free(syslocale);
		free(locale);
		return PMINFO_R_ERROR;
	}
	/*Start constructing query*/
	memset(where, '\0', MAX_QUERY_LEN);
	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN - 1, METADATA_FILTER_QUERY_SELECT_CLAUSE);
	/*Get where clause*/
	for (list = filter->list; list; list = g_slist_next(list)) {
		__get_metadata_filter_condition(list->data, &condition);
		if (condition) {
			strncat(where, condition, sizeof(where) - strlen(where) -1);
			free(condition);
			condition = NULL;
		}
		if (g_slist_next(list)) {
			strncat(where, METADATA_FILTER_QUERY_UNION_CLAUSE, sizeof(where) - strlen(where) - 1);
		}
	}
	if (strlen(where) > 0) {
		strncat(query, where, sizeof(query) - strlen(query) - 1);
	}
	/*To get filtered list*/
	info = (pkgmgr_pkginfo_x *)calloc(1, sizeof(pkgmgr_pkginfo_x));
	tryvm_if(info == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	info->pkg_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	tryvm_if(info->pkg_info == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	/*To get detail app info for each member of filtered list*/
	filtinfo = (pkgmgr_pkginfo_x *)calloc(1, sizeof(pkgmgr_pkginfo_x));
	tryvm_if(filtinfo == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	filtinfo->pkg_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	tryvm_if(filtinfo->pkg_info == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	appinfo = (pkgmgr_appinfo_x *)calloc(1, sizeof(pkgmgr_appinfo_x));
	tryvm_if(appinfo == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	ret = sqlite3_exec(GET_DB(manifest_db), query, __app_list_cb, (void *)info, &error_message);
	tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Don't execute query = %s error message = %s\n", query, error_message);
	memset(query, '\0', MAX_QUERY_LEN);

	if (info->pkg_info->uiapplication) {
		LISTHEAD(info->pkg_info->uiapplication, ptr1);
		info->pkg_info->uiapplication = ptr1;
	}
	if (info->pkg_info->serviceapplication) {
		LISTHEAD(info->pkg_info->serviceapplication, ptr2);
		info->pkg_info->serviceapplication = ptr2;
	}

	/*UI Apps*/
	for(ptr1 = info->pkg_info->uiapplication; ptr1; ptr1 = ptr1->next)
	{
		snprintf(query, MAX_QUERY_LEN, "select * from package_app_info where app_id='%s' and app_component='%s'",
							ptr1->appid, "uiapp");
		ret = sqlite3_exec(GET_DB(manifest_db), query, __uiapp_list_cb, (void *)filtinfo, &error_message);
		tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Don't execute query = %s error message = %s\n", query, error_message);
		memset(query, '\0', MAX_QUERY_LEN);
	}
	/*Service Apps*/
	for(ptr2 = info->pkg_info->serviceapplication; ptr2; ptr2 = ptr2->next)
	{
		snprintf(query, MAX_QUERY_LEN, "select * from package_app_info where app_id='%s' and app_component='%s'",
							ptr2->appid, "svcapp");
		ret = sqlite3_exec(GET_DB(manifest_db), query, __svcapp_list_cb, (void *)filtinfo, &error_message);
		tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Don't execute query = %s error message = %s\n", query, error_message);
		memset(query, '\0', MAX_QUERY_LEN);
	}
	/*Filtered UI Apps*/
	if (filtinfo->pkg_info->uiapplication) {
		LISTHEAD(filtinfo->pkg_info->uiapplication, ptr1);
		filtinfo->pkg_info->uiapplication = ptr1;
	}
	/*If the callback func return < 0 we break and no more call back is called*/
	while(ptr1 != NULL)
	{
		appinfo->locale = strdup(locale);
		appinfo->uiapp_info = ptr1;
		appinfo->app_component = PMINFO_UI_APP;
		ret = app_cb((void *)appinfo, user_data);
		if (ret < 0)
			break;
		ptr1 = ptr1->next;
	}
	/*Filtered Service Apps*/
	if (filtinfo->pkg_info->serviceapplication) {
		LISTHEAD(filtinfo->pkg_info->serviceapplication, ptr2);
		filtinfo->pkg_info->serviceapplication = ptr2;
	}
	/*If the callback func return < 0 we break and no more call back is called*/
	while(ptr2 != NULL)
	{
		appinfo->locale = strdup(locale);
		appinfo->svcapp_info = ptr2;
		appinfo->app_component = PMINFO_SVC_APP;
		ret = app_cb((void *)appinfo, user_data);
		if (ret < 0)
			break;
		ptr2 = ptr2->next;
	}
	ret = PMINFO_R_OK;
catch:
	if (locale) {
		free(locale);
		locale = NULL;
	}
	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	sqlite3_free(error_message);
	__close_manifest_db();
	if (appinfo) {
		free(appinfo);
		appinfo = NULL;
	}
	__cleanup_pkginfo(info);
	__cleanup_pkginfo(filtinfo);
	return ret;
}

API int pkgmgrinfo_appinfo_metadata_filter_foreach(pkgmgrinfo_appinfo_metadata_filter_h handle,
		pkgmgrinfo_app_list_cb app_cb, void *user_data)
{
	return pkgmgrinfo_appinfo_usr_metadata_filter_foreach(handle, app_cb, user_data, GLOBAL_USER);
}

API int pkgmgrinfo_pkginfo_create_certinfo(pkgmgrinfo_certinfo_h *handle)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_certinfo_x *certinfo = NULL;
	certinfo = calloc(1, sizeof(pkgmgr_certinfo_x));
	*handle = NULL;
	retvm_if(certinfo == NULL, PMINFO_R_ERROR, "Malloc Failed\n");
	*handle = (void *)certinfo;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_load_certinfo(const char *pkgid, pkgmgrinfo_certinfo_h handle, uid_t uid)
{
	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "package ID is NULL\n");
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Certinfo handle is NULL\n");
	pkgmgr_certinfo_x *certinfo = NULL;
	char *error_message = NULL;
	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	int exist = 0;
	int i = 0;

	/*Open db.*/
	ret = __open_cert_db(uid,"r");
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	_check_create_Cert_db(GET_DB(cert_db));
	/*validate pkgid*/
	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", pkgid);
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(cert_db), query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}
	if (exist == 0) {
		_LOGE("Package for user[%d] is not found in DB\n", uid);
		ret = PMINFO_R_ERROR;
		goto err;
	}
	certinfo = (pkgmgr_certinfo_x *)handle;
	/*populate certinfo from DB*/
	snprintf(query, MAX_QUERY_LEN, "select * from package_cert_info where package='%s' ", pkgid);
	ret = __exec_certinfo_query(query, (void *)certinfo);
	if (ret == -1) {
		_LOGE("Package Cert Info DB Information retrieval failed\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	for (i = 0; i < MAX_CERT_TYPE; i++) {
		memset(query, '\0', MAX_QUERY_LEN);
		if (uid == GLOBAL_USER || uid == ROOT_UID)
			snprintf(query, MAX_QUERY_LEN, "select cert_info from package_cert_index_info where cert_id=%d", (certinfo->cert_id)[i]);
		else
			snprintf(query, MAX_QUERY_LEN, "select cert_info from package_cert_index_info where cert_id=%d and for_all_users=%d", (certinfo->cert_id)[i], certinfo->for_all_users);
		ret = __exec_certinfo_query(query, (void *)certinfo);
		if (ret == -1) {
			_LOGE("Cert Info DB Information retrieval failed\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		if (certinfo->cert_value) {
			(certinfo->cert_info)[i] = strdup(certinfo->cert_value);
			free(certinfo->cert_value);
			certinfo->cert_value = NULL;
		}
	}
err:
	__close_cert_db();
	return ret;
}

API int pkgmgrinfo_pkginfo_get_cert_value(pkgmgrinfo_certinfo_h handle, pkgmgrinfo_cert_type cert_type, const char **cert_value)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(cert_value == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(cert_type < PMINFO_AUTHOR_ROOT_CERT, PMINFO_R_EINVAL, "Invalid certificate type\n");
	retvm_if(cert_type > PMINFO_DISTRIBUTOR2_SIGNER_CERT, PMINFO_R_EINVAL, "Invalid certificate type\n");
	pkgmgr_certinfo_x *certinfo = NULL;
	certinfo = (pkgmgr_certinfo_x *)handle;
	if ((certinfo->cert_info)[cert_type])
		*cert_value = (certinfo->cert_info)[cert_type];
	else
		*cert_value = NULL;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_destroy_certinfo(pkgmgrinfo_certinfo_h handle)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	int i = 0;
	pkgmgr_certinfo_x *certinfo = NULL;
	certinfo = (pkgmgr_certinfo_x *)handle;
	if (certinfo->pkgid) {
		free(certinfo->pkgid);
		certinfo->pkgid = NULL;
	}
	for (i = 0; i < MAX_CERT_TYPE; i++) {
		if ((certinfo->cert_info)[i]) {
			free((certinfo->cert_info)[i]);
			(certinfo->cert_info)[i] = NULL;
		}
	}
	free(certinfo);
	certinfo = NULL;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_create_certinfo_set_handle(pkgmgrinfo_instcertinfo_h *handle)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_instcertinfo_x *certinfo = NULL;
	*handle = NULL;
	certinfo = calloc(1, sizeof(pkgmgr_instcertinfo_x));
	retvm_if(certinfo == NULL, PMINFO_R_ERROR, "Malloc Failed\n");
	*handle = (void *)certinfo;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_cert_value(pkgmgrinfo_instcertinfo_h handle, pkgmgrinfo_instcert_type cert_type, char *cert_value)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(cert_value == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(cert_type < PMINFO_SET_AUTHOR_ROOT_CERT, PMINFO_R_EINVAL, "Invalid certificate type\n");
	retvm_if(cert_type > PMINFO_SET_DISTRIBUTOR2_SIGNER_CERT, PMINFO_R_EINVAL, "Invalid certificate type\n");
	pkgmgr_instcertinfo_x *certinfo = NULL;
	certinfo = (pkgmgr_instcertinfo_x *)handle;
	(certinfo->cert_info)[cert_type] = strdup(cert_value);
	return PMINFO_R_OK;
}

API int pkgmgrinfo_save_certinfo(const char *pkgid, pkgmgrinfo_instcertinfo_h handle, uid_t uid)
{
	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "package ID is NULL\n");
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Certinfo handle is NULL\n");
	char *error_message = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *vquery = NULL;
	int len = 0;
	int i = 0;
	int j = 0;
	int c = 0;
	int unique_id[MAX_CERT_TYPE] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
	int newid = 0;
	int is_new = 0;
	int exist = -1;
	int ret = -1;
	int maxid = 0;
	int flag = 0;
	pkgmgr_instcertinfo_x *info = (pkgmgr_instcertinfo_x *)handle;
	pkgmgr_certindexinfo_x *indexinfo = NULL;
	indexinfo = calloc(1, sizeof(pkgmgr_certindexinfo_x));
	if (indexinfo == NULL) {
		_LOGE("Out of Memory!!!");
		return PMINFO_R_ERROR;
	}
	info->pkgid = strdup(pkgid);

	/*Open db.*/
	ret =__open_cert_db(uid, "w");
	if (ret != 0) {
		ret = PMINFO_R_ERROR;
		_LOGE("Failed to open cert db \n");
		goto err;
	}
	_check_create_Cert_db(GET_DB(cert_db));
	/*Begin Transaction*/
	ret = sqlite3_exec(GET_DB(cert_db), "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret == -1) {
		_LOGE("Failed to begin transaction %s\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}

	/*Check if request is to insert/update*/
	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", pkgid);
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(cert_db), query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}
	if (exist) {
		/*Update request.
		We cant just issue update query directly. We need to manage index table also.
		Hence it is better to delete and insert again in case of update*/
		ret = __delete_certinfo(pkgid, uid);
		if (ret < 0)
			_LOGE("Certificate Deletion Failed\n");
	}
	for (i = 0; i < MAX_CERT_TYPE; i++) {
		if ((info->cert_info)[i]) {
			for (j = 0; j < i; j++) {
				if ( (info->cert_info)[j]) {
					if (strcmp((info->cert_info)[i], (info->cert_info)[j]) == 0) {
						(info->cert_id)[i] = (info->cert_id)[j];
						(info->is_new)[i] = 0;
						(info->ref_count)[i] = (info->ref_count)[j];
						break;
					}
				}
			}
			if (j < i)
				continue;
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_cert_index_info " \
				"where cert_info='%s'",(info->cert_info)[i]);
			ret = __exec_certindexinfo_query(query, (void *)indexinfo);
			if (ret == -1) {
				_LOGE("Cert Info DB Information retrieval failed\n");
				ret = PMINFO_R_ERROR;
				goto err;
			}
			if (indexinfo->cert_id == 0) {
				/*New certificate. Get newid*/
				memset(query, '\0', MAX_QUERY_LEN);
				snprintf(query, MAX_QUERY_LEN, "select MAX(cert_id) from package_cert_index_info ");
				if (SQLITE_OK !=
				    sqlite3_exec(GET_DB(cert_db), query, __maxid_cb, (void *)&newid, &error_message)) {
					_LOGE("Don't execute query = %s error message = %s\n", query,
					       error_message);
					sqlite3_free(error_message);
					ret = PMINFO_R_ERROR;
					goto err;
				}
				newid = newid + 1;
				if (flag == 0) {
					maxid = newid;
					flag = 1;
				}
				indexinfo->cert_id = maxid;
				indexinfo->cert_ref_count = 1;
				is_new = 1;
				maxid = maxid + 1;
			}
			(info->cert_id)[i] = indexinfo->cert_id;
			(info->is_new)[i] = is_new;
			(info->ref_count)[i] = indexinfo->cert_ref_count;
			indexinfo->cert_id = 0;
			indexinfo->cert_ref_count = 0;
			is_new = 0;
		}
	}
	len = MAX_QUERY_LEN;
	for (i = 0; i < MAX_CERT_TYPE; i++) {
		if ((info->cert_info)[i])
			len+= strlen((info->cert_info)[i]);
	}
	vquery = (char *)calloc(1, len);
	/*insert*/
	snprintf(vquery, len,
                 "insert into package_cert_info(package, author_root_cert, author_im_cert, author_signer_cert, dist_root_cert, " \
                "dist_im_cert, dist_signer_cert, dist2_root_cert, dist2_im_cert, dist2_signer_cert) " \
                "values('%s', %d, %d, %d, %d, %d, %d, %d, %d, %d)",\
                 info->pkgid,(info->cert_id)[PMINFO_SET_AUTHOR_ROOT_CERT],(info->cert_id)[PMINFO_SET_AUTHOR_INTERMEDIATE_CERT],
		(info->cert_id)[PMINFO_SET_AUTHOR_SIGNER_CERT], (info->cert_id)[PMINFO_SET_DISTRIBUTOR_ROOT_CERT],
		(info->cert_id)[PMINFO_SET_DISTRIBUTOR_INTERMEDIATE_CERT], (info->cert_id)[PMINFO_SET_DISTRIBUTOR_SIGNER_CERT],
		(info->cert_id)[PMINFO_SET_DISTRIBUTOR2_ROOT_CERT],(info->cert_id)[PMINFO_SET_DISTRIBUTOR2_INTERMEDIATE_CERT],
		(info->cert_id)[PMINFO_SET_DISTRIBUTOR2_SIGNER_CERT]);
        if (SQLITE_OK !=
            sqlite3_exec(GET_DB(cert_db), vquery, NULL, NULL, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", vquery,
		       error_message);
		sqlite3_free(error_message);
		ret = PMINFO_R_ERROR;
		goto err;
        }
	/*Update index table info*/
	/*If cert_id exists and is repeated for current package, ref count should only be increased once*/
	for (i = 0; i < MAX_CERT_TYPE; i++) {
		if ((info->cert_info)[i]) {
			memset(vquery, '\0', len);
			if ((info->is_new)[i]) {
				snprintf(vquery, len, "insert into package_cert_index_info(cert_info, cert_id, cert_ref_count) " \
				"values('%s', '%d', '%d') ", (info->cert_info)[i], (info->cert_id)[i], 1);
				unique_id[c++] = (info->cert_id)[i];
			} else {
				/*Update*/
				for (j = 0; j < MAX_CERT_TYPE; j++) {
					if ((info->cert_id)[i] == unique_id[j]) {
						/*Ref count has already been increased. Just continue*/
						break;
					}
				}
				if (j == MAX_CERT_TYPE)
					unique_id[c++] = (info->cert_id)[i];
				else
					continue;
				snprintf(vquery, len, "update package_cert_index_info set cert_ref_count=%d " \
				"where cert_id=%d",  (info->ref_count)[i] + 1, (info->cert_id)[i]);
			}
		        if (SQLITE_OK !=
		            sqlite3_exec(GET_DB(cert_db), vquery, NULL, NULL, &error_message)) {
				_LOGE("Don't execute query = %s error message = %s\n", vquery,
				       error_message);
				sqlite3_free(error_message);
				ret = PMINFO_R_ERROR;
				goto err;
		        }
		}
	}
	/*Commit transaction*/
	ret = sqlite3_exec(GET_DB(cert_db), "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to commit transaction, Rollback now\n");
		sqlite3_exec(GET_DB(cert_db), "ROLLBACK", NULL, NULL, NULL);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	ret =  PMINFO_R_OK;
err:
	__close_cert_db();
	if (vquery) {
		free(vquery);
		vquery = NULL;
	}
	if (indexinfo) {
		free(indexinfo);
		indexinfo = NULL;
	}
	return ret;
}

API int pkgmgrinfo_destroy_certinfo_set_handle(pkgmgrinfo_instcertinfo_h handle)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	int i = 0;
	pkgmgr_instcertinfo_x *certinfo = NULL;
	certinfo = (pkgmgr_instcertinfo_x *)handle;
	if (certinfo->pkgid) {
		free(certinfo->pkgid);
		certinfo->pkgid = NULL;
	}
	for (i = 0; i < MAX_CERT_TYPE; i++) {
		if ((certinfo->cert_info)[i]) {
			free((certinfo->cert_info)[i]);
			(certinfo->cert_info)[i] = NULL;
		}
	}
	free(certinfo);
	certinfo = NULL;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_delete_usr_certinfo(const char *pkgid, uid_t uid)
{
	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	int ret = -1;
	/*Open db.*/
	ret = __open_cert_db(uid, "w");
	if (ret != 0) {
		_LOGE("connect db [%s] failed!\n", getUserPkgCertDBPathUID(uid));
		ret = PMINFO_R_ERROR;
		goto err;
	}
	_check_create_Cert_db(GET_DB(cert_db));
	/*Begin Transaction*/
	ret = sqlite3_exec(GET_DB(cert_db), "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to begin transaction\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	_LOGE("Transaction Begin\n");
	ret = __delete_certinfo(pkgid, uid);
	if (ret < 0) {
		_LOGE("Certificate Deletion Failed\n");
	} else {
		_LOGE("Certificate Deletion Success\n");
	}
	/*Commit transaction*/
	ret = sqlite3_exec(GET_DB(cert_db), "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to commit transaction, Rollback now\n");
		sqlite3_exec(GET_DB(cert_db), "ROLLBACK", NULL, NULL, NULL);
		ret = PMINFO_R_ERROR;
		goto err;
	}
	_LOGE("Transaction Commit and End\n");
	ret = PMINFO_R_OK;
err:
	__close_cert_db();
	return ret;
}


API int pkgmgrinfo_delete_certinfo(const char *pkgid)
{
	return pkgmgrinfo_delete_usr_certinfo(pkgid, GLOBAL_USER);
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

API int pkgmgrinfo_pkginfo_set_state_enabled(const char *pkgid, bool enabled)
{
	/* Should be implemented later */
	return 0;
}

API int pkgmgrinfo_appinfo_set_usr_state_enabled(const char *appid, bool enabled, uid_t uid)
{
	int ret;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message;

	retvm_if(appid == NULL, PMINFO_R_EINVAL, "appid is NULL\n");

	/* Open db.*/
	ret = __open_manifest_db(uid);
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n", getUserPkgParserDBPathUID(uid));
		return PMINFO_R_ERROR;
	}

	/*Begin transaction*/
	ret = sqlite3_exec(GET_DB(manifest_db), "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to begin transaction\n");
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}
	_LOGD("Transaction Begin\n");

	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN,
		"update package_app_info set app_enabled='%s' where app_id='%s'", enabled?"true":"false", appid);

	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(manifest_db), query, NULL, NULL, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return PMINFO_R_ERROR;
	}
	sqlite3_free(error_message);

	/*Commit transaction*/
	ret = sqlite3_exec(GET_DB(manifest_db), "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to commit transaction. Rollback now\n");
		sqlite3_exec(GET_DB(manifest_db), "ROLLBACK", NULL, NULL, NULL);
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}
	_LOGD("Transaction Commit and End\n");
	__close_manifest_db();
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_set_state_enabled(const char *appid, bool enabled)
{
	return pkgmgrinfo_appinfo_set_usr_state_enabled(appid, enabled, GLOBAL_USER);
}

API int pkgmgrinfo_datacontrol_get_info(const char *providerid, const char * type, char **appid, char **access)
{
	int ret;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message;
	pkgmgr_datacontrol_x *data;

	retvm_if(providerid == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(type == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(appid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	retvm_if(access == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	ret = __open_datacontrol_db();
	if (ret == -1) {
		_LOGE("Fail to open datacontrol DB\n");
		return PMINFO_R_ERROR;
	}

	data = (pkgmgr_datacontrol_x *)calloc(1, sizeof(pkgmgr_datacontrol_x));
	if (data == NULL) {
		_LOGE("Failed to allocate memory for pkgmgr_datacontrol_x\n");
		__close_datacontrol_db();
		return PMINFO_R_ERROR;
	}

	snprintf(query, MAX_QUERY_LEN, 
		"select appinfo.package_name, datacontrol.access from appinfo, datacontrol where datacontrol.id=appinfo.unique_id and datacontrol.providerid = '%s' and datacontrol.type='%s' COLLATE NOCASE",
		providerid, type);

	if (SQLITE_OK !=
		sqlite3_exec(GET_DB(datacontrol_db), query, __datacontrol_cb, (void *)data, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
			   error_message);
		sqlite3_free(error_message);
		__close_datacontrol_db();
		return PMINFO_R_ERROR;
	}

	*appid = (char *)data->appid;
	*access = (char *)data->access;
	free(data);
	__close_datacontrol_db();

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_set_usr_default_label(const char *appid, const char *label, uid_t uid)
{
	int ret;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message;

	retvm_if(appid == NULL, PMINFO_R_EINVAL, "appid is NULL\n");

	ret = __open_manifest_db(uid);
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		return PMINFO_R_ERROR;
	}

	/*Begin transaction*/
	ret = sqlite3_exec(GET_DB(manifest_db), "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to begin transaction\n");
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}
	_LOGD("Transaction Begin\n");

	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN,
		"update package_app_localized_info set app_label='%s' where app_id='%s' and app_locale='No Locale'", label, appid);

	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(manifest_db), query, NULL, NULL, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return PMINFO_R_ERROR;
	}

	/*Commit transaction*/
	ret = sqlite3_exec(GET_DB(manifest_db), "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to commit transaction. Rollback now\n");
		sqlite3_exec(GET_DB(manifest_db), "ROLLBACK", NULL, NULL, NULL);
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}
	_LOGD("Transaction Commit and End\n");
	__close_manifest_db();
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_set_default_label(const char *appid, const char *label)
{
	return pkgmgrinfo_appinfo_set_usr_default_label(appid, label, GLOBAL_USER);
}

API int pkgmgrinfo_appinfo_is_guestmode_visibility(pkgmgrinfo_appinfo_h handle, bool *status)
{
	const char *val;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(status == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	val = info->uiapp_info->guestmode_visibility;
	if (val) {
		if (strcasecmp(val, "true") == 0){
			*status = 1;
		}else if (strcasecmp(val, "false") == 0){
			*status = 0;
		}else{
			*status = 1;
		}
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_set_usr_guestmode_visibility(pkgmgrinfo_appinfo_h handle, uid_t uid, bool status)
{
	const char *val;
	int ret;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *errmsg;
	sqlite3 *pkgmgr_parser_db;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");

	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	val = info->uiapp_info->guestmode_visibility;
	if (val) {
		ret = db_util_open_with_options(getUserPkgParserDBPathUID(uid), &pkgmgr_parser_db,
				SQLITE_OPEN_READWRITE, NULL);
		if (ret != SQLITE_OK) {
			_LOGE("DB Open Failed\n");
			return PMINFO_R_ERROR;
		}

		/*TODO: Write to DB here*/
		if (status == true)
			snprintf(query, MAX_QUERY_LEN, "update package_app_info set app_guestmodevisibility = 'true' where app_id = '%s'", (char *)info->uiapp_info->appid);
		else
			snprintf(query, MAX_QUERY_LEN, "update package_app_info set app_guestmodevisibility = 'false' where app_id = '%s'", (char *)info->uiapp_info->appid);

		ret = sqlite3_exec(pkgmgr_parser_db, query, NULL, NULL, &errmsg);
		sqlite3_close(pkgmgr_parser_db);
		if (ret != SQLITE_OK) {
			_LOGE("DB update [%s] failed, error message = %s\n", query, errmsg);
			free(errmsg);
			return PMINFO_R_ERROR;
		}
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_set_guestmode_visibility(pkgmgrinfo_appinfo_h handle, bool status)
{
	return pkgmgrinfo_appinfo_set_usr_guestmode_visibility(handle, GLOBAL_USER, status);
}

/* pkgmgrinfo client start*/
API pkgmgrinfo_client *pkgmgrinfo_client_new(pkgmgrinfo_client_type ctype)
{
	char *errmsg;
	void *pc = NULL;
	void *handle;
	pkgmgrinfo_client *(*__pkgmgr_client_new)(pkgmgrinfo_client_type ctype) = NULL;

	handle = dlopen("libpkgmgr-client.so.0", RTLD_LAZY | RTLD_GLOBAL);
	retvm_if(!handle, NULL, "dlopen() failed. [%s]", dlerror());

	__pkgmgr_client_new = dlsym(handle, "pkgmgr_client_new");
	errmsg = dlerror();
	trym_if((errmsg != NULL) || (__pkgmgr_client_new == NULL), "dlsym() failed. [%s]", errmsg);

	pc = __pkgmgr_client_new(ctype);
	trym_if(pc == NULL, "pkgmgr_client_new failed.");

catch:
	dlclose(handle);
	return (pkgmgrinfo_client *) pc;
}

API int pkgmgrinfo_client_set_status_type(pkgmgrinfo_client *pc, int status_type)
{
	int ret;
	char *errmsg;
	void *handle;
	int (*__pkgmgr_client_set_status_type)(pkgmgrinfo_client *pc, int status_type) = NULL;

	handle = dlopen("libpkgmgr-client.so.0", RTLD_LAZY | RTLD_GLOBAL);
	retvm_if(!handle, PMINFO_R_ERROR, "dlopen() failed. [%s]", dlerror());

	__pkgmgr_client_set_status_type = dlsym(handle, "pkgmgr_client_set_status_type");
	errmsg = dlerror();
	tryvm_if((errmsg != NULL) || (__pkgmgr_client_set_status_type == NULL), ret = PMINFO_R_ERROR, "dlsym() failed. [%s]", errmsg);

	ret = __pkgmgr_client_set_status_type(pc, status_type);
	tryvm_if(ret < 0, ret = PMINFO_R_ERROR, "pkgmgr_client_new failed.");

catch:
        /*
         * Do not close libpkgmgr-client.so.0 to avoid munmap registered callback
         *
         * The lib dependency chain like below
         * amd --> pkgmgr-info -- dlopen --> libpkgmgr-client --> libpkgmgr-installer-client
         *
         * And there is a function in libpkgmgr-installer-client named _on_signal_handle_filter()
         * which will registered to dbus callback in amd though in fact amd doesn't direct depends
         * on libpkgmgr-installer-client.
         *
         * So when the dlcose happen, then libpkgmgr-installer-client been closed too since no one
         * link to it then.
         *
         * However, when the libdbus call into the callback function, it suddenly fond that the
         * function address is gone (unmapped), then we receive a SIGSEGV.
         *
         * I'm not sure why we're using dlopen/dlclose in this case, I think it's much simple and
         * robust if we just link to the well-known lib.
         *
         * See https://bugs.tizen.org/jira/browse/PTREL-591
	dlclose(handle);
         */
	return ret;
}

API int pkgmgrinfo_client_listen_status(pkgmgrinfo_client *pc, pkgmgrinfo_handler event_cb, void *data)
{
	int ret = 0;
	char *errmsg = NULL;
	void *handle = NULL;
	int (*__pkgmgr_client_listen_status)(pkgmgrinfo_client *pc, pkgmgrinfo_handler event_cb, void *data) = NULL;

	handle = dlopen("libpkgmgr-client.so.0", RTLD_LAZY | RTLD_GLOBAL);
	retvm_if(!handle, PMINFO_R_ERROR, "dlopen() failed. [%s]", dlerror());

	__pkgmgr_client_listen_status = dlsym(handle, "pkgmgr_client_listen_status");
	errmsg = dlerror();
	tryvm_if((errmsg != NULL) || (__pkgmgr_client_listen_status == NULL), ret = PMINFO_R_ERROR, "dlsym() failed. [%s]", errmsg);

	ret = __pkgmgr_client_listen_status(pc, event_cb, data);
	tryvm_if(ret < 0, ret = PMINFO_R_ERROR, "pkgmgr_client_new failed.");

catch:
        /* same as pkgmgrinfo_client_new */
	return ret;
}

API int pkgmgrinfo_client_free(pkgmgrinfo_client *pc)
{
	int ret = 0;
	char *errmsg = NULL;
	void *handle = NULL;
	int (*__pkgmgr_client_free)(pkgmgrinfo_client *pc) = NULL;

	handle = dlopen("libpkgmgr-client.so.0", RTLD_LAZY | RTLD_GLOBAL);
	retvm_if(!handle, PMINFO_R_ERROR, "dlopen() failed. [%s]", dlerror());

	__pkgmgr_client_free = dlsym(handle, "pkgmgr_client_free");
	errmsg = dlerror();
	tryvm_if((errmsg != NULL) || (__pkgmgr_client_free == NULL), ret = PMINFO_R_ERROR, "dlsym() failed. [%s]", errmsg);

	ret = __pkgmgr_client_free(pc);
	tryvm_if(ret < 0, ret = PMINFO_R_ERROR, "pkgmgr_client_new failed.");

catch:
        /* same as pkgmgrinfo_client_new */
	return ret;
}

API int pkgmgrinfo_client_request_enable_external_pkg(char *pkgid)
{
	DBusConnection *bus;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;

	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "pkgid is NULL\n");

	if(__get_pkg_location(pkgid) != PMINFO_EXTERNAL_STORAGE)
		return PMINFO_R_OK;

	bus = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	retvm_if(bus == NULL, PMINFO_R_EINVAL, "dbus_bus_get() failed.");

	message = dbus_message_new_method_call (SERVICE_NAME, PATH_NAME, INTERFACE_NAME, METHOD_NAME);
	trym_if(message == NULL, "dbus_message_new_method_call() failed.");

	dbus_message_append_args(message, DBUS_TYPE_STRING, &pkgid, DBUS_TYPE_INVALID);

	reply = dbus_connection_send_with_reply_and_block(bus, message, -1, NULL);
	trym_if(reply == NULL, "connection_send dbus fail");

catch:
	dbus_connection_flush(bus);
	if (message)
		dbus_message_unref(message);
	if (reply)
		dbus_message_unref(reply);

	return PMINFO_R_OK;
}

/* pkgmgrinfo client end*/

