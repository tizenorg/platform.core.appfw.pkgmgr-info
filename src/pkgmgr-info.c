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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <db-util.h>
#include <sqlite3.h>
#include <vconf.h>
#include <glib.h>
#include <ctype.h>
#include <assert.h>
#include <dlfcn.h>

#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlschemas.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "pkgmgr_parser.h"
#include "pkgmgr-info-internal.h"
#include "pkgmgr-info-debug.h"
#include "pkgmgr-info.h"
#include "pkgmgr_parser_db.h"
#include <dirent.h>
#include <sys/stat.h>

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "PKGMGR_INFO"

#define ASC_CHAR(s) (const char *)s
#define XML_CHAR(s) (const xmlChar *)s

#define MANIFEST_DB	"/opt/dbspace/.pkgmgr_parser.db"
#define MAX_QUERY_LEN	4096
#define MAX_CERT_TYPE	9
#define CERT_DB		"/opt/dbspace/.pkgmgr_cert.db"
#define DATACONTROL_DB	"/opt/usr/dbspace/.app-package.db"
#define PKG_TYPE_STRING_LEN_MAX		128
#define PKG_VERSION_STRING_LEN_MAX	128
#define PKG_VALUE_STRING_LEN_MAX		512
#define PKG_LOCALE_STRING_LEN_MAX		8
#define PKG_RW_PATH "/opt/usr/apps/"
#define PKG_RO_PATH "/usr/apps/"
#define BLOCK_SIZE      4096 /*in bytes*/

#define MMC_PATH "/opt/storage/sdcard"
#define PKG_SD_PATH MMC_PATH"/app2sd/"
#define PKG_INSTALLATION_PATH "/opt/usr/apps/"

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
#define LIBAIL_PATH "/usr/lib/libail.so.0"

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
	manifest_x *manifest_info;
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
	};
} pkgmgr_appinfo_x;

typedef struct _pkgmgr_certinfo_x {
	char *pkgid;
	char *cert_value;
	char *cert_info[MAX_CERT_TYPE];	/*certificate info*/
	int cert_id[MAX_CERT_TYPE];		/*certificate ID in index table*/
} pkgmgr_certinfo_x;

/*For filter APIs*/
typedef struct _pkgmgrinfo_filter_x {
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

char *pkgtype = "rpm";

__thread sqlite3 *cert_db = NULL;

static int __exec_certinfo_query(char *query, void *data);
static int __exec_certindexinfo_query(char *query, void *data);
static int __pkginfo_cb(void *data, int ncols, char **coltxt, char **colname);
static int __appinfo_cb(void *data, int ncols, char **coltxt, char **colname);
static int __certinfo_cb(void *data, int ncols, char **coltxt, char **colname);
static int __certindexinfo_cb(void *data, int ncols, char **coltxt, char **colname);
static int __validate_cb(void *data, int ncols, char **coltxt, char **colname);
static int __maxid_cb(void *data, int ncols, char **coltxt, char **colname);
static int __count_cb(void *data, int ncols, char **coltxt, char **colname);
static int __uiapp_list_cb(void *data, int ncols, char **coltxt, char **colname);
static int __svcapp_list_cb(void *data, int ncols, char **coltxt, char **colname);
static int __pkg_list_cb(void *data, int ncols, char **coltxt, char **colname);
static int __app_list_cb(void *data, int ncols, char **coltxt, char **colname);
static void __cleanup_pkginfo(pkgmgr_pkginfo_x *data);
static void __cleanup_appinfo(pkgmgr_appinfo_x *data);
static char* __convert_system_locale_to_manifest_locale(char *syslocale);
static void __destroy_each_node(gpointer data, gpointer user_data);
static void __get_filter_condition(gpointer data, char **condition);
static void __get_metadata_filter_condition(gpointer data, char **condition);
static gint __compare_func(gconstpointer data1, gconstpointer data2);
static int __delete_certinfo(const char *pkgid);

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

	pkgmgr_parser_free_manifest_xml(data->manifest_info);
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

	manifest_x *mfx = calloc(1, sizeof(manifest_x));
	if (data->app_component == PMINFO_UI_APP)
		mfx->uiapplication = data->uiapp_info;
	else if (data->app_component == PMINFO_SVC_APP)
		mfx->serviceapplication = data->svcapp_info;
	pkgmgr_parser_free_manifest_xml(mfx);
	free((void *)data);
	data = NULL;
	return;
}

static int __pkg_list_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_pkginfo_x *udata = (pkgmgr_pkginfo_x *)data;
	int i = 0;
	pkgmgr_pkginfo_x *info = NULL;
	info = calloc(1, sizeof(pkgmgr_pkginfo_x));
	info->manifest_info = (manifest_x *)calloc(1, sizeof(manifest_x));

	LISTADD(udata, info);
	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "package") == 0) {
			if (coltxt[i])
				info->manifest_info->package = strdup(coltxt[i]);
			else
				info->manifest_info->package = NULL;
		} else
			continue;
	}

	return 0;
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
					LISTADD(info->manifest_info->uiapplication, uiapp);
					for(j = 0; j < ncols; j++)
					{
						if ((strcmp(colname[j], "app_id") == 0) ||
							(strcmp(colname[j], "package_app_info.app_id") == 0)) {
							if (coltxt[j])
								info->manifest_info->uiapplication->appid = strdup(coltxt[j]);
						} else if (strcmp(colname[j], "package") == 0) {
							if (coltxt[j])
								info->manifest_info->uiapplication->package = strdup(coltxt[j]);
						} else
							continue;
					}
				} else {
					svcapp = calloc(1, sizeof(serviceapplication_x));
					if (svcapp == NULL) {
						_LOGE("Out of Memory!!!\n");
						return -1;
					}
					LISTADD(info->manifest_info->serviceapplication, svcapp);
					for(j = 0; j < ncols; j++)
					{
						if ((strcmp(colname[j], "app_id") == 0) ||
							(strcmp(colname[j], "package_app_info.app_id") == 0)) {
							if (coltxt[j])
								info->manifest_info->serviceapplication->appid = strdup(coltxt[j]);
						} else if (strcmp(colname[j], "package") == 0) {
							if (coltxt[j])
								info->manifest_info->serviceapplication->package = strdup(coltxt[j]);
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
	LISTADD(info->manifest_info->uiapplication, uiapp);
	icon = calloc(1, sizeof(icon_x));
	LISTADD(info->manifest_info->uiapplication->icon, icon);
	label = calloc(1, sizeof(label_x));
	LISTADD(info->manifest_info->uiapplication->label, label);

	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "app_id") == 0) {
			if (coltxt[i])
				info->manifest_info->uiapplication->appid = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->appid = NULL;
		} else if (strcmp(colname[i], "app_exec") == 0) {
			if (coltxt[i])
				info->manifest_info->uiapplication->exec = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->exec = NULL;
		} else if (strcmp(colname[i], "app_type") == 0 ){
			if (coltxt[i])
				info->manifest_info->uiapplication->type = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->type = NULL;
		} else if (strcmp(colname[i], "app_nodisplay") == 0 ){
			if (coltxt[i])
				info->manifest_info->uiapplication->nodisplay = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->nodisplay = NULL;
		} else if (strcmp(colname[i], "app_multiple") == 0 ){
			if (coltxt[i])
				info->manifest_info->uiapplication->multiple = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->multiple = NULL;
		} else if (strcmp(colname[i], "app_taskmanage") == 0 ){
			if (coltxt[i])
				info->manifest_info->uiapplication->taskmanage = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->taskmanage = NULL;
		} else if (strcmp(colname[i], "app_hwacceleration") == 0 ){
			if (coltxt[i])
				info->manifest_info->uiapplication->hwacceleration = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->hwacceleration = NULL;
		} else if (strcmp(colname[i], "app_screenreader") == 0 ){
			if (coltxt[i])
				info->manifest_info->uiapplication->screenreader = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->screenreader = NULL;
		} else if (strcmp(colname[i], "app_indicatordisplay") == 0 ){
			if (coltxt[i])
				info->manifest_info->uiapplication->indicatordisplay = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->indicatordisplay = NULL;
		} else if (strcmp(colname[i], "app_portraitimg") == 0 ){
			if (coltxt[i])
				info->manifest_info->uiapplication->portraitimg = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->portraitimg = NULL;
		} else if (strcmp(colname[i], "app_landscapeimg") == 0 ){
			if (coltxt[i])
				info->manifest_info->uiapplication->landscapeimg = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->landscapeimg = NULL;
		} else if (strcmp(colname[i], "app_guestmodevisibility") == 0 ){
			if (coltxt[i])
				info->manifest_info->uiapplication->guestmode_visibility = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->guestmode_visibility = NULL;
		} else if (strcmp(colname[i], "package") == 0 ){
			if (coltxt[i])
				info->manifest_info->uiapplication->package = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->package = NULL;
		} else if (strcmp(colname[i], "app_icon") == 0) {
			if (coltxt[i])
				info->manifest_info->uiapplication->icon->text = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->icon->text = NULL;
		} else if (strcmp(colname[i], "app_enabled") == 0 ) {
			if (coltxt[i])
				info->manifest_info->uiapplication->enabled= strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->enabled = NULL;
		} else if (strcmp(colname[i], "app_label") == 0 ) {
			if (coltxt[i])
				info->manifest_info->uiapplication->label->text = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->label->text = NULL;
		} else if (strcmp(colname[i], "app_recentimage") == 0 ) {
			if (coltxt[i])
				info->manifest_info->uiapplication->recentimage = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->recentimage = NULL;
		} else if (strcmp(colname[i], "app_mainapp") == 0 ) {
			if (coltxt[i])
				info->manifest_info->uiapplication->mainapp = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->mainapp = NULL;
		} else if (strcmp(colname[i], "app_locale") == 0 ) {
			if (coltxt[i]) {
				info->manifest_info->uiapplication->icon->lang = strdup(coltxt[i]);
				info->manifest_info->uiapplication->label->lang = strdup(coltxt[i]);
			}
			else {
				info->manifest_info->uiapplication->icon->lang = NULL;
				info->manifest_info->uiapplication->label->lang = NULL;
			}
		} else if (strcmp(colname[i], "app_permissiontype") == 0 ) {
			if (coltxt[i])
				info->manifest_info->uiapplication->permission_type = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->permission_type = NULL;
		} else if (strcmp(colname[i], "component_type") == 0 ) {
			if (coltxt[i])
				info->manifest_info->uiapplication->component_type = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->component_type = NULL;
		} else if (strcmp(colname[i], "app_preload") == 0 ) {
			if (coltxt[i])
				info->manifest_info->uiapplication->preload = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->preload = NULL;
		} else if (strcmp(colname[i], "app_submode") == 0 ) {
			if (coltxt[i])
				info->manifest_info->uiapplication->submode = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->submode = NULL;
		} else if (strcmp(colname[i], "app_submode_mainid") == 0 ) {
			if (coltxt[i])
				info->manifest_info->uiapplication->submode_mainid = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->submode_mainid = NULL;
		} else if (strcmp(colname[i], "app_installed_storage") == 0 ) {
			if (coltxt[i])
				info->manifest_info->uiapplication->installed_storage = strdup(coltxt[i]);
			else
				info->manifest_info->uiapplication->installed_storage = NULL;
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
	LISTADD(info->manifest_info->serviceapplication, svcapp);
	icon = calloc(1, sizeof(icon_x));
	LISTADD(info->manifest_info->serviceapplication->icon, icon);
	label = calloc(1, sizeof(label_x));
	LISTADD(info->manifest_info->serviceapplication->label, label);
	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "app_id") == 0) {
			if (coltxt[i])
				info->manifest_info->serviceapplication->appid = strdup(coltxt[i]);
			else
				info->manifest_info->serviceapplication->appid = NULL;
		} else if (strcmp(colname[i], "app_exec") == 0) {
			if (coltxt[i])
				info->manifest_info->serviceapplication->exec = strdup(coltxt[i]);
			else
				info->manifest_info->serviceapplication->exec = NULL;
		} else if (strcmp(colname[i], "app_type") == 0 ){
			if (coltxt[i])
				info->manifest_info->serviceapplication->type = strdup(coltxt[i]);
			else
				info->manifest_info->serviceapplication->type = NULL;
		} else if (strcmp(colname[i], "app_onboot") == 0 ){
			if (coltxt[i])
				info->manifest_info->serviceapplication->onboot = strdup(coltxt[i]);
			else
				info->manifest_info->serviceapplication->onboot = NULL;
		} else if (strcmp(colname[i], "app_autorestart") == 0 ){
			if (coltxt[i])
				info->manifest_info->serviceapplication->autorestart = strdup(coltxt[i]);
			else
				info->manifest_info->serviceapplication->autorestart = NULL;
		} else if (strcmp(colname[i], "package") == 0 ){
			if (coltxt[i])
				info->manifest_info->serviceapplication->package = strdup(coltxt[i]);
			else
				info->manifest_info->serviceapplication->package = NULL;
		} else if (strcmp(colname[i], "app_icon") == 0) {
			if (coltxt[i])
				info->manifest_info->serviceapplication->icon->text = strdup(coltxt[i]);
			else
				info->manifest_info->serviceapplication->icon->text = NULL;
		} else if (strcmp(colname[i], "app_label") == 0 ) {
			if (coltxt[i])
				info->manifest_info->serviceapplication->label->text = strdup(coltxt[i]);
			else
				info->manifest_info->serviceapplication->label->text = NULL;
		} else if (strcmp(colname[i], "app_locale") == 0 ) {
			if (coltxt[i]) {
				info->manifest_info->serviceapplication->icon->lang = strdup(coltxt[i]);
				info->manifest_info->serviceapplication->label->lang = strdup(coltxt[i]);
			}
			else {
				info->manifest_info->serviceapplication->icon->lang = NULL;
				info->manifest_info->serviceapplication->label->lang = NULL;
			}
		} else if (strcmp(colname[i], "app_permissiontype") == 0 ) {
			if (coltxt[i])
				info->manifest_info->serviceapplication->permission_type = strdup(coltxt[i]);
			else
				info->manifest_info->serviceapplication->permission_type = NULL;
		} else
			continue;
	}
	return 0;
}

static int __allapp_list_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)data;
	int i = 0;
	int j = 0;
	uiapplication_x *uiapp = NULL;
	serviceapplication_x *svcapp = NULL;
	for(j = 0; j < ncols; j++)
	{
		if (strcmp(colname[j], "app_component") == 0) {
			if (coltxt[j]) {
				if (strcmp(coltxt[j], "uiapp") == 0) {
					uiapp = calloc(1, sizeof(uiapplication_x));
					if (uiapp == NULL) {
						_LOGE("Out of Memory!!!\n");
						return -1;
					}
					LISTADD(info->manifest_info->uiapplication, uiapp);
					for(i = 0; i < ncols; i++)
					{
						if (strcmp(colname[i], "app_id") == 0) {
							if (coltxt[i])
								info->manifest_info->uiapplication->appid = strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->appid = NULL;
						} else if (strcmp(colname[i], "app_exec") == 0) {
							if (coltxt[i])
								info->manifest_info->uiapplication->exec = strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->exec = NULL;
						} else if (strcmp(colname[i], "app_type") == 0 ){
							if (coltxt[i])
								info->manifest_info->uiapplication->type = strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->type = NULL;
						} else if (strcmp(colname[i], "app_nodisplay") == 0 ){
							if (coltxt[i])
								info->manifest_info->uiapplication->nodisplay = strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->nodisplay = NULL;
						} else if (strcmp(colname[i], "app_multiple") == 0 ){
							if (coltxt[i])
								info->manifest_info->uiapplication->multiple = strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->multiple = NULL;
						} else if (strcmp(colname[i], "app_taskmanage") == 0 ){
							if (coltxt[i])
								info->manifest_info->uiapplication->taskmanage = strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->taskmanage = NULL;
						} else if (strcmp(colname[i], "app_hwacceleration") == 0 ){
							if (coltxt[i])
								info->manifest_info->uiapplication->hwacceleration = strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->hwacceleration = NULL;
						} else if (strcmp(colname[i], "app_screenreader") == 0 ){
							if (coltxt[i])
								info->manifest_info->uiapplication->screenreader = strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->screenreader = NULL;
						} else if (strcmp(colname[i], "app_indicatordisplay") == 0 ){
							if (coltxt[i])
								info->manifest_info->uiapplication->indicatordisplay = strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->indicatordisplay = NULL;
						} else if (strcmp(colname[i], "app_portraitimg") == 0 ){
							if (coltxt[i])
								info->manifest_info->uiapplication->portraitimg = strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->portraitimg = NULL;
						} else if (strcmp(colname[i], "app_landscapeimg") == 0 ){
							if (coltxt[i])
								info->manifest_info->uiapplication->landscapeimg = strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->landscapeimg = NULL;
						} else if (strcmp(colname[i], "app_guestmodevisibility") == 0 ){
							if (coltxt[i])
								info->manifest_info->uiapplication->guestmode_visibility = strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->guestmode_visibility = NULL;
						} else if (strcmp(colname[i], "package") == 0 ){
							if (coltxt[i])
								info->manifest_info->uiapplication->package = strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->package = NULL;
						} else if (strcmp(colname[i], "app_icon") == 0) {
							if (coltxt[i])
								info->manifest_info->uiapplication->icon->text = strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->icon->text = NULL;
						} else if (strcmp(colname[i], "app_label") == 0 ) {
							if (coltxt[i])
								info->manifest_info->uiapplication->label->text = strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->label->text = NULL;
						} else if (strcmp(colname[i], "app_recentimage") == 0 ) {
							if (coltxt[i])
								info->manifest_info->uiapplication->recentimage = strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->recentimage = NULL;
						} else if (strcmp(colname[i], "app_mainapp") == 0 ) {
							if (coltxt[i])
								info->manifest_info->uiapplication->mainapp= strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->mainapp = NULL;
						} else if (strcmp(colname[i], "app_locale") == 0 ) {
							if (coltxt[i]) {
								info->manifest_info->uiapplication->icon->lang = strdup(coltxt[i]);
								info->manifest_info->uiapplication->label->lang = strdup(coltxt[i]);
							}
							else {
								info->manifest_info->uiapplication->icon->lang = NULL;
								info->manifest_info->uiapplication->label->lang = NULL;
							}
						} else if (strcmp(colname[i], "app_permissiontype") == 0 ) {
							if (coltxt[i])
								info->manifest_info->uiapplication->permission_type = strdup(coltxt[i]);
							else
								info->manifest_info->uiapplication->permission_type = NULL;
						} else
							continue;
					}
				} else {
					svcapp = calloc(1, sizeof(serviceapplication_x));
					if (svcapp == NULL) {
						_LOGE("Out of Memory!!!\n");
						return -1;
					}
					LISTADD(info->manifest_info->serviceapplication, svcapp);
					for(i = 0; i < ncols; i++)
					{
						if (strcmp(colname[i], "app_id") == 0) {
							if (coltxt[i])
								info->manifest_info->serviceapplication->appid = strdup(coltxt[i]);
							else
								info->manifest_info->serviceapplication->appid = NULL;
						} else if (strcmp(colname[i], "app_exec") == 0) {
							if (coltxt[i])
								info->manifest_info->serviceapplication->exec = strdup(coltxt[i]);
							else
								info->manifest_info->serviceapplication->exec = NULL;
						} else if (strcmp(colname[i], "app_type") == 0 ){
							if (coltxt[i])
								info->manifest_info->serviceapplication->type = strdup(coltxt[i]);
							else
								info->manifest_info->serviceapplication->type = NULL;
						} else if (strcmp(colname[i], "app_onboot") == 0 ){
							if (coltxt[i])
								info->manifest_info->serviceapplication->onboot = strdup(coltxt[i]);
							else
								info->manifest_info->serviceapplication->onboot = NULL;
						} else if (strcmp(colname[i], "app_autorestart") == 0 ){
							if (coltxt[i])
								info->manifest_info->serviceapplication->autorestart = strdup(coltxt[i]);
							else
								info->manifest_info->serviceapplication->autorestart = NULL;
						} else if (strcmp(colname[i], "package") == 0 ){
							if (coltxt[i])
								info->manifest_info->serviceapplication->package = strdup(coltxt[i]);
							else
								info->manifest_info->serviceapplication->package = NULL;
						} else if (strcmp(colname[i], "app_icon") == 0) {
							if (coltxt[i])
								info->manifest_info->serviceapplication->icon->text = strdup(coltxt[i]);
							else
								info->manifest_info->serviceapplication->icon->text = NULL;
						} else if (strcmp(colname[i], "app_label") == 0 ) {
							if (coltxt[i])
								info->manifest_info->serviceapplication->label->text = strdup(coltxt[i]);
							else
								info->manifest_info->serviceapplication->label->text = NULL;
						} else if (strcmp(colname[i], "app_locale") == 0 ) {
							if (coltxt[i]) {
								info->manifest_info->serviceapplication->icon->lang = strdup(coltxt[i]);
								info->manifest_info->serviceapplication->label->lang = strdup(coltxt[i]);
							}
							else {
								info->manifest_info->serviceapplication->icon->lang = NULL;
								info->manifest_info->serviceapplication->label->lang = NULL;
							}
						} else if (strcmp(colname[i], "app_permissiontype") == 0 ) {
							if (coltxt[i])
								info->manifest_info->serviceapplication->permission_type = strdup(coltxt[i]);
							else
								info->manifest_info->serviceapplication->permission_type = NULL;
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

static int __pkginfo_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)data;
	int i = 0;
	author_x *author = NULL;
	icon_x *icon = NULL;
	label_x *label = NULL;
	description_x *description = NULL;
	privilege_x *privilege = NULL;

	author = calloc(1, sizeof(author_x));
	LISTADD(info->manifest_info->author, author);
	icon = calloc(1, sizeof(icon_x));
	LISTADD(info->manifest_info->icon, icon);
	label = calloc(1, sizeof(label_x));
	LISTADD(info->manifest_info->label, label);
	description = calloc(1, sizeof(description_x));
	LISTADD(info->manifest_info->description, description);
	privilege = calloc(1, sizeof(privilege_x));
	LISTADD(info->manifest_info->privileges->privilege, privilege);
	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "package_version") == 0) {
			if (coltxt[i])
				info->manifest_info->version = strdup(coltxt[i]);
			else
				info->manifest_info->version = NULL;
		} else if (strcmp(colname[i], "package_type") == 0) {
			if (coltxt[i])
				info->manifest_info->type = strdup(coltxt[i]);
			else
				info->manifest_info->type = NULL;
		} else if (strcmp(colname[i], "install_location") == 0) {
			if (coltxt[i])
				info->manifest_info->installlocation = strdup(coltxt[i]);
			else
				info->manifest_info->installlocation = NULL;
		} else if (strcmp(colname[i], "package_size") == 0) {
			if (coltxt[i])
				info->manifest_info->package_size = strdup(coltxt[i]);
			else
				info->manifest_info->package_size = NULL;
		} else if (strcmp(colname[i], "author_email") == 0 ){
			if (coltxt[i])
				info->manifest_info->author->email = strdup(coltxt[i]);
			else
				info->manifest_info->author->email = NULL;
		} else if (strcmp(colname[i], "author_href") == 0 ){
			if (coltxt[i])
				info->manifest_info->author->href = strdup(coltxt[i]);
			else
				info->manifest_info->author->href = NULL;
		} else if (strcmp(colname[i], "package_label") == 0 ){
			if (coltxt[i])
				info->manifest_info->label->text = strdup(coltxt[i]);
			else
				info->manifest_info->label->text = NULL;
		} else if (strcmp(colname[i], "package_icon") == 0 ){
			if (coltxt[i])
				info->manifest_info->icon->text = strdup(coltxt[i]);
			else
				info->manifest_info->icon->text = NULL;
		} else if (strcmp(colname[i], "package_description") == 0 ){
			if (coltxt[i])
				info->manifest_info->description->text = strdup(coltxt[i]);
			else
				info->manifest_info->description->text = NULL;
		} else if (strcmp(colname[i], "package_author") == 0 ){
			if (coltxt[i])
				info->manifest_info->author->text = strdup(coltxt[i]);
			else
				info->manifest_info->author->text = NULL;
		} else if (strcmp(colname[i], "package_removable") == 0 ){
			if (coltxt[i])
				info->manifest_info->removable = strdup(coltxt[i]);
			else
				info->manifest_info->removable = NULL;
		} else if (strcmp(colname[i], "package_preload") == 0 ){
			if (coltxt[i])
				info->manifest_info->preload = strdup(coltxt[i]);
			else
				info->manifest_info->preload = NULL;
		} else if (strcmp(colname[i], "package_readonly") == 0 ){
			if (coltxt[i])
				info->manifest_info->readonly = strdup(coltxt[i]);
			else
				info->manifest_info->readonly = NULL;
		} else if (strcmp(colname[i], "package_update") == 0 ){
			if (coltxt[i])
				info->manifest_info->update= strdup(coltxt[i]);
			else
				info->manifest_info->update = NULL;
		} else if (strcmp(colname[i], "package_system") == 0 ){
			if (coltxt[i])
				info->manifest_info->system= strdup(coltxt[i]);
			else
				info->manifest_info->system = NULL;
		} else if (strcmp(colname[i], "package_appsetting") == 0 ){
			if (coltxt[i])
				info->manifest_info->appsetting = strdup(coltxt[i]);
			else
				info->manifest_info->appsetting = NULL;
		} else if (strcmp(colname[i], "installed_time") == 0 ){
			if (coltxt[i])
				info->manifest_info->installed_time = strdup(coltxt[i]);
			else
				info->manifest_info->installed_time = NULL;
		} else if (strcmp(colname[i], "installed_storage") == 0 ){
			if (coltxt[i])
				info->manifest_info->installed_storage = strdup(coltxt[i]);
			else
				info->manifest_info->installed_storage = NULL;
		} else if (strcmp(colname[i], "mainapp_id") == 0 ){
			if (coltxt[i])
				info->manifest_info->mainapp_id = strdup(coltxt[i]);
			else
				info->manifest_info->mainapp_id = NULL;
		} else if (strcmp(colname[i], "storeclient_id") == 0 ){
			if (coltxt[i])
				info->manifest_info->storeclient_id = strdup(coltxt[i]);
			else
				info->manifest_info->storeclient_id = NULL;
		} else if (strcmp(colname[i], "root_path") == 0 ){
			if (coltxt[i])
				info->manifest_info->root_path = strdup(coltxt[i]);
			else
				info->manifest_info->root_path = NULL;
		} else if (strcmp(colname[i], "csc_path") == 0 ){
			if (coltxt[i])
				info->manifest_info->csc_path = strdup(coltxt[i]);
			else
				info->manifest_info->csc_path = NULL;
		} else if (strcmp(colname[i], "privilege") == 0 ){
			if (coltxt[i])
				info->manifest_info->privileges->privilege->text = strdup(coltxt[i]);
			else
				info->manifest_info->privileges->privilege->text = NULL;
		} else if (strcmp(colname[i], "package_locale") == 0 ){
			if (coltxt[i]) {
				info->manifest_info->author->lang = strdup(coltxt[i]);
				info->manifest_info->icon->lang = strdup(coltxt[i]);
				info->manifest_info->label->lang = strdup(coltxt[i]);
				info->manifest_info->description->lang = strdup(coltxt[i]);
			}
			else {
				info->manifest_info->author->lang = NULL;
				info->manifest_info->icon->lang = NULL;
				info->manifest_info->label->lang = NULL;
				info->manifest_info->description->lang = NULL;
			}
		} else if (strcmp(colname[i], "package_url") == 0 ){
			if (coltxt[i])
				info->manifest_info->package_url = strdup(coltxt[i]);
			else
				info->manifest_info->package_url = NULL;
		} else
			continue;
	}
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
		} else
			continue;
	}
	return 0;
}

static int __mini_appinfo_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)data;
	int i = 0;
	int j = 0;
	uiapplication_x *uiapp = NULL;
	serviceapplication_x *svcapp = NULL;
	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "app_component") == 0) {
			if (coltxt[i]) {
				if (strcmp(coltxt[i], "uiapp") == 0) {
					uiapp = calloc(1, sizeof(uiapplication_x));
					if (uiapp == NULL) {
						_LOGE("Out of Memory!!!\n");
						return -1;
					}
					LISTADD(info->manifest_info->uiapplication, uiapp);
					for(j = 0; j < ncols; j++)
					{
						if (strcmp(colname[j], "app_id") == 0) {
							if (coltxt[j])
								info->manifest_info->uiapplication->appid = strdup(coltxt[j]);
						} else if (strcmp(colname[j], "app_exec") == 0) {
							if (coltxt[j])
								info->manifest_info->uiapplication->exec = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->exec = NULL;
						} else if (strcmp(colname[j], "app_nodisplay") == 0) {
							if (coltxt[j])
								info->manifest_info->uiapplication->nodisplay = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->nodisplay = NULL;
						} else if (strcmp(colname[j], "app_type") == 0 ) {
							if (coltxt[j])
								info->manifest_info->uiapplication->type = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->type = NULL;
						} else if (strcmp(colname[j], "app_multiple") == 0 ) {
							if (coltxt[j])
								info->manifest_info->uiapplication->multiple = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->multiple = NULL;
						} else if (strcmp(colname[j], "app_taskmanage") == 0 ) {
							if (coltxt[j])
								info->manifest_info->uiapplication->taskmanage = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->taskmanage = NULL;
						} else if (strcmp(colname[j], "app_hwacceleration") == 0 ) {
							if (coltxt[j])
								info->manifest_info->uiapplication->hwacceleration = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->hwacceleration = NULL;
						} else if (strcmp(colname[j], "app_screenreader") == 0 ) {
							if (coltxt[j])
								info->manifest_info->uiapplication->screenreader = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->screenreader = NULL;
						} else if (strcmp(colname[j], "app_enabled") == 0 ) {
							if (coltxt[j])
								info->manifest_info->uiapplication->enabled= strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->enabled = NULL;
						} else if (strcmp(colname[j], "app_indicatordisplay") == 0){
							if (coltxt[j])
								info->manifest_info->uiapplication->indicatordisplay = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->indicatordisplay = NULL;
						} else if (strcmp(colname[j], "app_portraitimg") == 0){
							if (coltxt[j])
								info->manifest_info->uiapplication->portraitimg = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->portraitimg = NULL;
						} else if (strcmp(colname[j], "app_landscapeimg") == 0){
							if (coltxt[j])
								info->manifest_info->uiapplication->landscapeimg = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->landscapeimg = NULL;
						} else if (strcmp(colname[j], "app_guestmodevisibility") == 0){
							if (coltxt[j])
								info->manifest_info->uiapplication->guestmode_visibility = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->guestmode_visibility = NULL;
						} else if (strcmp(colname[j], "app_recentimage") == 0 ) {
							if (coltxt[j])
								info->manifest_info->uiapplication->recentimage = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->recentimage = NULL;
						} else if (strcmp(colname[j], "app_mainapp") == 0 ) {
							if (coltxt[j])
								info->manifest_info->uiapplication->mainapp = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->mainapp = NULL;
						} else if (strcmp(colname[j], "package") == 0 ) {
							if (coltxt[j])
								info->manifest_info->uiapplication->package = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->package = NULL;
						} else if (strcmp(colname[j], "app_component") == 0) {
							if (coltxt[j])
								info->manifest_info->uiapplication->app_component = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->app_component = NULL;
						} else if (strcmp(colname[j], "app_permissiontype") == 0 ) {
							if (coltxt[j])
								info->manifest_info->uiapplication->permission_type = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->permission_type = NULL;
						} else if (strcmp(colname[j], "component_type") == 0 ) {
							if (coltxt[j])
								info->manifest_info->uiapplication->component_type = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->component_type = NULL;
						} else if (strcmp(colname[j], "app_preload") == 0 ) {
							if (coltxt[j])
								info->manifest_info->uiapplication->preload = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->preload = NULL;
						} else if (strcmp(colname[j], "app_submode") == 0 ) {
							if (coltxt[j])
								info->manifest_info->uiapplication->submode = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->submode = NULL;
						} else if (strcmp(colname[j], "app_submode_mainid") == 0 ) {
							if (coltxt[j])
								info->manifest_info->uiapplication->submode_mainid = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->submode_mainid = NULL;
						} else if (strcmp(colname[j], "app_installed_storage") == 0 ) {
							if (coltxt[j])
								info->manifest_info->uiapplication->installed_storage = strdup(coltxt[j]);
							else
								info->manifest_info->uiapplication->installed_storage = NULL;
						} else
							continue;
					}
				} else {
					svcapp = calloc(1, sizeof(serviceapplication_x));
					if (svcapp == NULL) {
						_LOGE("Out of Memory!!!\n");
						return -1;
					}
					LISTADD(info->manifest_info->serviceapplication, svcapp);
					for(j = 0; j < ncols; j++)
					{
						if (strcmp(colname[j], "app_id") == 0) {
							if (coltxt[j])
								info->manifest_info->serviceapplication->appid = strdup(coltxt[j]);
						} else if (strcmp(colname[j], "app_exec") == 0) {
							if (coltxt[j])
								info->manifest_info->serviceapplication->exec = strdup(coltxt[j]);
							else
								info->manifest_info->serviceapplication->exec = NULL;
						} else if (strcmp(colname[j], "app_type") == 0 ){
							if (coltxt[j])
								info->manifest_info->serviceapplication->type = strdup(coltxt[j]);
							else
								info->manifest_info->serviceapplication->type = NULL;
						} else if (strcmp(colname[j], "app_onboot") == 0 ){
							if (coltxt[j])
								info->manifest_info->serviceapplication->onboot = strdup(coltxt[j]);
							else
								info->manifest_info->serviceapplication->onboot = NULL;
						} else if (strcmp(colname[j], "app_autorestart") == 0 ){
							if (coltxt[j])
								info->manifest_info->serviceapplication->autorestart = strdup(coltxt[j]);
							else
								info->manifest_info->serviceapplication->autorestart = NULL;
						} else if (strcmp(colname[j], "package") == 0 ){
							if (coltxt[j])
								info->manifest_info->serviceapplication->package = strdup(coltxt[j]);
							else
								info->manifest_info->serviceapplication->package = NULL;
						} else if (strcmp(colname[j], "app_permissiontype") == 0 ) {
							if (coltxt[j])
								info->manifest_info->serviceapplication->permission_type = strdup(coltxt[j]);
							else
								info->manifest_info->serviceapplication->permission_type = NULL;
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

static int __appinfo_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)data;
	int i = 0;
	icon_x *icon = NULL;
	label_x *label = NULL;
	category_x *category = NULL;
	metadata_x *metadata = NULL;
	permission_x *permission = NULL;
	image_x *image = NULL;

	switch (info->app_component) {
	case PMINFO_UI_APP:
		icon = calloc(1, sizeof(icon_x));
		LISTADD(info->uiapp_info->icon, icon);
		label = calloc(1, sizeof(label_x));
		LISTADD(info->uiapp_info->label, label);
		category = calloc(1, sizeof(category_x));
		LISTADD(info->uiapp_info->category, category);
		metadata = calloc(1, sizeof(metadata_x));
		LISTADD(info->uiapp_info->metadata, metadata);
		permission = calloc(1, sizeof(permission_x));
		LISTADD(info->uiapp_info->permission, permission);
		image = calloc(1, sizeof(image_x));
		LISTADD(info->uiapp_info->image, image);

		for(i = 0; i < ncols; i++)
		{
			if (strcmp(colname[i], "app_id") == 0) {
				/*appid being foreign key, is column in every table
				Hence appid gets strduped every time leading to memory leak.
				If appid is already set, just continue.*/
				if (info->uiapp_info->appid)
					continue;
				if (coltxt[i])
					info->uiapp_info->appid = strdup(coltxt[i]);
				else
					info->uiapp_info->appid = NULL;
			} else if (strcmp(colname[i], "app_exec") == 0) {
				if (coltxt[i])
					info->uiapp_info->exec = strdup(coltxt[i]);
				else
					info->uiapp_info->exec = NULL;
			} else if (strcmp(colname[i], "app_nodisplay") == 0) {
				if (coltxt[i])
					info->uiapp_info->nodisplay = strdup(coltxt[i]);
				else
					info->uiapp_info->nodisplay = NULL;
			} else if (strcmp(colname[i], "app_type") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->type = strdup(coltxt[i]);
				else
					info->uiapp_info->type = NULL;
			} else if (strcmp(colname[i], "app_icon_section") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->icon->section= strdup(coltxt[i]);
				else
					info->uiapp_info->icon->section = NULL;
			} else if (strcmp(colname[i], "app_icon") == 0) {
				if (coltxt[i])
					info->uiapp_info->icon->text = strdup(coltxt[i]);
				else
					info->uiapp_info->icon->text = NULL;
			} else if (strcmp(colname[i], "app_label") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->label->text = strdup(coltxt[i]);
				else
					info->uiapp_info->label->text = NULL;
			} else if (strcmp(colname[i], "app_multiple") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->multiple = strdup(coltxt[i]);
				else
					info->uiapp_info->multiple = NULL;
			} else if (strcmp(colname[i], "app_taskmanage") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->taskmanage = strdup(coltxt[i]);
				else
					info->uiapp_info->taskmanage = NULL;
			} else if (strcmp(colname[i], "app_hwacceleration") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->hwacceleration = strdup(coltxt[i]);
				else
					info->uiapp_info->hwacceleration = NULL;
			} else if (strcmp(colname[i], "app_screenreader") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->screenreader = strdup(coltxt[i]);
				else
					info->uiapp_info->screenreader = NULL;
			} else if (strcmp(colname[i], "app_enabled") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->enabled= strdup(coltxt[i]);
				else
					info->uiapp_info->enabled = NULL;
			} else if (strcmp(colname[i], "app_indicatordisplay") == 0){
				if (coltxt[i])
					info->uiapp_info->indicatordisplay = strdup(coltxt[i]);
				else
					info->uiapp_info->indicatordisplay = NULL;
			} else if (strcmp(colname[i], "app_portraitimg") == 0){
				if (coltxt[i])
					info->uiapp_info->portraitimg = strdup(coltxt[i]);
				else
					info->uiapp_info->portraitimg = NULL;
			} else if (strcmp(colname[i], "app_landscapeimg") == 0){
				if (coltxt[i])
					info->uiapp_info->landscapeimg = strdup(coltxt[i]);
				else
					info->uiapp_info->landscapeimg = NULL;
			} else if (strcmp(colname[i], "app_guestmodevisibility") == 0){
				if (coltxt[i])
					info->uiapp_info->guestmode_visibility = strdup(coltxt[i]);
				else
					info->uiapp_info->guestmode_visibility = NULL;
			} else if (strcmp(colname[i], "category") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->category->name = strdup(coltxt[i]);
				else
					info->uiapp_info->category->name = NULL;
			} else if (strcmp(colname[i], "md_key") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->metadata->key = strdup(coltxt[i]);
				else
					info->uiapp_info->metadata->key = NULL;
			} else if (strcmp(colname[i], "md_value") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->metadata->value = strdup(coltxt[i]);
				else
					info->uiapp_info->metadata->value = NULL;
			} else if (strcmp(colname[i], "pm_type") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->permission->type= strdup(coltxt[i]);
				else
					info->uiapp_info->permission->type = NULL;
			} else if (strcmp(colname[i], "pm_value") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->permission->value = strdup(coltxt[i]);
				else
					info->uiapp_info->permission->value = NULL;
			} else if (strcmp(colname[i], "app_recentimage") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->recentimage = strdup(coltxt[i]);
				else
					info->uiapp_info->recentimage = NULL;
			} else if (strcmp(colname[i], "app_mainapp") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->mainapp = strdup(coltxt[i]);
				else
					info->uiapp_info->mainapp = NULL;
			} else if (strcmp(colname[i], "app_locale") == 0 ) {
				if (coltxt[i]) {
					info->uiapp_info->icon->lang = strdup(coltxt[i]);
					info->uiapp_info->label->lang = strdup(coltxt[i]);
				}
				else {
					info->uiapp_info->icon->lang = NULL;
					info->uiapp_info->label->lang = NULL;
				}
			} else if (strcmp(colname[i], "app_image") == 0) {
					if (coltxt[i])
						info->uiapp_info->image->text= strdup(coltxt[i]);
					else
						info->uiapp_info->image->text = NULL;
			} else if (strcmp(colname[i], "app_image_section") == 0) {
					if (coltxt[i])
						info->uiapp_info->image->section= strdup(coltxt[i]);
					else
						info->uiapp_info->image->section = NULL;
			} else if (strcmp(colname[i], "app_permissiontype") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->permission_type = strdup(coltxt[i]);
				else
					info->uiapp_info->permission_type = NULL;
			} else if (strcmp(colname[i], "component_type") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->component_type = strdup(coltxt[i]);
				else
					info->uiapp_info->component_type = NULL;
			} else if (strcmp(colname[i], "app_preload") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->preload = strdup(coltxt[i]);
				else
					info->uiapp_info->preload = NULL;
			} else if (strcmp(colname[i], "app_submode") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->submode = strdup(coltxt[i]);
				else
					info->uiapp_info->submode = NULL;
			} else if (strcmp(colname[i], "app_submode_mainid") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->submode_mainid = strdup(coltxt[i]);
				else
					info->uiapp_info->submode_mainid = NULL;
			} else if (strcmp(colname[i], "app_installed_storage") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->installed_storage = strdup(coltxt[i]);
				else
					info->uiapp_info->installed_storage = NULL;
			} else
				continue;
		}
		break;
	case PMINFO_SVC_APP:
		icon = calloc(1, sizeof(icon_x));
		LISTADD(info->svcapp_info->icon, icon);
		label = calloc(1, sizeof(label_x));
		LISTADD(info->svcapp_info->label, label);
		category = calloc(1, sizeof(category_x));
		LISTADD(info->svcapp_info->category, category);
		metadata = calloc(1, sizeof(metadata_x));
		LISTADD(info->svcapp_info->metadata, metadata);
		permission = calloc(1, sizeof(permission_x));
		LISTADD(info->svcapp_info->permission, permission);
		for(i = 0; i < ncols; i++)
		{
			if (strcmp(colname[i], "app_id") == 0) {
				/*appid being foreign key, is column in every table
				Hence appid gets strduped every time leading to memory leak.
				If appid is already set, just continue.*/
				if (info->svcapp_info->appid)
					continue;
				if (coltxt[i])
					info->svcapp_info->appid = strdup(coltxt[i]);
				else
					info->svcapp_info->appid = NULL;
			} else if (strcmp(colname[i], "app_exec") == 0) {
				if (coltxt[i])
					info->svcapp_info->exec = strdup(coltxt[i]);
				else
					info->svcapp_info->exec = NULL;
			} else if (strcmp(colname[i], "app_icon") == 0) {
				if (coltxt[i])
					info->svcapp_info->icon->text = strdup(coltxt[i]);
				else
					info->svcapp_info->icon->text = NULL;
			} else if (strcmp(colname[i], "app_label") == 0 ) {
				if (coltxt[i])
					info->svcapp_info->label->text = strdup(coltxt[i]);
				else
					info->svcapp_info->label->text = NULL;
			} else if (strcmp(colname[i], "app_type") == 0 ) {
				if (coltxt[i])
					info->svcapp_info->type = strdup(coltxt[i]);
				else
					info->svcapp_info->type = NULL;
			} else if (strcmp(colname[i], "app_onboot") == 0 ) {
				if (coltxt[i])
					info->svcapp_info->onboot = strdup(coltxt[i]);
				else
					info->svcapp_info->onboot = NULL;
			} else if (strcmp(colname[i], "app_autorestart") == 0 ) {
				if (coltxt[i])
					info->svcapp_info->autorestart = strdup(coltxt[i]);
				else
					info->svcapp_info->autorestart = NULL;
			} else if (strcmp(colname[i], "app_enabled") == 0 ) {
				if (coltxt[i])
					info->svcapp_info->enabled= strdup(coltxt[i]);
				else
					info->svcapp_info->enabled = NULL;
			} else if (strcmp(colname[i], "category") == 0 ) {
				if (coltxt[i])
					info->svcapp_info->category->name = strdup(coltxt[i]);
				else
					info->svcapp_info->category->name = NULL;
			} else if (strcmp(colname[i], "md_key") == 0 ) {
				if (coltxt[i])
					info->svcapp_info->metadata->key = strdup(coltxt[i]);
				else
					info->svcapp_info->metadata->key = NULL;
			} else if (strcmp(colname[i], "md_value") == 0 ) {
				if (coltxt[i])
					info->svcapp_info->metadata->value = strdup(coltxt[i]);
				else
					info->svcapp_info->metadata->value = NULL;
			} else if (strcmp(colname[i], "pm_type") == 0 ) {
				if (coltxt[i])
					info->svcapp_info->permission->type= strdup(coltxt[i]);
				else
					info->svcapp_info->permission->type = NULL;
			} else if (strcmp(colname[i], "pm_value") == 0 ) {
				if (coltxt[i])
					info->svcapp_info->permission->value = strdup(coltxt[i]);
				else
					info->svcapp_info->permission->value = NULL;
			} else if (strcmp(colname[i], "app_locale") == 0 ) {
				if (coltxt[i]) {
					info->svcapp_info->icon->lang = strdup(coltxt[i]);
					info->svcapp_info->label->lang = strdup(coltxt[i]);
				}
				else {
					info->svcapp_info->icon->lang = NULL;
					info->svcapp_info->label->lang = NULL;
				}
			} else if (strcmp(colname[i], "app_permissiontype") == 0 ) {
				if (coltxt[i])
					info->svcapp_info->permission_type = strdup(coltxt[i]);
				else
					info->svcapp_info->permission_type = NULL;
			} else
				continue;
		}
		break;
	default:
		break;
	}

	return 0;
}


static int __appcomponent_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)data;
	int i = 0;
	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "app_component") == 0) {
			info->app_component = __appcomponent_convert(coltxt[i]);
		} else if (strcmp(colname[i], "package") == 0) {
			info->package = strdup(coltxt[i]);
		}
	}

	return 0;
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

/* get the first locale value*/
static int __fallback_locale_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_locale_x *info = (pkgmgr_locale_x *)data;

	if (ncols >= 1)
		info->locale = strdup(coltxt[0]);
	else
		info->locale = NULL;

	return 0;
}

static int __exec_certinfo_query(char *query, void *data)
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(cert_db, query, __certinfo_cb, data, &error_message)) {
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
	    sqlite3_exec(cert_db, query, __certindexinfo_cb, data, &error_message)) {
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
	if (SQLITE_OK !=
	    sqlite3_exec(db, query, callback, data, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
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

static int __check_validation_of_qurey_cb(void *data, int ncols, char **coltxt, char **colname)
{
	int *p = (int*)data;
	*p = atoi(coltxt[0]);
	return 0;
}

static int __check_app_locale_from_app_localized_info_by_exact(sqlite3 *db, const char *appid, const char *locale)
{
	int result_query = -1;
	int ret = 0;
	char query[MAX_QUERY_LEN];

	snprintf(query, MAX_QUERY_LEN, "select exists(select app_locale from package_app_localized_info where app_id='%s' and app_locale='%s')", appid, locale);
	ret = __exec_db_query(db, query, __check_validation_of_qurey_cb, (void *)&result_query);
	retvm_if(ret == -1, PMINFO_R_ERROR, "Exec DB query failed");
	return result_query;
}

static int __check_app_locale_from_app_localized_info_by_fallback(sqlite3 *db, const char *appid, const char *locale)
{
	int result_query = -1;
	int ret = 0;
	char wildcard[2] = {'%','\0'};
	char query[MAX_QUERY_LEN];
	char lang[3] = {'\0'};
	strncpy(lang, locale, LANGUAGE_LENGTH);

	snprintf(query, MAX_QUERY_LEN, "select exists(select app_locale from package_app_localized_info where app_id='%s' and app_locale like '%s%s')", appid, lang, wildcard);
	ret = __exec_db_query(db, query, __check_validation_of_qurey_cb, (void *)&result_query);
	retvm_if(ret == -1, PMINFO_R_ERROR, "Exec DB query failed");
	return result_query;
}

static char* __get_app_locale_from_app_localized_info_by_fallback(sqlite3 *db, const char *appid, const char *locale)
{
	int ret = 0;
	char wildcard[2] = {'%','\0'};
	char lang[3] = {'\0'};
	char query[MAX_QUERY_LEN];
	char *locale_new = NULL;
	pkgmgr_locale_x *info = NULL;

	info = (pkgmgr_locale_x *)malloc(sizeof(pkgmgr_locale_x));
	if (info == NULL) {
		_LOGE("Out of Memory!!!\n");
		return NULL;
	}
	memset(info, '\0', sizeof(*info));

	strncpy(lang, locale, 2);
	snprintf(query, MAX_QUERY_LEN, "select app_locale from package_app_localized_info where app_id='%s' and app_locale like '%s%s'", appid, lang, wildcard);
	ret = __exec_db_query(db, query, __fallback_locale_cb, (void *)info);
	tryvm_if(ret == -1, PMINFO_R_ERROR, "Exec DB query failed");
	locale_new = info->locale;
	free(info);
	return locale_new;
catch:
	if (info) {
		free(info);
		info = NULL;
	}
	return NULL;
}

static char* __convert_syslocale_to_manifest_locale(char *syslocale)
{
	char *locale = malloc(6);
	if (!locale) {
		_LOGE("Malloc Failed\n");
		return NULL;
	}

	sprintf(locale, "%c%c-%c%c", syslocale[0], syslocale[1], tolower(syslocale[3]), tolower(syslocale[4]));
	return locale;
}

static char* __get_app_locale_by_fallback(sqlite3 *db, const char *appid, const char *syslocale)
{
	assert(appid);
	assert(syslocale);

	char *locale = NULL;
	char *locale_new = NULL;
	int check_result = 0;

	locale = __convert_syslocale_to_manifest_locale((char *)syslocale);

	/*check exact matching */
	check_result = __check_app_locale_from_app_localized_info_by_exact(db, appid, locale);

	/* Exact found */
	if (check_result == 1) {
//		_LOGD("%s find exact locale(%s)\n", appid, locale);
		return locale;
	}

	/* fallback matching */
	check_result = __check_app_locale_from_app_localized_info_by_fallback(db, appid, locale);
	if(check_result == 1) {
		   locale_new = __get_app_locale_from_app_localized_info_by_fallback(db, appid, locale);
		   free(locale);
		   if (locale_new == NULL)
			   locale_new =  strdup(DEFAULT_LOCALE);
		   return locale_new;
	}

	/* default locale */
	free(locale);
	return	strdup(DEFAULT_LOCALE);
}

static int __delete_certinfo(const char *pkgid)
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
		            sqlite3_exec(cert_db, query, NULL, NULL, &error_message)) {
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
            sqlite3_exec(cert_db, query, NULL, NULL, &error_message)) {
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
	free(certinfo);
	certinfo = NULL;
	return ret;
}


int __reqeust_get_size(const char *pkgid, int type)
{
	int ret = 0;
	int size = 0;
	char *errmsg = NULL;
	void *pc = NULL;
	void *handle = NULL;
	FILE *fp = NULL;
	pkgmgr_client *(*__pkgmgr_client_new)(client_type ctype) = NULL;
	int (*__pkgmgr_client_get_size)(pkgmgr_client * pc, const char *pkgid, pkgmgr_getsize_type get_type, pkgmgr_handler event_cb, void *data) = NULL;
	int (*__pkgmgr_client_request_service)(pkgmgr_request_service_type service_type, int service_mode,
					  pkgmgr_client * pc, const char *pkg_type, const char *pkgid,
					  const char *custom_info, pkgmgr_handler event_cb, void *data) = NULL;

	retvm_if(pkgid == NULL, PMINFO_R_ERROR, "pkgid is NULL");

	handle = dlopen("libpkgmgr-client.so.0", RTLD_LAZY | RTLD_GLOBAL);
	retvm_if(!handle, PMINFO_R_ERROR, "dlopen() failed. [%s]", dlerror());

	__pkgmgr_client_new = dlsym(handle, "pkgmgr_client_new");
	errmsg = dlerror();
	tryvm_if((errmsg != NULL) || (__pkgmgr_client_new == NULL), ret = PMINFO_R_ERROR, "dlsym() failed. [%s]", errmsg);

	__pkgmgr_client_request_service = dlsym(handle, "pkgmgr_client_request_service");
	errmsg = dlerror();
	tryvm_if((errmsg != NULL) || (__pkgmgr_client_request_service == NULL), ret = PMINFO_R_ERROR, "dlsym() failed. [%s]", errmsg);

	pc = __pkgmgr_client_new(PC_REQUEST);
	tryvm_if(pc == NULL, ret = PMINFO_R_ERROR, "pkgmgr_client_new failed.");

	size = __pkgmgr_client_request_service(PM_REQUEST_GET_SIZE, type, pc, NULL, pkgid, NULL, NULL, NULL);
	tryvm_if(size < 0, ret = PMINFO_R_ERROR, "get size failed.");

	ret = size;

catch:
	dlclose(handle);
	return ret;
}

void __get_package_size(const char *size_info, const char *pkgid, int *total_size, int *data_size)
{
	char *p = NULL;
	p = strstr(size_info, pkgid);
	if (p == NULL)
		return;

	p += strlen(pkgid);
	if (*p == '=') {
		*total_size = atoi(p+1);

		while (*p)
		{
			if (*p == '/') {
				*data_size = atoi(p+1);
				break;
			} else {
				p++;
			}
		}
	} else {
		return;
	}

	return;
}

int __get_package_size_info(char **size_info)
{
	int ret = 0;
	char *pInfo = NULL;
	FILE *fp = NULL;
	pInfo = (char *)malloc(MAX_PKG_BUF_LEN * MAX_PKG_INFO_LEN);
	memset(pInfo, 0, MAX_PKG_BUF_LEN * MAX_PKG_INFO_LEN);

	fp = fopen(PKG_SIZE_INFO_FILE, "r");
	if (fp != NULL) {
		fread(pInfo, 1, MAX_PKG_BUF_LEN * MAX_PKG_INFO_LEN, fp);
		fclose(fp);
	}

	*size_info = pInfo;
	return PMINFO_R_OK;
}

int __set_package_size_info(manifest_x *manifest, const char* size_info)
{
	int total_size = 0;
	int data_size = 0;
	int ret = 0;
	char total_buf[PKG_TYPE_STRING_LEN_MAX] = {'\0'};
	char data_buf[PKG_TYPE_STRING_LEN_MAX] = {'\0'};

	__get_package_size(size_info, manifest->package, &total_size, &data_size);

	manifest->package_size = strdup("true");

	snprintf(total_buf, PKG_TYPE_STRING_LEN_MAX - 1, "%d", total_size);
	manifest->package_total_size = strndup(total_buf, PKG_TYPE_STRING_LEN_MAX - 1);

	snprintf(data_buf, PKG_TYPE_STRING_LEN_MAX - 1, "%d", data_size);
	manifest->package_data_size = strndup(data_buf, PKG_TYPE_STRING_LEN_MAX - 1);

	return 0;
}

static int __pkginfo_check_installed_storage(pkgmgr_pkginfo_x *pkginfo)
{
	char buf[MAX_QUERY_LEN] = {'\0'};
	retvm_if(pkginfo->manifest_info->package == NULL, PMINFO_R_OK, "pkgid is NULL\n");

	if (strcmp(pkginfo->manifest_info->installed_storage,"installed_external") == 0) {
		snprintf(buf, MAX_QUERY_LEN - 1, "%s%s", PKG_SD_PATH, pkginfo->manifest_info->package);
		if (access(buf, R_OK) != 0) {
			_LOGE("can not access [%s]", buf);
			return PMINFO_R_OK;//tmep, it will be fixed to ::  return PMINFO_R_ERROR;
		}
	}

	return PMINFO_R_OK;
}

static int __appinfo_check_installed_storage(pkgmgr_appinfo_x *appinfo)
{
	char buf[MAX_QUERY_LEN] = {'\0'};
	char *pkgid = NULL;

	pkgid = appinfo->package;
	if(pkgid == NULL)
		pkgid = appinfo->uiapp_info->package;
	retvm_if(pkgid == NULL, PMINFO_R_OK, "pkgid is NULL\n");

	if (strcmp(appinfo->uiapp_info->installed_storage,"installed_external") == 0) {
		snprintf(buf, MAX_QUERY_LEN - 1, "%s%s", PKG_SD_PATH, pkgid);
		if (access(buf, R_OK) != 0) {
			_LOGE("can not access [%s]", buf);
			return PMINFO_R_OK;//tmep, it will be fixed to ::  return PMINFO_R_ERROR;
		}
	}

	return PMINFO_R_OK;
}

static int __update_ail_appinfo(manifest_x * mfx)
{
	int ret = -1;
	uiapplication_x *uiapplication = mfx->uiapplication;
	void *lib_handle = NULL;
	int (*ail_desktop_operation) (const char *appid, const char *property, const char *value, bool broadcast);
	char *aop = NULL;

	if ((lib_handle = dlopen(LIBAIL_PATH, RTLD_LAZY)) == NULL) {
		_LOGE("dlopen is failed LIBAIL_PATH[%s]\n", LIBAIL_PATH);
		goto END;
	}

	aop  = "ail_desktop_appinfo_modify_str";

	if ((ail_desktop_operation =
	     dlsym(lib_handle, aop)) == NULL || dlerror() != NULL) {
		_LOGE("can not find symbol \n");
		goto END;
	}

	for(; uiapplication; uiapplication=uiapplication->next) {
		ret = ail_desktop_operation(uiapplication->appid, "AIL_PROP_X_SLP_INSTALLEDSTORAGE_STR", mfx->installed_storage, FALSE);
		if (ret != 0)
			_LOGE("Failed to store info in DB\n");
	}

END:
	if (lib_handle)
		dlclose(lib_handle);

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

API int pkgmgrinfo_pkginfo_get_list(pkgmgrinfo_pkg_list_cb pkg_list_cb, void *user_data)
{
	retvm_if(pkg_list_cb == NULL, PMINFO_R_EINVAL, "callback function is NULL\n");
	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *syslocale = NULL;
	char *locale = NULL;
	pkgmgr_pkginfo_x *pkginfo = NULL;
	label_x *tmp1 = NULL;
	icon_x *tmp2 = NULL;
	description_x *tmp3 = NULL;
	author_x *tmp4 = NULL;
	privilege_x *tmp5 = NULL;
	sqlite3 *pkginfo_db = NULL;

	/*open db*/
	ret = db_util_open(MANIFEST_DB, &pkginfo_db, 0);
	retvm_if(ret != SQLITE_OK, PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	/*get system locale*/
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	tryvm_if(locale == NULL, ret = PMINFO_R_ERROR, "manifest locale is NULL");

	pkgmgr_pkginfo_x *tmphead = (pkgmgr_pkginfo_x *)calloc(1, sizeof(pkgmgr_pkginfo_x));
	pkgmgr_pkginfo_x *node = NULL;
	pkgmgr_pkginfo_x *temp_node = NULL;

	snprintf(query, MAX_QUERY_LEN, "select * from package_info");
	ret = __exec_db_query(pkginfo_db, query, __pkg_list_cb, (void *)tmphead);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");

	LISTHEAD(tmphead, node);

	for(node = node->next; node ; node = node->next) {
		pkginfo = node;
		pkginfo->locale = strdup(locale);
		pkginfo->manifest_info->privileges = (privileges_x *)calloc(1, sizeof(privileges_x));
		tryvm_if(pkginfo->manifest_info->privileges == NULL, ret = PMINFO_R_ERROR, "Failed to allocate memory for privileges info\n");

		/*populate manifest_info from DB*/
		snprintf(query, MAX_QUERY_LEN, "select * from package_info where package='%s' ", pkginfo->manifest_info->package);
		ret = __exec_db_query(pkginfo_db, query, __pkginfo_cb, (void *)pkginfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");

		memset(query, '\0', MAX_QUERY_LEN);
		/*populate privilege_info from DB*/
		snprintf(query, MAX_QUERY_LEN, "select * from package_privilege_info where package='%s' ", pkginfo->manifest_info->package);
		ret = __exec_db_query(pkginfo_db, query, __pkginfo_cb, (void *)pkginfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package privilege Info DB Information retrieval failed");

		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select * from package_localized_info where" \
			" package='%s' and package_locale='%s'", pkginfo->manifest_info->package, locale);
		ret = __exec_db_query(pkginfo_db, query, __pkginfo_cb, (void *)pkginfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");

		/*Also store the values corresponding to default locales*/
		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select * from package_localized_info where" \
			" package='%s' and package_locale='%s'", pkginfo->manifest_info->package, DEFAULT_LOCALE);
		ret = __exec_db_query(pkginfo_db, query, __pkginfo_cb, (void *)pkginfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");

		if (pkginfo->manifest_info->label) {
			LISTHEAD(pkginfo->manifest_info->label, tmp1);
			pkginfo->manifest_info->label = tmp1;
		}
		if (pkginfo->manifest_info->icon) {
			LISTHEAD(pkginfo->manifest_info->icon, tmp2);
			pkginfo->manifest_info->icon = tmp2;
		}
		if (pkginfo->manifest_info->description) {
			LISTHEAD(pkginfo->manifest_info->description, tmp3);
			pkginfo->manifest_info->description = tmp3;
		}
		if (pkginfo->manifest_info->author) {
			LISTHEAD(pkginfo->manifest_info->author, tmp4);
			pkginfo->manifest_info->author = tmp4;
		}
		if (pkginfo->manifest_info->privileges->privilege) {
			LISTHEAD(pkginfo->manifest_info->privileges->privilege, tmp5);
			pkginfo->manifest_info->privileges->privilege = tmp5;
		}
	}

	LISTHEAD(tmphead, node);

	for(node = node->next; node ; node = node->next) {
		pkginfo = node;

		ret = __pkginfo_check_installed_storage(pkginfo);
		if(ret < 0)
			continue;

		ret = pkg_list_cb( (void *)pkginfo, user_data);
		if(ret < 0)
			break;
	}

	ret = PMINFO_R_OK;

catch:
	sqlite3_close(pkginfo_db);
	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	if (locale) {
		free(locale);
		locale = NULL;
	}
	LISTHEAD(tmphead, node);
	temp_node = node->next;
	node = temp_node;
	while (node) {
		temp_node = node->next;
		__cleanup_pkginfo(node);
		node = temp_node;
	}
	__cleanup_pkginfo(tmphead);
	return ret;
}


API int pkgmgrinfo_pkginfo_get_pkginfo(const char *pkgid, pkgmgrinfo_pkginfo_h *handle)
{
	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "pkgid is NULL\n");
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_pkginfo_x *pkginfo = NULL;
	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *syslocale = NULL;
	char *locale = NULL;
	int exist = 0;
	label_x *tmp1 = NULL;
	icon_x *tmp2 = NULL;
	description_x *tmp3 = NULL;
	author_x *tmp4 = NULL;
	privilege_x *tmp5 = NULL;
	sqlite3 *pkginfo_db = NULL;

	/*validate pkgid*/
	ret = db_util_open(MANIFEST_DB, &pkginfo_db, 0);
	retvm_if(ret != SQLITE_OK, PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	/*check pkgid exist on db*/
	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_info where package='%s')", pkgid);
	ret = __exec_db_query(pkginfo_db, query, __validate_cb, (void *)&exist);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "sqlite3_exec[%s] fail", pkgid);
	tryvm_if(exist == 0, ret = PMINFO_R_ERROR, "pkgid[%s] not found in DB", pkgid);

	/*get system locale*/
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	tryvm_if(locale == NULL, ret = PMINFO_R_ERROR, "manifest locale is NULL");

	pkginfo = (pkgmgr_pkginfo_x *)calloc(1, sizeof(pkgmgr_pkginfo_x));
	tryvm_if(pkginfo == NULL, ret = PMINFO_R_ERROR, "Failed to allocate memory for pkginfo");

	pkginfo->locale = strdup(locale);

	pkginfo->manifest_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	tryvm_if(pkginfo->manifest_info == NULL, ret = PMINFO_R_ERROR, "Failed to allocate memory for manifest info");

	pkginfo->manifest_info->package = strdup(pkgid);
	pkginfo->manifest_info->privileges = (privileges_x *)calloc(1, sizeof(privileges_x));
	tryvm_if(pkginfo->manifest_info->privileges == NULL, ret = PMINFO_R_ERROR, "Failed to allocate memory for privileges info");

	/*populate manifest_info from DB*/
	snprintf(query, MAX_QUERY_LEN, "select * from package_info where package='%s' ", pkgid);
	ret = __exec_db_query(pkginfo_db, query, __pkginfo_cb, (void *)pkginfo);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");

	memset(query, '\0', MAX_QUERY_LEN);
	/*populate privilege_info from DB*/
	snprintf(query, MAX_QUERY_LEN, "select * from package_privilege_info where package='%s' ", pkgid);
	ret = __exec_db_query(pkginfo_db, query, __pkginfo_cb, (void *)pkginfo);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Privilege Info DB Information retrieval failed");

	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select * from package_localized_info where" \
		" package='%s' and package_locale='%s'", pkgid, locale);
	ret = __exec_db_query(pkginfo_db, query, __pkginfo_cb, (void *)pkginfo);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");

	/*Also store the values corresponding to default locales*/
	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select * from package_localized_info where" \
		" package='%s' and package_locale='%s'", pkgid, DEFAULT_LOCALE);
	ret = __exec_db_query(pkginfo_db, query, __pkginfo_cb, (void *)pkginfo);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");

	if (pkginfo->manifest_info->label) {
		LISTHEAD(pkginfo->manifest_info->label, tmp1);
		pkginfo->manifest_info->label = tmp1;
	}
	if (pkginfo->manifest_info->icon) {
		LISTHEAD(pkginfo->manifest_info->icon, tmp2);
		pkginfo->manifest_info->icon = tmp2;
	}
	if (pkginfo->manifest_info->description) {
		LISTHEAD(pkginfo->manifest_info->description, tmp3);
		pkginfo->manifest_info->description = tmp3;
	}
	if (pkginfo->manifest_info->author) {
		LISTHEAD(pkginfo->manifest_info->author, tmp4);
		pkginfo->manifest_info->author = tmp4;
	}
	if (pkginfo->manifest_info->privileges->privilege) {
		LISTHEAD(pkginfo->manifest_info->privileges->privilege, tmp5);
		pkginfo->manifest_info->privileges->privilege = tmp5;
	}

	ret = __pkginfo_check_installed_storage(pkginfo);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "[%s] is installed external, but is not in mmc", pkgid);

catch:
	if (ret == PMINFO_R_OK)
		*handle = (void*)pkginfo;
	else {
		*handle = NULL;
		__cleanup_pkginfo(pkginfo);
	}
	sqlite3_close(pkginfo_db);

	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	if (locale) {
		free(locale);
		locale = NULL;
	}
	return ret;
}


API int pkgmgrinfo_pkginfo_get_pkgname(pkgmgrinfo_pkginfo_h handle, char **pkg_name)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(pkg_name == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	if (info->manifest_info->package)
		*pkg_name = (char *)info->manifest_info->package;
	else
		return PMINFO_R_ERROR;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_pkgid(pkgmgrinfo_pkginfo_h handle, char **pkgid)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	if (info->manifest_info->package)
		*pkgid = (char *)info->manifest_info->package;
	else
		return PMINFO_R_ERROR;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_type(pkgmgrinfo_pkginfo_h handle, char **type)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(type == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	if (info->manifest_info->type)
		*type = (char *)info->manifest_info->type;
	else
		*type = pkgtype;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_version(pkgmgrinfo_pkginfo_h handle, char **version)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(version == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	*version = (char *)info->manifest_info->version;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_install_location(pkgmgrinfo_pkginfo_h handle, pkgmgrinfo_install_location *location)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(location == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	char *val = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	val = (char *)info->manifest_info->installlocation;
	if (val) {
		if (strcmp(val, "internal-only") == 0)
			*location = PMINFO_INSTALL_LOCATION_INTERNAL_ONLY;
		else if (strcmp(val, "prefer-external") == 0)
			*location = PMINFO_INSTALL_LOCATION_PREFER_EXTERNAL;
		else
			*location = PMINFO_INSTALL_LOCATION_AUTO;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_package_size(pkgmgrinfo_pkginfo_h handle, int *size)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(size == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	char *val = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	val = (char *)info->manifest_info->package_size;
	if (val) {
		*size = atoi(val);
	} else {
		*size = 0;
		_LOGE("package size is not specified\n");
		return PMINFO_R_ERROR;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_total_size(pkgmgrinfo_pkginfo_h handle, int *size)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(size == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	int ret = -1;
	char *pkgid = NULL;
	char *val = NULL;

	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	val = (char *)info->manifest_info->package_size;
	if (strcmp(val, "true") == 0) {
		*size = atoi(info->manifest_info->package_total_size);
		return 0;
	} else {
		*size = 0;
		return 0;
	}
}

API int pkgmgrinfo_pkginfo_get_data_size(pkgmgrinfo_pkginfo_h handle, int *size)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(size == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	int ret = -1;
	char *pkgid = NULL;
	char *val = NULL;

	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	val = (char *)info->manifest_info->package_size;
	if (strcmp(val, "true") == 0) {
		*size = atoi(info->manifest_info->package_data_size);
		return 0;
	} else {
		*size = 0;
		return 0;
	}
}

API int pkgmgrinfo_pkginfo_get_size_info(pkgmgrinfo_pkginfo_h handle, int *total_size, int *data_size)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(total_size == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	retvm_if(data_size == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	int ret = -1;
	int total_tmp = 0;
	int data_tmp = 0;
	char *val = NULL;
	char *pkgid = NULL;
	char* package_size_info = NULL;

	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	val = (char *)info->manifest_info->package_size;
	if (strcmp(val, "true") == 0) {
		*total_size = atoi(info->manifest_info->package_total_size);
		*data_size = atoi(info->manifest_info->package_data_size);
		return 0;
	} else {
		*total_size = 0;
		*data_size = 0;

		return 0;
	}
	return -1;
}

API int pkgmgrinfo_pkginfo_get_icon(pkgmgrinfo_pkginfo_h handle, char **icon)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL");
	retvm_if(icon == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	int ret = PMINFO_R_OK;
	char *locale = NULL;
	icon_x *ptr = NULL;
	*icon = NULL;

	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	locale = info->locale;
	retvm_if(locale == NULL, PMINFO_R_ERROR, "manifest locale is NULL");

	for(ptr = info->manifest_info->icon; ptr != NULL; ptr = ptr->next)
	{
		if (ptr->lang) {
			if (strcmp(ptr->lang, locale) == 0) {
				*icon = (char *)ptr->text;
				if (strcasecmp(*icon, "(null)") == 0) {
					locale = DEFAULT_LOCALE;
					continue;
				} else
					break;
			} else if (strcmp(ptr->lang, DEFAULT_LOCALE) == 0) {
				*icon = (char *)ptr->text;
				break;
			}
		}
	}

	return ret;
}

API int pkgmgrinfo_pkginfo_get_label(pkgmgrinfo_pkginfo_h handle, char **label)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL");
	retvm_if(label == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	int ret = PMINFO_R_OK;
	char *locale = NULL;
	label_x *ptr = NULL;
	*label = NULL;

	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	locale = info->locale;
	retvm_if(locale == NULL, PMINFO_R_ERROR, "manifest locale is NULL");

	for(ptr = info->manifest_info->label; ptr != NULL; ptr = ptr->next)
	{
		if (ptr->lang) {
			if (strcmp(ptr->lang, locale) == 0) {
				*label = (char *)ptr->text;
				if (strcasecmp(*label, "(null)") == 0) {
					locale = DEFAULT_LOCALE;
					continue;
				} else
					break;
			} else if (strcmp(ptr->lang, DEFAULT_LOCALE) == 0) {
				*label = (char *)ptr->text;
				break;
			}
		}
	}

	return ret;
}

API int pkgmgrinfo_pkginfo_get_description(pkgmgrinfo_pkginfo_h handle, char **description)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(description == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	char *locale = NULL;
	description_x *ptr = NULL;
	*description = NULL;

	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	locale = info->locale;
	retvm_if(locale == NULL, PMINFO_R_ERROR, "manifest locale is NULL");

	for(ptr = info->manifest_info->description; ptr != NULL; ptr = ptr->next)
	{
		if (ptr->lang) {
			if (strcmp(ptr->lang, locale) == 0) {
				*description = (char *)ptr->text;
				if (strcasecmp(*description, PKGMGR_PARSER_EMPTY_STR) == 0) {
					locale = DEFAULT_LOCALE;
					continue;
				} else
					break;
			} else if (strcmp(ptr->lang, DEFAULT_LOCALE) == 0) {
				*description = (char *)ptr->text;
				break;
			}
		}
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_author_name(pkgmgrinfo_pkginfo_h handle, char **author_name)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(author_name == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	char *locale = NULL;
	author_x *ptr = NULL;
	*author_name = NULL;

	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	locale = info->locale;
	retvm_if(locale == NULL, PMINFO_R_ERROR, "manifest locale is NULL");

	for(ptr = info->manifest_info->author; ptr != NULL; ptr = ptr->next)
	{
		if (ptr->lang) {
			if (strcmp(ptr->lang, locale) == 0) {
				*author_name = (char *)ptr->text;
				if (strcasecmp(*author_name, PKGMGR_PARSER_EMPTY_STR) == 0) {
					locale = DEFAULT_LOCALE;
					continue;
				} else
					break;
			} else if (strcmp(ptr->lang, DEFAULT_LOCALE) == 0) {
				*author_name = (char *)ptr->text;
				break;
			}
		}
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_author_email(pkgmgrinfo_pkginfo_h handle, char **author_email)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(author_email == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	*author_email = (char *)info->manifest_info->author->email;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_author_href(pkgmgrinfo_pkginfo_h handle, char **author_href)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(author_href == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	*author_href = (char *)info->manifest_info->author->href;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_installed_storage(pkgmgrinfo_pkginfo_h handle, pkgmgrinfo_installed_storage *storage)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(storage == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	 if (strcmp(info->manifest_info->installed_storage,"installed_internal") == 0)
	 	*storage = PMINFO_INTERNAL_STORAGE;
	 else if (strcmp(info->manifest_info->installed_storage,"installed_external") == 0)
		 *storage = PMINFO_EXTERNAL_STORAGE;
	 else
		 return PMINFO_R_ERROR;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_installed_time(pkgmgrinfo_pkginfo_h handle, int *installed_time)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(installed_time == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	if (info->manifest_info->installed_time)
		*installed_time = atoi(info->manifest_info->installed_time);
	else
		return PMINFO_R_ERROR;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_storeclientid(pkgmgrinfo_pkginfo_h handle, char **storeclientid)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(storeclientid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	*storeclientid = (char *)info->manifest_info->storeclient_id;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_mainappid(pkgmgrinfo_pkginfo_h handle, char **mainappid)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(mainappid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	*mainappid = (char *)info->manifest_info->mainapp_id;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_url(pkgmgrinfo_pkginfo_h handle, char **url)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(url == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	*url = (char *)info->manifest_info->package_url;
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

	if (reader){
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
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(path == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	if (info->manifest_info->root_path)
		*path = (char *)info->manifest_info->root_path;
	else
		return PMINFO_R_ERROR;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_csc_path(pkgmgrinfo_pkginfo_h handle, char **path)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(path == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	if (info->manifest_info->csc_path)
		*path = (char *)info->manifest_info->csc_path;
	else
		*path = (char *)info->manifest_info->csc_path;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_compare_pkg_cert_info(const char *lhs_package_id, const char *rhs_package_id, pkgmgrinfo_cert_compare_result_type_e *compare_result)
{
	retvm_if(lhs_package_id == NULL, PMINFO_R_EINVAL, "lhs package ID is NULL");
	retvm_if(rhs_package_id == NULL, PMINFO_R_EINVAL, "rhs package ID is NULL");
	retvm_if(compare_result == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message = NULL;
	pkgmgr_cert_x *info= NULL;
	int lcert = 0;
	int rcert = 0;
	int exist = -1;
	*compare_result = PMINFO_CERT_COMPARE_ERROR;
	info = (pkgmgr_cert_x *)calloc(1, sizeof(pkgmgr_cert_x));
	retvm_if(info == NULL, PMINFO_R_ERROR, "Out of Memory!!!");

	ret = db_util_open_with_options(CERT_DB, &cert_db, SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n", CERT_DB);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", lhs_package_id);
	if (SQLITE_OK !=
	    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	if (exist == 0) {
		lcert = 0;
	} else {
		snprintf(query, MAX_QUERY_LEN, "select author_signer_cert from package_cert_info where package='%s'", lhs_package_id);
		if (SQLITE_OK !=
			sqlite3_exec(cert_db, query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto err;
		}
		lcert = info->cert_id;
	}

	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", rhs_package_id);
	if (SQLITE_OK !=
		sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
			   error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	if (exist == 0) {
		rcert = 0;
	} else {
		snprintf(query, MAX_QUERY_LEN, "select author_signer_cert from package_cert_info where package='%s'", rhs_package_id);
		if (SQLITE_OK !=
			sqlite3_exec(cert_db, query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto err;
		}
		rcert = info->cert_id;
	}

	if ((lcert == 0) || (rcert == 0))
	{
		if ((lcert == 0) && (rcert == 0))
			*compare_result = PMINFO_CERT_COMPARE_BOTH_NO_CERT;
		else if (lcert == 0)
			*compare_result = PMINFO_CERT_COMPARE_LHS_NO_CERT;
		else if (rcert == 0)
			*compare_result = PMINFO_CERT_COMPARE_RHS_NO_CERT;
	} else {
		if (lcert == rcert)
			*compare_result = PMINFO_CERT_COMPARE_MATCH;
		else
			*compare_result = PMINFO_CERT_COMPARE_MISMATCH;
	}

err:
	sqlite3_free(error_message);
	sqlite3_close(cert_db);
	if (info) {
		if (info->pkgid) {
			free(info->pkgid);
			info->pkgid = NULL;
		}
		free(info);
		info = NULL;
	}
	return ret;
}


API int pkgmgrinfo_pkginfo_compare_app_cert_info(const char *lhs_app_id, const char *rhs_app_id, pkgmgrinfo_cert_compare_result_type_e *compare_result)
{
	retvm_if(lhs_app_id == NULL, PMINFO_R_EINVAL, "lhs app ID is NULL");
	retvm_if(rhs_app_id == NULL, PMINFO_R_EINVAL, "rhs app ID is NULL");
	retvm_if(compare_result == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message = NULL;
	pkgmgr_cert_x *info= NULL;
 	int exist = -1;
	char *lpkgid = NULL;
	char *rpkgid = NULL;
	sqlite3 *pkginfo_db = NULL;

	info = (pkgmgr_cert_x *)calloc(1, sizeof(pkgmgr_cert_x));
	retvm_if(info == NULL, PMINFO_R_ERROR, "Out of Memory!!!");

	ret = db_util_open(MANIFEST_DB, &pkginfo_db, 0);
	tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_app_info where app_id='%s')", lhs_app_id);
	if (SQLITE_OK !=
	    sqlite3_exec(pkginfo_db, query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		ret = PMINFO_R_ERROR;
		goto catch;
	}

	if (exist == 0) {
		lpkgid = NULL;
	} else {
		snprintf(query, MAX_QUERY_LEN, "select package from package_app_info where app_id='%s' ", lhs_app_id);
		if (SQLITE_OK !=
			sqlite3_exec(pkginfo_db, query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto catch;
		}
		lpkgid = strdup(info->pkgid);
		if (lpkgid == NULL) {
			_LOGE("Out of Memory\n");
			ret = PMINFO_R_ERROR;
			goto catch;
		}
		free(info->pkgid);
		info->pkgid = NULL;
	}

	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_app_info where app_id='%s')", rhs_app_id);
	if (SQLITE_OK !=
	    sqlite3_exec(pkginfo_db, query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		ret = PMINFO_R_ERROR;
		goto catch;
	}

	if (exist == 0) {
		rpkgid = NULL;
	} else {
		snprintf(query, MAX_QUERY_LEN, "select package from package_app_info where app_id='%s' ", rhs_app_id);
		if (SQLITE_OK !=
			sqlite3_exec(pkginfo_db, query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto catch;
		}
		rpkgid = strdup(info->pkgid);
		if (rpkgid == NULL) {
			_LOGE("Out of Memory\n");
			ret = PMINFO_R_ERROR;
			goto catch;
		}
		free(info->pkgid);
		info->pkgid = NULL;
	}
	ret = pkgmgrinfo_pkginfo_compare_pkg_cert_info(lpkgid, rpkgid, compare_result);

 catch:
	sqlite3_free(error_message);
	sqlite3_close(pkginfo_db);
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
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(removable == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	char *val = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	val = (char *)info->manifest_info->removable;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*removable = 1;
		else if (strcasecmp(val, "false") == 0)
			*removable = 0;
		else
			*removable = 1;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_movable(pkgmgrinfo_pkginfo_h handle, bool *movable)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(movable == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	char *val = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;

	val = (char *)info->manifest_info->installlocation;
	if (val) {
		if (strcmp(val, "internal-only") == 0)
			*movable = 0;
		else if (strcmp(val, "prefer-external") == 0)
			*movable = 1;
		else
			*movable = 1;
	}

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_preload(pkgmgrinfo_pkginfo_h handle, bool *preload)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(preload == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	char *val = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	val = (char *)info->manifest_info->preload;
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

API int pkgmgrinfo_pkginfo_is_system(pkgmgrinfo_pkginfo_h handle, bool *system)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(system == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	char *val = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	val = (char *)info->manifest_info->system;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*system = 1;
		else if (strcasecmp(val, "false") == 0)
			*system = 0;
		else
			*system = 0;
	}

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_readonly(pkgmgrinfo_pkginfo_h handle, bool *readonly)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(readonly == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	char *val = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	val = (char *)info->manifest_info->readonly;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*readonly = 1;
		else if (strcasecmp(val, "false") == 0)
			*readonly = 0;
		else
			*readonly = 0;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_update(pkgmgrinfo_pkginfo_h handle, bool *update)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	retvm_if(update == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	char *val = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	val = (char *)info->manifest_info->update;
	if (val) {
		if (strcasecmp(val, "true") == 0)
			*update = 1;
		else if (strcasecmp(val, "false") == 0)
			*update = 0;
		else
			*update = 1;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_destroy_pkginfo(pkgmgrinfo_pkginfo_h handle)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL\n");
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	__cleanup_pkginfo(info);
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_filter_create(pkgmgrinfo_pkginfo_filter_h *handle)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle output parameter is NULL\n");
	*handle = NULL;
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)calloc(1, sizeof(pkgmgrinfo_filter_x));
	if (filter == NULL) {
		_LOGE("Out of Memory!!!");
		return PMINFO_R_ERROR;
	}
	*handle = filter;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_filter_destroy(pkgmgrinfo_pkginfo_filter_h handle)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)handle;
	if (filter->list){
		g_slist_foreach(filter->list, __destroy_each_node, NULL);
		g_slist_free(filter->list);
	}
	free(filter);
	filter = NULL;

	if (access(PKG_SIZE_INFO_FILE, F_OK) == 0) {
		char info_file[PKG_VALUE_STRING_LEN_MAX] = { 0, };
		snprintf(info_file, PKG_VALUE_STRING_LEN_MAX, "%s", PKG_SIZE_INFO_FILE);
		remove(info_file);
	}

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_filter_add_int(pkgmgrinfo_pkginfo_filter_h handle,
				const char *property, const int value)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(property == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	char buf[PKG_VALUE_STRING_LEN_MAX] = {'\0'};
	char *val = NULL;
	GSList *link = NULL;
	int prop = -1;
	prop = _pminfo_pkginfo_convert_to_prop_int(property);
	if (prop < E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_INT ||
		prop > E_PMINFO_PKGINFO_PROP_PACKAGE_MAX_INT) {
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

API int pkgmgrinfo_pkginfo_filter_add_bool(pkgmgrinfo_pkginfo_filter_h handle,
				const char *property, const bool value)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(property == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	char *val = NULL;
	GSList *link = NULL;
	int prop = -1;
	prop = _pminfo_pkginfo_convert_to_prop_bool(property);
	if (prop < E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_BOOL ||
		prop > E_PMINFO_PKGINFO_PROP_PACKAGE_MAX_BOOL) {
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

API int pkgmgrinfo_pkginfo_filter_add_string(pkgmgrinfo_pkginfo_filter_h handle,
				const char *property, const char *value)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(property == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(value == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	char *val = NULL;
	GSList *link = NULL;
	int prop = -1;
	prop = _pminfo_pkginfo_convert_to_prop_str(property);
	if (prop < E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_STR ||
		prop > E_PMINFO_PKGINFO_PROP_PACKAGE_MAX_STR) {
		_LOGE("Invalid String Property\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)handle;
	pkgmgrinfo_node_x *node = (pkgmgrinfo_node_x*)calloc(1, sizeof(pkgmgrinfo_node_x));
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

API int pkgmgrinfo_pkginfo_filter_count(pkgmgrinfo_pkginfo_filter_h handle, int *count)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(count == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	char *syslocale = NULL;
	char *locale = NULL;
	char *condition = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	char where[MAX_QUERY_LEN] = {'\0'};
	GSList *list;
	int ret = 0;
	pkgmgr_pkginfo_x *node = NULL;
	pkgmgr_pkginfo_x *tmphead = NULL;
	pkgmgr_pkginfo_x *pkginfo = NULL;
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)handle;
	sqlite3 *pkginfo_db = NULL;
	int filter_count = 0;

	/*open db*/
	ret = db_util_open(MANIFEST_DB, &pkginfo_db, 0);
	retvm_if(ret != SQLITE_OK, PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	/*get system locale*/
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	tryvm_if(locale == NULL, ret = PMINFO_R_ERROR, "manifest locale is NULL");

	/*Start constructing query*/
	snprintf(query, MAX_QUERY_LEN - 1, FILTER_QUERY_LIST_PACKAGE, locale);

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
	_LOGE("where = %s\n", where);
	if (strlen(where) > 0) {
		strncat(query, where, sizeof(query) - strlen(query) - 1);
		query[sizeof(query) - 1] = '\0';
	}
	_LOGE("query = %s\n", query);

	tmphead = calloc(1, sizeof(pkgmgr_pkginfo_x));
	tryvm_if(tmphead == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	ret = __exec_db_query(pkginfo_db, query, __pkg_list_cb, (void *)tmphead);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");

	LISTHEAD(tmphead, node);
	for(node = node->next ; node ; node = node->next) {
		pkginfo = node;
		pkginfo->locale = strdup(locale);
		pkginfo->manifest_info->privileges = (privileges_x *)calloc(1, sizeof(privileges_x));
		tryvm_if(pkginfo->manifest_info->privileges == NULL, ret = PMINFO_R_ERROR, "Failed to allocate memory for privileges info\n");

		/*populate manifest_info from DB*/
		snprintf(query, MAX_QUERY_LEN, "select * from package_info where package='%s' ", pkginfo->manifest_info->package);
		ret = __exec_db_query(pkginfo_db, query, __pkginfo_cb, (void *)pkginfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");

		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select * from package_localized_info where" \
			" package='%s' and package_locale='%s'", pkginfo->manifest_info->package, locale);
		ret = __exec_db_query(pkginfo_db, query, __pkginfo_cb, (void *)pkginfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");

		/*Also store the values corresponding to default locales*/
		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select * from package_localized_info where" \
			" package='%s' and package_locale='%s'", pkginfo->manifest_info->package, DEFAULT_LOCALE);
		ret = __exec_db_query(pkginfo_db, query, __pkginfo_cb, (void *)pkginfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");
	}

	LISTHEAD(tmphead, node);

	for(node = node->next ; node ; node = node->next) {
		pkginfo = node;
		ret = __pkginfo_check_installed_storage(pkginfo);
		if(ret < 0)
			continue;
		filter_count++;
	}

	*count = filter_count;
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
	sqlite3_close(pkginfo_db);
	__cleanup_pkginfo(tmphead);
	return ret;
}

API int pkgmgrinfo_pkginfo_filter_foreach_pkginfo(pkgmgrinfo_pkginfo_filter_h handle,
				pkgmgrinfo_pkg_list_cb pkg_cb, void *user_data)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(pkg_cb == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	char *syslocale = NULL;
	char *locale = NULL;
	char *condition = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	char where[MAX_QUERY_LEN] = {'\0'};
	GSList *list;
	int ret = 0;
	label_x *tmp1 = NULL;
	icon_x *tmp2 = NULL;
	description_x *tmp3 = NULL;
	author_x *tmp4 = NULL;
	privilege_x *tmp5 = NULL;
	pkgmgr_pkginfo_x *node = NULL;
	pkgmgr_pkginfo_x *tmphead = NULL;
	pkgmgr_pkginfo_x *pkginfo = NULL;
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)handle;
	sqlite3 *pkginfo_db = NULL;
	const char* package_size_info = NULL;
	bool is_setting = false;

	/*open db*/
	ret = db_util_open(MANIFEST_DB, &pkginfo_db, 0);
	retvm_if(ret != SQLITE_OK, PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	/*get system locale*/
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	tryvm_if(locale == NULL, ret = PMINFO_R_ERROR, "manifest locale is NULL");

	/*Start constructing query*/
	snprintf(query, MAX_QUERY_LEN - 1, FILTER_QUERY_LIST_PACKAGE, locale);

	/*Get where clause*/
	for (list = filter->list; list; list = g_slist_next(list)) {
		__get_filter_condition(list->data, &condition);
		if (condition) {
			strncat(where, condition, sizeof(where) - strlen(where) -1);
			where[sizeof(where) - 1] = '\0';

			if (strstr(condition, "package_info.package_nodisplay"))
				is_setting = true;

			free(condition);
			condition = NULL;
		}
		if (g_slist_next(list)) {
			strncat(where, " and ", sizeof(where) - strlen(where) - 1);
			where[sizeof(where) - 1] = '\0';
		}
	}
	_LOGE("where = %s\n", where);
	if (strlen(where) > 0) {
		strncat(query, where, sizeof(query) - strlen(query) - 1);
		query[sizeof(query) - 1] = '\0';
	}
	_LOGE("query = %s\n", query);

	tmphead = calloc(1, sizeof(pkgmgr_pkginfo_x));
	tryvm_if(tmphead == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	ret = __exec_db_query(pkginfo_db, query, __pkg_list_cb, (void *)tmphead);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");

	if (is_setting) {
		ret = __reqeust_get_size("size_info", PM_GET_SIZE_INFO);
		tryvm_if(ret < 0, ret = PMINFO_R_ERROR, "fail reqeust size info");

		ret = __get_package_size_info(&package_size_info);
		tryvm_if(ret != 0 || package_size_info == NULL, ret = PMINFO_R_ERROR, "__get_package_size_info() failed");
		_LOGD("is_setting is true, get package size info success!! ");
	}

	LISTHEAD(tmphead, node);
	for(node = node->next ; node ; node = node->next) {
		pkginfo = node;
		pkginfo->locale = strdup(locale);
		pkginfo->manifest_info->privileges = (privileges_x *)calloc(1, sizeof(privileges_x));
		tryvm_if(pkginfo->manifest_info->privileges == NULL, ret = PMINFO_R_ERROR, "Failed to allocate memory for privileges info\n");

		/*populate manifest_info from DB*/
		snprintf(query, MAX_QUERY_LEN, "select * from package_info where package='%s' ", pkginfo->manifest_info->package);
		ret = __exec_db_query(pkginfo_db, query, __pkginfo_cb, (void *)pkginfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");

		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select * from package_localized_info where" \
			" package='%s' and package_locale='%s'", pkginfo->manifest_info->package, locale);
		ret = __exec_db_query(pkginfo_db, query, __pkginfo_cb, (void *)pkginfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");

		/*Also store the values corresponding to default locales*/
		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select * from package_localized_info where" \
			" package='%s' and package_locale='%s'", pkginfo->manifest_info->package, DEFAULT_LOCALE);
		ret = __exec_db_query(pkginfo_db, query, __pkginfo_cb, (void *)pkginfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");

		if (pkginfo->manifest_info->label) {
			LISTHEAD(pkginfo->manifest_info->label, tmp1);
			pkginfo->manifest_info->label = tmp1;
		}
		if (pkginfo->manifest_info->icon) {
			LISTHEAD(pkginfo->manifest_info->icon, tmp2);
			pkginfo->manifest_info->icon = tmp2;
		}
		if (pkginfo->manifest_info->description) {
			LISTHEAD(pkginfo->manifest_info->description, tmp3);
			pkginfo->manifest_info->description = tmp3;
		}
		if (pkginfo->manifest_info->author) {
			LISTHEAD(pkginfo->manifest_info->author, tmp4);
			pkginfo->manifest_info->author = tmp4;
		}
		if (pkginfo->manifest_info->privileges->privilege) {
			LISTHEAD(pkginfo->manifest_info->privileges->privilege, tmp5);
			pkginfo->manifest_info->privileges->privilege = tmp5;
		}
		if (is_setting) {
			__set_package_size_info(pkginfo->manifest_info, package_size_info);
		}
	}

	LISTHEAD(tmphead, node);

	for(node = node->next ; node ; node = node->next) {
		pkginfo = node;

		ret = __pkginfo_check_installed_storage(pkginfo);
		if(ret < 0)
			continue;

		ret = pkg_cb( (void *)pkginfo, user_data);
		if(ret < 0)
			break;
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
	if (package_size_info) {
		free(package_size_info);
	}

	sqlite3_close(pkginfo_db);
	__cleanup_pkginfo(tmphead);
	return ret;
}

API int pkgmgrinfo_pkginfo_foreach_privilege(pkgmgrinfo_pkginfo_h handle,
			pkgmgrinfo_pkg_privilege_list_cb privilege_func, void *user_data)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL");
	retvm_if(privilege_func == NULL, PMINFO_R_EINVAL, "Callback function is NULL");
	int ret = -1;
	privilege_x *ptr = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	ptr = info->manifest_info->privileges->privilege;
	for (; ptr; ptr = ptr->next) {
		if (ptr->text){
			ret = privilege_func(ptr->text, user_data);
			if (ret < 0)
				break;
		}
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_list(pkgmgrinfo_pkginfo_h handle, pkgmgrinfo_app_component component,
						pkgmgrinfo_app_list_cb app_func, void *user_data)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "pkginfo handle is NULL");
	retvm_if(app_func == NULL, PMINFO_R_EINVAL, "callback pointer is NULL");
	retvm_if((component != PMINFO_UI_APP) && (component != PMINFO_SVC_APP) && (component != PMINFO_ALL_APP), PMINFO_R_EINVAL, "Invalid App Component Type");

	char *syslocale = NULL;
	char *locale = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	pkgmgr_pkginfo_x *allinfo = NULL;
	pkgmgr_appinfo_x *appinfo = NULL;
	icon_x *ptr1 = NULL;
	label_x *ptr2 = NULL;
	category_x *ptr3 = NULL;
	metadata_x *ptr4 = NULL;
	permission_x *ptr5 = NULL;
	image_x *ptr6 = NULL;
	sqlite3 *appinfo_db = NULL;

	/*check installed storage*/
	ret = __pkginfo_check_installed_storage(info);
	retvm_if(ret < 0, PMINFO_R_EINVAL, "[%s] is installed external, but is not in mmc", info->manifest_info->package);

	/*get system locale*/
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	tryvm_if(locale == NULL, ret = PMINFO_R_EINVAL, "manifest locale is NULL");

	/*calloc allinfo*/
	allinfo = (pkgmgr_pkginfo_x *)calloc(1, sizeof(pkgmgr_pkginfo_x));
	tryvm_if(allinfo == NULL, ret = PMINFO_R_ERROR, "Failed to allocate memory for appinfo");

	/*calloc manifest_info*/
	allinfo->manifest_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	tryvm_if(allinfo->manifest_info == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!");

	/*calloc appinfo*/
	appinfo = (pkgmgr_appinfo_x *)calloc(1, sizeof(pkgmgr_appinfo_x));
	tryvm_if(appinfo == NULL, ret = PMINFO_R_ERROR, "Failed to allocate memory for appinfo");

	/*set component type*/
	if (component == PMINFO_UI_APP)
		appinfo->app_component = PMINFO_UI_APP;
	if (component == PMINFO_SVC_APP)
		appinfo->app_component = PMINFO_SVC_APP;
	if (component == PMINFO_ALL_APP)
		appinfo->app_component = PMINFO_ALL_APP;

	/*open db */
	ret = db_util_open(MANIFEST_DB, &appinfo_db, 0);
	tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	appinfo->package = strdup(info->manifest_info->package);
	snprintf(query, MAX_QUERY_LEN, "select DISTINCT * " \
			"from package_app_info where " \
			"package='%s' and app_component='%s'",
			info->manifest_info->package,
			(appinfo->app_component==PMINFO_UI_APP ? "uiapp" : "svcapp"));

	switch(component) {
	case PMINFO_UI_APP:
		/*Populate ui app info */
		ret = __exec_db_query(appinfo_db, query, __uiapp_list_cb, (void *)info);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Info list retrieval failed");

		uiapplication_x *tmp = NULL;
		if (info->manifest_info->uiapplication) {
			LISTHEAD(info->manifest_info->uiapplication, tmp);
			info->manifest_info->uiapplication = tmp;
		}
		/*Populate localized info for default locales and call callback*/
		/*If the callback func return < 0 we break and no more call back is called*/
		while(tmp != NULL)
		{
			appinfo->locale = strdup(locale);
			appinfo->uiapp_info = tmp;
			if (strcmp(appinfo->uiapp_info->type,"c++app") == 0){
				if (locale) {
					free(locale);
				}
				locale = __get_app_locale_by_fallback(appinfo_db, appinfo->uiapp_info->appid, syslocale);
			}

			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where app_id='%s' and app_locale='%s'", appinfo->uiapp_info->appid, locale);
			ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
			tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Localized Info DB Information retrieval failed");

			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where app_id='%s' and app_locale='%s'", appinfo->uiapp_info->appid, DEFAULT_LOCALE);
			ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
			tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Localized Info DB Information retrieval failed");

			/*store setting notification icon section*/
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_icon_section_info where app_id='%s'", appinfo->uiapp_info->appid);
			ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
			tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App icon section Info DB Information retrieval failed");
			
			/*store app preview image info*/
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select app_image_section, app_image from package_app_image_info where app_id='%s'", appinfo->uiapp_info->appid);
			ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
			tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App image Info DB Information retrieval failed");

			if (appinfo->uiapp_info->label) {
				LISTHEAD(appinfo->uiapp_info->label, ptr2);
				appinfo->uiapp_info->label = ptr2;
			}
			if (appinfo->uiapp_info->icon) {
				LISTHEAD(appinfo->uiapp_info->icon, ptr1);
				appinfo->uiapp_info->icon = ptr1;
			}
			if (appinfo->uiapp_info->category) {
				LISTHEAD(appinfo->uiapp_info->category, ptr3);
				appinfo->uiapp_info->category = ptr3;
			}
			if (appinfo->uiapp_info->metadata) {
				LISTHEAD(appinfo->uiapp_info->metadata, ptr4);
				appinfo->uiapp_info->metadata = ptr4;
			}
			if (appinfo->uiapp_info->permission) {
				LISTHEAD(appinfo->uiapp_info->permission, ptr5);
				appinfo->uiapp_info->permission = ptr5;
			}
			if (appinfo->uiapp_info->image) {
				LISTHEAD(appinfo->uiapp_info->image, ptr6);
				appinfo->uiapp_info->image = ptr6;
			}
			ret = app_func((void *)appinfo, user_data);
			if (ret < 0)
				break;
			tmp = tmp->next;
		}
		break;
	case PMINFO_SVC_APP:
		/*Populate svc app info */
		ret = __exec_db_query(appinfo_db, query, __svcapp_list_cb, (void *)info);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Info list retrieval failed");

		serviceapplication_x *tmp1 = NULL;
		if (info->manifest_info->serviceapplication) {
			LISTHEAD(info->manifest_info->serviceapplication, tmp1);
			info->manifest_info->serviceapplication = tmp1;
		}
		/*Populate localized info for default locales and call callback*/
		/*If the callback func return < 0 we break and no more call back is called*/
		while(tmp1 != NULL)
		{
			appinfo->locale = strdup(locale);
			appinfo->svcapp_info = tmp1;
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where app_id='%s' and app_locale='%s'", appinfo->svcapp_info->appid, locale);
			ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
			tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Localized Info DB Information retrieval failed");

			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where app_id='%s' and app_locale='%s'", appinfo->svcapp_info->appid, DEFAULT_LOCALE);
			ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
			tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Localized Info DB Information retrieval failed");

			if (appinfo->svcapp_info->label) {
				LISTHEAD(appinfo->svcapp_info->label, ptr2);
				appinfo->svcapp_info->label = ptr2;
			}
			if (appinfo->svcapp_info->icon) {
				LISTHEAD(appinfo->svcapp_info->icon, ptr1);
				appinfo->svcapp_info->icon = ptr1;
			}
			if (appinfo->svcapp_info->category) {
				LISTHEAD(appinfo->svcapp_info->category, ptr3);
				appinfo->svcapp_info->category = ptr3;
			}
			if (appinfo->svcapp_info->metadata) {
				LISTHEAD(appinfo->svcapp_info->metadata, ptr4);
				appinfo->svcapp_info->metadata = ptr4;
			}
			if (appinfo->svcapp_info->permission) {
				LISTHEAD(appinfo->svcapp_info->permission, ptr5);
				appinfo->svcapp_info->permission = ptr5;
			}
			ret = app_func((void *)appinfo, user_data);
			if (ret < 0)
				break;
			tmp1 = tmp1->next;
		}
		break;
	case PMINFO_ALL_APP:
		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select * from package_app_info where package='%s'", info->manifest_info->package);

		/*Populate all app info */
		ret = __exec_db_query(appinfo_db, query, __allapp_list_cb, (void *)allinfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Info list retrieval failed");

		/*UI Apps*/
		appinfo->app_component = PMINFO_UI_APP;
		uiapplication_x *tmp2 = NULL;
		if (allinfo->manifest_info->uiapplication) {
			LISTHEAD(allinfo->manifest_info->uiapplication, tmp2);
			allinfo->manifest_info->uiapplication = tmp2;
		}
		/*Populate localized info for default locales and call callback*/
		/*If the callback func return < 0 we break and no more call back is called*/
		while(tmp2 != NULL)
		{
			appinfo->locale = strdup(locale);
			appinfo->uiapp_info = tmp2;
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where app_id='%s' and app_locale='%s'", appinfo->uiapp_info->appid, locale);
			ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
			tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Localized Info DB Information retrieval failed");

			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where app_id='%s' and app_locale='%s'", appinfo->uiapp_info->appid, DEFAULT_LOCALE);
			ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
			tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Localized Info DB Information retrieval failed");

			/*store setting notification icon section*/
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_icon_section_info where app_id='%s'", appinfo->uiapp_info->appid);
			ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
			tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App icon section Info DB Information retrieval failed");
			
			/*store app preview image info*/
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select app_image_section, app_image from package_app_image_info where app_id='%s'", appinfo->uiapp_info->appid);
			ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
			tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App image Info DB Information retrieval failed");

			if (appinfo->uiapp_info->label) {
				LISTHEAD(appinfo->uiapp_info->label, ptr2);
				appinfo->uiapp_info->label = ptr2;
			}
			if (appinfo->uiapp_info->icon) {
				LISTHEAD(appinfo->uiapp_info->icon, ptr1);
				appinfo->uiapp_info->icon = ptr1;
			}
			if (appinfo->uiapp_info->category) {
				LISTHEAD(appinfo->uiapp_info->category, ptr3);
				appinfo->uiapp_info->category = ptr3;
			}
			if (appinfo->uiapp_info->metadata) {
				LISTHEAD(appinfo->uiapp_info->metadata, ptr4);
				appinfo->uiapp_info->metadata = ptr4;
			}
			if (appinfo->uiapp_info->permission) {
				LISTHEAD(appinfo->uiapp_info->permission, ptr5);
				appinfo->uiapp_info->permission = ptr5;
			}
			if (appinfo->uiapp_info->image) {
				LISTHEAD(appinfo->uiapp_info->image, ptr6);
				appinfo->uiapp_info->image = ptr6;
			}
			ret = app_func((void *)appinfo, user_data);
			if (ret < 0)
				break;
			tmp2 = tmp2->next;
		}

		/*SVC Apps*/
		appinfo->app_component = PMINFO_SVC_APP;
		serviceapplication_x *tmp3 = NULL;
		if (allinfo->manifest_info->serviceapplication) {
			LISTHEAD(allinfo->manifest_info->serviceapplication, tmp3);
			allinfo->manifest_info->serviceapplication = tmp3;
		}
		/*Populate localized info for default locales and call callback*/
		/*If the callback func return < 0 we break and no more call back is called*/
		while(tmp3 != NULL)
		{
			appinfo->locale = strdup(locale);
			appinfo->svcapp_info = tmp3;
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where app_id='%s' and app_locale='%s'", appinfo->svcapp_info->appid, locale);
			ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
			tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Localized Info DB Information retrieval failed");

			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where app_id='%s' and app_locale='%s'", appinfo->svcapp_info->appid, DEFAULT_LOCALE);
			ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
			tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Localized Info DB Information retrieval failed");

			if (appinfo->svcapp_info->label) {
				LISTHEAD(appinfo->svcapp_info->label, ptr2);
				appinfo->svcapp_info->label = ptr2;
			}
			if (appinfo->svcapp_info->icon) {
				LISTHEAD(appinfo->svcapp_info->icon, ptr1);
				appinfo->svcapp_info->icon = ptr1;
			}
			if (appinfo->svcapp_info->category) {
				LISTHEAD(appinfo->svcapp_info->category, ptr3);
				appinfo->svcapp_info->category = ptr3;
			}
			if (appinfo->svcapp_info->metadata) {
				LISTHEAD(appinfo->svcapp_info->metadata, ptr4);
				appinfo->svcapp_info->metadata = ptr4;
			}
			if (appinfo->svcapp_info->permission) {
				LISTHEAD(appinfo->svcapp_info->permission, ptr5);
				appinfo->svcapp_info->permission = ptr5;
			}
			ret = app_func((void *)appinfo, user_data);
			if (ret < 0)
				break;
			tmp3 = tmp3->next;
		}
		appinfo->app_component = PMINFO_ALL_APP;
		break;

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
	if (appinfo) {
		if (appinfo->package) {
			free((void *)appinfo->package);
			appinfo->package = NULL;
		}
		free(appinfo);
		appinfo = NULL;
	}
	__cleanup_pkginfo(allinfo);

	sqlite3_close(appinfo_db);
	return ret;
}

API int pkgmgrinfo_appinfo_get_install_list(pkgmgrinfo_app_list_cb app_func, void *user_data)
{
	retvm_if(app_func == NULL, PMINFO_R_EINVAL, "callback function is NULL");

	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	pkgmgr_appinfo_x *appinfo = NULL;
	uiapplication_x *ptr1 = NULL;
	serviceapplication_x *ptr2 = NULL;
	sqlite3 *appinfo_db = NULL;

	/*open db*/
	ret = db_util_open(MANIFEST_DB, &appinfo_db, 0);
	retvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	/*calloc pkginfo*/
	pkgmgr_pkginfo_x *info = NULL;
	info = (pkgmgr_pkginfo_x *)calloc(1, sizeof(pkgmgr_pkginfo_x));
	tryvm_if(info == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!");

	/*calloc manifest_info*/
	info->manifest_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	tryvm_if(info->manifest_info == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!");

	/*calloc appinfo*/
	appinfo = (pkgmgr_appinfo_x *)calloc(1, sizeof(pkgmgr_appinfo_x));
	tryvm_if(appinfo == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!");

	snprintf(query, MAX_QUERY_LEN, "select * from package_app_info");
	ret = __exec_db_query(appinfo_db, query, __mini_appinfo_cb, (void *)info);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Info DB Information retrieval failed");

	if (info->manifest_info->uiapplication) {
		LISTHEAD(info->manifest_info->uiapplication, ptr1);
		info->manifest_info->uiapplication = ptr1;
	}
	if (info->manifest_info->serviceapplication) {
		LISTHEAD(info->manifest_info->serviceapplication, ptr2);
		info->manifest_info->serviceapplication = ptr2;
	}

	/*UI Apps*/
	for(ptr1 = info->manifest_info->uiapplication; ptr1; ptr1 = ptr1->next)
	{
		appinfo->app_component = PMINFO_UI_APP;
		appinfo->package = strdup(ptr1->package);
		appinfo->uiapp_info = ptr1;

		ret = __appinfo_check_installed_storage(appinfo);
		if(ret < 0)
			continue;

		ret = app_func((void *)appinfo, user_data);
		if (ret < 0)
			break;
		free((void *)appinfo->package);
		appinfo->package = NULL;
	}
	/*Service Apps*/
	for(ptr2 = info->manifest_info->serviceapplication; ptr2; ptr2 = ptr2->next)
	{
		appinfo->app_component = PMINFO_SVC_APP;
		appinfo->package = strdup(ptr2->package);
		appinfo->svcapp_info = ptr2;

		ret = app_func((void *)appinfo, user_data);
		if (ret < 0)
			break;
		free((void *)appinfo->package);
		appinfo->package = NULL;
	}
	ret = PMINFO_R_OK;

catch:
	sqlite3_close(appinfo_db);

	if (appinfo) {
		free(appinfo);
		appinfo = NULL;
	}
	__cleanup_pkginfo(info);
	return ret;
}

API int pkgmgrinfo_appinfo_get_installed_list(pkgmgrinfo_app_list_cb app_func, void *user_data)
{
	retvm_if(app_func == NULL, PMINFO_R_EINVAL, "callback function is NULL");

	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *syslocale = NULL;
	char *locale = NULL;
	pkgmgr_appinfo_x *appinfo = NULL;
	uiapplication_x *ptr1 = NULL;
	serviceapplication_x *ptr2 = NULL;
	label_x *tmp1 = NULL;
	icon_x *tmp2 = NULL;
	category_x *tmp3 = NULL;
	metadata_x *tmp4 = NULL;
	permission_x *tmp5 = NULL;
	image_x *tmp6 = NULL;
	sqlite3 *appinfo_db = NULL;

	/*get system locale*/
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	tryvm_if(locale == NULL, ret = PMINFO_R_ERROR, "manifest locale is NULL");

	/*open db*/
	ret = db_util_open(MANIFEST_DB, &appinfo_db, 0);
	retvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	/*calloc pkginfo*/
	pkgmgr_pkginfo_x *info = NULL;
	info = (pkgmgr_pkginfo_x *)calloc(1, sizeof(pkgmgr_pkginfo_x));
	tryvm_if(info == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!");

	/*calloc manifest_info*/
	info->manifest_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	tryvm_if(info->manifest_info == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!");

	/*calloc appinfo*/
	appinfo = (pkgmgr_appinfo_x *)calloc(1, sizeof(pkgmgr_appinfo_x));
	tryvm_if(appinfo == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!");

	snprintf(query, MAX_QUERY_LEN, "select * from package_app_info");
	ret = __exec_db_query(appinfo_db, query, __app_list_cb, (void *)info);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Info DB Information retrieval failed");

	if (info->manifest_info->uiapplication) {
		LISTHEAD(info->manifest_info->uiapplication, ptr1);
		info->manifest_info->uiapplication = ptr1;
	}
	if (info->manifest_info->serviceapplication) {
		LISTHEAD(info->manifest_info->serviceapplication, ptr2);
		info->manifest_info->serviceapplication = ptr2;
	}

	/*UI Apps*/
	for(ptr1 = info->manifest_info->uiapplication; ptr1; ptr1 = ptr1->next)
	{
		appinfo->locale = strdup(locale);
		appinfo->app_component = PMINFO_UI_APP;
		appinfo->package = strdup(ptr1->package);
		appinfo->uiapp_info = ptr1;
		snprintf(query, MAX_QUERY_LEN, "select DISTINCT * " \
				"from package_app_info where " \
				"app_id='%s'", ptr1->appid);
		ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Info DB Information retrieval failed");

		if (strcmp(appinfo->uiapp_info->type,"c++app") == 0){
			if (locale) {
				free(locale);
			}
			locale = __get_app_locale_by_fallback(appinfo_db, ptr1->appid, syslocale);
		}

		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select DISTINCT * " \
				"from package_app_localized_info where " \
				"app_id='%s' and app_locale='%s'",
				ptr1->appid, locale);
		ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Localized Info DB Information retrieval failed");

		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select DISTINCT * " \
				"from package_app_localized_info where " \
				"app_id='%s' and app_locale='%s'",
				ptr1->appid, DEFAULT_LOCALE);

		ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Localized Info DB Information retrieval failed");

		/*store setting notification icon section*/
		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select * from package_app_icon_section_info where app_id='%s'", ptr1->appid);
		ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App icon section Info DB Information retrieval failed");
		
		/*store app preview image info*/
		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select app_image_section, app_image from package_app_image_info where app_id='%s'", ptr1->appid);
		ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App image Info DB Information retrieval failed");

		if (appinfo->uiapp_info->label) {
			LISTHEAD(appinfo->uiapp_info->label, tmp1);
			appinfo->uiapp_info->label = tmp1;
		}
		if (appinfo->uiapp_info->icon) {
			LISTHEAD(appinfo->uiapp_info->icon, tmp2);
			appinfo->uiapp_info->icon= tmp2;
		}
		if (appinfo->uiapp_info->category) {
			LISTHEAD(appinfo->uiapp_info->category, tmp3);
			appinfo->uiapp_info->category = tmp3;
		}
		if (appinfo->uiapp_info->metadata) {
			LISTHEAD(appinfo->uiapp_info->metadata, tmp4);
			appinfo->uiapp_info->metadata = tmp4;
		}
		if (appinfo->uiapp_info->permission) {
			LISTHEAD(appinfo->uiapp_info->permission, tmp5);
			appinfo->uiapp_info->permission = tmp5;
		}
		if (appinfo->uiapp_info->image) {
			LISTHEAD(appinfo->uiapp_info->image, tmp6);
			appinfo->uiapp_info->image = tmp6;
		}

		ret = __appinfo_check_installed_storage(appinfo);
		if(ret < 0)
			continue;

		ret = app_func((void *)appinfo, user_data);
		if (ret < 0)
			break;
		free((void *)appinfo->package);
		appinfo->package = NULL;
	}
	/*Service Apps*/
	for(ptr2 = info->manifest_info->serviceapplication; ptr2; ptr2 = ptr2->next)
	{
		appinfo->locale = strdup(locale);
		appinfo->app_component = PMINFO_SVC_APP;
		appinfo->package = strdup(ptr2->package);
		appinfo->svcapp_info = ptr2;
		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select DISTINCT * " \
				"from package_app_info where " \
				"app_id='%s'", ptr2->appid);
		ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Info DB Information retrieval failed");

		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select DISTINCT * " \
				"from package_app_localized_info where " \
				"app_id='%s' and app_locale='%s'",
				ptr2->appid, locale);
		ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Info DB Information retrieval failed");

		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select DISTINCT * " \
				"from package_app_localized_info where " \
				"app_id='%s' and app_locale='%s'",
				ptr2->appid, DEFAULT_LOCALE);
		ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Info DB Information retrieval failed");

		if (appinfo->svcapp_info->label) {
			LISTHEAD(appinfo->svcapp_info->label, tmp1);
			appinfo->svcapp_info->label = tmp1;
		}
		if (appinfo->svcapp_info->icon) {
			LISTHEAD(appinfo->svcapp_info->icon, tmp2);
			appinfo->svcapp_info->icon= tmp2;
		}
		if (appinfo->svcapp_info->category) {
			LISTHEAD(appinfo->svcapp_info->category, tmp3);
			appinfo->svcapp_info->category = tmp3;
		}
		if (appinfo->svcapp_info->metadata) {
			LISTHEAD(appinfo->svcapp_info->metadata, tmp4);
			appinfo->svcapp_info->metadata = tmp4;
		}
		if (appinfo->svcapp_info->permission) {
			LISTHEAD(appinfo->svcapp_info->permission, tmp5);
			appinfo->svcapp_info->permission = tmp5;
		}
		ret = app_func((void *)appinfo, user_data);
		if (ret < 0)
			break;
		free((void *)appinfo->package);
		appinfo->package = NULL;
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
	sqlite3_close(appinfo_db);
	if (appinfo) {
		free(appinfo);
		appinfo = NULL;
	}
	__cleanup_pkginfo(info);
	return ret;
}

API int pkgmgrinfo_appinfo_get_appinfo(const char *appid, pkgmgrinfo_appinfo_h *handle)
{
	retvm_if(appid == NULL, PMINFO_R_EINVAL, "appid is NULL");
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	pkgmgr_appinfo_x *appinfo = NULL;
	char *syslocale = NULL;
	char *locale = NULL;
	int ret = -1;
	int exist = 0;
	label_x *tmp1 = NULL;
	icon_x *tmp2 = NULL;
	category_x *tmp3 = NULL;
	metadata_x *tmp4 = NULL;
	permission_x *tmp5 = NULL;
	image_x *tmp6 = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	sqlite3 *appinfo_db = NULL;

	/*open db*/
	ret = db_util_open(MANIFEST_DB, &appinfo_db, 0);
	retvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	/*check appid exist on db*/
	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_app_info where app_id='%s')", appid);
	ret = __exec_db_query(appinfo_db, query, __validate_cb, (void *)&exist);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "sqlite3_exec fail");
	tryvm_if(exist == 0, ret = PMINFO_R_ERROR, "Appid[%s] not found in DB", appid);

	/*get system locale*/
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	tryvm_if(locale == NULL, ret = PMINFO_R_ERROR, "manifest locale is NULL");

	/*calloc appinfo*/
	appinfo = (pkgmgr_appinfo_x *)calloc(1, sizeof(pkgmgr_appinfo_x));
	tryvm_if(appinfo == NULL, ret = PMINFO_R_ERROR, "Failed to allocate memory for appinfo");

	/*check app_component from DB*/
	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select app_component, package from package_app_info where app_id='%s' ", appid);
	ret = __exec_db_query(appinfo_db, query, __appcomponent_cb, (void *)appinfo);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Info DB Information retrieval failed");

	/*calloc app_component*/
	if (appinfo->app_component == PMINFO_UI_APP) {
		appinfo->uiapp_info = (uiapplication_x *)calloc(1, sizeof(uiapplication_x));
		tryvm_if(appinfo->uiapp_info == NULL, ret = PMINFO_R_ERROR, "Failed to allocate memory for uiapp info");
	} else {
		appinfo->svcapp_info = (serviceapplication_x *)calloc(1, sizeof(serviceapplication_x));
		tryvm_if(appinfo->svcapp_info == NULL, ret = PMINFO_R_ERROR, "Failed to allocate memory for svcapp info");
	}
	appinfo->locale = strdup(locale);

	/*populate app_info from DB*/
	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select * from package_app_info where app_id='%s' ", appid);
	ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Info DB Information retrieval failed");

	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where app_id='%s' and app_locale='%s'", appid, locale);
	ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Info DB Information retrieval failed");

	/*Also store the values corresponding to default locales*/
	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where app_id='%s' and app_locale='%s'", appid, DEFAULT_LOCALE);
	ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Localized Info DB Information retrieval failed");

	/*Populate app category*/
	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select * from package_app_app_category where app_id='%s'", appid);
	ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Category Info DB Information retrieval failed");

	/*Populate app metadata*/
	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select * from package_app_app_metadata where app_id='%s'", appid);
	ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App Metadata Info DB Information retrieval failed");

	/*Populate app permission*/
	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select * from package_app_app_permission where app_id='%s'", appid);
	ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App permission Info DB Information retrieval failed");

	/*store setting notification icon section*/
	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select * from package_app_icon_section_info where app_id='%s'", appid);
	ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App icon section Info DB Information retrieval failed");

	/*store app preview image info*/
	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select app_image_section, app_image from package_app_image_info where app_id='%s'", appid);
	ret = __exec_db_query(appinfo_db, query, __appinfo_cb, (void *)appinfo);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "App image Info DB Information retrieval failed");

	ret = __appinfo_check_installed_storage(appinfo);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "[%s] is installed external, but is not in mmc", appinfo->package);

	switch (appinfo->app_component) {
	case PMINFO_UI_APP:
		if (appinfo->uiapp_info->label) {
			LISTHEAD(appinfo->uiapp_info->label, tmp1);
			appinfo->uiapp_info->label = tmp1;
		}
		if (appinfo->uiapp_info->icon) {
			LISTHEAD(appinfo->uiapp_info->icon, tmp2);
			appinfo->uiapp_info->icon = tmp2;
		}
		if (appinfo->uiapp_info->category) {
			LISTHEAD(appinfo->uiapp_info->category, tmp3);
			appinfo->uiapp_info->category = tmp3;
		}
		if (appinfo->uiapp_info->metadata) {
			LISTHEAD(appinfo->uiapp_info->metadata, tmp4);
			appinfo->uiapp_info->metadata = tmp4;
		}
		if (appinfo->uiapp_info->permission) {
			LISTHEAD(appinfo->uiapp_info->permission, tmp5);
			appinfo->uiapp_info->permission = tmp5;
		}
		if (appinfo->uiapp_info->image) {
			LISTHEAD(appinfo->uiapp_info->image, tmp6);
			appinfo->uiapp_info->image = tmp6;
		}
		break;
	case PMINFO_SVC_APP:
		if (appinfo->svcapp_info->label) {
			LISTHEAD(appinfo->svcapp_info->label, tmp1);
			appinfo->svcapp_info->label = tmp1;
		}
		if (appinfo->svcapp_info->icon) {
			LISTHEAD(appinfo->svcapp_info->icon, tmp2);
			appinfo->svcapp_info->icon = tmp2;
		}
		if (appinfo->svcapp_info->category) {
			LISTHEAD(appinfo->svcapp_info->category, tmp3);
			appinfo->svcapp_info->category = tmp3;
		}
		if (appinfo->svcapp_info->metadata) {
			LISTHEAD(appinfo->svcapp_info->metadata, tmp4);
			appinfo->svcapp_info->metadata = tmp4;
		}
		if (appinfo->svcapp_info->permission) {
			LISTHEAD(appinfo->svcapp_info->permission, tmp5);
			appinfo->svcapp_info->permission = tmp5;
		}
		break;
	default:
		break;
	}

	ret = PMINFO_R_OK;

catch:
	if (ret == PMINFO_R_OK)
		*handle = (void*)appinfo;
	else {
		*handle = NULL;
		__cleanup_appinfo(appinfo);
	}

	sqlite3_close(appinfo_db);
	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	if (locale) {
		free(locale);
		locale = NULL;
	}
	return ret;
}


API int pkgmgrinfo_appinfo_get_appid(pkgmgrinfo_appinfo_h  handle, char **appid)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(appid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_component == PMINFO_UI_APP)
		*appid = (char *)info->uiapp_info->appid;
	else if (info->app_component == PMINFO_SVC_APP)
		*appid = (char *)info->svcapp_info->appid;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_pkgname(pkgmgrinfo_appinfo_h  handle, char **pkg_name)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(pkg_name == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	*pkg_name = (char *)info->package;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_pkgid(pkgmgrinfo_appinfo_h  handle, char **pkgid)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	*pkgid = (char *)info->package;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_exec(pkgmgrinfo_appinfo_h  handle, char **exec)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(exec == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_component == PMINFO_UI_APP)
		*exec = (char *)info->uiapp_info->exec;
	if (info->app_component == PMINFO_SVC_APP)
		*exec = (char *)info->svcapp_info->exec;

	return PMINFO_R_OK;
}


API int pkgmgrinfo_appinfo_get_icon(pkgmgrinfo_appinfo_h  handle, char **icon)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(icon == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
        char *locale = NULL;
        icon_x *ptr = NULL;
        icon_x *start = NULL;
        *icon = NULL;

        pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
		locale = info->locale;
		retvm_if(locale == NULL, PMINFO_R_ERROR, "manifest locale is NULL");

        if (info->app_component == PMINFO_UI_APP)
                start = info->uiapp_info->icon;
        if (info->app_component == PMINFO_SVC_APP)
                start = info->svcapp_info->icon;
        for(ptr = start; ptr != NULL; ptr = ptr->next)
        {
                if (ptr->lang) {
                        if (strcmp(ptr->lang, locale) == 0) {
                                *icon = (char *)ptr->text;
                                if (strcasecmp(*icon, "(null)") == 0) {
                                        locale = DEFAULT_LOCALE;
                                        continue;
                                } else
                                        break;
                        } else if (strcmp(ptr->lang, DEFAULT_LOCALE) == 0) {
                                *icon = (char *)ptr->text;
                                break;
                        }
                }
        }
	return PMINFO_R_OK;
}


API int pkgmgrinfo_appinfo_get_label(pkgmgrinfo_appinfo_h  handle, char **label)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(label == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	char *locale = NULL;
	label_x *ptr = NULL;
	label_x *start = NULL;
	*label = NULL;

	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	locale = info->locale;
	retvm_if(locale == NULL, PMINFO_R_ERROR, "manifest locale is NULL");

	if (info->app_component == PMINFO_UI_APP)
		start = info->uiapp_info->label;
	if (info->app_component == PMINFO_SVC_APP)
		start = info->svcapp_info->label;
	for(ptr = start; ptr != NULL; ptr = ptr->next)
	{
		if (ptr->lang) {
			if (strcmp(ptr->lang, locale) == 0) {
				*label = (char *)ptr->text;
				if (strcasecmp(*label, "(null)") == 0) {
					locale = DEFAULT_LOCALE;
					continue;
				} else
					break;
			} else if (strncasecmp(ptr->lang, locale, 2) == 0) {
				*label = (char *)ptr->text;
				if (strcasecmp(*label, "(null)") == 0) {
						locale = DEFAULT_LOCALE;
						continue;
				} else
						break;
			} else if (strcmp(ptr->lang, DEFAULT_LOCALE) == 0) {
				*label = (char *)ptr->text;
				break;
			}
		}
	}
	return PMINFO_R_OK;
}


API int pkgmgrinfo_appinfo_get_component(pkgmgrinfo_appinfo_h  handle, pkgmgrinfo_app_component *component)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(component == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_component == PMINFO_UI_APP)
		*component = PMINFO_UI_APP;
	else if (info->app_component == PMINFO_SVC_APP)
		*component = PMINFO_SVC_APP;
	else
		return PMINFO_R_ERROR;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_apptype(pkgmgrinfo_appinfo_h  handle, char **app_type)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(app_type == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_component == PMINFO_UI_APP)
		*app_type = (char *)info->uiapp_info->type;
	if (info->app_component == PMINFO_SVC_APP)
		*app_type = (char *)info->svcapp_info->type;

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

API int pkgmgrinfo_appinfo_get_setting_icon(pkgmgrinfo_appinfo_h  handle, char **icon)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(icon == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	char *val = NULL;
	icon_x *ptr = NULL;
	icon_x *start = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	start = info->uiapp_info->icon;

	for(ptr = start; ptr != NULL; ptr = ptr->next)
	{
		if (ptr->section) {
			val = (char *)ptr->section;
			if (strcmp(val, "setting") == 0){
				*icon = (char *)ptr->text;
				break;
			}
		}
	}
	return PMINFO_R_OK;
}


API int pkgmgrinfo_appinfo_get_notification_icon(pkgmgrinfo_appinfo_h  handle, char **icon)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(icon == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	char *val = NULL;
	icon_x *ptr = NULL;
	icon_x *start = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	start = info->uiapp_info->icon;

	for(ptr = start; ptr != NULL; ptr = ptr->next)
	{
		if (ptr->section) {
			val = (char *)ptr->section;

			if (strcmp(val, "notification") == 0){
				*icon = (char *)ptr->text;
				break;
			}
		}
	}

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_recent_image_type(pkgmgrinfo_appinfo_h  handle, pkgmgrinfo_app_recentimage *type)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(type == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	val = (char *)info->uiapp_info->recentimage;
	if (val) {
		if (strcasecmp(val, "capture") == 0)
			*type = PMINFO_RECENTIMAGE_USE_CAPTURE;
		else if (strcasecmp(val, "icon") == 0)
			*type = PMINFO_RECENTIMAGE_USE_ICON;
		else
			*type = PMINFO_RECENTIMAGE_USE_NOTHING;
	}

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_preview_image(pkgmgrinfo_appinfo_h  handle, char **preview_img)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(preview_img == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	char *val = NULL;
	image_x *ptr = NULL;
	image_x *start = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	start = info->uiapp_info->image;

	for(ptr = start; ptr != NULL; ptr = ptr->next)
	{
		if (ptr->section) {
			val = (char *)ptr->section;

			if (strcmp(val, "preview") == 0)
				*preview_img = (char *)ptr->text;

			break;
		}
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_permission_type(pkgmgrinfo_appinfo_h  handle, pkgmgrinfo_permission_type *permission)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(permission == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_component == PMINFO_UI_APP)
		val = info->uiapp_info->permission_type;
	else if (info->app_component == PMINFO_SVC_APP)
		val = info->svcapp_info->permission_type;
	else
		return PMINFO_R_ERROR;

	if (strcmp(val, "signature") == 0)
		*permission = PMINFO_PERMISSION_SIGNATURE;
	else if (strcmp(val, "privilege") == 0)
		*permission = PMINFO_PERMISSION_PRIVILEGE;
	else
		*permission = PMINFO_PERMISSION_NORMAL;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_component_type(pkgmgrinfo_appinfo_h  handle, char **component_type)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(component_type == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	*component_type = (char *)info->uiapp_info->component_type;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_hwacceleration(pkgmgrinfo_appinfo_h  handle, pkgmgrinfo_app_hwacceleration *hwacceleration)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(hwacceleration == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	val = (char *)info->uiapp_info->hwacceleration;
	if (val) {
		if (strcasecmp(val, "not-use-GL") == 0)
			*hwacceleration = PMINFO_HWACCELERATION_NOT_USE_GL;
		else if (strcasecmp(val, "use-GL") == 0)
			*hwacceleration = PMINFO_HWACCELERATION_USE_GL;
		else
			*hwacceleration = PMINFO_HWACCELERATION_USE_SYSTEM_SETTING;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_screenreader(pkgmgrinfo_appinfo_h  handle, pkgmgrinfo_app_screenreader *screenreader)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(screenreader == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	val = (char *)info->uiapp_info->screenreader;
	if (val) {
		if (strcasecmp(val, "screenreader-off") == 0)
			*screenreader = PMINFO_SCREENREADER_OFF;
		else if (strcasecmp(val, "screenreader-on") == 0)
			*screenreader = PMINFO_SCREENREADER_ON;
		else
			*screenreader = PMINFO_SCREENREADER_USE_SYSTEM_SETTING;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_effectimage(pkgmgrinfo_appinfo_h  handle, char **portrait_img, char **landscape_img)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(portrait_img == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	retvm_if(landscape_img == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_component == PMINFO_UI_APP){
		*portrait_img = (char *)info->uiapp_info->portraitimg;
		*landscape_img = (char *)info->uiapp_info->landscapeimg;
	}

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_submode_mainid(pkgmgrinfo_appinfo_h  handle, char **submode_mainid)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(submode_mainid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	*submode_mainid = (char *)info->uiapp_info->submode_mainid;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_foreach_permission(pkgmgrinfo_appinfo_h handle,
			pkgmgrinfo_app_permission_list_cb permission_func, void *user_data)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(permission_func == NULL, PMINFO_R_EINVAL, "Callback function is NULL");
	int ret = -1;
	permission_x *ptr = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	if (info->app_component == PMINFO_UI_APP)
		ptr = info->uiapp_info->permission;
	else if (info->app_component == PMINFO_SVC_APP)
		ptr = info->svcapp_info->permission;
	else
		return PMINFO_R_EINVAL;
	for (; ptr; ptr = ptr->next) {
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
	if (info->app_component == PMINFO_UI_APP)
		ptr = info->uiapp_info->category;
	else if (info->app_component == PMINFO_SVC_APP)
		ptr = info->svcapp_info->category;
	else
		return PMINFO_R_EINVAL;
	for (; ptr; ptr = ptr->next) {
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
	if (info->app_component == PMINFO_UI_APP)
		ptr = info->uiapp_info->metadata;
	else if (info->app_component == PMINFO_SVC_APP)
		ptr = info->svcapp_info->metadata;
	else
		return PMINFO_R_EINVAL;
	for (; ptr; ptr = ptr->next) {
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
	int i = 0;
	int ret = -1;
	int oc = 0;
	int mc = 0;
	int uc = 0;
	int sc = 0;
	char *pkgid = NULL;
	char *manifest = NULL;
	char **operation = NULL;
	char **uri = NULL;
	char **mime = NULL;
	char **subapp = NULL;
	appcontrol_x *appcontrol = NULL;
	manifest_x *mfx = NULL;
	operation_x *op = NULL;
	uri_x *ui = NULL;
	mime_x *mi = NULL;
	subapp_x *sa = NULL;
	pkgmgrinfo_app_component component;
	pkgmgrinfo_appcontrol_x *ptr = NULL;
	ret = pkgmgrinfo_appinfo_get_pkgid(handle, &pkgid);
	if (ret < 0) {
		_LOGE("Failed to get package name\n");
		return PMINFO_R_ERROR;
	}
	ret = pkgmgrinfo_appinfo_get_component(handle, &component);
	if (ret < 0) {
		_LOGE("Failed to get app component name\n");
		return PMINFO_R_ERROR;
	}
	manifest = pkgmgr_parser_get_manifest_file(pkgid);
	if (manifest == NULL) {
		_LOGE("Failed to fetch package manifest file\n");
		return PMINFO_R_ERROR;
	}
	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	if (mfx == NULL) {
		_LOGE("Failed to parse package manifest file\n");
		free(manifest);
		manifest = NULL;
		return PMINFO_R_ERROR;
	}
	free(manifest);
	ptr  = calloc(1, sizeof(pkgmgrinfo_appcontrol_x));
	if (ptr == NULL) {
		_LOGE("Out of Memory!!!\n");
		pkgmgr_parser_free_manifest_xml(mfx);
		return PMINFO_R_ERROR;
	}
	/*Get Operation, Uri, Mime*/
	switch (component) {
	case PMINFO_UI_APP:
		if (mfx->uiapplication) {
			if (mfx->uiapplication->appsvc) {
				appcontrol = mfx->uiapplication->appsvc;
			}
		}
		break;
	case PMINFO_SVC_APP:
		if (mfx->serviceapplication) {
			if (mfx->serviceapplication->appsvc) {
				appcontrol = mfx->serviceapplication->appsvc;
			}
		}
		break;
	default:
		break;
	}
	for (; appcontrol; appcontrol = appcontrol->next) {
		op = appcontrol->operation;
		for (; op; op = op->next)
			oc = oc + 1;
		op = appcontrol->operation;

		ui = appcontrol->uri;
		for (; ui; ui = ui->next)
			uc = uc + 1;
		ui = appcontrol->uri;

		mi = appcontrol->mime;
		for (; mi; mi = mi->next)
			mc = mc + 1;
		mi = appcontrol->mime;

		sa = appcontrol->subapp;
		for (; sa; sa = sa->next)
			sc = sc + 1;
		sa = appcontrol->subapp;

		operation = (char **)calloc(oc, sizeof(char *));
		for (i = 0; i < oc; i++) {
			operation[i] = strndup(op->name, PKG_STRING_LEN_MAX - 1);
			op = op->next;
		}

		uri = (char **)calloc(uc, sizeof(char *));
		for (i = 0; i < uc; i++) {
			uri[i] = strndup(ui->name, PKG_STRING_LEN_MAX - 1);
			ui = ui->next;
		}

		mime = (char **)calloc(mc, sizeof(char *));
		for (i = 0; i < mc; i++) {
			mime[i] = strndup(mi->name, PKG_STRING_LEN_MAX - 1);
			mi = mi->next;
		}

		subapp = (char **)calloc(sc, sizeof(char *));
		for (i = 0; i < sc; i++) {
			subapp[i] = strndup(sa->name, PKG_STRING_LEN_MAX - 1);
			sa = sa->next;
		}

		/*populate appcontrol handle*/
		ptr->operation_count = oc;
		ptr->uri_count = uc;
		ptr->mime_count = mc;
		ptr->subapp_count = sc;
		ptr->operation = operation;
		ptr->uri = uri;
		ptr->mime = mime;
		ptr->subapp = subapp;

		ret = appcontrol_func((void *)ptr, user_data);
		for (i = 0; i < oc; i++) {
			if (operation[i]) {
				free(operation[i]);
				operation[i] = NULL;
			}
		}
		if (operation) {
			free(operation);
			operation = NULL;
		}
		for (i = 0; i < uc; i++) {
			if (uri[i]) {
				free(uri[i]);
				uri[i] = NULL;
			}
		}
		if (uri) {
			free(uri);
			uri = NULL;
		}
		for (i = 0; i < mc; i++) {
			if (mime[i]) {
				free(mime[i]);
				mime[i] = NULL;
			}
		}
		if (mime) {
			free(mime);
			mime = NULL;
		}
		for (i = 0; i < sc; i++) {
			if (subapp[i]) {
				free(subapp[i]);
				subapp[i] = NULL;
			}
		}
		if (subapp) {
			free(subapp);
			subapp = NULL;
		}
		if (ret < 0)
			break;
		uc = 0;
		mc = 0;
		oc = 0;
		sc = 0;
	}
	pkgmgr_parser_free_manifest_xml(mfx);
	if (ptr) {
		free(ptr);
		ptr = NULL;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_nodisplay(pkgmgrinfo_appinfo_h  handle, bool *nodisplay)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(nodisplay == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	val = (char *)info->uiapp_info->nodisplay;
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

API int pkgmgrinfo_appinfo_is_multiple(pkgmgrinfo_appinfo_h  handle, bool *multiple)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(multiple == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	val = (char *)info->uiapp_info->multiple;
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
	val = (char *)info->uiapp_info->indicatordisplay;
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
	val = (char *)info->uiapp_info->taskmanage;
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
	if (info->app_component == PMINFO_UI_APP)
		val = (char *)info->uiapp_info->enabled;
	else if (info->app_component == PMINFO_SVC_APP)
		val = (char *)info->uiapp_info->enabled;
	else {
		_LOGE("invalid component type\n");
		return PMINFO_R_EINVAL;
	}

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
	val = (char *)info->svcapp_info->onboot;
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
	val = (char *)info->svcapp_info->autorestart;
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
	val = (char *)info->uiapp_info->mainapp;
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
	val = (char *)info->uiapp_info->preload;
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
	val = (char *)info->uiapp_info->submode;
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

API int pkgmgrinfo_appinfo_filter_count(pkgmgrinfo_appinfo_filter_h handle, int *count)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(count == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	char *syslocale = NULL;
	char *locale = NULL;
	char *condition = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	char where[MAX_QUERY_LEN] = {'\0'};
	GSList *list;
	int ret = 0;
	uiapplication_x *ptr1 = NULL;
	serviceapplication_x *ptr2 = NULL;
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)handle;
	sqlite3 *pkginfo_db = NULL;
	int filter_count = 0;

	/*open db*/
	ret = db_util_open(MANIFEST_DB, &pkginfo_db, 0);
	retvm_if(ret != SQLITE_OK, PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	/*get system locale*/
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	tryvm_if(locale == NULL, ret = PMINFO_R_ERROR, "manifest locale is NULL");

	/*Start constructing query*/
	snprintf(query, MAX_QUERY_LEN - 1, FILTER_QUERY_LIST_APP, locale);
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
	_LOGE("where = %s\n", where);
	if (strlen(where) > 0) {
		strncat(query, where, sizeof(query) - strlen(query) - 1);
		query[sizeof(query) - 1] = '\0';
	}
//	SECURE_LOGD("query = %s\n", query);
	/*To get filtered list*/
	pkgmgr_pkginfo_x *info = NULL;
	info = (pkgmgr_pkginfo_x *)calloc(1, sizeof(pkgmgr_pkginfo_x));
	tryvm_if(info == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	info->manifest_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	tryvm_if(info->manifest_info == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	/*To get detail app info for each member of filtered list*/
	pkgmgr_pkginfo_x *filtinfo = NULL;
	filtinfo = (pkgmgr_pkginfo_x *)calloc(1, sizeof(pkgmgr_pkginfo_x));
	tryvm_if(filtinfo == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	filtinfo->manifest_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	tryvm_if(filtinfo->manifest_info == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	pkgmgr_appinfo_x *appinfo = (pkgmgr_appinfo_x *)calloc(1, sizeof(pkgmgr_appinfo_x));
	tryvm_if(appinfo == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	ret = __exec_db_query(pkginfo_db, query, __app_list_cb, (void *)info);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");

	memset(query, '\0', MAX_QUERY_LEN);
	if (info->manifest_info->uiapplication) {
		LISTHEAD(info->manifest_info->uiapplication, ptr1);
		info->manifest_info->uiapplication = ptr1;
	}
	if (info->manifest_info->serviceapplication) {
		LISTHEAD(info->manifest_info->serviceapplication, ptr2);
		info->manifest_info->serviceapplication = ptr2;
	}
	/*Filtered UI Apps*/
	for(ptr1 = info->manifest_info->uiapplication; ptr1; ptr1 = ptr1->next)
	{
		snprintf(query, MAX_QUERY_LEN, "select * from package_app_info where app_id='%s' and app_component='%s'",
							ptr1->appid, "uiapp");
		ret = __exec_db_query(pkginfo_db, query, __uiapp_list_cb, (void *)filtinfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");
	}
	for(ptr2 = info->manifest_info->serviceapplication; ptr2; ptr2 = ptr2->next)
	{
		snprintf(query, MAX_QUERY_LEN, "select * from package_app_info where app_id='%s' and app_component='%s'",
							ptr2->appid, "svcapp");
		ret = __exec_db_query(pkginfo_db, query, __svcapp_list_cb, (void *)filtinfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");
	}
	if (filtinfo->manifest_info->uiapplication) {
		LISTHEAD(filtinfo->manifest_info->uiapplication, ptr1);
		filtinfo->manifest_info->uiapplication = ptr1;
	}
	/*If the callback func return < 0 we break and no more call back is called*/
	while(ptr1 != NULL)
	{
		appinfo->locale = strdup(locale);
		appinfo->uiapp_info = ptr1;
		appinfo->app_component = PMINFO_UI_APP;

		ret = __appinfo_check_installed_storage(appinfo);
		if(ret < 0) {
			ptr1 = ptr1->next;
			continue;
		}

		filter_count++;

		ptr1 = ptr1->next;
	}
	/*Filtered Service Apps*/
	if (filtinfo->manifest_info->serviceapplication) {
		LISTHEAD(filtinfo->manifest_info->serviceapplication, ptr2);
		filtinfo->manifest_info->serviceapplication = ptr2;
	}
	/*If the callback func return < 0 we break and no more call back is called*/
	while(ptr2 != NULL)
	{
		appinfo->locale = strdup(locale);
		appinfo->svcapp_info = ptr2;
		appinfo->app_component = PMINFO_SVC_APP;
		filter_count++;
		ptr2 = ptr2->next;
	}
	*count = filter_count;

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
	sqlite3_close(pkginfo_db);
	if (appinfo) {
		free(appinfo);
		appinfo = NULL;
	}
	__cleanup_pkginfo(info);
	__cleanup_pkginfo(filtinfo);
	return ret;
}

API int pkgmgrinfo_appinfo_filter_foreach_appinfo(pkgmgrinfo_appinfo_filter_h handle,
				pkgmgrinfo_app_list_cb app_cb, void * user_data)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(app_cb == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	char *syslocale = NULL;
	char *locale = NULL;
	char *condition = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	char where[MAX_QUERY_LEN] = {'\0'};
	GSList *list;
	int ret = 0;
	uiapplication_x *ptr1 = NULL;
	serviceapplication_x *ptr2 = NULL;
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)handle;
	sqlite3 *pkginfo_db = NULL;

	/*open db*/
	ret = db_util_open(MANIFEST_DB, &pkginfo_db, 0);
	retvm_if(ret != SQLITE_OK, PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	/*get system locale*/
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	tryvm_if(locale == NULL, ret = PMINFO_R_ERROR, "manifest locale is NULL");

	/*Start constructing query*/
	snprintf(query, MAX_QUERY_LEN - 1, FILTER_QUERY_LIST_APP, locale);
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
	_LOGE("where = %s\n", where);
	if (strlen(where) > 0) {
		strncat(query, where, sizeof(query) - strlen(query) - 1);
		query[sizeof(query) - 1] = '\0';
	}
	_LOGE("query = %s\n", query);
	/*To get filtered list*/
	pkgmgr_pkginfo_x *info = NULL;
	info = (pkgmgr_pkginfo_x *)calloc(1, sizeof(pkgmgr_pkginfo_x));
	tryvm_if(info == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	info->manifest_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	tryvm_if(info->manifest_info == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	/*To get detail app info for each member of filtered list*/
	pkgmgr_pkginfo_x *filtinfo = NULL;
	filtinfo = (pkgmgr_pkginfo_x *)calloc(1, sizeof(pkgmgr_pkginfo_x));
	tryvm_if(filtinfo == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	filtinfo->manifest_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	tryvm_if(filtinfo->manifest_info == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	pkgmgr_appinfo_x *appinfo = (pkgmgr_appinfo_x *)calloc(1, sizeof(pkgmgr_appinfo_x));
	tryvm_if(appinfo == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	ret = __exec_db_query(pkginfo_db, query, __app_list_cb, (void *)info);
	tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");

	memset(query, '\0', MAX_QUERY_LEN);
	if (info->manifest_info->uiapplication) {
		LISTHEAD(info->manifest_info->uiapplication, ptr1);
		info->manifest_info->uiapplication = ptr1;
	}
	if (info->manifest_info->serviceapplication) {
		LISTHEAD(info->manifest_info->serviceapplication, ptr2);
		info->manifest_info->serviceapplication = ptr2;
	}
	/*Filtered UI Apps*/
	for(ptr1 = info->manifest_info->uiapplication; ptr1; ptr1 = ptr1->next)
	{
		snprintf(query, MAX_QUERY_LEN, "select * from package_app_info where app_id='%s' and app_component='%s'",
							ptr1->appid, "uiapp");
		ret = __exec_db_query(pkginfo_db, query, __uiapp_list_cb, (void *)filtinfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");
	}
	for(ptr2 = info->manifest_info->serviceapplication; ptr2; ptr2 = ptr2->next)
	{
		snprintf(query, MAX_QUERY_LEN, "select * from package_app_info where app_id='%s' and app_component='%s'",
							ptr2->appid, "svcapp");
		ret = __exec_db_query(pkginfo_db, query, __svcapp_list_cb, (void *)filtinfo);
		tryvm_if(ret == -1, ret = PMINFO_R_ERROR, "Package Info DB Information retrieval failed");
	}
	if (filtinfo->manifest_info->uiapplication) {
		LISTHEAD(filtinfo->manifest_info->uiapplication, ptr1);
		filtinfo->manifest_info->uiapplication = ptr1;
	}
	/*If the callback func return < 0 we break and no more call back is called*/
	while(ptr1 != NULL)
	{
		appinfo->locale = strdup(locale);
		appinfo->uiapp_info = ptr1;
		appinfo->app_component = PMINFO_UI_APP;

		ret = __appinfo_check_installed_storage(appinfo);
		if(ret < 0) {
			ptr1 = ptr1->next;
			continue;
		}

		ret = app_cb((void *)appinfo, user_data);
		if (ret < 0)
			break;
		ptr1 = ptr1->next;
	}
	/*Filtered Service Apps*/
	if (filtinfo->manifest_info->serviceapplication) {
		LISTHEAD(filtinfo->manifest_info->serviceapplication, ptr2);
		filtinfo->manifest_info->serviceapplication = ptr2;
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
	sqlite3_close(pkginfo_db);
	if (appinfo) {
		free(appinfo);
		appinfo = NULL;
	}
	__cleanup_pkginfo(info);
	__cleanup_pkginfo(filtinfo);
	return ret;
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

API int pkgmgrinfo_appinfo_metadata_filter_foreach(pkgmgrinfo_appinfo_metadata_filter_h handle,
		pkgmgrinfo_app_list_cb app_cb, void *user_data)
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
	sqlite3 *pkginfo_db = NULL;

	/*open db*/
	ret = db_util_open(MANIFEST_DB, &pkginfo_db, 0);
	retvm_if(ret != SQLITE_OK, PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	/*Get current locale*/
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	tryvm_if(locale == NULL, ret = PMINFO_R_ERROR, "manifest locale is NULL\n");

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
	_LOGE("where = %s (%d)\n", where, strlen(where));
	if (strlen(where) > 0) {
		strncat(query, where, sizeof(query) - strlen(query) - 1);
	}
	_LOGE("query = %s (%d)\n", query, strlen(query));
	/*To get filtered list*/
	info = (pkgmgr_pkginfo_x *)calloc(1, sizeof(pkgmgr_pkginfo_x));
	tryvm_if(info == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	info->manifest_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	tryvm_if(info->manifest_info == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	/*To get detail app info for each member of filtered list*/
	filtinfo = (pkgmgr_pkginfo_x *)calloc(1, sizeof(pkgmgr_pkginfo_x));
	tryvm_if(filtinfo == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	filtinfo->manifest_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	tryvm_if(filtinfo->manifest_info == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	appinfo = (pkgmgr_appinfo_x *)calloc(1, sizeof(pkgmgr_appinfo_x));
	tryvm_if(appinfo == NULL, ret = PMINFO_R_ERROR, "Out of Memory!!!\n");

	ret = sqlite3_exec(pkginfo_db, query, __app_list_cb, (void *)info, &error_message);
	tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Don't execute query = %s error message = %s\n", query, error_message);
	memset(query, '\0', MAX_QUERY_LEN);

	if (info->manifest_info->uiapplication) {
		LISTHEAD(info->manifest_info->uiapplication, ptr1);
		info->manifest_info->uiapplication = ptr1;
	}
	if (info->manifest_info->serviceapplication) {
		LISTHEAD(info->manifest_info->serviceapplication, ptr2);
		info->manifest_info->serviceapplication = ptr2;
	}

	/*UI Apps*/
	for(ptr1 = info->manifest_info->uiapplication; ptr1; ptr1 = ptr1->next)
	{
		snprintf(query, MAX_QUERY_LEN, "select * from package_app_info where app_id='%s' and app_component='%s'",
							ptr1->appid, "uiapp");
		ret = sqlite3_exec(pkginfo_db, query, __uiapp_list_cb, (void *)filtinfo, &error_message);
		tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Don't execute query = %s error message = %s\n", query, error_message);
		memset(query, '\0', MAX_QUERY_LEN);
	}
	/*Service Apps*/
	for(ptr2 = info->manifest_info->serviceapplication; ptr2; ptr2 = ptr2->next)
	{
		snprintf(query, MAX_QUERY_LEN, "select * from package_app_info where app_id='%s' and app_component='%s'",
							ptr2->appid, "svcapp");
		ret = sqlite3_exec(pkginfo_db, query, __svcapp_list_cb, (void *)filtinfo, &error_message);
		tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Don't execute query = %s error message = %s\n", query, error_message);
		memset(query, '\0', MAX_QUERY_LEN);
	}
	/*Filtered UI Apps*/
	if (filtinfo->manifest_info->uiapplication) {
		LISTHEAD(filtinfo->manifest_info->uiapplication, ptr1);
		filtinfo->manifest_info->uiapplication = ptr1;
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
	if (filtinfo->manifest_info->serviceapplication) {
		LISTHEAD(filtinfo->manifest_info->serviceapplication, ptr2);
		filtinfo->manifest_info->serviceapplication = ptr2;
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
	sqlite3_close(pkginfo_db);
	if (appinfo) {
		free(appinfo);
		appinfo = NULL;
	}
	__cleanup_pkginfo(info);
	__cleanup_pkginfo(filtinfo);
	return ret;
}

API int pkgmgrinfo_pkginfo_create_certinfo(pkgmgrinfo_certinfo_h *handle)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_certinfo_x *certinfo = NULL;
	certinfo = calloc(1, sizeof(pkgmgr_certinfo_x));
	retvm_if(certinfo == NULL, PMINFO_R_ERROR, "Malloc Failed\n");
	*handle = (void *)certinfo;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_load_certinfo(const char *pkgid, pkgmgrinfo_certinfo_h handle)
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
	ret = db_util_open_with_options(CERT_DB, &cert_db, SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n", CERT_DB);
		return PMINFO_R_ERROR;
	}
	/*validate pkgid*/
	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", pkgid);
	if (SQLITE_OK !=
	    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}
	if (exist == 0) {
		_LOGE("Package not found in DB\n");
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
		snprintf(query, MAX_QUERY_LEN, "select cert_info from package_cert_index_info where cert_id=%d ", (certinfo->cert_id)[i]);
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
	sqlite3_close(cert_db);
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

API int pkgmgrinfo_save_certinfo(const char *pkgid, pkgmgrinfo_instcertinfo_h handle)
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
	ret = db_util_open_with_options(CERT_DB, &cert_db, SQLITE_OPEN_READWRITE, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n", CERT_DB);
		ret = PMINFO_R_ERROR;
		goto err;
	}
	/*Begin Transaction*/
	ret = sqlite3_exec(cert_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to begin transaction\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	_LOGE("Transaction Begin\n");
	/*Check if request is to insert/update*/
	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", pkgid);
	if (SQLITE_OK !=
	    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
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
		ret = __delete_certinfo(pkgid);
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
				    sqlite3_exec(cert_db, query, __maxid_cb, (void *)&newid, &error_message)) {
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
			_LOGE("Id:Count = %d %d\n", indexinfo->cert_id, indexinfo->cert_ref_count);
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
            sqlite3_exec(cert_db, vquery, NULL, NULL, &error_message)) {
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
		            sqlite3_exec(cert_db, vquery, NULL, NULL, &error_message)) {
				_LOGE("Don't execute query = %s error message = %s\n", vquery,
				       error_message);
				sqlite3_free(error_message);
				ret = PMINFO_R_ERROR;
				goto err;
		        }
		}
	}
	/*Commit transaction*/
	ret = sqlite3_exec(cert_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to commit transaction, Rollback now\n");
		sqlite3_exec(cert_db, "ROLLBACK", NULL, NULL, NULL);
		ret = PMINFO_R_ERROR;
		goto err;
	}
	_LOGE("Transaction Commit and End\n");
	ret =  PMINFO_R_OK;
err:
	sqlite3_close(cert_db);
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

API int pkgmgrinfo_delete_certinfo(const char *pkgid)
{
	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	int ret = -1;
	/*Open db.*/
	ret = db_util_open_with_options(CERT_DB, &cert_db, SQLITE_OPEN_READWRITE, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n", CERT_DB);
		ret = PMINFO_R_ERROR;
		goto err;
	}
	/*Begin Transaction*/
	ret = sqlite3_exec(cert_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to begin transaction\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	_LOGE("Transaction Begin\n");
	ret = __delete_certinfo(pkgid);
	if (ret < 0) {
		_LOGE("Certificate Deletion Failed\n");
	} else {
		_LOGE("Certificate Deletion Success\n");
	}
	/*Commit transaction*/
	ret = sqlite3_exec(cert_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to commit transaction, Rollback now\n");
		sqlite3_exec(cert_db, "ROLLBACK", NULL, NULL, NULL);
		ret = PMINFO_R_ERROR;
		goto err;
	}
	_LOGE("Transaction Commit and End\n");
	ret = PMINFO_R_OK;
err:
	sqlite3_close(cert_db);
	return ret;
}

API int pkgmgrinfo_create_pkgdbinfo(const char *pkgid, pkgmgrinfo_pkgdbinfo_h *handle)
{
	retvm_if(!pkgid, PMINFO_R_EINVAL, "pkgid is NULL");
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");

	char *manifest = NULL;
	manifest_x *mfx = NULL;

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
	retvm_if(!type, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");

	int len = strlen(type);
	retvm_if(len > PKG_TYPE_STRING_LEN_MAX, PMINFO_R_EINVAL, "pkg type length exceeds the max limit");

	manifest_x *mfx = (manifest_x *)handle;

	mfx->type = strndup(type, PKG_TYPE_STRING_LEN_MAX);
	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_version_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, const char *version)
{
	retvm_if(!version, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");

	int len = strlen(version);
	retvm_if(len > PKG_TYPE_STRING_LEN_MAX, PMINFO_R_EINVAL, "pkg type length exceeds the max limit");

	manifest_x *mfx = (manifest_x *)handle;

	mfx->version = strndup(version, PKG_VERSION_STRING_LEN_MAX);
	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_install_location_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, INSTALL_LOCATION location)
{
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if((location < 0) || (location > 1), PMINFO_R_EINVAL, "Argument supplied is NULL");

	manifest_x *mfx = (manifest_x *)handle;

	if (location == INSTALL_INTERNAL)
		strcpy(mfx->installlocation, "internal-only");
	else if (location == INSTALL_EXTERNAL)
		strcpy(mfx->installlocation, "prefer-external");

	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_size_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, const char *size)
{
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if(size == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL");

	manifest_x *mfx = (manifest_x *)handle;

	mfx->package_size = strdup(size);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_label_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, const char *label_txt, const char *locale)
{
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if(!label_txt, PMINFO_R_EINVAL, "Argument supplied is NULL");

	int len = strlen(label_txt);
	retvm_if(len > PKG_TYPE_STRING_LEN_MAX, PMINFO_R_EINVAL, "pkg type length exceeds the max limit");

	manifest_x *mfx = (manifest_x *)handle;

	label_x *label = calloc(1, sizeof(label_x));
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
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if(!icon_txt, PMINFO_R_EINVAL, "Argument supplied is NULL");

	int len = strlen(icon_txt);
	retvm_if(len > PKG_TYPE_STRING_LEN_MAX, PMINFO_R_EINVAL, "pkg type length exceeds the max limit");

	manifest_x *mfx = (manifest_x *)handle;

	icon_x *icon = calloc(1, sizeof(icon_x));
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
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if(!desc_txt, PMINFO_R_EINVAL, "Argument supplied is NULL");

	int len = strlen(desc_txt);
	retvm_if(len > PKG_TYPE_STRING_LEN_MAX, PMINFO_R_EINVAL, "pkg type length exceeds the max limit");

	manifest_x *mfx = (manifest_x *)handle;

	description_x *description = calloc(1, sizeof(description_x));
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
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");
	manifest_x *mfx = (manifest_x *)handle;
	author_x *author = calloc(1, sizeof(author_x));
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
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if((removable < 0) || (removable > 1), PMINFO_R_EINVAL, "Argument supplied is NULL");

	manifest_x *mfx = (manifest_x *)handle;

	if (removable == 0)
		strcpy(mfx->removable, "false");
	else if (removable == 1)
		strcpy(mfx->removable, "true");

	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_preload_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, int preload)
{
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if((preload < 0) || (preload > 1), PMINFO_R_EINVAL, "Argument supplied is NULL");

	manifest_x *mfx = (manifest_x *)handle;

	if (preload == 0)
		strcpy(mfx->preload, "false");
	else if (preload == 1)
		strcpy(mfx->preload, "true");

	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_installed_storage_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, INSTALL_LOCATION location)
{
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");
	retvm_if((location < 0) || (location > 1), PMINFO_R_EINVAL, "Argument supplied is NULL");

	manifest_x *mfx = (manifest_x *)handle;

	if (location == INSTALL_INTERNAL)
		strcpy(mfx->installed_storage, "installed_internal");
	else if (location == INSTALL_EXTERNAL)
		strcpy(mfx->installed_storage, "installed_external");

	return PMINFO_R_OK;
}

API int pkgmgrinfo_save_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle)
{
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");

	int ret = 0;
	manifest_x *mfx = NULL;
	mfx = (manifest_x *)handle;

	ret = pkgmgr_parser_update_manifest_info_in_db(mfx);
	retvm_if(ret != 0, PMINFO_R_ERROR, "Failed to store info in DB\n");
	
	ret = __update_ail_appinfo(mfx);
	retvm_if(ret != 0, PMINFO_R_ERROR, "Failed to store info in DB\n");

	_LOGE("Successfully stored info in DB\n");
	return PMINFO_R_OK;
}

API int pkgmgrinfo_destroy_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle)
{
	retvm_if(!handle, PMINFO_R_EINVAL, "Argument supplied is NULL");

	manifest_x *mfx = NULL;
	mfx = (manifest_x *)handle;
	pkgmgr_parser_free_manifest_xml(mfx);
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_set_state_enabled(const char *pkgid, bool enabled)
{
	/* Should be implemented later */
	return 0;
}

API int pkgmgrinfo_appinfo_set_state_enabled(const char *appid, bool enabled)
{
	retvm_if(appid == NULL, PMINFO_R_EINVAL, "appid is NULL\n");
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	sqlite3 *pkginfo_db = NULL;

	ret = db_util_open(MANIFEST_DB, &pkginfo_db, 0);
	retvm_if(ret != SQLITE_OK, PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	/*Begin transaction*/
	ret = sqlite3_exec(pkginfo_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to begin transaction\n");
		sqlite3_close(pkginfo_db);
		return PMINFO_R_ERROR;
	}
	_LOGD("Transaction Begin\n");

	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN,
		"update package_app_info set app_enabled='%s' where app_id='%s'", enabled?"true":"false", appid);

	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(pkginfo_db, query, NULL, NULL, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return PMINFO_R_ERROR;
	}
	sqlite3_free(error_message);

	/*Commit transaction*/
	ret = sqlite3_exec(pkginfo_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to commit transaction. Rollback now\n");
		sqlite3_exec(pkginfo_db, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(pkginfo_db);
		return PMINFO_R_ERROR;
	}
	_LOGD("Transaction Commit and End\n");
	sqlite3_close(pkginfo_db);

	return PMINFO_R_OK;
}


API int pkgmgrinfo_datacontrol_get_info(const char *providerid, const char * type, char **appid, char **access)
{
	retvm_if(providerid == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(type == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(appid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	retvm_if(access == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message = NULL;
	pkgmgr_datacontrol_x *data = NULL;

	sqlite3 *datacontrol_info_db = NULL;

	/*open db*/
	ret = db_util_open(DATACONTROL_DB, &datacontrol_info_db, 0);
	retvm_if(ret != SQLITE_OK, PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	data = (pkgmgr_datacontrol_x *)calloc(1, sizeof(pkgmgr_datacontrol_x));
	if (data == NULL) {
		_LOGE("Failed to allocate memory for pkgmgr_datacontrol_x\n");
		sqlite3_close(datacontrol_info_db);
		return PMINFO_R_ERROR;
	}

	snprintf(query, MAX_QUERY_LEN, 
		"select appinfo.package_name, datacontrol.access from appinfo, datacontrol where datacontrol.id=appinfo.unique_id and datacontrol.provider_id = '%s' and datacontrol.type='%s' COLLATE NOCASE",
		providerid, type);

	if (SQLITE_OK !=
		sqlite3_exec(datacontrol_info_db, query, __datacontrol_cb, (void *)data, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
			   error_message);
		sqlite3_free(error_message);
		sqlite3_close(datacontrol_info_db);
		return PMINFO_R_ERROR;
	}

	*appid = (char *)data->appid;
	*access = (char *)data->access;
	free(data);
	sqlite3_close(datacontrol_info_db);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_set_default_label(const char *appid, const char *label)
{
	retvm_if(appid == NULL, PMINFO_R_EINVAL, "appid is NULL\n");
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message = NULL;
	sqlite3 *pkginfo_db = NULL;

	/*open db*/
	ret = db_util_open(MANIFEST_DB, &pkginfo_db, 0);
	retvm_if(ret != SQLITE_OK, PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	/*Begin transaction*/
	ret = sqlite3_exec(pkginfo_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to begin transaction\n");
		sqlite3_close(pkginfo_db);
		return PMINFO_R_ERROR;
	}
	_LOGD("Transaction Begin\n");

	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "update package_app_localized_info set app_label='%s' where app_id='%s'", label, appid);

	ret = sqlite3_exec(pkginfo_db, query, NULL, NULL, &error_message);
	if (ret != SQLITE_OK) {
		_LOGE("Don't execute query = %s error message = %s\n", query, error_message);
		sqlite3_free(error_message);
		return PMINFO_R_ERROR;
	}

	/*Commit transaction*/
	ret = sqlite3_exec(pkginfo_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to commit transaction. Rollback now\n");
		sqlite3_exec(pkginfo_db, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(pkginfo_db);
		return PMINFO_R_ERROR;
	}
	_LOGD("Transaction Commit and End\n");
	sqlite3_close(pkginfo_db);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_guestmode_visibility(pkgmgrinfo_appinfo_h handle, bool *status)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(status == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	char *val = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	val = (char *)info->uiapp_info->guestmode_visibility;
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

API int pkgmgrinfo_appinfo_set_guestmode_visibility(pkgmgrinfo_appinfo_h handle, bool status)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	char *val = NULL;
	int ret = 0;
	char *noti_string = NULL;
	int len = 0;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *errmsg = NULL;
	sqlite3 *pkgmgr_parser_db;

	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	val = (char *)info->uiapp_info->guestmode_visibility;
	if (val ) {
                ret =
		    db_util_open_with_options(MANIFEST_DB, &pkgmgr_parser_db, SQLITE_OPEN_READWRITE, NULL);

                if (ret != SQLITE_OK) {
			_LOGE("DB Open Failed\n");
			return PMINFO_R_ERROR;
                }

		/*TODO: Write to DB here*/
		if (status == true)
			snprintf(query, MAX_QUERY_LEN, "update package_app_info set app_guestmodevisibility = 'true' where app_id = '%s'", (char *)info->uiapp_info->appid);
		else
			snprintf(query, MAX_QUERY_LEN, "update package_app_info set app_guestmodevisibility = 'false' where app_id = '%s'", (char *)info->uiapp_info->appid);

		if (SQLITE_OK != sqlite3_exec(pkgmgr_parser_db, query, NULL, NULL, &errmsg)) {
			_LOGE("DB update [%s] failed, error message = %s\n", query, errmsg);
			free(errmsg);
			sqlite3_close(pkgmgr_parser_db);
	                return PMINFO_R_ERROR;
		}else{
			sqlite3_close(pkgmgr_parser_db);
			len = strlen((char *)info->uiapp_info->appid) + 8;
		        noti_string = calloc(1, len);
			if (noti_string == NULL){
				return PMINFO_R_ERROR;
			}
			snprintf(noti_string, len, "update:%s", (char *)info->uiapp_info->appid);
        	vconf_set_str(VCONFKEY_AIL_INFO_STATE, noti_string);
			vconf_set_str(VCONFKEY_MENUSCREEN_DESKTOP, noti_string); // duplicate, will be removed
			free(noti_string);
		}
	}
	return PMINFO_R_OK;
}

/* pkgmgrinfo client start*/
API pkgmgrinfo_client *pkgmgrinfo_client_new(pkgmgrinfo_client_type ctype)
{
	int ret = 0;
	char *errmsg = NULL;
	void *pc = NULL;
	void *handle = NULL;
	pkgmgrinfo_client *(*__pkgmgr_client_new)(pkgmgrinfo_client_type ctype) = NULL;

	handle = dlopen("libpkgmgr-client.so.0", RTLD_LAZY | RTLD_GLOBAL);
	retvm_if(!handle, PMINFO_R_ERROR, "dlopen() failed. [%s]", dlerror());

	__pkgmgr_client_new = dlsym(handle, "pkgmgr_client_new");
	errmsg = dlerror();
	tryvm_if((errmsg != NULL) || (__pkgmgr_client_new == NULL), ret = PMINFO_R_ERROR, "dlsym() failed. [%s]", errmsg);

	pc = __pkgmgr_client_new(ctype);
	tryvm_if(pc == NULL, ret = PMINFO_R_ERROR, "pkgmgr_client_new failed.");

catch:
//	dlclose(handle);
	return (pkgmgrinfo_client *) pc;
}

API int pkgmgrinfo_client_set_status_type(pkgmgrinfo_client *pc, int status_type)
{
	int ret = 0;
	char *errmsg = NULL;
	void *handle = NULL;
	int (*__pkgmgr_client_set_status_type)(pkgmgrinfo_client *pc, int status_type) = NULL;

	handle = dlopen("libpkgmgr-client.so.0", RTLD_LAZY | RTLD_GLOBAL);
	retvm_if(!handle, PMINFO_R_ERROR, "dlopen() failed. [%s]", dlerror());

	__pkgmgr_client_set_status_type = dlsym(handle, "pkgmgr_client_set_status_type");
	errmsg = dlerror();
	tryvm_if((errmsg != NULL) || (__pkgmgr_client_set_status_type == NULL), ret = PMINFO_R_ERROR, "dlsym() failed. [%s]", errmsg);

	ret = __pkgmgr_client_set_status_type(pc, status_type);
	tryvm_if(ret < 0, ret = PMINFO_R_ERROR, "pkgmgr_client_new failed.");

catch:
//	dlclose(handle);
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
//	dlclose(handle);
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
//	dlclose(handle);
	return ret;
}

API int pkgmgrinfo_client_request_enable_external_pkg(char *pkgid)
{
	int ret = 0;
	DBusConnection *bus;
	DBusMessage *message;

	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "pkgid is NULL\n");

	if(__get_pkg_location(pkgid) != PMINFO_EXTERNAL_STORAGE)
		return PMINFO_R_OK;

	bus = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	retvm_if(bus == NULL, PMINFO_R_EINVAL, "dbus_bus_get() failed.");

	message = dbus_message_new_method_call (SERVICE_NAME, PATH_NAME, INTERFACE_NAME, METHOD_NAME);
	retvm_if(message == NULL, PMINFO_R_EINVAL, "dbus_message_new_method_call() failed.");

	dbus_message_append_args(message, DBUS_TYPE_STRING, &pkgid, DBUS_TYPE_INVALID);

	ret = dbus_connection_send_with_reply_and_block(bus, message, -1, NULL);
	retvm_if(!ret, ret = PMINFO_R_EINVAL, "connection_send dbus fail");

	dbus_connection_flush(bus);
	dbus_message_unref(message);

	return PMINFO_R_OK;
}

/* pkgmgrinfo client end*/

