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
#include <assert.h>

#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlschemas.h>

#include "pkgmgr_parser.h"
#include "pkgmgr-info-internal.h"
#include "pkgmgr-info.h"
#include <dirent.h>
#include <sys/stat.h>

#define ASC_CHAR(s) (const char *)s
#define XML_CHAR(s) (const xmlChar *)s

#define MANIFEST_DB	"/opt/dbspace/.pkgmgr_parser.db"
#define MAX_QUERY_LEN	4096
#define CERT_DB		"/opt/dbspace/.pkgmgr_cert.db"
#define DATACONTROL_DB	"/opt/usr/dbspace/.app-package.db"
#define PKG_TYPE_STRING_LEN_MAX		128
#define PKG_VERSION_STRING_LEN_MAX	128
#define PKG_VALUE_STRING_LEN_MAX		512
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

#define retv_if(expr, val) do { \
	if(expr) { \
		_LOGE("(%s) -> %s() return\n", #expr, __FUNCTION__); \
		return (val); \
	} \
} while (0)

#define LANGUAGE_LENGTH 2

typedef struct _pkgmgr_instcertinfo_x {
	char *pkgid;
	char *auth_signer_cert;
	char *auth_im_cert;
	char *auth_root_cert;
	char *dist_signer_cert;
	char *dist_im_cert;
	char *dist_root_cert;
	char *dist2_signer_cert;
	char *dist2_im_cert;
	char *dist2_root_cert;
} pkgmgr_instcertinfo_x;

sqlite3 *cert_db = NULL;

typedef struct _pkgmgr_pkginfo_x {
	manifest_x *manifest_info;
	char *tmp;
	char *tmp_dup;

	struct _pkgmgr_pkginfo_x *prev;
	struct _pkgmgr_pkginfo_x *next;
} pkgmgr_pkginfo_x;

typedef struct _pkgmgr_cert_x {
	const char *pkgid;
	const char *certvalue;
} pkgmgr_cert_x;

typedef struct _pkgmgr_datacontrol_x {
	char *appid;
	char *access;
} pkgmgr_datacontrol_x;

typedef struct _pkgmgr_iconpath_x {
	char *appid;
	char *iconpath;
} pkgmgr_iconpath_x;

typedef struct _pkgmgr_locale_x {
	char *locale;
} pkgmgr_locale_x;

typedef struct _pkgmgr_appinfo_x {
	const char *package;
	pkgmgrinfo_app_component app_component;
	union {
		uiapplication_x *uiapp_info;
		serviceapplication_x *svcapp_info;
	};
} pkgmgr_appinfo_x;

typedef struct _pkgmgr_certinfo_x {
	char *pkgid;
	char *auth_signer_cert;
	char *auth_im_cert;
	char *auth_root_cert;
	char *dist_signer_cert;
	char *dist_im_cert;
	char *dist_root_cert;
	char *dist2_signer_cert;
	char *dist2_im_cert;
	char *dist2_root_cert;
} pkgmgr_certinfo_x;

/*For filter APIs*/
typedef struct _pkgmgrinfo_filter_x {
	GSList *list;
} pkgmgrinfo_filter_x;

typedef struct _pkgmgrinfo_node_x {
	int prop;
	char *value;
} pkgmgrinfo_node_x;

typedef struct _pkgmgrinfo_appcontrol_x {
	int operation_count;
	int uri_count;
	int mime_count;
	char **operation;
	char **uri;
	char **mime;
} pkgmgrinfo_appcontrol_x;

typedef int (*sqlite_query_callback)(void *data, int ncols, char **coltxt, char **colname);

char *pkgtype = "rpm";
sqlite3 *manifest_db = NULL;
sqlite3 *datacontrol_db = NULL;
int gflag[9];/*one for each cert type*/
char *gpkgcert[9];/*To store pkg cert values*/

static int __open_manifest_db();
static int __exec_pkginfo_query(char *query, void *data);
static int __exec_appinfo_query(char *query, void *data);
static int __exec_certinfo_query(char *query, void *data);
static int __exec_sqlite_query(char *query, sqlite_query_callback callback, void *data);
static int __pkginfo_cb(void *data, int ncols, char **coltxt, char **colname);
static int __appinfo_cb(void *data, int ncols, char **coltxt, char **colname);
static int __certinfo_cb(void *data, int ncols, char **coltxt, char **colname);
static int __validate_cb(void *data, int ncols, char **coltxt, char **colname);
static int __delete_certinfo_cb(void *data, int ncols, char **coltxt, char **colname);
static int __count_cb(void *data, int ncols, char **coltxt, char **colname);
static int __uiapp_list_cb(void *data, int ncols, char **coltxt, char **colname);
static int __svcapp_list_cb(void *data, int ncols, char **coltxt, char **colname);
static int __pkg_list_cb(void *data, int ncols, char **coltxt, char **colname);
static int __app_list_cb(void *data, int ncols, char **coltxt, char **colname);
static int __pkgmgr_appinfo_new_handle_id();
static int __pkgmgr_pkginfo_new_handle_id();
static void __cleanup_pkginfo(pkgmgr_pkginfo_x *data);
static void __cleanup_appinfo(pkgmgr_appinfo_x *data);
static char* __convert_system_locale_to_manifest_locale(char *syslocale);
static void __destroy_each_node(gpointer data, gpointer user_data);
static void __get_filter_condition(gpointer data, char **condition);
static gint __compare_func(gconstpointer data1, gconstpointer data2);

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
	if (data == NULL)
		return;
	pkgmgrinfo_node_x *node = (pkgmgrinfo_node_x*)data;
	if (node->value) {
		free(node->value);
		node->value = NULL;
	}
	free(node);
	node = NULL;
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
	if (!locale) {
		_LOGE("Malloc Failed\n");
		return NULL;
	}
	strncpy(locale, syslocale, 2);
	strncat(locale, "-", 1);
	locale[3] = syslocale[3] + 32;
	locale[4] = syslocale[4] + 32;
	return locale;
}

static void __cleanup_pkginfo(pkgmgr_pkginfo_x *data)
{
	if (data == NULL)
		return;
	if (data->tmp_dup){
		free((void *)data->tmp_dup);
		data->tmp_dup = NULL;
	}

	pkgmgr_parser_free_manifest_xml(data->manifest_info);
	free((void *)data);
	data = NULL;
	return;
}

static void __cleanup_appinfo(pkgmgr_appinfo_x *data)
{
	if (data == NULL)
		return;

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

static int __open_manifest_db()
{
	int ret = -1;
	if (access(MANIFEST_DB, F_OK) == 0) {
		ret =
		    db_util_open_with_options(MANIFEST_DB, &manifest_db,
				 SQLITE_OPEN_READONLY, NULL);
		if (ret != SQLITE_OK) {
			_LOGE("connect db [%s] failed!\n", MANIFEST_DB);
			return -1;
		}
		return 0;
	}
	_LOGE("Manifest DB does not exists !!\n");
	return -1;
}

static int __open_datacontrol_db()
{
	int ret = -1;
	if (access(DATACONTROL_DB, F_OK) == 0) {
		ret =
		    db_util_open_with_options(DATACONTROL_DB, &datacontrol_db,
				 SQLITE_OPEN_READONLY, NULL);
		if (ret != SQLITE_OK) {
			_LOGE("connect db [%s] failed!\n", DATACONTROL_DB);
			return -1;
		}
		return 0;
	}
	_LOGE("Datacontrol DB does not exists !!\n");
	return -1;
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
						if (strcmp(colname[j], "app_id") == 0) {
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
		} else if (strcmp(colname[i], "app_locale") == 0 ) {
			if (coltxt[i]) {
				info->manifest_info->uiapplication->icon->lang = strdup(coltxt[i]);
				info->manifest_info->uiapplication->label->lang = strdup(coltxt[i]);
			}
			else {
				info->manifest_info->uiapplication->icon->lang = NULL;
				info->manifest_info->uiapplication->label->lang = NULL;
			}
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
						} else if (strcmp(colname[i], "app_locale") == 0 ) {
							if (coltxt[i]) {
								info->manifest_info->uiapplication->icon->lang = strdup(coltxt[i]);
								info->manifest_info->uiapplication->label->lang = strdup(coltxt[i]);
							}
							else {
								info->manifest_info->uiapplication->icon->lang = NULL;
								info->manifest_info->uiapplication->label->lang = NULL;
							}
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

static int __pkginfo_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)data;
	int i = 0;
	author_x *author = NULL;
	icon_x *icon = NULL;
	label_x *label = NULL;
	description_x *description = NULL;

	author = calloc(1, sizeof(author_x));
	LISTADD(info->manifest_info->author, author);
	icon = calloc(1, sizeof(icon_x));
	LISTADD(info->manifest_info->icon, icon);
	label = calloc(1, sizeof(label_x));
	LISTADD(info->manifest_info->label, label);
	description = calloc(1, sizeof(description_x));
	LISTADD(info->manifest_info->description, description);
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
		} else if (strcmp(colname[i], "installed_time") == 0 ){
			if (coltxt[i])
				info->manifest_info->installed_time = strdup(coltxt[i]);
			else
				info->manifest_info->installed_time = NULL;
		} else if (strcmp(colname[i], "mainapp_id") == 0 ){
			if (coltxt[i])
				info->manifest_info->mainapp_id = strdup(coltxt[i]);
			else
				info->manifest_info->mainapp_id = NULL;

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

static int __delete_certinfo_cb(void *data, int ncols, char **coltxt, char **colname)
{
	const char *pkgid = (const char *)data;
	int i = 0;
	char *error_message = NULL;
	int ret =0;
	char query[MAX_QUERY_LEN] = {'\0'};
	pkgmgr_instcertinfo_x *certinfo = NULL;
	certinfo = calloc(1, sizeof(pkgmgr_certinfo_x));
	if (certinfo == NULL) {
		_LOGE("Out of Memory!!!\n");
		return PMINFO_R_ERROR;
	}
	for (i  = 0; i < ncols; i++) {
		if (strcmp(colname[i], "package") == 0) {
			if (coltxt[i])
				certinfo->pkgid = coltxt[i];
		} else if (strcmp(colname[i], "author_signer_cert") == 0) {
			if (coltxt[i]) {
				if (strcmp(coltxt[i], pkgid) == 0) {
					if (gflag[PMINFO_AUTHOR_SIGNER_CERT] && gpkgcert[PMINFO_AUTHOR_SIGNER_CERT]) {
						certinfo->auth_signer_cert = strdup(gpkgcert[PMINFO_AUTHOR_SIGNER_CERT]);
						continue;
					}
					snprintf(query, MAX_QUERY_LEN, "select author_signer_cert from package_cert_info " \
						"where package='%s'", pkgid);
					if (SQLITE_OK !=
					    sqlite3_exec(cert_db, query, __certinfo_cb, (void *)certinfo, &error_message)) {
						_LOGE("Don't execute query = %s error message = %s\n", query,
						       error_message);
						sqlite3_free(error_message);
						ret = PMINFO_R_ERROR;
						goto err;
					}
					gpkgcert[PMINFO_AUTHOR_SIGNER_CERT] = strdup(certinfo->pkgid);
					gflag[PMINFO_AUTHOR_SIGNER_CERT] = 1;
				} else {
					certinfo->auth_signer_cert = strdup(coltxt[i]);
				}
			}
			continue;
		} else if (strcmp(colname[i], "author_im_cert") == 0) {
			if (coltxt[i]) {
				if (strcmp(coltxt[i], pkgid) == 0) {
					if (gflag[PMINFO_AUTHOR_INTERMEDIATE_CERT] && gpkgcert[PMINFO_AUTHOR_INTERMEDIATE_CERT]) {
						certinfo->auth_im_cert = strdup(gpkgcert[PMINFO_AUTHOR_INTERMEDIATE_CERT]);
						continue;
					}
					snprintf(query, MAX_QUERY_LEN, "select author_im_cert from package_cert_info " \
						"where package='%s'", pkgid);
					if (SQLITE_OK !=
					    sqlite3_exec(cert_db, query, __certinfo_cb, (void *)certinfo, &error_message)) {
						_LOGE("Don't execute query = %s error message = %s\n", query,
						       error_message);
						sqlite3_free(error_message);
						ret = PMINFO_R_ERROR;
						goto err;
					}
					gpkgcert[PMINFO_AUTHOR_INTERMEDIATE_CERT] = strdup(certinfo->pkgid);
					gflag[PMINFO_AUTHOR_INTERMEDIATE_CERT] = 1;
				} else {
					certinfo->auth_im_cert = strdup(coltxt[i]);
				}
			}
			continue;
		} else if (strcmp(colname[i], "author_root_cert") == 0) {
			if (coltxt[i]) {
				if (strcmp(coltxt[i], pkgid) == 0) {
					if (gflag[PMINFO_AUTHOR_ROOT_CERT] && gpkgcert[PMINFO_AUTHOR_ROOT_CERT]) {
						certinfo->auth_root_cert = strdup(gpkgcert[PMINFO_AUTHOR_ROOT_CERT]);
						continue;
					}
					snprintf(query, MAX_QUERY_LEN, "select author_root_cert from package_cert_info " \
						"where package='%s'", pkgid);
					if (SQLITE_OK !=
					    sqlite3_exec(cert_db, query, __certinfo_cb, (void *)certinfo, &error_message)) {
						_LOGE("Don't execute query = %s error message = %s\n", query,
						       error_message);
						sqlite3_free(error_message);
						ret = PMINFO_R_ERROR;
						goto err;
					}
					gpkgcert[PMINFO_AUTHOR_ROOT_CERT] = strdup(certinfo->pkgid);
					gflag[PMINFO_AUTHOR_ROOT_CERT] = 1;
				} else {
					certinfo->auth_root_cert = strdup(coltxt[i]);
				}
			}
			continue;
		} else if (strcmp(colname[i], "dist_signer_cert") == 0 ) {
			if (coltxt[i]) {
				if (strcmp(coltxt[i], pkgid) == 0) {
					if (gflag[PMINFO_DISTRIBUTOR_SIGNER_CERT] && gpkgcert[PMINFO_DISTRIBUTOR_SIGNER_CERT]) {
						certinfo->dist_signer_cert = strdup(gpkgcert[PMINFO_DISTRIBUTOR_SIGNER_CERT]);
						continue;
					}
					snprintf(query, MAX_QUERY_LEN, "select dist_signer_cert from package_cert_info " \
						"where package='%s'", pkgid);
					if (SQLITE_OK !=
					    sqlite3_exec(cert_db, query, __certinfo_cb, (void *)certinfo, &error_message)) {
						_LOGE("Don't execute query = %s error message = %s\n", query,
						       error_message);
						sqlite3_free(error_message);
						ret = PMINFO_R_ERROR;
						goto err;
					}
					gpkgcert[PMINFO_DISTRIBUTOR_SIGNER_CERT] = strdup(certinfo->pkgid);
					gflag[PMINFO_DISTRIBUTOR_SIGNER_CERT] = 1;
				} else {
					certinfo->dist_signer_cert = strdup(coltxt[i]);
				}
			}
			continue;
		} else if (strcmp(colname[i], "dist_im_cert") == 0 ) {
			if (coltxt[i]) {
				if (strcmp(coltxt[i], pkgid) == 0) {
					if (gflag[PMINFO_DISTRIBUTOR_INTERMEDIATE_CERT] && gpkgcert[PMINFO_DISTRIBUTOR_INTERMEDIATE_CERT]) {
						certinfo->dist_im_cert = strdup(gpkgcert[PMINFO_DISTRIBUTOR_INTERMEDIATE_CERT]);
						continue;
					}
					snprintf(query, MAX_QUERY_LEN, "select dist_im_cert from package_cert_info " \
						"where package='%s'", pkgid);
					if (SQLITE_OK !=
					    sqlite3_exec(cert_db, query, __certinfo_cb, (void *)certinfo, &error_message)) {
						_LOGE("Don't execute query = %s error message = %s\n", query,
						       error_message);
						sqlite3_free(error_message);
						ret = PMINFO_R_ERROR;
						goto err;
					}
					gpkgcert[PMINFO_DISTRIBUTOR_INTERMEDIATE_CERT] = strdup(certinfo->pkgid);
					gflag[PMINFO_DISTRIBUTOR_INTERMEDIATE_CERT] = 1;
				} else {
					certinfo->dist_im_cert = strdup(coltxt[i]);
				}
			}
			continue;
		} else if (strcmp(colname[i], "dist_root_cert") == 0 ) {
			if (coltxt[i]) {
				if (strcmp(coltxt[i], pkgid) == 0) {
					if (gflag[PMINFO_DISTRIBUTOR_ROOT_CERT] && gpkgcert[PMINFO_DISTRIBUTOR_ROOT_CERT]) {
						certinfo->dist_root_cert = strdup(gpkgcert[PMINFO_DISTRIBUTOR_ROOT_CERT]);
						continue;
					}
					snprintf(query, MAX_QUERY_LEN, "select dist_root_cert from package_cert_info " \
						"where package='%s'", pkgid);
					if (SQLITE_OK !=
					    sqlite3_exec(cert_db, query, __certinfo_cb, (void *)certinfo, &error_message)) {
						_LOGE("Don't execute query = %s error message = %s\n", query,
						       error_message);
						sqlite3_free(error_message);
						ret = PMINFO_R_ERROR;
						goto err;
					}
					gpkgcert[PMINFO_DISTRIBUTOR_ROOT_CERT] = strdup(certinfo->pkgid);
					gflag[PMINFO_DISTRIBUTOR_ROOT_CERT] = 1;
				} else {
					certinfo->dist_root_cert = strdup(coltxt[i]);
				}
			}
			continue;
		} else if (strcmp(colname[i], "dist2_signer_cert") == 0 ) {
			if (coltxt[i]) {
				if (strcmp(coltxt[i], pkgid) == 0) {
					if (gflag[PMINFO_DISTRIBUTOR2_SIGNER_CERT] && gpkgcert[PMINFO_DISTRIBUTOR2_SIGNER_CERT]) {
						certinfo->dist2_signer_cert = strdup(gpkgcert[PMINFO_DISTRIBUTOR2_SIGNER_CERT]);
						continue;
					}
					snprintf(query, MAX_QUERY_LEN, "select dist2_signer_cert from package_cert_info " \
						"where package='%s'", pkgid);
					if (SQLITE_OK !=
					    sqlite3_exec(cert_db, query, __certinfo_cb, (void *)certinfo, &error_message)) {
						_LOGE("Don't execute query = %s error message = %s\n", query,
						       error_message);
						sqlite3_free(error_message);
						ret = PMINFO_R_ERROR;
						goto err;
					}
					gpkgcert[PMINFO_DISTRIBUTOR2_SIGNER_CERT] = strdup(certinfo->pkgid);
					gflag[PMINFO_DISTRIBUTOR2_SIGNER_CERT] = 1;
				} else {
					certinfo->dist2_signer_cert = strdup(coltxt[i]);
				}
			}
			continue;
		} else if (strcmp(colname[i], "dist2_im_cert") == 0 ) {
			if (coltxt[i]) {
				if (strcmp(coltxt[i], pkgid) == 0) {
					if (gflag[PMINFO_DISTRIBUTOR2_INTERMEDIATE_CERT] && gpkgcert[PMINFO_DISTRIBUTOR2_INTERMEDIATE_CERT]) {
						certinfo->dist2_im_cert = strdup(gpkgcert[PMINFO_DISTRIBUTOR2_INTERMEDIATE_CERT]);
						continue;
					}
					snprintf(query, MAX_QUERY_LEN, "select dist2_im_cert from package_cert_info " \
						"where package='%s'", pkgid);
					if (SQLITE_OK !=
					    sqlite3_exec(cert_db, query, __certinfo_cb, (void *)certinfo, &error_message)) {
						_LOGE("Don't execute query = %s error message = %s\n", query,
						       error_message);
						sqlite3_free(error_message);
						ret = PMINFO_R_ERROR;
						goto err;
					}
					gpkgcert[PMINFO_DISTRIBUTOR2_INTERMEDIATE_CERT] = strdup(certinfo->pkgid);
					gflag[PMINFO_DISTRIBUTOR2_INTERMEDIATE_CERT] = 1;
				} else {
					certinfo->dist2_im_cert = strdup(coltxt[i]);
				}
			}
			continue;
		} else if (strcmp(colname[i], "dist2_root_cert") == 0 ) {
			if (coltxt[i]) {
				if (strcmp(coltxt[i], pkgid) == 0) {
					if (gflag[PMINFO_DISTRIBUTOR2_ROOT_CERT] && gpkgcert[PMINFO_DISTRIBUTOR2_ROOT_CERT]) {
						certinfo->dist2_root_cert = strdup(gpkgcert[PMINFO_DISTRIBUTOR2_ROOT_CERT]);
						continue;
					}
					snprintf(query, MAX_QUERY_LEN, "select dist2_root_cert from package_cert_info " \
						"where package='%s'", pkgid);
					if (SQLITE_OK !=
					    sqlite3_exec(cert_db, query, __certinfo_cb, (void *)certinfo, &error_message)) {
						_LOGE("Don't execute query = %s error message = %s\n", query,
						       error_message);
						sqlite3_free(error_message);
						ret = PMINFO_R_ERROR;
						goto err;
					}
					gpkgcert[PMINFO_DISTRIBUTOR2_ROOT_CERT] = strdup(certinfo->pkgid);
					gflag[PMINFO_DISTRIBUTOR2_ROOT_CERT] = 1;
				} else {
					certinfo->dist2_root_cert = strdup(coltxt[i]);
				}
			}
			continue;
		}
	}
	/*Update cert info db*/
	pkgmgrinfo_save_certinfo(certinfo->pkgid, (void *)certinfo);
	ret = PMINFO_R_OK;
err:
	if (certinfo->auth_signer_cert) {
		free(certinfo->auth_signer_cert);
		certinfo->auth_signer_cert = NULL;
	}
	if (certinfo->auth_im_cert) {
		free(certinfo->auth_im_cert);
		certinfo->auth_im_cert = NULL;
	}
	if (certinfo->auth_root_cert) {
		free(certinfo->auth_root_cert);
		certinfo->auth_root_cert = NULL;
	}
	if (certinfo->dist_signer_cert) {
		free(certinfo->dist_signer_cert);
		certinfo->dist_signer_cert = NULL;
	}
	if (certinfo->dist_im_cert) {
		free(certinfo->dist_im_cert);
		certinfo->dist_im_cert = NULL;
	}
	if (certinfo->dist_root_cert) {
		free(certinfo->dist_root_cert);
		certinfo->dist_root_cert = NULL;
	}
	if (certinfo->dist2_signer_cert) {
		free(certinfo->dist2_signer_cert);
		certinfo->dist2_signer_cert = NULL;
	}
	if (certinfo->dist2_im_cert) {
		free(certinfo->dist2_im_cert);
		certinfo->dist2_im_cert = NULL;
	}
	if (certinfo->dist2_root_cert) {
		free(certinfo->dist2_root_cert);
		certinfo->dist2_root_cert = NULL;
	}
	free(certinfo);
	certinfo = NULL;
	return ret;
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
				info->auth_signer_cert = strdup(coltxt[i]);
			else
				info->auth_signer_cert = NULL;
		} else if (strcmp(colname[i], "author_im_cert") == 0) {
			if (coltxt[i])
				info->auth_im_cert = strdup(coltxt[i]);
			else
				info->auth_im_cert = NULL;
		} else if (strcmp(colname[i], "author_root_cert") == 0) {
			if (coltxt[i])
				info->auth_root_cert = strdup(coltxt[i]);
			else
				info->auth_root_cert = NULL;
		} else if (strcmp(colname[i], "dist_signer_cert") == 0 ){
			if (coltxt[i])
				info->dist_signer_cert = strdup(coltxt[i]);
			else
				info->dist_signer_cert = NULL;
		} else if (strcmp(colname[i], "dist_im_cert") == 0 ){
			if (coltxt[i])
				info->dist_im_cert = strdup(coltxt[i]);
			else
				info->dist_im_cert = NULL;
		} else if (strcmp(colname[i], "dist_root_cert") == 0 ){
			if (coltxt[i])
				info->dist_root_cert = strdup(coltxt[i]);
			else
				info->dist_root_cert = NULL;
		} else if (strcmp(colname[i], "dist2_signer_cert") == 0 ){
			if (coltxt[i])
				info->dist2_signer_cert = strdup(coltxt[i]);
			else
				info->dist2_signer_cert = NULL;
		} else if (strcmp(colname[i], "dist2_im_cert") == 0 ){
			if (coltxt[i])
				info->dist2_im_cert = strdup(coltxt[i]);
			else
				info->dist2_im_cert = NULL;
		} else if (strcmp(colname[i], "dist2_root_cert") == 0 ){
			if (coltxt[i])
				info->dist2_root_cert = strdup(coltxt[i]);
			else
				info->dist2_root_cert = NULL;
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

	switch (info->app_component) {
	case PMINFO_UI_APP:
		icon = calloc(1, sizeof(icon_x));
		LISTADD(info->uiapp_info->icon, icon);
		label = calloc(1, sizeof(label_x));
		LISTADD(info->uiapp_info->label, label);
		category = calloc(1, sizeof(category_x));
		LISTADD(info->uiapp_info->category, category);
		for(i = 0; i < ncols; i++)
		{
			if (strcmp(colname[i], "app_id") == 0) {
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
			} else if (strcmp(colname[i], "category") == 0 ) {
				if (coltxt[i])
					info->uiapp_info->category->name = strdup(coltxt[i]);
				else
					info->uiapp_info->category->name = NULL;
			} else if (strcmp(colname[i], "app_locale") == 0 ) {
				if (coltxt[i]) {
					info->uiapp_info->icon->lang = strdup(coltxt[i]);
					info->uiapp_info->label->lang = strdup(coltxt[i]);
				}
				else {
					info->uiapp_info->icon->lang = NULL;
					info->uiapp_info->label->lang = NULL;
				}
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
		for(i = 0; i < ncols; i++)
		{
			if (strcmp(colname[i], "app_id") == 0) {
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
			} else if (strcmp(colname[i], "category") == 0 ) {
				if (coltxt[i])
					info->svcapp_info->category->name = strdup(coltxt[i]);
				else
					info->svcapp_info->category->name = NULL;
			} else if (strcmp(colname[i], "app_locale") == 0 ) {
				if (coltxt[i]) {
					info->svcapp_info->icon->lang = strdup(coltxt[i]);
					info->svcapp_info->label->lang = strdup(coltxt[i]);
				}
				else {
					info->svcapp_info->icon->lang = NULL;
					info->svcapp_info->label->lang = NULL;
				}
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

static int __icon_name_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_iconpath_x *icon_name = (pkgmgr_iconpath_x *)data;
	int i = 0;
	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "app_icon") == 0) {
			if (coltxt[i])
				icon_name->iconpath = strdup(coltxt[i]);
			else
				icon_name->iconpath = NULL;
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
				info->certvalue= strdup(coltxt[i]);
			else
				info->certvalue = NULL;
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

static int __exec_pkginfo_query(char *query, void *data)
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __pkginfo_cb, data, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
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

static int __exec_appcomponent_query(char *query, void *data)
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __appcomponent_cb, data, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}


static int __exec_appinfo_query(char *query, void *data)
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __appinfo_cb, data, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __exec_sqlite_query(char *query, sqlite_query_callback callback, void *data)
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, callback, data, &error_message)) {
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

static char *__get_package_from_icon(char *icon)
{
	char *package;
	char *extension;

	retv_if(!icon, NULL);

	package = strdup(icon);
	retv_if(!package, NULL);
	extension = rindex(package, '.');
	if (extension) {
		*extension = '\0';
	} else {
		_LOGE("cannot extract from icon [%s] to package.", icon);
	}

	return package;
}

static char *__get_icon_with_path(char *icon)
{
	retv_if(!icon, NULL);

	if (index(icon, '/') == NULL) {
		char *package;
		char *theme = NULL;
		char *icon_with_path = NULL;
		int len;

		package = __get_package_from_icon(icon);
		retv_if(!package, NULL);

		theme = vconf_get_str("db/setting/theme");
		if (!theme) {
			theme = strdup("default");
			if(!theme) {
				free(package);
				return NULL;
			}
		}

		len = (0x01 << 7) + strlen(icon) + strlen(package) + strlen(theme);
		icon_with_path = malloc(len);
		if(icon_with_path == NULL) {
			_LOGE("(icon_with_path == NULL) return\n");
			free(package);
			free(theme);
			return NULL;
		}

		memset(icon_with_path, 0, len);

		sqlite3_snprintf( len, icon_with_path,"/opt/share/icons/%q/small/%q", theme, icon);
		do {
			if (access(icon_with_path, R_OK) == 0) break;
			sqlite3_snprintf( len, icon_with_path,"/usr/share/icons/%q/small/%q", theme, icon);
			if (access(icon_with_path, R_OK) == 0) break;
			_LOGE("cannot find icon %s", icon_with_path);
			sqlite3_snprintf( len, icon_with_path, "/opt/share/icons/default/small/%q", icon);
			if (access(icon_with_path, R_OK) == 0) break;
			sqlite3_snprintf( len, icon_with_path, "/usr/share/icons/default/small/%q", icon);
			if (access(icon_with_path, R_OK) == 0) break;

			#if 1 /* this will be remove when finish the work for moving icon path */
			_LOGE("icon file must be moved to %s", icon_with_path);
			sqlite3_snprintf( len, icon_with_path,  "/opt/apps/%q/res/icons/%q/small/%q", package, theme, icon);
			if (access(icon_with_path, R_OK) == 0) break;
			sqlite3_snprintf( len, icon_with_path, "/usr/apps/%q/res/icons/%q/small/%q", package, theme, icon);
			if (access(icon_with_path, R_OK) == 0) break;
			_LOGE("cannot find icon %s", icon_with_path);
			sqlite3_snprintf( len, icon_with_path, "/opt/apps/%q/res/icons/default/small/%q", package, icon);
			if (access(icon_with_path, R_OK) == 0) break;
			sqlite3_snprintf( len, icon_with_path, "/usr/apps/%q/res/icons/default/small/%q", package, icon);
			if (access(icon_with_path, R_OK) == 0) break;
			#endif
		} while (0);

		free(theme);
		free(package);

		_LOGD("Icon path : %s ---> %s", icon, icon_with_path);

		return icon_with_path;
	} else {
		char* confirmed_icon = NULL;

		confirmed_icon = strdup(icon);
		retv_if(!confirmed_icon, NULL);
		return confirmed_icon;
	}
}

static int __check_validation_of_qurey_cb(void *data, int ncols, char **coltxt, char **colname)
{
	int *p = (int*)data;
	*p = atoi(coltxt[0]);
	return 0;
}

static int __check_app_locale_from_app_localized_info_by_exact(const char *appid, const char *locale)
{
	int result_query = -1;
	char query[MAX_QUERY_LEN];

	snprintf(query, MAX_QUERY_LEN, "select exists(select app_locale from package_app_localized_info where app_id='%s' and app_locale='%s')", appid, locale);
	__exec_sqlite_query(query, __check_validation_of_qurey_cb, (void *)&result_query);

	return result_query;
}

static int __check_app_locale_from_app_localized_info_by_fallback(const char *appid, const char *locale)
{
	int result_query = -1;
	char wildcard[2] = {'%','\0'};
	char query[MAX_QUERY_LEN];
	char lang[3] = {'\0'};
	strncpy(lang, locale, LANGUAGE_LENGTH);

	snprintf(query, MAX_QUERY_LEN, "select exists(select app_locale from package_app_localized_info where app_id='%s' and app_locale like '%s%s')", appid, lang, wildcard);
	__exec_sqlite_query(query, __check_validation_of_qurey_cb, (void *)&result_query);

	return result_query;
}

static char* __get_app_locale_from_app_localized_info_by_fallback(const char *appid, const char *locale)
{
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
	memset(info, NULL, sizeof(*info));

	strncpy(lang, locale, 2);
	snprintf(query, MAX_QUERY_LEN, "select app_locale from package_app_localized_info where app_id='%s' and app_locale like '%s%s'", appid, lang, wildcard);
	__exec_sqlite_query(query, __fallback_locale_cb, (void *)info);
	locale_new = info->locale;
	free(info);

	return locale_new;
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

static char* __get_app_locale_by_fallback(const char *appid, const char *syslocale)
{
	assert(appid);
	assert(syslocale);

	char *locale = NULL;
	char *locale_new = NULL;
	int check_result = 0;

	locale = __convert_syslocale_to_manifest_locale(syslocale);

	/*check exact matching */
	check_result = __check_app_locale_from_app_localized_info_by_exact(appid, locale);

	/* Exact found */
	if (check_result == 1) {
		_LOGD("%s find exact locale(%s)\n", appid, locale);
		return locale;
	}

	/* fallback matching */
	check_result = __check_app_locale_from_app_localized_info_by_fallback(appid, locale);
	if(check_result == 1) {
		   locale_new = __get_app_locale_from_app_localized_info_by_fallback(appid, locale);
		   _LOGD("%s found (%s) language-locale in DB by fallback!\n", appid, locale_new);
		   free(locale);
		   if (locale_new == NULL)
			   locale_new =  strdup(DEFAULT_LOCALE);
		   return locale_new;
	}

	/* default locale */
	free(locale);
	_LOGD("%s DEFAULT_LOCALE)\n", appid);
	return	strdup(DEFAULT_LOCALE);
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
	if (dirname == NULL) {
		_LOGE("dirname is NULL");
		return PMINFO_R_ERROR;
	}
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

API int pkgmgrinfo_pkginfo_get_list(pkgmgrinfo_pkg_list_cb pkg_list_cb, void *user_data)
{
	if (pkg_list_cb == NULL) {
		_LOGE("callback function is NULL\n");
		return PMINFO_R_EINVAL;
	}
	char *error_message = NULL;
	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *syslocale = NULL;
	char *locale = NULL;
	pkgmgr_pkginfo_x *pkginfo = NULL;
	label_x *tmp1 = NULL;
	icon_x *tmp2 = NULL;
	description_x *tmp3 = NULL;
	author_x *tmp4 = NULL;

	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	if (syslocale == NULL) {
		_LOGE("current locale is NULL\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		ret = PMINFO_R_EINVAL;
		goto err;
	}

	ret = __open_manifest_db();
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	pkgmgr_pkginfo_x *tmphead = calloc(1, sizeof(pkgmgr_pkginfo_x));
	pkgmgr_pkginfo_x *node = NULL;
	pkgmgr_pkginfo_x *temp_node = NULL;

	snprintf(query, MAX_QUERY_LEN, "select * from package_info");
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __pkg_list_cb, (void *)tmphead, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		sqlite3_close(manifest_db);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	LISTHEAD(tmphead, node);

	for(node = node->next; node ; node = node->next) {
		pkginfo = node;

		/*populate manifest_info from DB*/
		snprintf(query, MAX_QUERY_LEN, "select * from package_info where package='%s' ", pkginfo->manifest_info->package);
		ret = __exec_pkginfo_query(query, (void *)pkginfo);
		if (ret == -1) {
			_LOGE("Package Info DB Information retrieval failed\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select * from package_localized_info where" \
			" package='%s' and package_locale='%s'", pkginfo->manifest_info->package, locale);
		ret = __exec_pkginfo_query(query, (void *)pkginfo);
		if (ret == -1) {
			_LOGE("Package Info DB Information retrieval failed\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		/*Also store the values corresponding to default locales*/
		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select * from package_localized_info where" \
			" package='%s' and package_locale='%s'", pkginfo->manifest_info->package, DEFAULT_LOCALE);
		ret = __exec_pkginfo_query(query, (void *)pkginfo);
		if (ret == -1) {
			_LOGE("Package Info DB Information retrieval failed\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
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
	}

	LISTHEAD(tmphead, node);

	for(node = node->next; node ; node = node->next) {
		pkginfo = node;
		ret = pkg_list_cb( (void *)pkginfo, user_data);
		if(ret < 0)
			break;
	}

	ret = PMINFO_R_OK;

err:
	sqlite3_close(manifest_db);
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
	if (pkgid == NULL) {
		_LOGE("package name is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (handle == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_pkginfo_x *pkginfo = NULL;
	char *error_message = NULL;
	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *syslocale = NULL;
	char *locale = NULL;
	int exist = 0;
	label_x *tmp1 = NULL;
	icon_x *tmp2 = NULL;
	description_x *tmp3 = NULL;
	author_x *tmp4 = NULL;

	/*validate pkgid*/
	ret = __open_manifest_db();
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_info where package='%s')", pkgid);
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		sqlite3_close(manifest_db);
		return PMINFO_R_ERROR;
	}
	if (exist == 0) {
		_LOGE("Package not found in DB\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}

	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	if (syslocale == NULL) {
		_LOGE("current locale is NULL\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		ret = PMINFO_R_EINVAL;
		goto err;
	}
	pkginfo = (pkgmgr_pkginfo_x *)calloc(1, sizeof(pkgmgr_pkginfo_x));
	if (pkginfo == NULL) {
		_LOGE("Failed to allocate memory for pkginfo\n");
		return PMINFO_R_ERROR;
	}

	pkginfo->manifest_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	if (pkginfo->manifest_info == NULL) {
		_LOGE("Failed to allocate memory for manifest info\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	pkginfo->manifest_info->package = strdup(pkgid);
	/*populate manifest_info from DB*/
	snprintf(query, MAX_QUERY_LEN, "select * from package_info where package='%s' ", pkgid);
	ret = __exec_pkginfo_query(query, (void *)pkginfo);
	if (ret == -1) {
		_LOGE("Package Info DB Information retrieval failed\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select * from package_localized_info where" \
		" package='%s' and package_locale='%s'", pkgid, locale);
	ret = __exec_pkginfo_query(query, (void *)pkginfo);
	if (ret == -1) {
		_LOGE("Package Info DB Information retrieval failed\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	/*Also store the values corresponding to default locales*/
	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select * from package_localized_info where" \
		" package='%s' and package_locale='%s'", pkgid, DEFAULT_LOCALE);
	ret = __exec_pkginfo_query(query, (void *)pkginfo);
	if (ret == -1) {
		_LOGE("Package Info DB Information retrieval failed\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
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
	*handle = (void *)pkginfo;
	sqlite3_close(manifest_db);
	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	if (locale) {
		free(locale);
		locale = NULL;
	}
	return PMINFO_R_OK;

err:
	*handle = NULL;
	__cleanup_pkginfo(pkginfo);
	sqlite3_close(manifest_db);
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
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (pkg_name == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	if (info->manifest_info->package)
		*pkg_name = info->manifest_info->package;
	else
		return PMINFO_R_ERROR;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_pkgid(pkgmgrinfo_pkginfo_h handle, char **pkgid)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (pkgid == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	if (info->manifest_info->package)
		*pkgid = info->manifest_info->package;
	else
		return PMINFO_R_ERROR;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_type(pkgmgrinfo_pkginfo_h handle, char **type)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (type == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	if (info->manifest_info->type)
		*type = info->manifest_info->type;
	else
		*type = pkgtype;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_version(pkgmgrinfo_pkginfo_h handle, char **version)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (version == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	*version = (char *)info->manifest_info->version;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_install_location(pkgmgrinfo_pkginfo_h handle, pkgmgrinfo_install_location *location)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (location == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
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
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (size == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	char *val = NULL;
	char *location = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	location = (char *)info->manifest_info->installlocation;
	if (strcmp(location, "prefer-external") == 0)
	{
		val = (char *)info->manifest_info->package_size;
		if (val) {
			*size = atoi(val);
		} else {
			*size = 0;
			_LOGE("package size is not specified\n");
			return PMINFO_R_ERROR;
		}
	} else {
		*size = 0;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_total_size(pkgmgrinfo_pkginfo_h handle, int *size)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (size == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}

	char *pkgid = NULL;
	char device_path[PKG_STRING_LEN_MAX] = { '\0', };
	long long rw_size = 0;
	long long ro_size= 0;
	long long tmp_size= 0;
	long long total_size= 0;
	struct stat fileinfo;
	int ret = -1;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle,&pkgid);
	if(ret < 0)
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
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (size == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}

	char *pkgid = NULL;
	char device_path[PKG_STRING_LEN_MAX] = { '\0', };
	long long total_size= 0;
	int ret = -1;

	ret = pkgmgrinfo_pkginfo_get_pkgid(handle,&pkgid);
	if(ret < 0)
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
#if 0
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (icon == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	char *syslocale = NULL;
	char *locale = NULL;
	char *save = NULL;
	icon_x *ptr = NULL;
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	if (syslocale == NULL) {
		_LOGE("current locale is NULL\n");
		return PMINFO_R_EINVAL;
	}
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		return PMINFO_R_EINVAL;
	}
	save = locale;
	*icon = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
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

	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	locale = save;
	if (locale) {
		free(locale);
		locale = NULL;
	}
#else
	pkgmgr_pkginfo_x *info_tmp = (pkgmgr_pkginfo_x *)handle;
	pkgmgrinfo_appinfo_h apphandle;

	pkgmgrinfo_appinfo_get_appinfo(info_tmp->manifest_info->mainapp_id, &apphandle);
	pkgmgrinfo_appinfo_get_icon(apphandle, &info_tmp->tmp);
	if (info_tmp->tmp_dup){
		free((void *)info_tmp->tmp_dup);
		info_tmp->tmp_dup = NULL;
	}
	info_tmp->tmp_dup= strdup(info_tmp->tmp);
	*icon = info_tmp->tmp_dup;
	pkgmgrinfo_appinfo_destroy_appinfo(apphandle);
#endif
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_label(pkgmgrinfo_pkginfo_h handle, char **label)
{
#if 0
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (label == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	char *syslocale = NULL;
	char *locale = NULL;
	char *save = NULL;
	label_x *ptr = NULL;
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	if (syslocale == NULL) {
		_LOGE("current locale is NULL\n");
		return PMINFO_R_EINVAL;
	}
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		return PMINFO_R_EINVAL;
	}
	save = locale;
	*label = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
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

	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	locale = save;
	if (locale) {
		free(locale);
		locale = NULL;
	}
#else
	pkgmgr_pkginfo_x *info_tmp = (pkgmgr_pkginfo_x *)handle;
	pkgmgrinfo_appinfo_h apphandle;

	pkgmgrinfo_appinfo_get_appinfo(info_tmp->manifest_info->mainapp_id, &apphandle);
	pkgmgrinfo_appinfo_get_label(apphandle, &info_tmp->tmp);
	if (info_tmp->tmp_dup){
		free((void *)info_tmp->tmp_dup);
		info_tmp->tmp_dup = NULL;
	}
	info_tmp->tmp_dup = strdup(info_tmp->tmp);
	*label = info_tmp->tmp_dup;
	pkgmgrinfo_appinfo_destroy_appinfo(apphandle);
#endif
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_description(pkgmgrinfo_pkginfo_h handle, char **description)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (description == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	char *syslocale = NULL;
	char *locale = NULL;
	char *save = NULL;
	description_x *ptr = NULL;
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	if (syslocale == NULL) {
		_LOGE("current locale is NULL\n");
		return PMINFO_R_EINVAL;
	}
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		return PMINFO_R_EINVAL;
	}
	save = locale;
	*description = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	for(ptr = info->manifest_info->description; ptr != NULL; ptr = ptr->next)
	{
		if (ptr->lang) {
			if (strcmp(ptr->lang, locale) == 0) {
				*description = (char *)ptr->text;
				if (strcasecmp(*description, "(null)") == 0) {
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
	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	locale = save;
	if (locale) {
		free(locale);
		locale = NULL;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_author_name(pkgmgrinfo_pkginfo_h handle, char **author_name)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (author_name == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	char *syslocale = NULL;
	char *locale = NULL;
	char *save = NULL;
	author_x *ptr = NULL;
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	if (syslocale == NULL) {
		_LOGE("current locale is NULL\n");
		return PMINFO_R_EINVAL;
	}
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		return PMINFO_R_EINVAL;
	}
	save = locale;
	*author_name = NULL;
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	for(ptr = info->manifest_info->author; ptr != NULL; ptr = ptr->next)
	{
		if (ptr->lang) {
			if (strcmp(ptr->lang, locale) == 0) {
				*author_name = (char *)ptr->text;
				if (strcasecmp(*author_name, "(null)") == 0) {
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
	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	locale = save;
	if (locale) {
		free(locale);
		locale = NULL;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_author_email(pkgmgrinfo_pkginfo_h handle, char **author_email)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (author_email == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	*author_email = (char *)info->manifest_info->author->email;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_author_href(pkgmgrinfo_pkginfo_h handle, char **author_href)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (author_href == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	*author_href = (char *)info->manifest_info->author->href;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_installed_storage(pkgmgrinfo_pkginfo_h handle, pkgmgrinfo_installed_storage *storage)
{
	int ret = -1;
	char *pkgid;

	pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid);
	if (pkgid == NULL){
		 _LOGE("invalid func parameters\n");
		 return PMINFO_R_ERROR;
	}

	FILE *fp = NULL;
	char app_mmc_path[FILENAME_MAX] = { 0, };
	char app_dir_path[FILENAME_MAX] = { 0, };
	char app_mmc_internal_path[FILENAME_MAX] = { 0, };
	snprintf(app_dir_path, FILENAME_MAX,
	"%s%s", PKG_INSTALLATION_PATH, pkgid);
	snprintf(app_mmc_path, FILENAME_MAX,
	"%s%s", PKG_SD_PATH, pkgid);
	snprintf(app_mmc_internal_path, FILENAME_MAX,
	"%s%s/.mmc", PKG_INSTALLATION_PATH, pkgid);

	/*check whether application is in external memory or not */
	fp = fopen(app_mmc_path, "r");
	if (fp == NULL) {
		_LOGE(" app path in external memory not accesible\n");
	} else {
		fclose(fp);
		fp = NULL;
		*storage = PMINFO_EXTERNAL_STORAGE;
		return PMINFO_R_OK;
	}

	/*check whether application is in internal or not */
	fp = fopen(app_dir_path, "r");
	if (fp == NULL) {
		_LOGE(" app path in internal memory not accesible\n");
		*storage = -1;
		return PMINFO_R_ERROR;
	} else {
		fclose(fp);
		/*check whether the application is installed in SD card
			but SD card is not present*/
		fp = fopen(app_mmc_internal_path, "r");
		if (fp == NULL) {
			*storage = PMINFO_INTERNAL_STORAGE;
			return PMINFO_R_OK;
		} else {
			fclose(fp);
			*storage = PMINFO_EXTERNAL_STORAGE;
			return PMINFO_R_OK;
		}
	}
}

API int pkgmgrinfo_pkginfo_get_installed_time(pkgmgrinfo_pkginfo_h handle, int *installed_time)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (installed_time == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	if (info->manifest_info->installed_time)
		*installed_time = atoi(info->manifest_info->installed_time);
	else
		return PMINFO_R_ERROR;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_storeclientid(pkgmgrinfo_pkginfo_h handle, char **storeclientid)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (storeclientid == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	*storeclientid = (char *)info->manifest_info->storeclient_id;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_mainappid(pkgmgrinfo_pkginfo_h handle, char **mainappid)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (mainappid == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	*mainappid = (char *)info->manifest_info->mainapp_id;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_url(pkgmgrinfo_pkginfo_h handle, char **url)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (url == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	*url = (char *)info->manifest_info->package_url;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_get_size_from_xml(const char *manifest, int *size)
{
	char *val = NULL;
	const xmlChar *node;
	xmlTextReaderPtr reader;

	if (manifest == NULL) {
		_LOGE("input argument is NULL\n");
		return PMINFO_R_ERROR;
	}

	if (size == NULL) {
		_LOGE("output argument is NULL\n");
		return PMINFO_R_ERROR;
	}

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
	char *val = NULL;
	const xmlChar *node;
	xmlTextReaderPtr reader;

	if (manifest == NULL) {
		_LOGE("input argument is NULL\n");
		return PMINFO_R_ERROR;
	}

	if (location == NULL) {
		_LOGE("output argument is NULL\n");
		return PMINFO_R_ERROR;
	}

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

API int pkgmgrinfo_pkginfo_compare_pkg_cert_info(const char *lhs_package_id, const char *rhs_package_id, pkgmgrinfo_cert_compare_result_type_e *compare_result)
{
	if (lhs_package_id == NULL || rhs_package_id == NULL)
	{
		_LOGE("pkginfo id is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (compare_result == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}

	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message = NULL;
	pkgmgr_cert_x *info= NULL;
	char *lcert = NULL;
	char *rcert = NULL;
	int exist = -1;

	info = (pkgmgr_cert_x *)calloc(1, sizeof(pkgmgr_cert_x));
	if (info == NULL) {
		_LOGE("Out of Memory!!!\n");
		return PMINFO_R_ERROR;
	}

	ret = db_util_open_with_options(CERT_DB, &cert_db,
					SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n", CERT_DB);
		free(info);
		info = NULL;
		return PMINFO_R_ERROR;
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
		lcert = NULL;
	} else {
		snprintf(query, MAX_QUERY_LEN, "select author_signer_cert from package_cert_info where package='%s'", lhs_package_id);
		if (SQLITE_OK !=
			sqlite3_exec(cert_db, query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto err;
		}
		snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", info->certvalue);
		if (SQLITE_OK !=
		    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
			       error_message);
			sqlite3_free(error_message);
			return PMINFO_R_ERROR;
		}
		if (exist == 0)
			lcert = info->certvalue;
		else {
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select author_signer_cert from package_cert_info where package='%s'", info->certvalue);
			free(info->certvalue);
			info->certvalue = NULL;
			if (SQLITE_OK !=
				sqlite3_exec(cert_db, query, __cert_cb, (void *)info, &error_message)) {
				_LOGE("Don't execute query = %s error message = %s\n", query,
					   error_message);
				ret = PMINFO_R_ERROR;
				goto err;
			}
			lcert = info->certvalue;
		}
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
		rcert = NULL;
	} else {
		snprintf(query, MAX_QUERY_LEN, "select author_signer_cert from package_cert_info where package='%s'", rhs_package_id);
		if (SQLITE_OK !=
			sqlite3_exec(cert_db, query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto err;
		}
		snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", info->certvalue);
		if (SQLITE_OK !=
		    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
			       error_message);
			sqlite3_free(error_message);
			return PMINFO_R_ERROR;
		}
		if (exist == 0)
			rcert = info->certvalue;
		else {
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select author_signer_cert from package_cert_info where package='%s'", info->certvalue);
			free(info->certvalue);
			info->certvalue = NULL;
			if (SQLITE_OK !=
				sqlite3_exec(cert_db, query, __cert_cb, (void *)info, &error_message)) {
				_LOGE("Don't execute query = %s error message = %s\n", query,
					   error_message);
				ret = PMINFO_R_ERROR;
				goto err;
			}
			rcert = info->certvalue;
		}
	}

	if ((lcert == NULL) || (rcert == NULL))
	{
		if ((lcert == NULL) && (rcert == NULL))
			*compare_result = PMINFO_CERT_COMPARE_BOTH_NO_CERT;
		else if (lcert == NULL)
			*compare_result = PMINFO_CERT_COMPARE_LHS_NO_CERT;
		else if (rcert == NULL)
			*compare_result = PMINFO_CERT_COMPARE_RHS_NO_CERT;
	} else {
		if (strcmp(lcert, rcert) == 0)
			*compare_result = PMINFO_CERT_COMPARE_MATCH;
		else
			*compare_result = PMINFO_CERT_COMPARE_MISMATCH;
	}

err:
	sqlite3_free(error_message);
	sqlite3_close(cert_db);
	if (info) {
		free(info);
		info = NULL;
	}

	return ret;
}


API int pkgmgrinfo_pkginfo_compare_app_cert_info(const char *lhs_app_id, const char *rhs_app_id, pkgmgrinfo_cert_compare_result_type_e *compare_result)
{
	if (lhs_app_id == NULL || rhs_app_id == NULL)
	{
		_LOGE("pkginfo id is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (compare_result == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}

	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message = NULL;
	pkgmgr_cert_x *info= NULL;
	char *lcert = NULL;
	char *rcert = NULL;
	char *lhs_package_id = NULL;
	char *rhs_package_id = NULL;
	int exist = -1;

	info = (pkgmgr_cert_x *)calloc(1, sizeof(pkgmgr_cert_x));
	if (info == NULL) {
		_LOGE("Out of Memory!!!\n");
		return PMINFO_R_ERROR;
	}

	ret = db_util_open_with_options(MANIFEST_DB, &manifest_db,
					SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n", MANIFEST_DB);
		free(info);
		info = NULL;
		return PMINFO_R_ERROR;
	}
	ret = db_util_open_with_options(CERT_DB, &cert_db,
					SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n", CERT_DB);
		sqlite3_close(manifest_db);
		free(info);
		info = NULL;
		return PMINFO_R_ERROR;
	}

	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_app_info where app_id='%s')", lhs_app_id);
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	if (exist == 0) {
		lcert = NULL;
	} else {
		snprintf(query, MAX_QUERY_LEN, "select package from package_app_info where app_id='%s' ", lhs_app_id);
		if (SQLITE_OK !=
			sqlite3_exec(manifest_db, query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto err;
		}

		snprintf(query, MAX_QUERY_LEN, "select author_signer_cert from package_cert_info where package='%s'", info->pkgid);
		if (SQLITE_OK !=
			sqlite3_exec(cert_db, query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto err;
		}
		snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", info->certvalue);
		if (SQLITE_OK !=
		    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
			       error_message);
			sqlite3_free(error_message);
			return PMINFO_R_ERROR;
		}
		if (exist == 0)
			lcert = info->certvalue;
		else {
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select author_signer_cert from package_cert_info where package='%s'", info->certvalue);
			free(info->certvalue);
			info->certvalue = NULL;
			if (SQLITE_OK !=
				sqlite3_exec(cert_db, query, __cert_cb, (void *)info, &error_message)) {
				_LOGE("Don't execute query = %s error message = %s\n", query,
					   error_message);
				ret = PMINFO_R_ERROR;
				goto err;
			}
			lcert = info->certvalue;
		}
	}

	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_app_info where app_id='%s')", rhs_app_id);
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	if (exist == 0) {
		rcert = NULL;
	} else {
		snprintf(query, MAX_QUERY_LEN, "select package from package_app_info where app_id='%s' ", rhs_app_id);
		if (SQLITE_OK !=
			sqlite3_exec(manifest_db, query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto err;
		}

		snprintf(query, MAX_QUERY_LEN, "select author_signer_cert from package_cert_info where package='%s'", info->pkgid);
		if (SQLITE_OK !=
			sqlite3_exec(cert_db, query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto err;
		}
		snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", info->certvalue);
		if (SQLITE_OK !=
		    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
			       error_message);
			sqlite3_free(error_message);
			return PMINFO_R_ERROR;
		}
		if (exist == 0)
			rcert = info->certvalue;
		else {
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select author_signer_cert from package_cert_info where package='%s'", info->certvalue);
			free(info->certvalue);
			info->certvalue = NULL;
			if (SQLITE_OK !=
				sqlite3_exec(cert_db, query, __cert_cb, (void *)info, &error_message)) {
				_LOGE("Don't execute query = %s error message = %s\n", query,
					   error_message);
				ret = PMINFO_R_ERROR;
				goto err;
			}
			rcert = info->certvalue;
		}
	}

	if ((lcert == NULL) || (rcert == NULL))
	{
		if ((lcert == NULL) && (rcert == NULL))
			*compare_result = PMINFO_CERT_COMPARE_BOTH_NO_CERT;
		else if (lcert == NULL)
			*compare_result = PMINFO_CERT_COMPARE_LHS_NO_CERT;
		else if (rcert == NULL)
			*compare_result = PMINFO_CERT_COMPARE_RHS_NO_CERT;
	} else {
		if (strcmp(lcert, rcert) == 0)
			*compare_result = PMINFO_CERT_COMPARE_MATCH;
		else
			*compare_result = PMINFO_CERT_COMPARE_MISMATCH;
	}

err:
	sqlite3_free(error_message);
	sqlite3_close(manifest_db);
	sqlite3_close(cert_db);
	if (info) {
		free(info);
		info = NULL;
	}

	return ret;
}

API int pkgmgrinfo_pkginfo_is_accessible(pkgmgrinfo_pkginfo_h handle, bool *accessible)
{
	char *pkgid;

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
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_is_removable(pkgmgrinfo_pkginfo_h handle, bool *removable)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (removable == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
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

API int pkgmgrinfo_pkginfo_is_preload(pkgmgrinfo_pkginfo_h handle, bool *preload)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (preload == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
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

API int pkgmgrinfo_pkginfo_is_readonly(pkgmgrinfo_pkginfo_h handle, bool *readonly)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (readonly == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
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

API int pkgmgrinfo_pkginfo_destroy_pkginfo(pkgmgrinfo_pkginfo_h handle)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	__cleanup_pkginfo(info);
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_filter_create(pkgmgrinfo_pkginfo_filter_h *handle)
{
	if (handle == NULL) {
		_LOGE("Filter handle output parameter is NULL\n");
		return PMINFO_R_EINVAL;
	}
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
	if (handle == NULL) {
		_LOGE("Filter handle input parameter is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)handle;
	if (filter->list){
		g_slist_foreach(filter->list, __destroy_each_node, NULL);
		g_slist_free(filter->list);
	}
	free(filter);
	filter = NULL;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_filter_add_int(pkgmgrinfo_pkginfo_filter_h handle,
				const char *property, const int value)
{
	if (handle == NULL || property == NULL) {
		_LOGE("Filter handle input parameter is NULL\n");
		return PMINFO_R_EINVAL;
	}
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
	if (handle == NULL || property == NULL) {
		_LOGE("Filter handle input parameter is NULL\n");
		return PMINFO_R_EINVAL;
	}
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
	if (handle == NULL || property == NULL || value == NULL) {
		_LOGE("Filter handle input parameter is NULL\n");
		return PMINFO_R_EINVAL;
	}
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
	if (handle == NULL || count == NULL) {
		_LOGE("Filter handle input parameter is NULL\n");
		return PMINFO_R_EINVAL;
	}
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
	ret = __open_manifest_db();
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		ret = PMINFO_R_ERROR;
		goto err;
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
	_LOGE("where = %s\n", where);
	if (strlen(where) > 0) {
		strncat(query, where, sizeof(query) - strlen(query) - 1);
		query[sizeof(query) - 1] = '\0';
	}
	_LOGE("query = %s\n", query);

	/*Execute Query*/
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __count_cb, (void *)count, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		sqlite3_close(manifest_db);
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
	sqlite3_close(manifest_db);
	return ret;
}

API int pkgmgrinfo_pkginfo_filter_foreach_pkginfo(pkgmgrinfo_pkginfo_filter_h handle,
				pkgmgrinfo_pkg_list_cb pkg_cb, void *user_data)
{
	if (handle == NULL || pkg_cb == NULL) {
		_LOGE("Filter handle input parameter is NULL\n");
		return PMINFO_R_EINVAL;
	}
	char *syslocale = NULL;
	char *locale = NULL;
	char *condition = NULL;
	char *error_message = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	char where[MAX_QUERY_LEN] = {'\0'};
	GSList *list;
	int ret = 0;
	label_x *tmp1 = NULL;
	icon_x *tmp2 = NULL;
	description_x *tmp3 = NULL;
	author_x *tmp4 = NULL;
	pkgmgr_pkginfo_x *node = NULL;
	pkgmgr_pkginfo_x *tmphead = NULL;
	pkgmgr_pkginfo_x *pkginfo = NULL;

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
	ret = __open_manifest_db();
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
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
	if (tmphead == NULL) {
		_LOGE("Out of Memory!!!\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}

	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __pkg_list_cb, (void *)tmphead, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		sqlite3_close(manifest_db);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	LISTHEAD(tmphead, node);
	for(node = node->next ; node ; node = node->next) {
		pkginfo = node;

		/*populate manifest_info from DB*/
		snprintf(query, MAX_QUERY_LEN, "select * from package_info where package='%s' ", pkginfo->manifest_info->package);
		ret = __exec_pkginfo_query(query, (void *)pkginfo);
		if (ret == -1) {
			_LOGE("Package Info DB Information retrieval failed\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select * from package_localized_info where" \
			" package='%s' and package_locale='%s'", pkginfo->manifest_info->package, locale);
		ret = __exec_pkginfo_query(query, (void *)pkginfo);
		if (ret == -1) {
			_LOGE("Package Info DB Information retrieval failed\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		/*Also store the values corresponding to default locales*/
		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select * from package_localized_info where" \
			" package='%s' and package_locale='%s'", pkginfo->manifest_info->package, DEFAULT_LOCALE);
		ret = __exec_pkginfo_query(query, (void *)pkginfo);
		if (ret == -1) {
			_LOGE("Package Info DB Information retrieval failed\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
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
	}

	LISTHEAD(tmphead, node);

	for(node = node->next ; node ; node = node->next) {
		pkginfo = node;
		ret = pkg_cb( (void *)pkginfo, user_data);
		if(ret < 0)
			break;
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
	sqlite3_close(manifest_db);
	__cleanup_pkginfo(tmphead);
	return ret;
}

API int pkgmgrinfo_appinfo_get_list(pkgmgrinfo_pkginfo_h handle, pkgmgrinfo_app_component component,
						pkgmgrinfo_app_list_cb app_func, void *user_data)
{
	if (handle == NULL) {
		_LOGE("pkginfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (app_func == NULL) {
		_LOGE("callback pointer is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (component != PMINFO_UI_APP && component != PMINFO_SVC_APP && component != PMINFO_ALL_APP) {
		_LOGE("Invalid App Component Type\n");
		return PMINFO_R_EINVAL;
	}
	char *error_message = NULL;
	char *syslocale = NULL;
	char *locale = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	pkgmgr_pkginfo_x *info = (pkgmgr_pkginfo_x *)handle;
	pkgmgr_pkginfo_x *allinfo = NULL;
	pkgmgr_appinfo_x *appinfo = NULL;
	icon_x *ptr1 = NULL;
	label_x *ptr2 = NULL;

	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	if (syslocale == NULL) {
		_LOGE("current locale is NULL\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		ret = PMINFO_R_EINVAL;
		goto err;
	}

	allinfo = (pkgmgr_appinfo_x *)calloc(1, sizeof(pkgmgr_appinfo_x));
	if (allinfo == NULL) {
		_LOGE("Failed to allocate memory for appinfo\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	allinfo->manifest_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	if (allinfo->manifest_info == NULL) {
		_LOGE("Out of Memory!!!\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}

	appinfo = (pkgmgr_appinfo_x *)calloc(1, sizeof(pkgmgr_appinfo_x));
	if (appinfo == NULL) {
		_LOGE("Failed to allocate memory for appinfo\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	if (component == PMINFO_UI_APP)
		appinfo->app_component = PMINFO_UI_APP;
	if (component == PMINFO_SVC_APP)
		appinfo->app_component = PMINFO_SVC_APP;
	if (component == PMINFO_ALL_APP)
		appinfo->app_component = PMINFO_ALL_APP;
	ret = __open_manifest_db();
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}

	appinfo->package = strdup(info->manifest_info->package);
	snprintf(query, MAX_QUERY_LEN, "select DISTINCT * " \
			"from package_app_info where " \
			"package='%s' and app_component='%s'",
			info->manifest_info->package,
			(appinfo->app_component==PMINFO_UI_APP ? "uiapp" : "svcapp"));

	switch(component) {
	case PMINFO_UI_APP:
		if (SQLITE_OK !=
		sqlite3_exec(manifest_db, query, __uiapp_list_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
			       error_message);
			sqlite3_free(error_message);
			sqlite3_close(manifest_db);
			ret = PMINFO_R_ERROR;
			goto err;
		}
		uiapplication_x *tmp = NULL;
		if (info->manifest_info->uiapplication) {
			LISTHEAD(info->manifest_info->uiapplication, tmp);
			info->manifest_info->uiapplication = tmp;
		}
		/*Populate localized info for default locales and call callback*/
		/*If the callback func return < 0 we break and no more call back is called*/
		while(tmp != NULL)
		{
			appinfo->uiapp_info = tmp;

			if (strcmp(appinfo->uiapp_info->type,"c++app") == 0){
				if (locale) {
					free(locale);
				}
				locale = __get_app_locale_by_fallback(appinfo->uiapp_info->appid, syslocale);
			}

			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where" \
				" app_id='%s' and app_locale='%s'", appinfo->uiapp_info->appid, locale);
			ret = __exec_appinfo_query(query, (void *)appinfo);
			if (ret == -1) {
				_LOGE("App Localized Info DB Information retrieval failed\n");
				ret = PMINFO_R_ERROR;
				goto err;
			}
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where" \
				" app_id='%s' and app_locale='%s'", appinfo->uiapp_info->appid, DEFAULT_LOCALE);
			ret = __exec_appinfo_query(query, (void *)appinfo);
			if (ret == -1) {
				_LOGE("App Localized Info DB Information retrieval failed\n");
				ret = PMINFO_R_ERROR;
				goto err;
			}
			if (appinfo->uiapp_info->label) {
				LISTHEAD(appinfo->uiapp_info->label, ptr2);
				appinfo->uiapp_info->label = ptr2;
			}
			if (appinfo->uiapp_info->icon) {
				LISTHEAD(appinfo->uiapp_info->icon, ptr1);
				appinfo->uiapp_info->icon = ptr1;
			}
			ret = app_func((void *)appinfo, user_data);
			if (ret < 0)
				break;
			tmp = tmp->next;
		}
		break;
	case PMINFO_SVC_APP:
		if (SQLITE_OK !=
		sqlite3_exec(manifest_db, query, __svcapp_list_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
			       error_message);
			sqlite3_free(error_message);
			sqlite3_close(manifest_db);
			ret = PMINFO_R_ERROR;
			goto err;
		}
		serviceapplication_x *tmp1 = NULL;
		if (info->manifest_info->serviceapplication) {
			LISTHEAD(info->manifest_info->serviceapplication, tmp1);
			info->manifest_info->serviceapplication = tmp1;
		}
		/*Populate localized info for default locales and call callback*/
		/*If the callback func return < 0 we break and no more call back is called*/
		while(tmp1 != NULL)
		{
			appinfo->svcapp_info = tmp1;
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where" \
				" app_id='%s' and app_locale='%s'", appinfo->svcapp_info->appid, locale);
			ret = __exec_appinfo_query(query, (void *)appinfo);
			if (ret == -1) {
				_LOGE("App Localized Info DB Information retrieval failed\n");
				ret = PMINFO_R_ERROR;
				goto err;
			}
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where" \
				" app_id='%s' and app_locale='%s'", appinfo->svcapp_info->appid, DEFAULT_LOCALE);
			ret = __exec_appinfo_query(query, (void *)appinfo);
			if (ret == -1) {
				_LOGE("App Localized Info DB Information retrieval failed\n");
				ret = PMINFO_R_ERROR;
				goto err;
			}
			if (appinfo->svcapp_info->label) {
				LISTHEAD(appinfo->svcapp_info->label, ptr2);
				appinfo->svcapp_info->label = ptr2;
			}
			if (appinfo->svcapp_info->icon) {
				LISTHEAD(appinfo->svcapp_info->icon, ptr1);
				appinfo->svcapp_info->icon = ptr1;
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
		if (SQLITE_OK !=
		sqlite3_exec(manifest_db, query, __allapp_list_cb, (void *)allinfo, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			sqlite3_free(error_message);
			sqlite3_close(manifest_db);
			ret = PMINFO_R_ERROR;
			goto err;
		}

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
			appinfo->uiapp_info = tmp2;
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where" \
				" app_id='%s' and app_locale='%s'", appinfo->uiapp_info->appid, locale);
			ret = __exec_appinfo_query(query, (void *)appinfo);
			if (ret == -1) {
				_LOGE("App Localized Info DB Information retrieval failed\n");
				ret = PMINFO_R_ERROR;
				goto err;
			}
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where" \
				" app_id='%s' and app_locale='%s'", appinfo->uiapp_info->appid, DEFAULT_LOCALE);
			ret = __exec_appinfo_query(query, (void *)appinfo);
			if (ret == -1) {
				_LOGE("App Localized Info DB Information retrieval failed\n");
				ret = PMINFO_R_ERROR;
				goto err;
			}
			if (appinfo->uiapp_info->label) {
				LISTHEAD(appinfo->uiapp_info->label, ptr2);
				appinfo->uiapp_info->label = ptr2;
			}
			if (appinfo->uiapp_info->icon) {
				LISTHEAD(appinfo->uiapp_info->icon, ptr1);
				appinfo->uiapp_info->icon = ptr1;
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
			appinfo->svcapp_info = tmp3;
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where" \
				" app_id='%s' and app_locale='%s'", appinfo->svcapp_info->appid, locale);
			ret = __exec_appinfo_query(query, (void *)appinfo);
			if (ret == -1) {
				_LOGE("App Localized Info DB Information retrieval failed\n");
				ret = PMINFO_R_ERROR;
				goto err;
			}
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where" \
				" app_id='%s' and app_locale='%s'", appinfo->svcapp_info->appid, DEFAULT_LOCALE);
			ret = __exec_appinfo_query(query, (void *)appinfo);
			if (ret == -1) {
				_LOGE("App Localized Info DB Information retrieval failed\n");
				ret = PMINFO_R_ERROR;
				goto err;
			}
			if (appinfo->svcapp_info->label) {
				LISTHEAD(appinfo->svcapp_info->label, ptr2);
				appinfo->svcapp_info->label = ptr2;
			}
			if (appinfo->svcapp_info->icon) {
				LISTHEAD(appinfo->svcapp_info->icon, ptr1);
				appinfo->svcapp_info->icon = ptr1;
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
err:
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
			free(appinfo->package);
			appinfo->package = NULL;
		}
		free(appinfo);
		appinfo = NULL;
	}
	__cleanup_pkginfo(allinfo);

	sqlite3_close(manifest_db);
	return ret;
}

API int pkgmgrinfo_appinfo_get_installed_list(pkgmgrinfo_app_list_cb app_func, void *user_data)
{
	if (app_func == NULL) {
		_LOGE("callback function is NULL\n");
		return PMINFO_R_EINVAL;
	}
	char *error_message = NULL;
	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *syslocale = NULL;
	char *locale = NULL;
	pkgmgr_appinfo_x *appinfo = NULL;
	uiapplication_x *ptr1 = NULL;
	serviceapplication_x *ptr2 = NULL;
	label_x *tmp1 = NULL;
	icon_x *tmp2 = NULL;

	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	if (syslocale == NULL) {
		_LOGE("current locale is NULL\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		ret = PMINFO_R_EINVAL;
		goto err;
	}

	ret = __open_manifest_db();
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	pkgmgr_pkginfo_x *info = NULL;
	info = (pkgmgr_pkginfo_x *)calloc(1, sizeof(pkgmgr_pkginfo_x));
	if (info == NULL) {
		_LOGE("Out of Memory!!!\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	info->manifest_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	if (info->manifest_info == NULL) {
		_LOGE("Out of Memory!!!\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	appinfo = (pkgmgr_appinfo_x *)calloc(1, sizeof(pkgmgr_appinfo_x));
	if (appinfo == NULL) {
		_LOGE("Out of Memory!!!\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}

	snprintf(query, MAX_QUERY_LEN, "select * from package_app_info");
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __app_list_cb, (void *)info, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		sqlite3_close(manifest_db);
		ret = PMINFO_R_ERROR;
		goto err;
	}
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
		appinfo->app_component = PMINFO_UI_APP;
		appinfo->package = strdup(ptr1->package);
		appinfo->uiapp_info = ptr1;
		snprintf(query, MAX_QUERY_LEN, "select DISTINCT * " \
				"from package_app_info where " \
				"app_id='%s'", ptr1->appid);
		ret = __exec_appinfo_query(query, (void *)appinfo);
		if (ret == -1) {
			_LOGE("App Info DB Information retrieval failed\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}

		if (strcmp(appinfo->uiapp_info->type,"c++app") == 0){
			if (locale) {
				free(locale);
			}
			locale = __get_app_locale_by_fallback(ptr1->appid, syslocale);
		}

		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select DISTINCT * " \
				"from package_app_localized_info where " \
				"app_id='%s' and app_locale='%s'",
				ptr1->appid, locale);
		ret = __exec_appinfo_query(query, (void *)appinfo);
		if (ret == -1) {
			_LOGE("App Localized Info DB Information retrieval failed\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select DISTINCT * " \
				"from package_app_localized_info where " \
				"app_id='%s' and app_locale='%s'",
				ptr1->appid, DEFAULT_LOCALE);
		ret = __exec_appinfo_query(query, (void *)appinfo);
		if (ret == -1) {
			_LOGE("App Localized Info DB Information retrieval failed\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		if (appinfo->uiapp_info->label) {
			LISTHEAD(appinfo->uiapp_info->label, tmp1);
			appinfo->uiapp_info->label = tmp1;
		}
		if (appinfo->uiapp_info->icon) {
			LISTHEAD(appinfo->uiapp_info->icon, tmp2);
			appinfo->uiapp_info->icon= tmp2;
		}
		ret = app_func((void *)appinfo, user_data);
		if (ret < 0)
			break;
		free(appinfo->package);
		appinfo->package = NULL;
	}
	/*Service Apps*/
	for(ptr2 = info->manifest_info->serviceapplication; ptr2; ptr2 = ptr2->next)
	{
		appinfo->app_component = PMINFO_SVC_APP;
		appinfo->package = strdup(ptr2->package);
		appinfo->svcapp_info = ptr2;
		snprintf(query, MAX_QUERY_LEN, "select DISTINCT * " \
				"from package_app_info where " \
				"app_id='%s'", ptr2->appid);
		ret = __exec_appinfo_query(query, (void *)appinfo);
		if (ret == -1) {
			_LOGE("App Info DB Information retrieval failed\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select DISTINCT * " \
				"from package_app_localized_info where " \
				"app_id='%s' and app_locale='%s'",
				ptr2->appid, locale);
		ret = __exec_appinfo_query(query, (void *)appinfo);
		if (ret == -1) {
			_LOGE("App Localized Info DB Information retrieval failed\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		snprintf(query, MAX_QUERY_LEN, "select DISTINCT * " \
				"from package_app_localized_info where " \
				"app_id='%s' and app_locale='%s'",
				ptr2->appid, DEFAULT_LOCALE);
		ret = __exec_appinfo_query(query, (void *)appinfo);
		if (ret == -1) {
			_LOGE("App Localized Info DB Information retrieval failed\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		if (appinfo->svcapp_info->label) {
			LISTHEAD(appinfo->svcapp_info->label, tmp1);
			appinfo->svcapp_info->label = tmp1;
		}
		if (appinfo->svcapp_info->icon) {
			LISTHEAD(appinfo->svcapp_info->icon, tmp2);
			appinfo->svcapp_info->icon= tmp2;
		}
		ret = app_func((void *)appinfo, user_data);
		if (ret < 0)
			break;
		free(appinfo->package);
		appinfo->package = NULL;
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
	sqlite3_close(manifest_db);
	if (appinfo) {
		free(appinfo);
		appinfo = NULL;
	}
	__cleanup_pkginfo(info);
	return ret;
}

API int pkgmgrinfo_appinfo_get_appinfo(const char *appid, pkgmgrinfo_appinfo_h *handle)
{
	if (appid == NULL) {
		_LOGE("appid is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (handle == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_appinfo_x *appinfo = NULL;
	char *error_message = NULL;
	char *syslocale = NULL;
	char *locale = NULL;
	int ret = -1;
	int exist = 0;
	label_x *tmp1 = NULL;
	icon_x *tmp2 = NULL;
	category_x *tmp3 = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};

	/*Validate appid*/
	ret = __open_manifest_db();
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_app_info where app_id='%s')", appid);
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		sqlite3_close(manifest_db);
		return PMINFO_R_ERROR;
	}
	if (exist == 0) {
		_LOGE("Appid not found in DB\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	if (syslocale == NULL) {
		_LOGE("current locale is NULL\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	appinfo = (pkgmgr_appinfo_x *)calloc(1, sizeof(pkgmgr_appinfo_x));
	if (appinfo == NULL) {
		_LOGE("Failed to allocate memory for appinfo\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}

	/*check app_component from DB*/
	snprintf(query, MAX_QUERY_LEN, "select app_component, package from package_app_info where app_id='%s' ", appid);
	ret = __exec_appcomponent_query(query, (void *)appinfo);
	if (ret == -1) {
		_LOGE("App Info DB Information retrieval failed\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}

	if (appinfo->app_component == PMINFO_UI_APP) {
		appinfo->uiapp_info = (uiapplication_x *)calloc(1, sizeof(uiapplication_x));
		if (appinfo->uiapp_info == NULL) {
			_LOGE("Failed to allocate memory for uiapp info\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
	} else {
		appinfo->svcapp_info = (serviceapplication_x *)calloc(1, sizeof(serviceapplication_x));
		if (appinfo->svcapp_info == NULL) {
			_LOGE("Failed to allocate memory for svcapp info\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
	}

	/*populate app_info from DB*/
	snprintf(query, MAX_QUERY_LEN, "select * from package_app_info where app_id='%s' ", appid);
	ret = __exec_appinfo_query(query, (void *)appinfo);
	if (ret == -1) {
		_LOGE("App Info DB Information retrieval failed\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}

	if (strcmp(appinfo->uiapp_info->type,"c++app") == 0){
		if (locale) {
			free(locale);
		}
		locale = __get_app_locale_by_fallback(appid, syslocale);
	}

	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where" \
		" app_id='%s' and app_locale='%s'", appid, locale);
	ret = __exec_appinfo_query(query, (void *)appinfo);
	if (ret == -1) {
		_LOGE("App Localized Info DB Information retrieval failed\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	/*Also store the values corresponding to default locales*/
	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select * from package_app_localized_info where" \
		" app_id='%s' and app_locale='%s'", appid, DEFAULT_LOCALE);
	ret = __exec_appinfo_query(query, (void *)appinfo);
	if (ret == -1) {
		_LOGE("App Localized Info DB Information retrieval failed\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	/*Populate app category*/
	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN, "select * from package_app_app_category where" \
		" app_id='%s'", appid);
	ret = __exec_appinfo_query(query, (void *)appinfo);
	if (ret == -1) {
		_LOGE("App Category Info DB Information retrieval failed\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
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
		break;
	default:
		break;
	}

	*handle = (void*)appinfo;
	sqlite3_close(manifest_db);
	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	if (locale) {
		free(locale);
		locale = NULL;
	}
	return PMINFO_R_OK;
err:
	*handle = NULL;
	__cleanup_appinfo(appinfo);
	sqlite3_close(manifest_db);
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
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (appid == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_component == PMINFO_UI_APP)
		*appid = (char *)info->uiapp_info->appid;
	else if (info->app_component == PMINFO_SVC_APP)
		*appid = (char *)info->svcapp_info->appid;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_pkgname(pkgmgrinfo_appinfo_h  handle, char **pkg_name)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (pkg_name == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	*pkg_name = (char *)info->package;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_pkgid(pkgmgrinfo_appinfo_h  handle, char **pkgid)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (pkgid == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	*pkgid = (char *)info->package;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_exec(pkgmgrinfo_appinfo_h  handle, char **exec)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (exec == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_component == PMINFO_UI_APP)
		*exec = (char *)info->uiapp_info->exec;
	if (info->app_component == PMINFO_SVC_APP)
		*exec = (char *)info->svcapp_info->exec;

	return PMINFO_R_OK;
}


API int pkgmgrinfo_appinfo_get_icon(pkgmgrinfo_appinfo_h  handle, char **icon)
{
        if (handle == NULL) {
                _LOGE("appinfo handle is NULL\n");
                return PMINFO_R_EINVAL;
        }
        if (icon == NULL) {
                _LOGE("Argument supplied to hold return value is NULL\n");
                return PMINFO_R_EINVAL;
        }
        char *syslocale = NULL;
        char *locale = NULL;
        char *save = NULL;
        icon_x *ptr = NULL;
        icon_x *start = NULL;
        syslocale = vconf_get_str(VCONFKEY_LANGSET);
        if (syslocale == NULL) {
                _LOGE("current locale is NULL\n");
                return PMINFO_R_EINVAL;
        }
        locale = __convert_system_locale_to_manifest_locale(syslocale);
        if (locale == NULL) {
                _LOGE("manifest locale is NULL\n");
                return PMINFO_R_EINVAL;
        }
        save = locale;
        *icon = NULL;
        pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
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
	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	locale = save;
	if (locale) {
		free(locale);
		locale = NULL;
	}
	return PMINFO_R_OK;
}


API int pkgmgrinfo_appinfo_get_label(pkgmgrinfo_appinfo_h  handle, char **label)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (label == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	char *syslocale = NULL;
	char *locale = NULL;
	char *save = NULL;
	label_x *ptr = NULL;
	label_x *start = NULL;
	syslocale = vconf_get_str(VCONFKEY_LANGSET);
	if (syslocale == NULL) {
		_LOGE("current locale is NULL\n");
		return PMINFO_R_EINVAL;
	}
	locale = __convert_system_locale_to_manifest_locale(syslocale);
	if (locale == NULL) {
		_LOGE("manifest locale is NULL\n");
		return PMINFO_R_EINVAL;
	}

	save = locale;
	*label = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
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
	if (syslocale) {
		free(syslocale);
		syslocale = NULL;
	}
	locale = save;
	if (locale) {
		free(locale);
		locale = NULL;
	}
	return PMINFO_R_OK;
}


API int pkgmgrinfo_appinfo_get_component(pkgmgrinfo_appinfo_h  handle, pkgmgrinfo_app_component *component)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (component == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
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
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (app_type == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
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
	if (handle == NULL) {
		_LOGE("appcontrol handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (operation_count == NULL || operation == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgrinfo_appcontrol_x *data = (pkgmgrinfo_appcontrol_x *)handle;
	*operation_count = data->operation_count;
	*operation = data->operation;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_uri(pkgmgrinfo_appcontrol_h  handle,
					int *uri_count, char ***uri)
{
	if (handle == NULL) {
		_LOGE("appcontrol handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (uri_count == NULL || uri == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgrinfo_appcontrol_x *data = (pkgmgrinfo_appcontrol_x *)handle;
	*uri_count = data->uri_count;
	*uri = data->uri;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_mime(pkgmgrinfo_appcontrol_h  handle,
					int *mime_count, char ***mime)
{
	if (handle == NULL) {
		_LOGE("appcontrol handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (mime_count == NULL || mime == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgrinfo_appcontrol_x *data = (pkgmgrinfo_appcontrol_x *)handle;
	*mime_count = data->mime_count;
	*mime = data->mime;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_setting_icon(pkgmgrinfo_appinfo_h  handle, char **icon)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (icon == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	int ret = -1;
	char *error_message = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	char path_buf[PKG_STRING_LEN_MAX] = {'\0'};
	pkgmgr_iconpath_x *data = NULL;
	char *icon_path;
	char *readpath;
	char *appid;

	ret = __open_manifest_db();
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		return PMINFO_R_ERROR;
	}

	ret = pkgmgrinfo_appinfo_get_appid(handle,&appid);
	if(ret < 0 || appid == NULL)
		return PMINFO_R_ERROR;

	data = (pkgmgr_iconpath_x *)calloc(1, sizeof(pkgmgr_iconpath_x));
	if (data == NULL) {
		_LOGE("Failed to allocate memory for pkgmgr_datacontrol_x\n");
		sqlite3_close(manifest_db);
		return PMINFO_R_ERROR;
	}

	snprintf(query, MAX_QUERY_LEN, "select app_icon from package_app_icon_localized_info where app_id='%s' and app_icon_section ='setting'", appid);
	if (SQLITE_OK !=
		sqlite3_exec(manifest_db, query, __icon_name_cb, (void *)data, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
			   error_message);
		free(data);
		sqlite3_free(error_message);
		sqlite3_close(manifest_db);
		return PMINFO_R_ERROR;
	}
	icon_path = __get_icon_with_path(data->iconpath);
	*icon = (char *)icon_path;

	if (data) {
	   free(data);
	   data = NULL;
	}
	sqlite3_close(manifest_db);
	return PMINFO_R_OK;
}


API int pkgmgrinfo_appinfo_get_notification_icon(pkgmgrinfo_appinfo_h  handle, char **icon)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (icon == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	int ret = -1;
	char *error_message = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	char path_buf[PKG_STRING_LEN_MAX] = {'\0'};
	pkgmgr_iconpath_x *data = NULL;
	char *icon_path;
	char *readpath;
	char *appid;

	ret = __open_manifest_db();
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		return PMINFO_R_ERROR;
	}

	ret = pkgmgrinfo_appinfo_get_appid(handle,&appid);
	if(ret < 0 || appid == NULL)
		return PMINFO_R_ERROR;

	data = (pkgmgr_iconpath_x *)calloc(1, sizeof(pkgmgr_iconpath_x));
	if (data == NULL) {
		_LOGE("Failed to allocate memory for pkgmgr_datacontrol_x\n");
		sqlite3_close(manifest_db);
		return PMINFO_R_ERROR;
	}

	snprintf(query, MAX_QUERY_LEN, "select app_icon from package_app_icon_localized_info where app_id='%s' and app_icon_section ='notification'", appid);
	if (SQLITE_OK !=
		sqlite3_exec(manifest_db, query, __icon_name_cb, (void *)data, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
			   error_message);
		free(data);
		sqlite3_free(error_message);
		sqlite3_close(manifest_db);
		return PMINFO_R_ERROR;
	}
	icon_path = __get_icon_with_path(data->iconpath);
	*icon = (char *)icon_path;

	if (data) {
	   free(data);
	   data = NULL;
	}
	sqlite3_close(manifest_db);
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_recent_image_type(pkgmgrinfo_appinfo_h  handle, pkgmgrinfo_app_recentimage *type)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (type == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
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

API int pkgmgrinfo_appinfo_foreach_category(pkgmgrinfo_appinfo_h handle,
			pkgmgrinfo_app_category_list_cb category_func, void *user_data)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (category_func == NULL) {
		_LOGE("Callback function is NULL\n");
		return PMINFO_R_EINVAL;
	}
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
		ret = category_func(ptr->name, user_data);
		if (ret < 0)
			break;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_foreach_appcontrol(pkgmgrinfo_appinfo_h handle,
			pkgmgrinfo_app_control_list_cb appcontrol_func, void *user_data)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (appcontrol_func == NULL) {
		_LOGE("Callback function is NULL\n");
		return PMINFO_R_EINVAL;
	}
	int i = 0;
	int ret = -1;
	int oc = 0;
	int mc = 0;
	int uc = 0;
	char *pkgid = NULL;
	char *manifest = NULL;
	char **operation = NULL;
	char **uri = NULL;
	char **mime = NULL;
	appcontrol_x *appcontrol = NULL;
	manifest_x *mfx = NULL;
	operation_x *op = NULL;
	uri_x *ui = NULL;
	mime_x *mi = NULL;
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
			if (mfx->uiapplication->appcontrol) {
				appcontrol = mfx->uiapplication->appcontrol;
			}
		}
		break;
	case PMINFO_SVC_APP:
		if (mfx->serviceapplication) {
			if (mfx->serviceapplication->appcontrol) {
				appcontrol = mfx->serviceapplication->appcontrol;
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
		/*populate appcontrol handle*/
		ptr->operation_count = oc;
		ptr->uri_count = uc;
		ptr->mime_count = mc;
		ptr->operation = operation;
		ptr->uri = uri;
		ptr->mime = mime;
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
		if (ret < 0)
			break;
		uc = 0;
		mc = 0;
		oc = 0;
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
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (nodisplay == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
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
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (multiple == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
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

API int pkgmgrinfo_appinfo_is_taskmanage(pkgmgrinfo_appinfo_h  handle, bool *taskmanage)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (taskmanage == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
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

API int pkgmgrinfo_appinfo_get_hwacceleration(pkgmgrinfo_appinfo_h  handle, pkgmgrinfo_app_hwacceleration *hwacceleration)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (hwacceleration == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
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

API int pkgmgrinfo_appinfo_is_onboot(pkgmgrinfo_appinfo_h  handle, bool *onboot)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (onboot == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
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
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (autorestart == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
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
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (mainapp == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
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

API int pkgmgrinfo_appinfo_destroy_appinfo(pkgmgrinfo_appinfo_h  handle)
{
	if (handle == NULL) {
		_LOGE("appinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
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
	if (handle == NULL || property == NULL) {
		_LOGE("Filter handle input parameter is NULL\n");
		return PMINFO_R_EINVAL;
	}
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
	if (handle == NULL || property == NULL) {
		_LOGE("Filter handle input parameter is NULL\n");
		return PMINFO_R_EINVAL;
	}
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
	if (handle == NULL || property == NULL || value == NULL) {
		_LOGE("Filter handle input parameter is NULL\n");
		return PMINFO_R_EINVAL;
	}
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
	if (handle == NULL || count == NULL) {
		_LOGE("Filter handle input parameter is NULL\n");
		return PMINFO_R_EINVAL;
	}
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
	ret = __open_manifest_db();
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		ret = PMINFO_R_ERROR;
		goto err;
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
	_LOGE("where = %s\n", where);
	if (strlen(where) > 0) {
		strncat(query, where, sizeof(query) - strlen(query) - 1);
		query[sizeof(query) - 1] = '\0';
	}
	_LOGE("query = %s\n", query);

	/*Execute Query*/
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __count_cb, (void *)count, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		sqlite3_close(manifest_db);
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
	sqlite3_close(manifest_db);
	return ret;
}

API int pkgmgrinfo_appinfo_filter_foreach_appinfo(pkgmgrinfo_appinfo_filter_h handle,
				pkgmgrinfo_app_list_cb app_cb, void * user_data)
{
	if (handle == NULL || app_cb == NULL) {
		_LOGE("Filter handle input parameter is NULL\n");
		return PMINFO_R_EINVAL;
	}
	char *syslocale = NULL;
	char *locale = NULL;
	char *condition = NULL;
	char *error_message = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	char where[MAX_QUERY_LEN] = {'\0'};
	GSList *list;
	int ret = 0;
	uiapplication_x *ptr1 = NULL;
	serviceapplication_x *ptr2 = NULL;
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
	ret = __open_manifest_db();
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
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
	if (info == NULL) {
		_LOGE("Out of Memory!!!\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	info->manifest_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	if (info->manifest_info == NULL) {
		_LOGE("Out of Memory!!!\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	/*To get detail app info for each member of filtered list*/
	pkgmgr_pkginfo_x *filtinfo = NULL;
	filtinfo = (pkgmgr_pkginfo_x *)calloc(1, sizeof(pkgmgr_pkginfo_x));
	if (filtinfo == NULL) {
		_LOGE("Out of Memory!!!\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	filtinfo->manifest_info = (manifest_x *)calloc(1, sizeof(manifest_x));
	if (filtinfo->manifest_info == NULL) {
		_LOGE("Out of Memory!!!\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	pkgmgr_appinfo_x *appinfo = (pkgmgr_appinfo_x *)calloc(1, sizeof(pkgmgr_appinfo_x));
	if (appinfo == NULL) {
		_LOGE("Out of Memory!!!\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	if (SQLITE_OK !=
	    sqlite3_exec(manifest_db, query, __app_list_cb, (void *)info, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		sqlite3_close(manifest_db);
		ret = PMINFO_R_ERROR;
		goto err;
	}
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
		if (SQLITE_OK !=
		sqlite3_exec(manifest_db, query, __uiapp_list_cb, (void *)filtinfo, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
			       error_message);
			sqlite3_free(error_message);
			sqlite3_close(manifest_db);
			ret = PMINFO_R_ERROR;
			goto err;
		}
	}
	for(ptr2 = info->manifest_info->serviceapplication; ptr2; ptr2 = ptr2->next)
	{
		snprintf(query, MAX_QUERY_LEN, "select * from package_app_info where app_id='%s' and app_component='%s'",
							ptr2->appid, "svcapp");
		if (SQLITE_OK !=
		sqlite3_exec(manifest_db, query, __svcapp_list_cb, (void *)filtinfo, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
			       error_message);
			sqlite3_free(error_message);
			sqlite3_close(manifest_db);
			ret = PMINFO_R_ERROR;
			goto err;
		}
	}
	if (filtinfo->manifest_info->uiapplication) {
		LISTHEAD(filtinfo->manifest_info->uiapplication, ptr1);
		filtinfo->manifest_info->uiapplication = ptr1;
	}
	/*If the callback func return < 0 we break and no more call back is called*/
	while(ptr1 != NULL)
	{
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
		appinfo->svcapp_info = ptr2;
		appinfo->app_component = PMINFO_SVC_APP;
		ret = app_cb((void *)appinfo, user_data);
		if (ret < 0)
			break;
		ptr2 = ptr2->next;
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
	sqlite3_close(manifest_db);
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
	if (!handle) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	int ret = 0;
	pkgmgr_certinfo_x *certinfo = NULL;
	certinfo = calloc(1, sizeof(pkgmgr_certinfo_x));
	if (!certinfo) {
		_LOGE("Malloc Failed\n");
		return PMINFO_R_ERROR;
	}
	*handle = (void *)certinfo;
	/*Open db. It will be closed in destroy handle API*/
	ret = db_util_open_with_options(CERT_DB, &cert_db,
					SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n", MANIFEST_DB);
		free(certinfo);
		return PMINFO_R_ERROR;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_load_certinfo(const char *pkgid, pkgmgrinfo_certinfo_h handle)
{
	if (pkgid == NULL) {
		_LOGE("package ID is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (handle == NULL) {
		_LOGE("Certinfo handle is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_certinfo_x *certinfo = NULL;
	char *error_message = NULL;
	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	int exist = 0;

	/*validate pkgid*/
	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", pkgid);
	if (SQLITE_OK !=
	    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return PMINFO_R_ERROR;
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
	return PMINFO_R_OK;
err:
	return ret;
}

API int pkgmgrinfo_pkginfo_get_cert_value(pkgmgrinfo_certinfo_h handle, pkgmgrinfo_cert_type cert_type, const char **cert_value)
{
	if (!handle || !cert_value) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if ((cert_type < PMINFO_AUTHOR_ROOT_CERT) || (cert_type > PMINFO_DISTRIBUTOR2_SIGNER_CERT)) {
		_LOGE("Invalid certificate type\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_certinfo_x *certinfo = NULL;
	char *error_message = NULL;
	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	int exist = 0;
	certinfo = (pkgmgr_certinfo_x *)handle;
	*cert_value = NULL;
	switch(cert_type) {
	case PMINFO_AUTHOR_SIGNER_CERT:
		snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", certinfo->auth_signer_cert);
		if (SQLITE_OK !=
		    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
			       error_message);
			sqlite3_free(error_message);
			return PMINFO_R_ERROR;
		}
		if (exist == 0)
			*cert_value = certinfo->auth_signer_cert;
		else {
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select author_signer_cert from package_cert_info " \
				"where package='%s'", certinfo->auth_signer_cert);
			free(certinfo->auth_signer_cert);
			certinfo->auth_signer_cert = NULL;
			ret = __exec_certinfo_query(query, (void *)certinfo);
			if (ret == -1) {
				_LOGE("Cert Info DB Information retrieval failed\n");
				return PMINFO_R_ERROR;
			}
			*cert_value = certinfo->auth_signer_cert;
		}
		break;
	case PMINFO_AUTHOR_INTERMEDIATE_CERT:
		snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", certinfo->auth_im_cert);
		if (SQLITE_OK !=
		    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
			       error_message);
			sqlite3_free(error_message);
			return PMINFO_R_ERROR;
		}
		if (exist == 0)
			*cert_value = certinfo->auth_im_cert;
		else {
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select author_im_cert from package_cert_info " \
				"where package='%s'", certinfo->auth_im_cert);
			free(certinfo->auth_im_cert);
			certinfo->auth_im_cert = NULL;
			ret = __exec_certinfo_query(query, (void *)certinfo);
			if (ret == -1) {
				_LOGE("Cert Info DB Information retrieval failed\n");
				return PMINFO_R_ERROR;
			}
			*cert_value = certinfo->auth_im_cert;
		}
		break;
	case PMINFO_AUTHOR_ROOT_CERT:
		snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", certinfo->auth_root_cert);
		if (SQLITE_OK !=
		    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
			       error_message);
			sqlite3_free(error_message);
			return PMINFO_R_ERROR;
		}
		if (exist == 0)
			*cert_value = certinfo->auth_root_cert;
		else {
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select author_root_cert from package_cert_info " \
				"where package='%s'", certinfo->auth_root_cert);
			free(certinfo->auth_root_cert);
			certinfo->auth_root_cert = NULL;
			ret = __exec_certinfo_query(query, (void *)certinfo);
			if (ret == -1) {
				_LOGE("Cert Info DB Information retrieval failed\n");
				return PMINFO_R_ERROR;
			}
			*cert_value = certinfo->auth_root_cert;
		}
		break;
	case PMINFO_DISTRIBUTOR_SIGNER_CERT:
		snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", certinfo->dist_signer_cert);
		if (SQLITE_OK !=
		    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
			       error_message);
			sqlite3_free(error_message);
			return PMINFO_R_ERROR;
		}
		if (exist == 0)
			*cert_value = certinfo->dist_signer_cert;
		else {
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select dist_signer_cert from package_cert_info " \
				"where package='%s'", certinfo->dist_signer_cert);
			free(certinfo->dist_signer_cert);
			certinfo->dist_signer_cert = NULL;
			ret = __exec_certinfo_query(query, (void *)certinfo);
			if (ret == -1) {
				_LOGE("Cert Info DB Information retrieval failed\n");
				return PMINFO_R_ERROR;
			}
			*cert_value = certinfo->dist_signer_cert;
		}
		break;
	case PMINFO_DISTRIBUTOR_INTERMEDIATE_CERT:
		snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", certinfo->dist_im_cert);
		if (SQLITE_OK !=
		    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
			       error_message);
			sqlite3_free(error_message);
			return PMINFO_R_ERROR;
		}
		if (exist == 0)
			*cert_value = certinfo->dist_im_cert;
		else {
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select dist_im_cert from package_cert_info " \
				"where package='%s'", certinfo->dist_im_cert);
			free(certinfo->dist_im_cert);
			certinfo->dist_im_cert = NULL;
			ret = __exec_certinfo_query(query, (void *)certinfo);
			if (ret == -1) {
				_LOGE("Cert Info DB Information retrieval failed\n");
				return PMINFO_R_ERROR;
			}
			*cert_value = certinfo->dist_im_cert;
		}
		break;
	case PMINFO_DISTRIBUTOR_ROOT_CERT:
		snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", certinfo->dist_root_cert);
		if (SQLITE_OK !=
		    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
			       error_message);
			sqlite3_free(error_message);
			return PMINFO_R_ERROR;
		}
		if (exist == 0)
			*cert_value = certinfo->dist_root_cert;
		else {
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select dist_root_cert from package_cert_info " \
				"where package='%s'", certinfo->dist_root_cert);
			free(certinfo->dist_root_cert);
			certinfo->dist_root_cert = NULL;
			ret = __exec_certinfo_query(query, (void *)certinfo);
			if (ret == -1) {
				_LOGE("Cert Info DB Information retrieval failed\n");
				return PMINFO_R_ERROR;
			}
			*cert_value = certinfo->dist_root_cert;
		}
		break;
	case PMINFO_DISTRIBUTOR2_SIGNER_CERT:
		snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", certinfo->dist2_signer_cert);
		if (SQLITE_OK !=
		    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
			       error_message);
			sqlite3_free(error_message);
			return PMINFO_R_ERROR;
		}
		if (exist == 0)
			*cert_value = certinfo->dist2_signer_cert;
		else {
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select dist2_signer_cert from package_cert_info " \
				"where package='%s'", certinfo->dist2_signer_cert);
			free(certinfo->dist2_signer_cert);
			certinfo->dist2_signer_cert = NULL;
			ret = __exec_certinfo_query(query, (void *)certinfo);
			if (ret == -1) {
				_LOGE("Cert Info DB Information retrieval failed\n");
				return PMINFO_R_ERROR;
			}
			*cert_value = certinfo->dist2_signer_cert;
		}
		break;
	case PMINFO_DISTRIBUTOR2_INTERMEDIATE_CERT:
		snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", certinfo->dist2_im_cert);
		if (SQLITE_OK !=
		    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
			       error_message);
			sqlite3_free(error_message);
			return PMINFO_R_ERROR;
		}
		if (exist == 0)
			*cert_value = certinfo->dist2_im_cert;
		else {
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select dist2_im_cert from package_cert_info " \
				"where package='%s'", certinfo->dist2_im_cert);
			free(certinfo->dist2_im_cert);
			certinfo->dist2_im_cert = NULL;
			ret = __exec_certinfo_query(query, (void *)certinfo);
			if (ret == -1) {
				_LOGE("Cert Info DB Information retrieval failed\n");
				return PMINFO_R_ERROR;
			}
			*cert_value = certinfo->dist2_im_cert;
		}
		break;
	case PMINFO_DISTRIBUTOR2_ROOT_CERT:
		snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", certinfo->dist2_root_cert);
		if (SQLITE_OK !=
		    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
			       error_message);
			sqlite3_free(error_message);
			return PMINFO_R_ERROR;
		}
		if (exist == 0)
			*cert_value = certinfo->dist2_root_cert;
		else {
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select dist2_root_cert from package_cert_info " \
				"where package='%s'", certinfo->dist2_root_cert);
			free(certinfo->dist2_root_cert);
			certinfo->dist2_root_cert = NULL;
			ret = __exec_certinfo_query(query, (void *)certinfo);
			if (ret == -1) {
				_LOGE("Cert Info DB Information retrieval failed\n");
				return PMINFO_R_ERROR;
			}
			*cert_value = certinfo->dist2_root_cert;
		}
		break;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_destroy_certinfo(pkgmgrinfo_certinfo_h handle)
{
	if (!handle) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_certinfo_x *certinfo = NULL;
	certinfo = (pkgmgr_certinfo_x *)handle;
	if (certinfo->pkgid) {
		free(certinfo->pkgid);
		certinfo->pkgid = NULL;
	}
	if (certinfo->auth_signer_cert) {
		free(certinfo->auth_signer_cert);
		certinfo->auth_signer_cert = NULL;
	}
	if (certinfo->auth_im_cert) {
		free(certinfo->auth_im_cert);
		certinfo->auth_im_cert = NULL;
	}
	if (certinfo->auth_root_cert) {
		free(certinfo->auth_root_cert);
		certinfo->auth_root_cert = NULL;
	}
	if (certinfo->dist_signer_cert) {
		free(certinfo->dist_signer_cert);
		certinfo->dist_signer_cert = NULL;
	}
	if (certinfo->dist_im_cert) {
		free(certinfo->dist_im_cert);
		certinfo->dist_im_cert = NULL;
	}
	if (certinfo->dist_root_cert) {
		free(certinfo->dist_root_cert);
		certinfo->dist_root_cert = NULL;
	}
	if (certinfo->dist2_signer_cert) {
		free(certinfo->dist2_signer_cert);
		certinfo->dist2_signer_cert = NULL;
	}
	if (certinfo->dist2_im_cert) {
		free(certinfo->dist2_im_cert);
		certinfo->dist2_im_cert = NULL;
	}
	if (certinfo->dist2_root_cert) {
		free(certinfo->dist2_root_cert);
		certinfo->dist2_root_cert = NULL;
	}
	free(certinfo);
	certinfo = NULL;
	sqlite3_close(cert_db);
	return PMINFO_R_OK;
}

API int pkgmgrinfo_create_certinfo_set_handle(pkgmgrinfo_instcertinfo_h *handle)
{
	if (!handle) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_instcertinfo_x *certinfo = NULL;
	int ret = 0;
	certinfo = calloc(1, sizeof(pkgmgr_instcertinfo_x));
	if (!certinfo) {
		_LOGE("Malloc Failed\n");
		return PMINFO_R_ERROR;
	}
	*handle = (void *)certinfo;
	/*Open db. It will be closed in destroy handle API*/
	ret = db_util_open(CERT_DB, &cert_db,
		DB_UTIL_REGISTER_HOOK_METHOD);
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n", CERT_DB);
		free(certinfo);
		return PMINFO_R_ERROR;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_cert_value(pkgmgrinfo_instcertinfo_h handle, pkgmgrinfo_instcert_type cert_type, char *cert_value)
{
	if (!handle || !cert_value) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if ((cert_type < PMINFO_SET_AUTHOR_ROOT_CERT) || (cert_type > PMINFO_SET_DISTRIBUTOR2_SIGNER_CERT)) {
		_LOGE("Invalid certificate type\n");
		return PMINFO_R_EINVAL;
	}
	char query[MAX_QUERY_LEN] = {'\0'};
	pkgmgr_instcertinfo_x *certinfo = NULL;
	int ret = 0;
	certinfo = (pkgmgr_instcertinfo_x *)handle;
	switch(cert_type) {
	case PMINFO_SET_AUTHOR_SIGNER_CERT:
		snprintf(query, MAX_QUERY_LEN, "select package from package_cert_info " \
			"where author_signer_cert='%s'", cert_value);
		ret = __exec_certinfo_query(query, (void *)certinfo);
		if (ret == -1) {
			_LOGE("Cert Info DB Information retrieval failed\n");
			return PMINFO_R_ERROR;
		}
		if (certinfo->pkgid)
			certinfo->auth_signer_cert = strdup(certinfo->pkgid);
		else
			certinfo->auth_signer_cert = strdup(cert_value);
		break;
	case PMINFO_SET_AUTHOR_INTERMEDIATE_CERT:
		snprintf(query, MAX_QUERY_LEN, "select package from package_cert_info " \
			"where author_im_cert='%s'", cert_value);
		ret = __exec_certinfo_query(query, (void *)certinfo);
		if (ret == -1) {
			_LOGE("Cert Info DB Information retrieval failed\n");
			return PMINFO_R_ERROR;
		}
		if (certinfo->pkgid)
			certinfo->auth_im_cert = strdup(certinfo->pkgid);
		else
			certinfo->auth_im_cert = strdup(cert_value);
		break;
	case PMINFO_SET_AUTHOR_ROOT_CERT:
		snprintf(query, MAX_QUERY_LEN, "select package from package_cert_info " \
			"where author_root_cert='%s'", cert_value);
		ret = __exec_certinfo_query(query, (void *)certinfo);
		if (ret == -1) {
			_LOGE("Cert Info DB Information retrieval failed\n");
			return PMINFO_R_ERROR;
		}
		if (certinfo->pkgid)
			certinfo->auth_root_cert = strdup(certinfo->pkgid);
		else
			certinfo->auth_root_cert = strdup(cert_value);
		break;
	case PMINFO_SET_DISTRIBUTOR_SIGNER_CERT:
		snprintf(query, MAX_QUERY_LEN, "select package from package_cert_info " \
			"where dist_signer_cert='%s'", cert_value);
		ret = __exec_certinfo_query(query, (void *)certinfo);
		if (ret == -1) {
			_LOGE("Cert Info DB Information retrieval failed\n");
			return PMINFO_R_ERROR;
		}
		if (certinfo->pkgid)
			certinfo->dist_signer_cert = strdup(certinfo->pkgid);
		else
			certinfo->dist_signer_cert = strdup(cert_value);
		break;
	case PMINFO_SET_DISTRIBUTOR_INTERMEDIATE_CERT:
		snprintf(query, MAX_QUERY_LEN, "select package from package_cert_info " \
			"where dist_im_cert='%s'", cert_value);
		ret = __exec_certinfo_query(query, (void *)certinfo);
		if (ret == -1) {
			_LOGE("Cert Info DB Information retrieval failed\n");
			return PMINFO_R_ERROR;
		}
		if (certinfo->pkgid)
			certinfo->dist_im_cert = strdup(certinfo->pkgid);
		else
			certinfo->dist_im_cert = strdup(cert_value);
		break;
	case PMINFO_SET_DISTRIBUTOR_ROOT_CERT:
		snprintf(query, MAX_QUERY_LEN, "select package from package_cert_info " \
			"where dist_root_cert='%s'", cert_value);
		ret = __exec_certinfo_query(query, (void *)certinfo);
		if (ret == -1) {
			_LOGE("Cert Info DB Information retrieval failed\n");
			return PMINFO_R_ERROR;
		}
		if (certinfo->pkgid)
			certinfo->dist_root_cert = strdup(certinfo->pkgid);
		else
			certinfo->dist_root_cert = strdup(cert_value);
		break;
	case PMINFO_SET_DISTRIBUTOR2_SIGNER_CERT:
		snprintf(query, MAX_QUERY_LEN, "select package from package_cert_info " \
			"where dist2_signer_cert='%s'", cert_value);
		ret = __exec_certinfo_query(query, (void *)certinfo);
		if (ret == -1) {
			_LOGE("Cert Info DB Information retrieval failed\n");
			return PMINFO_R_ERROR;
		}
		if (certinfo->pkgid)
			certinfo->dist2_signer_cert = strdup(certinfo->pkgid);
		else
			certinfo->dist2_signer_cert = strdup(cert_value);
		break;
	case PMINFO_SET_DISTRIBUTOR2_INTERMEDIATE_CERT:
		snprintf(query, MAX_QUERY_LEN, "select package from package_cert_info " \
			"where dist2_im_cert='%s'", cert_value);
		ret = __exec_certinfo_query(query, (void *)certinfo);
		if (ret == -1) {
			_LOGE("Cert Info DB Information retrieval failed\n");
			return PMINFO_R_ERROR;
		}
		if (certinfo->pkgid)
			certinfo->dist2_im_cert = strdup(certinfo->pkgid);
		else
			certinfo->dist2_im_cert = strdup(cert_value);
		break;
	case PMINFO_SET_DISTRIBUTOR2_ROOT_CERT:
		snprintf(query, MAX_QUERY_LEN, "select package from package_cert_info " \
			"where dist2_root_cert='%s'", cert_value);
		ret = __exec_certinfo_query(query, (void *)certinfo);
		if (ret == -1) {
			_LOGE("Cert Info DB Information retrieval failed\n");
			return PMINFO_R_ERROR;
		}
		if (certinfo->pkgid)
			certinfo->dist2_root_cert = strdup(certinfo->pkgid);
		else
			certinfo->dist2_root_cert = strdup(cert_value);
		break;
	}
	if (certinfo->pkgid) {
		free(certinfo->pkgid);
		certinfo->pkgid = NULL;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_save_certinfo(const char *pkgid, pkgmgrinfo_instcertinfo_h handle)
{
	if (!handle || !pkgid) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	int ret = -1;
	char *error_message = NULL;
	int exist = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *vquery = NULL;
	int len = 0;
	pkgmgr_instcertinfo_x *info = (pkgmgr_instcertinfo_x *)handle;
	info->pkgid = strdup(pkgid);
	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", pkgid);
	if (SQLITE_OK !=
	    sqlite3_exec(cert_db, query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return PMINFO_R_ERROR;
	}

	len = 4096;
	if (info->auth_root_cert)
		len += strlen(info->auth_root_cert);
	if (info->auth_im_cert)
		len += strlen(info->auth_im_cert);
	if (info->auth_signer_cert)
		len += strlen(info->auth_signer_cert);
	if (info->dist_root_cert)
		len += strlen(info->dist_root_cert);
	if (info->dist_im_cert)
		len += strlen(info->dist_im_cert);
	if (info->dist_signer_cert)
		len += strlen(info->dist_signer_cert);
	if (info->dist2_root_cert)
		len += strlen(info->dist2_root_cert);
	if (info->dist2_im_cert)
		len += strlen(info->dist2_im_cert);
	if (info->dist2_signer_cert)
		len += strlen(info->dist2_signer_cert);
	vquery = (char *)calloc(1, len);

	if (exist == 0) {
		_LOGE("pkgid not found in DB\n");
		/*insert*/
		snprintf(vquery, len,
	                 "insert into package_cert_info(package, author_root_cert, author_im_cert, author_signer_cert, dist_root_cert, " \
	                "dist_im_cert, dist_signer_cert, dist2_root_cert, dist2_im_cert, dist2_signer_cert) " \
	                "values('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')",\
	                 info->pkgid, info->auth_root_cert, info->auth_im_cert, info->auth_signer_cert, info->dist_root_cert, info->dist_im_cert,
	                 info->dist_signer_cert, info->dist2_root_cert, info->dist2_im_cert, info->dist2_signer_cert);
	} else {
		_LOGE("pkgid exists in DB..Update it\n");
		/*Update*/
		snprintf(vquery, len,
	                 "update package_cert_info set author_root_cert='%s', author_im_cert='%s', author_signer_cert='%s', dist_root_cert='%s', " \
	                "dist_im_cert='%s', dist_signer_cert='%s', dist2_root_cert='%s', dist2_im_cert='%s', dist2_signer_cert='%s' " \
	                "where package='%s'",\
	                 info->auth_root_cert, info->auth_im_cert, info->auth_signer_cert, info->dist_root_cert, info->dist_im_cert,
	                 info->dist_signer_cert, info->dist2_root_cert, info->dist2_im_cert, info->dist2_signer_cert, info->pkgid);
	}
        if (SQLITE_OK !=
            sqlite3_exec(cert_db, vquery, NULL, NULL, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", vquery,
		       error_message);
		sqlite3_free(error_message);
		return PMINFO_R_ERROR;
        }
	return PMINFO_R_OK;
}

API int pkgmgrinfo_destroy_certinfo_set_handle(pkgmgrinfo_instcertinfo_h handle)
{
	if (!handle) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgr_instcertinfo_x *certinfo = NULL;
	certinfo = (pkgmgr_instcertinfo_x *)handle;
	if (certinfo->pkgid) {
		free(certinfo->pkgid);
		certinfo->pkgid = NULL;
	}
	if (certinfo->auth_signer_cert) {
		free(certinfo->auth_signer_cert);
		certinfo->auth_signer_cert = NULL;
	}
	if (certinfo->auth_im_cert) {
		free(certinfo->auth_im_cert);
		certinfo->auth_im_cert = NULL;
	}
	if (certinfo->auth_root_cert) {
		free(certinfo->auth_root_cert);
		certinfo->auth_root_cert = NULL;
	}
	if (certinfo->dist_signer_cert) {
		free(certinfo->dist_signer_cert);
		certinfo->dist_signer_cert = NULL;
	}
	if (certinfo->dist_im_cert) {
		free(certinfo->dist_im_cert);
		certinfo->dist_im_cert = NULL;
	}
	if (certinfo->dist_root_cert) {
		free(certinfo->dist_root_cert);
		certinfo->dist_root_cert = NULL;
	}
	if (certinfo->dist2_signer_cert) {
		free(certinfo->dist2_signer_cert);
		certinfo->dist2_signer_cert = NULL;
	}
	if (certinfo->dist2_im_cert) {
		free(certinfo->dist2_im_cert);
		certinfo->dist2_im_cert = NULL;
	}
	if (certinfo->dist2_root_cert) {
		free(certinfo->dist2_root_cert);
		certinfo->dist2_root_cert = NULL;
	}
	free(certinfo);
	certinfo = NULL;
	sqlite3_close(cert_db);
	return PMINFO_R_OK;
}

API int pkgmgrinfo_delete_certinfo(const char *pkgid)
{
	if (!pkgid) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	int ret = -1;
	int i = 0;
	char *error_message = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	ret = db_util_open(CERT_DB, &cert_db,
		DB_UTIL_REGISTER_HOOK_METHOD);
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n", CERT_DB);
		return PMINFO_R_ERROR;
	}
	/*First make copy of all entries for which other packages have an index here*/
	snprintf(query, MAX_QUERY_LEN, "select * from package_cert_info where package!='%s'", pkgid);
        if (SQLITE_OK !=
            sqlite3_exec(cert_db, query, __delete_certinfo_cb, (void *)pkgid, &error_message)) {
                _LOGE("Don't execute query = %s error message = %s\n", query,
                       error_message);
		sqlite3_free(error_message);
		sqlite3_close(cert_db);
		ret = PMINFO_R_ERROR;
		goto err;
        }
	/*Now delete the entry from db*/
	snprintf(query, MAX_QUERY_LEN, "delete from package_cert_info where package='%s'", pkgid);
        if (SQLITE_OK !=
            sqlite3_exec(cert_db, query, NULL, NULL, &error_message)) {
                _LOGE("Don't execute query = %s error message = %s\n", query,
                       error_message);
		sqlite3_free(error_message);
		sqlite3_close(cert_db);
		ret = PMINFO_R_ERROR;
		goto err;
        }
	ret = PMINFO_R_OK;
err:
	sqlite3_close(cert_db);
	for (i = 0; i < 9; i++) {
		gflag[i] = 0;
		if (gpkgcert[i]) {
			free(gpkgcert[i]);
			gpkgcert[i] = NULL;
		}
	}
	return ret;
}

API int pkgmgrinfo_create_pkgdbinfo(const char *pkgid, pkgmgrinfo_pkgdbinfo_h *handle)
{
	if (!pkgid || !handle) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	manifest_x *mfx = NULL;
	mfx = calloc(1, sizeof(manifest_x));
	if (!mfx) {
		_LOGE("Malloc Failed\n");
		return PMINFO_R_ERROR;
	}
	mfx->package = strdup(pkgid);
	*handle = (void *)mfx;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_type_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, const char *type)
{
	if (!type || !handle) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	int len = strlen(type);
	manifest_x *mfx = (manifest_x *)handle;
	if (len > PKG_TYPE_STRING_LEN_MAX) {
		_LOGE("pkg type length exceeds the max limit\n");
		return PMINFO_R_EINVAL;
	}
	if (mfx->type == NULL)
		mfx->type = strndup(type, PKG_TYPE_STRING_LEN_MAX);
	else
		mfx->type = type;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_version_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, const char *version)
{
	if (!version || !handle) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	int len = strlen(version);
	manifest_x *mfx = (manifest_x *)handle;
	if (len > PKG_VERSION_STRING_LEN_MAX) {
		_LOGE("pkg version length exceeds the max limit\n");
		return PMINFO_R_EINVAL;
	}
	if (mfx->version == NULL)
		mfx->version = strndup(version, PKG_VERSION_STRING_LEN_MAX);
	else
		mfx->version = version;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_install_location_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, INSTALL_LOCATION location)
{
	if (!handle) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (location < 0 || location > 1) {
		_LOGE("Argument supplied is invalid\n");
		return PMINFO_R_EINVAL;
	}
	manifest_x *mfx = (manifest_x *)handle;
	if (mfx->installlocation == NULL) {
		mfx->installlocation = (char *)calloc(1, strlen("prefer-external"));
		if (mfx->installlocation == NULL) {
			_LOGE("Malloc Failed\n");
			return PMINFO_R_ERROR;
		}
	}
	if (location == INSTALL_INTERNAL) {
		strcpy(mfx->installlocation, "internal-only");
	} else if (location == INSTALL_EXTERNAL) {
		strcpy(mfx->installlocation, "prefer-external");
	} else {
		_LOGE("Invalid location type\n");
		return PMINFO_R_ERROR;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_size_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, const char *size)
{
	if (!handle) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (size == NULL) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	manifest_x *mfx = (manifest_x *)handle;
	if (mfx->installlocation == NULL) {
		_LOGE("cant set size without specifying install location\n");
		return PMINFO_R_ERROR;
	}
	if (strcmp(mfx->installlocation, "prefer-external") == 0) {
		if (mfx->package_size == NULL)
			mfx->package_size = strdup(size);
		else
			mfx->package_size = size;
	} else {
		_LOGE("cant set size for internal location\n");
		return PMINFO_R_ERROR;
	}
	return PMINFO_R_OK;
}
API int pkgmgrinfo_set_label_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, const char *label_txt, const char *locale)
{
	if (!handle || !label_txt) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	int len = strlen(label_txt);
	manifest_x *mfx = (manifest_x *)handle;
	if (len > PKG_VALUE_STRING_LEN_MAX) {
		_LOGE("label length exceeds the max limit\n");
		return PMINFO_R_EINVAL;
	}
	label_x *label = calloc(1, sizeof(label_x));
	if (label == NULL) {
		_LOGE("Malloc Failed\n");
		return PMINFO_R_ERROR;
	}
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
	if (!handle || !icon_txt) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	int len = strlen(icon_txt);
	manifest_x *mfx = (manifest_x *)handle;
	if (len > PKG_VALUE_STRING_LEN_MAX) {
		_LOGE("icon length exceeds the max limit\n");
		return PMINFO_R_EINVAL;
	}
	icon_x *icon = calloc(1, sizeof(icon_x));
	if (icon == NULL) {
		_LOGE("Malloc Failed\n");
		return PMINFO_R_ERROR;
	}
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
	if (!handle || !desc_txt) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	int len = strlen(desc_txt);
	manifest_x *mfx = (manifest_x *)handle;
	if (len > PKG_VALUE_STRING_LEN_MAX) {
		_LOGE("description length exceeds the max limit\n");
		return PMINFO_R_EINVAL;
	}
	description_x *description = calloc(1, sizeof(description_x));
	if (description == NULL) {
		_LOGE("Malloc Failed\n");
		return PMINFO_R_ERROR;
	}
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
	if (!handle) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	manifest_x *mfx = (manifest_x *)handle;
	author_x *author = calloc(1, sizeof(author_x));
	if (author == NULL) {
		_LOGE("Malloc Failed\n");
		return PMINFO_R_ERROR;
	}
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
	if (!handle) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (removable < 0 || removable > 1) {
		_LOGE("Argument supplied is invalid\n");
		return PMINFO_R_EINVAL;
	}
	manifest_x *mfx = (manifest_x *)handle;
	if (mfx->removable == NULL) {
		mfx->removable = (char *)calloc(1, strlen("false"));
		if (mfx->removable == NULL) {
			_LOGE("Malloc Failed\n");
			return PMINFO_R_ERROR;
		}
	}
	if (removable == 0) {
		strcpy(mfx->removable, "false");
	} else if (removable == 1) {
		strcpy(mfx->removable, "true");
	} else {
		_LOGE("Invalid removable type\n");
		return PMINFO_R_ERROR;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_preload_to_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle, int preload)
{
	if (!handle) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (preload < 0 || preload > 1) {
		_LOGE("Argument supplied is invalid\n");
		return PMINFO_R_EINVAL;
	}
	manifest_x *mfx = (manifest_x *)handle;
	if (mfx->preload == NULL) {
		mfx->preload = (char *)calloc(1, strlen("false"));
		if (mfx->preload == NULL) {
			_LOGE("Malloc Failed\n");
			return PMINFO_R_ERROR;
		}
	}
	if (preload == 0) {
		strcpy(mfx->preload, "false");
	} else if (preload == 1) {
		strcpy(mfx->preload, "true");
	} else {
		_LOGE("Invalid preload type\n");
		return PMINFO_R_ERROR;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_save_pkgdbinfo(pkgmgrinfo_pkgdbinfo_h handle)
{
	if (!handle) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	int ret = 0;
	manifest_x *mfx = NULL;
	label_x *tmp1 = NULL;
	icon_x *tmp2 = NULL;
	description_x *tmp3 = NULL;
	author_x *tmp4 = NULL;
	mfx = (manifest_x *)handle;
	/*First move to head of all list pointers*/
	if (mfx->label) {
		LISTHEAD(mfx->label, tmp1);
		mfx->label = tmp1;
	}
	if (mfx->icon) {
		LISTHEAD(mfx->icon, tmp2);
		mfx->icon = tmp2;
	}
	if (mfx->description) {
		LISTHEAD(mfx->description, tmp3);
		mfx->description= tmp3;
	}
	if (mfx->author) {
		LISTHEAD(mfx->author, tmp4);
		mfx->author = tmp4;
	}
	ret = pkgmgr_parser_insert_manifest_info_in_db(mfx);
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
	if (!handle) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	manifest_x *mfx = NULL;
	mfx = (manifest_x *)handle;
	pkgmgr_parser_free_manifest_xml(mfx);
	return PMINFO_R_OK;
}

API int pkgmgrinfo_datacontrol_get_info(const char *providerid, const char * type, char **appid, char **access)
{
	if (providerid == NULL) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (type == NULL) {
		_LOGE("Argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (appid == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}
	if (access == NULL) {
		_LOGE("Argument supplied to hold return value is NULL\n");
		return PMINFO_R_EINVAL;
	}

	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message = NULL;
	pkgmgr_datacontrol_x *data = NULL;

	ret = __open_datacontrol_db();
	if (ret == -1) {
		_LOGE("Fail to open datacontrol DB\n");
		return PMINFO_R_ERROR;
	}

	data = (pkgmgr_datacontrol_x *)calloc(1, sizeof(pkgmgr_datacontrol_x));
	if (data == NULL) {
		_LOGE("Failed to allocate memory for pkgmgr_datacontrol_x\n");
		sqlite3_close(datacontrol_db);
		return PMINFO_R_ERROR;
	}

	snprintf(query, MAX_QUERY_LEN, 
		"select appinfo.package_name, datacontrol.access from appinfo, datacontrol where datacontrol.id=appinfo.unique_id and datacontrol.provider_id = '%s' and datacontrol.type='%s' COLLATE NOCASE",
		providerid, type);

	if (SQLITE_OK !=
		sqlite3_exec(datacontrol_db, query, __datacontrol_cb, (void *)data, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
			   error_message);
		sqlite3_free(error_message);
		sqlite3_close(datacontrol_db);
		return PMINFO_R_ERROR;
	}

	*appid = (char *)data->appid;
	*access = (char *)data->access;
	free(data);
	sqlite3_close(datacontrol_db);

	return PMINFO_R_OK;
}
