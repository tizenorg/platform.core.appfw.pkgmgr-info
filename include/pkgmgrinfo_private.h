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


#ifndef __PKGMGRINFO_PRIVATE_H__
#define __PKGMGRINFO_PRIVATE_H__

#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>

#include <sqlite3.h>
#include <glib.h>
#include <tzplatform_config.h>

#include "pkgmgrinfo_type.h"
#include "pkgmgrinfo_basic.h"

#ifndef DEPRECATED
#define DEPRECATED	__attribute__ ((__deprecated__))
#endif

#ifndef API
#define API __attribute__ ((visibility("default")))
#endif

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
#define PKG_TYPE_STRING_LEN_MAX		128
#define PKG_VERSION_STRING_LEN_MAX	128
#define PKG_VALUE_STRING_LEN_MAX		512
#define PKG_RW_PATH tzplatform_mkpath(TZ_USER_APP, "")
#define PKG_RO_PATH tzplatform_mkpath(TZ_SYS_RO_APP, "")
#define BLOCK_SIZE      4096 /*in bytes*/
#define BUFSIZE 4096
#define ROOT_UID 0

#define PKG_SD_PATH tzplatform_mkpath3(TZ_SYS_STORAGE, "sdcard", "app2sd/")
#define PKG_INSTALLATION_PATH tzplatform_mkpath(TZ_USER_APP, "")

#define SERVICE_NAME "org.tizen.system.deviced"
#define PATH_NAME "/Org/Tizen/System/DeviceD/Mmc"
#define INTERFACE_NAME "org.tizen.system.deviced.Mmc"
#define METHOD_NAME "RequestMountApp2ext"

#define GET_DB(X)  (X).dbHandle

/*String properties for filtering based on package info*/
typedef enum _pkgmgrinfo_pkginfo_filter_prop_str {
	E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_STR = 101,
	E_PMINFO_PKGINFO_PROP_PACKAGE_ID = E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_STR,
	E_PMINFO_PKGINFO_PROP_PACKAGE_TYPE,
	E_PMINFO_PKGINFO_PROP_PACKAGE_VERSION,
	E_PMINFO_PKGINFO_PROP_PACKAGE_INSTALL_LOCATION,
	E_PMINFO_PKGINFO_PROP_PACKAGE_INSTALLED_STORAGE,
	E_PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_NAME,
	E_PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_EMAIL,
	E_PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_HREF,
	E_PMINFO_PKGINFO_PROP_PACKAGE_PRIVILEGE,
	E_PMINFO_PKGINFO_PROP_PACKAGE_MAX_STR = E_PMINFO_PKGINFO_PROP_PACKAGE_PRIVILEGE
} pkgmgrinfo_pkginfo_filter_prop_str;

/*Boolean properties for filtering based on package info*/
typedef enum _pkgmgrinfo_pkginfo_filter_prop_bool {
	E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_BOOL = 201,
	E_PMINFO_PKGINFO_PROP_PACKAGE_REMOVABLE = E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_BOOL,
	E_PMINFO_PKGINFO_PROP_PACKAGE_PRELOAD,
	E_PMINFO_PKGINFO_PROP_PACKAGE_READONLY,
	E_PMINFO_PKGINFO_PROP_PACKAGE_UPDATE,
	E_PMINFO_PKGINFO_PROP_PACKAGE_APPSETTING,
	E_PMINFO_PKGINFO_PROP_PACKAGE_NODISPLAY_SETTING,
	E_PMINFO_PKGINFO_PROP_PACKAGE_MAX_BOOL = E_PMINFO_PKGINFO_PROP_PACKAGE_NODISPLAY_SETTING
} pkgmgrinfo_pkginfo_filter_prop_bool;

/*Integer properties for filtering based on package info*/
typedef enum _pkgmgrinfo_pkginfo_filter_prop_int {
	E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_INT = 301,
	E_PMINFO_PKGINFO_PROP_PACKAGE_SIZE = E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_INT,
	E_PMINFO_PKGINFO_PROP_PACKAGE_MAX_INT = E_PMINFO_PKGINFO_PROP_PACKAGE_SIZE
} pkgmgrinfo_pkginfo_filter_prop_int;

/*String properties for filtering based on app info*/
typedef enum _pkgmgrinfo_appinfo_filter_prop_str {
	E_PMINFO_APPINFO_PROP_APP_MIN_STR = 401,
	E_PMINFO_APPINFO_PROP_APP_ID = E_PMINFO_APPINFO_PROP_APP_MIN_STR,
	E_PMINFO_APPINFO_PROP_APP_COMPONENT,
	E_PMINFO_APPINFO_PROP_APP_EXEC,
	E_PMINFO_APPINFO_PROP_APP_ICON,
	E_PMINFO_APPINFO_PROP_APP_TYPE,
	E_PMINFO_APPINFO_PROP_APP_OPERATION,
	E_PMINFO_APPINFO_PROP_APP_URI,
	E_PMINFO_APPINFO_PROP_APP_MIME,
	E_PMINFO_APPINFO_PROP_APP_HWACCELERATION,
	E_PMINFO_APPINFO_PROP_APP_CATEGORY,
	E_PMINFO_APPINFO_PROP_APP_SCREENREADER,
	E_PMINFO_APPINFO_PROP_APP_PACKAGE,
	E_PMINFO_APPINFO_PROP_APP_MAX_STR = E_PMINFO_APPINFO_PROP_APP_PACKAGE
} pkgmgrinfo_appinfo_filter_prop_str;

/*Boolean properties for filtering based on app info*/
typedef enum _pkgmgrinfo_appinfo_filter_prop_bool {
	E_PMINFO_APPINFO_PROP_APP_MIN_BOOL = 501,
	E_PMINFO_APPINFO_PROP_APP_NODISPLAY = E_PMINFO_APPINFO_PROP_APP_MIN_BOOL,
	E_PMINFO_APPINFO_PROP_APP_MULTIPLE,
	E_PMINFO_APPINFO_PROP_APP_ONBOOT,
	E_PMINFO_APPINFO_PROP_APP_AUTORESTART,
	E_PMINFO_APPINFO_PROP_APP_TASKMANAGE,
	E_PMINFO_APPINFO_PROP_APP_LAUNCHCONDITION,
	E_PMINFO_APPINFO_PROP_APP_UI_GADGET,
	E_PMINFO_APPINFO_PROP_APP_SUPPORT_DISABLE,
	E_PMINFO_APPINFO_PROP_APP_MAX_BOOL = E_PMINFO_APPINFO_PROP_APP_SUPPORT_DISABLE
} pkgmgrinfo_appinfo_filter_prop_bool;

/*Integer properties for filtering based on app info*/
typedef enum _pkgmgrinfo_appinfo_filter_prop_int {
	/*Currently No Fields*/
	E_PMINFO_APPINFO_PROP_APP_MIN_INT = 601,
	E_PMINFO_APPINFO_PROP_APP_MAX_INT = E_PMINFO_APPINFO_PROP_APP_MIN_INT
} pkgmgrinfo_appinfo_filter_prop_int;

/*Integer properties for filtering based on app info*/
typedef enum _pkgmgrinfo_pkginfo_filter_prop_range {
	/*Currently No Fields*/
	E_PMINFO_PKGINFO_PROP_RANGE_MIN_INT = 701,
	E_PMINFO_PKGINFO_PROP_RANGE_BASIC,
	E_PMINFO_PKGINFO_PROP_RANGE_MAX_INT = E_PMINFO_PKGINFO_PROP_RANGE_BASIC
} pkgmgrinfo_pkginfo_filter_prop_range;

typedef struct _pkgmgr_pkginfo_x {
	uid_t uid;
	package_x *pkg_info;
	char *locale;

	struct _pkgmgr_pkginfo_x *prev;
	struct _pkgmgr_pkginfo_x *next;
} pkgmgr_pkginfo_x;

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

extern __thread db_handle manifest_db;
extern __thread db_handle cert_db;

pkgmgrinfo_pkginfo_filter_prop_str _pminfo_pkginfo_convert_to_prop_str(const char *property);
pkgmgrinfo_pkginfo_filter_prop_int _pminfo_pkginfo_convert_to_prop_int(const char *property);
pkgmgrinfo_pkginfo_filter_prop_bool _pminfo_pkginfo_convert_to_prop_bool(const char *property);

pkgmgrinfo_appinfo_filter_prop_str _pminfo_appinfo_convert_to_prop_str(const char *property);
pkgmgrinfo_appinfo_filter_prop_int _pminfo_appinfo_convert_to_prop_int(const char *property);
pkgmgrinfo_appinfo_filter_prop_bool _pminfo_appinfo_convert_to_prop_bool(const char *property);

pkgmgrinfo_pkginfo_filter_prop_range _pminfo_pkginfo_convert_to_prop_range(const char *property);

int _check_create_cert_db(sqlite3 *certdb);
int __close_manifest_db(void);
int __open_manifest_db(uid_t uid, bool readonly);
int __close_cert_db(void);
int __open_cert_db(uid_t uid, bool readonly);
void _save_column_str(sqlite3_stmt *stmt, int idx, const char **str);
char *_get_system_locale(void);
void __get_filter_condition(gpointer data, char **condition);

#endif  /* __PKGMGRINFO_PRIVATE_H__ */
