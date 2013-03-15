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


#ifndef __PKGMGR_INFO_INTERNAL_H__
#define __PKGMGR_INFO_INTERNAL_H__

#include <dlog.h>
#include "pkgmgr-info-debug.h"

#ifndef DEPRECATED
#define DEPRECATED	__attribute__ ((__deprecated__))
#endif

#ifndef API
#define API __attribute__ ((visibility("default")))
#endif

/*String properties for filtering based on package info*/
typedef enum _pkgmgrinfo_pkginfo_filter_prop_str {
	E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_STR = 101,
	E_PMINFO_PKGINFO_PROP_PACKAGE_ID = E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_STR,
	E_PMINFO_PKGINFO_PROP_PACKAGE_TYPE,
	E_PMINFO_PKGINFO_PROP_PACKAGE_VERSION,
	E_PMINFO_PKGINFO_PROP_PACKAGE_INSTALL_LOCATION,
	E_PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_NAME,
	E_PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_EMAIL,
	E_PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_HREF,
	E_PMINFO_PKGINFO_PROP_PACKAGE_MAX_STR = E_PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_HREF
} pkgmgrinfo_pkginfo_filter_prop_str;

/*Boolean properties for filtering based on package info*/
typedef enum _pkgmgrinfo_pkginfo_filter_prop_bool {
	E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_BOOL = 201,
	E_PMINFO_PKGINFO_PROP_PACKAGE_REMOVABLE = E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_BOOL,
	E_PMINFO_PKGINFO_PROP_PACKAGE_PRELOAD,
	E_PMINFO_PKGINFO_PROP_PACKAGE_READONLY,
	E_PMINFO_PKGINFO_PROP_PACKAGE_MAX_BOOL = E_PMINFO_PKGINFO_PROP_PACKAGE_READONLY
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
	E_PMINFO_APPINFO_PROP_APP_MAX_STR = E_PMINFO_APPINFO_PROP_APP_CATEGORY
} pkgmgrinfo_appinfo_filter_prop_str;

/*Boolean properties for filtering based on app info*/
typedef enum _pkgmgrinfo_appinfo_filter_prop_bool {
	E_PMINFO_APPINFO_PROP_APP_MIN_BOOL = 501,
	E_PMINFO_APPINFO_PROP_APP_NODISPLAY = E_PMINFO_APPINFO_PROP_APP_MIN_BOOL,
	E_PMINFO_APPINFO_PROP_APP_MULTIPLE,
	E_PMINFO_APPINFO_PROP_APP_ONBOOT,
	E_PMINFO_APPINFO_PROP_APP_AUTORESTART,
	E_PMINFO_APPINFO_PROP_APP_TASKMANAGE,
	E_PMINFO_APPINFO_PROP_APP_MAX_BOOL = E_PMINFO_APPINFO_PROP_APP_TASKMANAGE
} pkgmgrinfo_appinfo_filter_prop_bool;

/*Integer properties for filtering based on app info*/
typedef enum _pkgmgrinfo_appinfo_filter_prop_int {
	/*Currently No Fields*/
	E_PMINFO_APPINFO_PROP_APP_MIN_INT = 601,
	E_PMINFO_APPINFO_PROP_APP_MAX_INT = E_PMINFO_APPINFO_PROP_APP_MIN_INT
} pkgmgrinfo_appinfo_filter_prop_int;

pkgmgrinfo_pkginfo_filter_prop_str _pminfo_pkginfo_convert_to_prop_str(const char *property);
pkgmgrinfo_pkginfo_filter_prop_int _pminfo_pkginfo_convert_to_prop_int(const char *property);
pkgmgrinfo_pkginfo_filter_prop_bool _pminfo_pkginfo_convert_to_prop_bool(const char *property);

pkgmgrinfo_appinfo_filter_prop_str _pminfo_appinfo_convert_to_prop_str(const char *property);
pkgmgrinfo_appinfo_filter_prop_int _pminfo_appinfo_convert_to_prop_int(const char *property);
pkgmgrinfo_appinfo_filter_prop_bool _pminfo_appinfo_convert_to_prop_bool(const char *property);

#endif  /* __PKGMGR_INFO_INTERNAL_H__ */
