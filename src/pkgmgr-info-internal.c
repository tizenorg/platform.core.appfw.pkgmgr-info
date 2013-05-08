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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "pkgmgr-info.h"
#include "pkgmgr-info-internal.h"

struct _pkginfo_str_map_t {
	pkgmgrinfo_pkginfo_filter_prop_str prop;
	const char *property;
};

static struct _pkginfo_str_map_t pkginfo_str_prop_map[] = {
	{E_PMINFO_PKGINFO_PROP_PACKAGE_ID,		PMINFO_PKGINFO_PROP_PACKAGE_ID},
	{E_PMINFO_PKGINFO_PROP_PACKAGE_TYPE, 		PMINFO_PKGINFO_PROP_PACKAGE_TYPE},
	{E_PMINFO_PKGINFO_PROP_PACKAGE_VERSION, 	PMINFO_PKGINFO_PROP_PACKAGE_VERSION},
	{E_PMINFO_PKGINFO_PROP_PACKAGE_INSTALL_LOCATION,PMINFO_PKGINFO_PROP_PACKAGE_INSTALL_LOCATION},
	{E_PMINFO_PKGINFO_PROP_PACKAGE_INSTALLED_STORAGE,PMINFO_PKGINFO_PROP_PACKAGE_INSTALLED_STORAGE},
	{E_PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_NAME, 	PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_NAME},
	{E_PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_EMAIL, 	PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_EMAIL},
	{E_PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_HREF, 	PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_HREF}
};

struct _pkginfo_int_map_t {
	pkgmgrinfo_pkginfo_filter_prop_int prop;
	const char *property;
};

static struct _pkginfo_int_map_t pkginfo_int_prop_map[] = {
	{E_PMINFO_PKGINFO_PROP_PACKAGE_SIZE,	PMINFO_PKGINFO_PROP_PACKAGE_SIZE}
};

struct _pkginfo_bool_map_t {
	pkgmgrinfo_pkginfo_filter_prop_bool prop;
	const char *property;
};

static struct _pkginfo_bool_map_t pkginfo_bool_prop_map[] = {
	{E_PMINFO_PKGINFO_PROP_PACKAGE_REMOVABLE,	PMINFO_PKGINFO_PROP_PACKAGE_REMOVABLE},
	{E_PMINFO_PKGINFO_PROP_PACKAGE_PRELOAD,		PMINFO_PKGINFO_PROP_PACKAGE_PRELOAD},
	{E_PMINFO_PKGINFO_PROP_PACKAGE_READONLY,	PMINFO_PKGINFO_PROP_PACKAGE_READONLY},
	{E_PMINFO_PKGINFO_PROP_PACKAGE_UPDATE,		PMINFO_PKGINFO_PROP_PACKAGE_UPDATE},
	{E_PMINFO_PKGINFO_PROP_PACKAGE_APPSETTING,	PMINFO_PKGINFO_PROP_PACKAGE_APPSETTING},
	{E_PMINFO_PKGINFO_PROP_PACKAGE_NODISPLAY_SETTING,	PMINFO_PKGINFO_PROP_PACKAGE_NODISPLAY_SETTING}
};

struct _appinfo_str_map_t {
	pkgmgrinfo_appinfo_filter_prop_str prop;
	const char *property;
};

static struct _appinfo_str_map_t appinfo_str_prop_map[] = {
	{E_PMINFO_APPINFO_PROP_APP_ID,		PMINFO_APPINFO_PROP_APP_ID},
	{E_PMINFO_APPINFO_PROP_APP_COMPONENT,	PMINFO_APPINFO_PROP_APP_COMPONENT},
	{E_PMINFO_APPINFO_PROP_APP_EXEC, 	PMINFO_APPINFO_PROP_APP_EXEC},
	{E_PMINFO_APPINFO_PROP_APP_ICON, 	PMINFO_APPINFO_PROP_APP_ICON},
	{E_PMINFO_APPINFO_PROP_APP_TYPE, 	PMINFO_APPINFO_PROP_APP_TYPE},
	{E_PMINFO_APPINFO_PROP_APP_OPERATION, 	PMINFO_APPINFO_PROP_APP_OPERATION},
	{E_PMINFO_APPINFO_PROP_APP_URI, 	PMINFO_APPINFO_PROP_APP_URI},
	{E_PMINFO_APPINFO_PROP_APP_MIME, 	PMINFO_APPINFO_PROP_APP_MIME},
	{E_PMINFO_APPINFO_PROP_APP_CATEGORY, 	PMINFO_APPINFO_PROP_APP_CATEGORY},
	{E_PMINFO_APPINFO_PROP_APP_HWACCELERATION,	PMINFO_APPINFO_PROP_APP_HWACCELERATION}
};

struct _appinfo_int_map_t {
	pkgmgrinfo_appinfo_filter_prop_int prop;
	const char *property;
};

static struct _appinfo_int_map_t appinfo_int_prop_map[] = {
	/*Currently No Fields*/
};

struct _appinfo_bool_map_t {
	pkgmgrinfo_appinfo_filter_prop_bool prop;
	const char *property;
};

static struct _appinfo_bool_map_t appinfo_bool_prop_map[] = {
	{E_PMINFO_APPINFO_PROP_APP_NODISPLAY,		PMINFO_APPINFO_PROP_APP_NODISPLAY},
	{E_PMINFO_APPINFO_PROP_APP_MULTIPLE,		PMINFO_APPINFO_PROP_APP_MULTIPLE},
	{E_PMINFO_APPINFO_PROP_APP_ONBOOT,		PMINFO_APPINFO_PROP_APP_ONBOOT},
	{E_PMINFO_APPINFO_PROP_APP_AUTORESTART,		PMINFO_APPINFO_PROP_APP_AUTORESTART},
	{E_PMINFO_APPINFO_PROP_APP_TASKMANAGE,		PMINFO_APPINFO_PROP_APP_TASKMANAGE},
	{E_PMINFO_APPINFO_PROP_APP_LAUNCHCONDITION,		PMINFO_APPINFO_PROP_APP_LAUNCHCONDITION}
};

inline pkgmgrinfo_pkginfo_filter_prop_str _pminfo_pkginfo_convert_to_prop_str(const char *property)
{
	int i = 0;
	int max = 0;
	pkgmgrinfo_pkginfo_filter_prop_str prop = -1;

	if (property == NULL)
		return -1;
	max = E_PMINFO_PKGINFO_PROP_PACKAGE_MAX_STR - E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_STR + 1;
	for (i = 0 ; i < max; i++) {
		if (strcmp(property, pkginfo_str_prop_map[i].property) == 0) {
			prop =	pkginfo_str_prop_map[i].prop;
			break;
		}
	}
	return prop;
}

inline pkgmgrinfo_pkginfo_filter_prop_int _pminfo_pkginfo_convert_to_prop_int(const char *property)
{
	int i = 0;
	int max = 0;
	pkgmgrinfo_pkginfo_filter_prop_int prop = -1;

	if (property == NULL)
		return -1;
	max = E_PMINFO_PKGINFO_PROP_PACKAGE_MAX_INT - E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_INT + 1;
	for (i = 0 ; i < max; i++) {
		if (strcmp(property, pkginfo_int_prop_map[i].property) == 0) {
			prop =	pkginfo_int_prop_map[i].prop;
			break;
		}
	}
	return prop;
}

inline pkgmgrinfo_pkginfo_filter_prop_bool _pminfo_pkginfo_convert_to_prop_bool(const char *property)
{
	int i = 0;
	int max = 0;
	pkgmgrinfo_pkginfo_filter_prop_bool prop = -1;

	if (property == NULL)
		return -1;
	max = E_PMINFO_PKGINFO_PROP_PACKAGE_MAX_BOOL - E_PMINFO_PKGINFO_PROP_PACKAGE_MIN_BOOL + 1;
	for (i = 0 ; i < max; i++) {
		if (strcmp(property, pkginfo_bool_prop_map[i].property) == 0) {
			prop =	pkginfo_bool_prop_map[i].prop;
			break;
		}
	}
	return prop;
}

inline pkgmgrinfo_appinfo_filter_prop_str _pminfo_appinfo_convert_to_prop_str(const char *property)
{
	int i = 0;
	int max = 0;
	pkgmgrinfo_appinfo_filter_prop_str prop = -1;

	if (property == NULL)
		return -1;
	max = E_PMINFO_APPINFO_PROP_APP_MAX_STR - E_PMINFO_APPINFO_PROP_APP_MIN_STR + 1;
	for (i = 0 ; i < max; i++) {
		if (strcmp(property, appinfo_str_prop_map[i].property) == 0) {
			prop =	appinfo_str_prop_map[i].prop;
			break;
		}
	}
	return prop;
}

inline pkgmgrinfo_appinfo_filter_prop_int _pminfo_appinfo_convert_to_prop_int(const char *property)
{
	int i = 0;
	int max = 0;
	pkgmgrinfo_appinfo_filter_prop_int prop = -1;

	if (property == NULL)
		return -1;
	max = E_PMINFO_APPINFO_PROP_APP_MAX_INT - E_PMINFO_APPINFO_PROP_APP_MIN_INT + 1;
	for (i = 0 ; i < max; i++) {
		if (strcmp(property, appinfo_int_prop_map[i].property) == 0) {
			prop =	appinfo_int_prop_map[i].prop;
			break;
		}
	}
	return prop;
}

inline pkgmgrinfo_appinfo_filter_prop_bool _pminfo_appinfo_convert_to_prop_bool(const char *property)
{
	int i = 0;
	int max = 0;
	pkgmgrinfo_appinfo_filter_prop_bool prop = -1;

	if (property == NULL)
		return -1;
	max = E_PMINFO_APPINFO_PROP_APP_MAX_BOOL - E_PMINFO_APPINFO_PROP_APP_MIN_BOOL + 1;
	for (i = 0 ; i < max; i++) {
		if (strcmp(property, appinfo_bool_prop_map[i].property) == 0) {
			prop =	appinfo_bool_prop_map[i].prop;
			break;
		}
	}
	return prop;
}
