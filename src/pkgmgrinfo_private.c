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
#include <ctype.h>

#include <vconf.h>
#include <sqlite3.h>
#include <glib.h>

#include "pkgmgr-info.h"
#include "pkgmgrinfo_debug.h"
#include "pkgmgrinfo_private.h"
#include "pkgmgr_parser.h"

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
	{E_PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_HREF, 	PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_HREF},
	{E_PMINFO_PKGINFO_PROP_PACKAGE_PRIVILEGE,	PMINFO_PKGINFO_PROP_PACKAGE_PRIVILEGE}
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
	{E_PMINFO_APPINFO_PROP_APP_HWACCELERATION,	PMINFO_APPINFO_PROP_APP_HWACCELERATION},
	{E_PMINFO_APPINFO_PROP_APP_SCREENREADER,	PMINFO_APPINFO_PROP_APP_SCREENREADER},
	{E_PMINFO_APPINFO_PROP_APP_METADATA_KEY,	PMINFO_APPINFO_PROP_APP_METADATA_KEY},
	{E_PMINFO_APPINFO_PROP_APP_METADATA_VALUE,	PMINFO_APPINFO_PROP_APP_METADATA_VALUE},
	{E_PMINFO_APPINFO_PROP_APP_PACKAGE,	PMINFO_APPINFO_PROP_APP_PACKAGE}
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
	{E_PMINFO_APPINFO_PROP_APP_LAUNCHCONDITION,		PMINFO_APPINFO_PROP_APP_LAUNCHCONDITION},
	{E_PMINFO_APPINFO_PROP_APP_UI_GADGET,		PMINFO_APPINFO_PROP_APP_UI_GADGET},
	{E_PMINFO_APPINFO_PROP_APP_SUPPORT_DISABLE,		PMINFO_APPINFO_PROP_APP_SUPPORT_DISABLE}
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

void __get_filter_condition(gpointer data, char **condition)
{
	pkgmgrinfo_node_x *node = (pkgmgrinfo_node_x*)data;
	char buf[MAX_QUERY_LEN] = {'\0'};
	char temp[PKG_STRING_LEN_MAX] = {'\0'};
	switch (node->prop) {
	case E_PMINFO_PKGINFO_PROP_PACKAGE_ID:
		snprintf(buf, sizeof(buf), "package_info.package='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_TYPE:
		snprintf(buf, sizeof(buf), "package_info.package_type='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_VERSION:
		snprintf(buf, sizeof(buf), "package_info.package_version='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_INSTALL_LOCATION:
		snprintf(buf, sizeof(buf), "package_info.install_location='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_INSTALLED_STORAGE:
		snprintf(buf, sizeof(buf), "package_info.installed_storage='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_NAME:
		snprintf(buf, sizeof(buf), "package_info.author_name='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_HREF:
		snprintf(buf, sizeof(buf), "package_info.author_href='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_AUTHOR_EMAIL:
		snprintf(buf, sizeof(buf), "package_info.author_email='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_PRIVILEGE:
		snprintf(buf, sizeof(buf), "package_privilege_info.privilege='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_SIZE:
		snprintf(buf, sizeof(buf), "package_info.package_size='%s'", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_REMOVABLE:
		snprintf(buf, sizeof(buf), "package_info.package_removable IN %s", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_PRELOAD:
		snprintf(buf, sizeof(buf), "package_info.package_preload IN %s", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_READONLY:
		snprintf(buf, sizeof(buf), "package_info.package_readonly IN %s", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_UPDATE:
		snprintf(buf, sizeof(buf), "package_info.package_update IN %s", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_APPSETTING:
		snprintf(buf, sizeof(buf), "package_info.package_appsetting IN %s", node->value);
		break;
	case E_PMINFO_PKGINFO_PROP_PACKAGE_NODISPLAY_SETTING:
		snprintf(buf, sizeof(buf), "package_info.package_nodisplay IN %s", node->value);
		break;

	case E_PMINFO_APPINFO_PROP_APP_ID:
		snprintf(buf, sizeof(buf), "package_app_info.app_id='%s'", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_COMPONENT:
		snprintf(buf, sizeof(buf), "package_app_info.app_component='%s'", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_EXEC:
		snprintf(buf, sizeof(buf), "package_app_info.app_exec='%s'", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_ICON:
		snprintf(buf, sizeof(buf), "package_app_localized_info.app_icon='%s'", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_TYPE:
		snprintf(buf, sizeof(buf), "package_app_info.app_type='%s'", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_OPERATION:
		snprintf(temp, sizeof(temp), "(%s)", node->value);
		snprintf(buf, sizeof(buf), "package_app_app_svc.operation IN %s", temp);
		break;
	case E_PMINFO_APPINFO_PROP_APP_URI:
		snprintf(temp, sizeof(temp), "(%s)", node->value);
		snprintf(buf, sizeof(buf), "package_app_app_svc.uri_scheme IN %s", temp);
		break;
	case E_PMINFO_APPINFO_PROP_APP_MIME:
		snprintf(temp, sizeof(temp), "(%s)", node->value);
		snprintf(buf, sizeof(buf), "package_app_app_svc.mime_type IN %s", temp);
		break;
	case E_PMINFO_APPINFO_PROP_APP_CATEGORY:
		snprintf(temp, sizeof(temp), "(%s)", node->value);
		snprintf(buf, sizeof(buf), "package_app_app_category.category IN %s", temp);
		break;
	case E_PMINFO_APPINFO_PROP_APP_NODISPLAY:
		snprintf(buf, sizeof(buf), "package_app_info.app_nodisplay IN %s", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_MULTIPLE:
		snprintf(buf, sizeof(buf), "package_app_info.app_multiple IN %s", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_ONBOOT:
		snprintf(buf, sizeof(buf), "package_app_info.app_onboot IN %s", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_AUTORESTART:
		snprintf(buf, sizeof(buf), "package_app_info.app_autorestart IN %s", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_TASKMANAGE:
		snprintf(buf, sizeof(buf), "package_app_info.app_taskmanage IN %s", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_HWACCELERATION:
		snprintf(buf, sizeof(buf), "package_app_info.app_hwacceleration='%s'", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_SCREENREADER:
		snprintf(buf, sizeof(buf), "package_app_info.app_screenreader='%s'", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_LAUNCHCONDITION:
		snprintf(buf, sizeof(buf), "package_app_info.app_launchcondition IN %s", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_PACKAGE:
		snprintf(buf, sizeof(buf), "package_app_info.package='%s'", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_UI_GADGET:
		snprintf(buf, sizeof(buf), "package_app_info.app_ui_gadget IN %s", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_METADATA_KEY:
		snprintf(buf, sizeof(buf), "package_app_app_metadata.md_key='%s'", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_METADATA_VALUE:
		snprintf(buf, sizeof(buf), "package_app_app_metadata.md_value='%s'", node->value);
		break;
	case E_PMINFO_APPINFO_PROP_APP_SUPPORT_DISABLE:
		snprintf(buf, MAX_QUERY_LEN, "package_app_info.app_support_disable IN %s", node->value);
		break;
	default:
		_LOGE("Invalid Property Type\n");
		*condition = NULL;
		return;
	}
	*condition = strdup(buf);
	return;
}

char *_get_system_locale(void)
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

	locale = malloc(sizeof(char) * 6);
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

