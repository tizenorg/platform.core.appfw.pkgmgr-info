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
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlschemas.h>
#include <vconf.h>
#include <glib.h>
#include <grp.h>

#include "pkgmgr_parser.h"
#include "pkgmgr_parser_internal.h"
#include "pkgmgr_parser_db.h"
#include "pkgmgr-info.h"
#include "pkgmgr_parser_signature.h"
#include "pkgmgr-info-debug.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "PKGMGR_PARSER"

#define ASCII(s) (const char *)s
#define XMLCHAR(s) (const xmlChar *)s

//#define METADATA_PARSER_LIST SYSCONFDIR "/package-manager/parserlib/metadata/metadata_parser_list.txt"
#define METADATA_PARSER_LIST SYSCONFDIR "/package-manager/parserlib/metadata/mdparser_list.txt"
#define METADATA_PARSER_NAME	"metadataparser:"

#define CATEGORY_PARSER_LIST SYSCONFDIR "/package-manager/parserlib/category/category_parser_list.txt"
#define CATEGORY_PARSER_NAME	"categoryparser:"

#define TAG_PARSER_LIST SYSCONFDIR "/package-manager/parserlib/tag_parser_list.txt"
#define TAG_PARSER_NAME	"parserlib:"

#define PKG_TAG_LEN_MAX 128
#define OWNER_ROOT 0
#define BUFSIZE 4096
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

/* operation_type */
typedef enum {
	ACTION_INSTALL = 0,
	ACTION_UPGRADE,
	ACTION_UNINSTALL,
	ACTION_FOTA,
	ACTION_MAX
} ACTION_TYPE;

/* plugin process_type */
typedef enum {
	PLUGIN_PRE_PROCESS = 0,
	PLUGIN_POST_PROCESS
} PLUGIN_PROCESS_TYPE;

typedef struct {
	const char *key;
	const char *value;
} __metadata_t;

typedef struct {
	const char *name;
} __category_t;

const char *package;

static int __ps_process_label(xmlTextReaderPtr reader, label_x *label);
static int __ps_process_privilege(xmlTextReaderPtr reader, privilege_x *privilege);
static int __ps_process_privileges(xmlTextReaderPtr reader, privileges_x *privileges);
static int __ps_process_deviceprofile(xmlTextReaderPtr reader, deviceprofile_x *deviceprofile);
static int __ps_process_allowed(xmlTextReaderPtr reader, allowed_x *allowed);
static int __ps_process_operation(xmlTextReaderPtr reader, operation_x *operation);
static int __ps_process_uri(xmlTextReaderPtr reader, uri_x *uri);
static int __ps_process_mime(xmlTextReaderPtr reader, mime_x *mime);
static int __ps_process_subapp(xmlTextReaderPtr reader, subapp_x *subapp);
static int __ps_process_condition(xmlTextReaderPtr reader, condition_x *condition);
static int __ps_process_notification(xmlTextReaderPtr reader, notification_x *notifiation);
static int __ps_process_category(xmlTextReaderPtr reader, category_x *category);
static int __ps_process_metadata(xmlTextReaderPtr reader, metadata_x *metadata);
static int __ps_process_permission(xmlTextReaderPtr reader, permission_x *permission);
static int __ps_process_compatibility(xmlTextReaderPtr reader, compatibility_x *compatibility);
static int __ps_process_resolution(xmlTextReaderPtr reader, resolution_x *resolution);
static int __ps_process_request(xmlTextReaderPtr reader, request_x *request);
static int __ps_process_define(xmlTextReaderPtr reader, define_x *define);
static int __ps_process_appsvc(xmlTextReaderPtr reader, appsvc_x *appsvc);
static int __ps_process_launchconditions(xmlTextReaderPtr reader, launchconditions_x *launchconditions);
static int __ps_process_datashare(xmlTextReaderPtr reader, datashare_x *datashare);
static int __ps_process_icon(xmlTextReaderPtr reader, icon_x *icon, uid_t uid);
static int __ps_process_author(xmlTextReaderPtr reader, author_x *author);
static int __ps_process_description(xmlTextReaderPtr reader, description_x *description);
static int __ps_process_capability(xmlTextReaderPtr reader, capability_x *capability);
static int __ps_process_license(xmlTextReaderPtr reader, license_x *license);
static int __ps_process_appcontrol(xmlTextReaderPtr reader, appcontrol_x *appcontrol);
static int __ps_process_datacontrol(xmlTextReaderPtr reader, datacontrol_x *datacontrol);
static int __ps_process_uiapplication(xmlTextReaderPtr reader, uiapplication_x *uiapplication, uid_t uid);
static int __ps_process_serviceapplication(xmlTextReaderPtr reader, serviceapplication_x *serviceapplication, uid_t uid);
static int __ps_process_font(xmlTextReaderPtr reader, font_x *font);
static int __ps_process_theme(xmlTextReaderPtr reader, theme_x *theme);
static int __ps_process_daemon(xmlTextReaderPtr reader, daemon_x *daemon);
static int __ps_process_ime(xmlTextReaderPtr reader, ime_x *ime);
static void __ps_free_label(label_x *label);
static void __ps_free_privilege(privilege_x *privilege);
static void __ps_free_privileges(privileges_x *privileges);
static void __ps_free_deviceprofile(deviceprofile_x * deviceprofile);
static void __ps_free_allowed(allowed_x *allowed);
static void __ps_free_operation(operation_x *operation);
static void __ps_free_uri(uri_x *uri);
static void __ps_free_mime(mime_x *mime);
static void __ps_free_subapp(subapp_x *subapp);
static void __ps_free_condition(condition_x *condition);
static void __ps_free_notification(notification_x *notifiation);
static void __ps_free_category(category_x *category);
static void __ps_free_metadata(metadata_x *metadata);
static void __ps_free_permission(permission_x *permission);
static void __ps_free_compatibility(compatibility_x *compatibility);
static void __ps_free_resolution(resolution_x *resolution);
static void __ps_free_request(request_x *request);
static void __ps_free_define(define_x *define);
static void __ps_free_appsvc(appsvc_x *appsvc);
static void __ps_free_launchconditions(launchconditions_x *launchconditions);
static void __ps_free_datashare(datashare_x *datashare);
static void __ps_free_icon(icon_x *icon);
static void __ps_free_author(author_x *author);
static void __ps_free_description(description_x *description);
static void __ps_free_capability(capability_x *capability);
static void __ps_free_license(license_x *license);
static void __ps_free_appcontrol(appcontrol_x *appcontrol);
static void __ps_free_datacontrol(datacontrol_x *datacontrol);
static void __ps_free_uiapplication(uiapplication_x *uiapplication);
static void __ps_free_serviceapplication(serviceapplication_x *serviceapplication);
static void __ps_free_font(font_x *font);
static void __ps_free_theme(theme_x *theme);
static void __ps_free_daemon(daemon_x *daemon);
static void __ps_free_ime(ime_x *ime);
static char *__pkgid_to_manifest(const char *pkgid, uid_t uid);
static int __next_child_element(xmlTextReaderPtr reader, int depth);
static int __start_process(xmlTextReaderPtr reader, manifest_x * mfx, uid_t uid);
static int __process_manifest(xmlTextReaderPtr reader, manifest_x * mfx, uid_t uid);
static void __str_trim(char *input);
static char *__get_parser_plugin(const char *type);
static int __ps_run_parser(xmlDocPtr docPtr, const char *tag, ACTION_TYPE action, const char *pkgid);
static int __run_parser_prestep(xmlTextReaderPtr reader, ACTION_TYPE action, const char *pkgid);
static void __processNode(xmlTextReaderPtr reader, ACTION_TYPE action, char *const tagv[], const char *pkgid);
static void __streamFile(const char *filename, ACTION_TYPE action, char *const tagv[], const char *pkgid);
static int __validate_appid(const char *pkgid, const char *appid, char **newappid);
API int __is_admin();

void *__open_lib_handle(char *tag)
{
	char *lib_path = NULL;
	void *lib_handle = NULL;

	lib_path = __get_parser_plugin(tag);
	retvm_if(!lib_path, NULL, "lib_path get fail");

	lib_handle = dlopen(lib_path, RTLD_LAZY);
	retvm_if(lib_handle == NULL, NULL, "dlopen is failed lib_path[%s]", lib_path);

	return lib_handle;
}

void __close_lib_handle(void *lib_handle)
{
	dlclose(lib_handle);
}

static void __str_trim(char *input)
{
	char *trim_str = input;

	if (input == NULL)
		return;

	while (*input != 0) {
		if (!isspace(*input)) {
			*trim_str = *input;
			trim_str++;
		}
		input++;
	}

	*trim_str = 0;
	return;
}

API int __is_admin()
{
	uid_t uid = getuid();
	if ((uid_t) 0 == uid )
		return 1;
	else
		return 0;
}



static int __validate_appid(const char *pkgid, const char *appid, char **newappid)
{
	if (!pkgid || !appid || !newappid) {
		_LOGD("Arg supplied is NULL\n");
		return -1;
	}
	int pkglen = strlen(pkgid);
	int applen = strlen(appid);
	char *ptr = NULL;
	char *newapp = NULL;
	int len = 0;
	if (strncmp(appid, ".", 1) == 0) {
		len = pkglen + applen + 1;
		newapp = calloc(1,len);
		if (newapp == NULL) {
			_LOGD("Malloc failed\n");
			return -1;
		}
		strncpy(newapp, pkgid, pkglen);
		strncat(newapp, appid, applen);
		_LOGD("new appid is %s\n", newapp);
		*newappid = newapp;
		return 0;
	}
	if (applen < pkglen) {
		_LOGD("app id is not proper\n");
		*newappid = NULL;
#ifdef _VALIDATE_APPID_
		return -1;
#else
		return 0;
#endif
	}
	if (!strcmp(appid, pkgid)) {
		_LOGD("appid is proper\n");
		*newappid = NULL;
		return 0;
	}
	else if (strncmp(appid, pkgid, pkglen) == 0) {
		ptr = strstr(appid, pkgid);
		ptr = ptr + pkglen;
		if (strncmp(ptr, ".", 1) == 0) {
			_LOGD("appid is proper\n");
			*newappid = NULL;
			return 0;
		}
		else {
			_LOGD("appid is not proper\n");
			*newappid = NULL;
#ifdef _VALIDATE_APPID_
			return -1;
#else
			return 0;
#endif
		}
	} else {
		_LOGD("appid is not proper\n");
		*newappid = NULL;
#ifdef _VALIDATE_APPID_
		return -1;
#else
		return 0;
#endif
	}
	return 0;
}

static char * __get_tag_by_key(char *md_key)
{
	char *md_tag = NULL;

	if (md_key == NULL) {
		_LOGD("md_key is NULL\n");
		return NULL;
	}

	md_tag = strrchr(md_key, 47) + 1;


	return strdup(md_tag);
}

static char *__get_metadata_parser_plugin(const char *type)
{
	FILE *fp = NULL;
	char buffer[1024] = { 0 };
	char temp_path[1024] = { 0 };
	char *path = NULL;

	if (type == NULL) {
		_LOGE("invalid argument\n");
		return NULL;
	}

	fp = fopen(PKG_PARSER_CONF_PATH, "r");
	if (fp == NULL) {
		_LOGE("no matching metadata parser\n");
		return NULL;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (buffer[0] == '#')
			continue;

		__str_trim(buffer);

		if ((path = strstr(buffer, METADATA_PARSER_NAME)) != NULL) {
			path = path + strlen(METADATA_PARSER_NAME);

			break;
		}

		memset(buffer, 0x00, 1024);
	}

	if (fp != NULL)
		fclose(fp);

	if (path == NULL) {
		_LOGE("no matching [%s] [%s]\n", METADATA_PARSER_NAME,type);
		return NULL;
	}

	snprintf(temp_path, sizeof(temp_path) - 1, "%slib%s.so", path, type);

	return strdup(temp_path);
}

static char *__get_category_parser_plugin(const char *type)
{
	FILE *fp = NULL;
	char buffer[1024] = { 0 };
	char temp_path[1024] = { 0 };
	char *path = NULL;

	if (type == NULL) {
		_LOGE("invalid argument\n");
		return NULL;
	}

	fp = fopen(PKG_PARSER_CONF_PATH, "r");
	if (fp == NULL) {
		_LOGE("no matching metadata parser\n");
		return NULL;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (buffer[0] == '#')
			continue;

		__str_trim(buffer);

		if ((path = strstr(buffer, CATEGORY_PARSER_NAME)) != NULL) {
			path = path + strlen(CATEGORY_PARSER_NAME);

			break;
		}

		memset(buffer, 0x00, 1024);
	}

	if (fp != NULL)
		fclose(fp);

	if (path == NULL) {
		_LOGE("no matching [%s] [%s]\n", CATEGORY_PARSER_NAME,type);
		return NULL;
	}

	snprintf(temp_path, sizeof(temp_path) - 1, "%slib%s.so", path, type);

	return strdup(temp_path);
}

static char *__get_parser_plugin(const char *type)
{
	FILE *fp = NULL;
	char buffer[1024] = { 0 };
	char temp_path[1024] = { 0 };
	char *path = NULL;

	if (type == NULL) {
		_LOGE("invalid argument\n");
		return NULL;
	}

	fp = fopen(PKG_PARSER_CONF_PATH, "r");
	if (fp == NULL) {
		_LOGE("no matching backendlib\n");
		return NULL;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (buffer[0] == '#')
			continue;

		__str_trim(buffer);

		if ((path = strstr(buffer, PKG_PARSERLIB)) != NULL) {
			path = path + strlen(PKG_PARSERLIB);
			break;
		}

		memset(buffer, 0x00, 1024);
	}

	if (fp != NULL)
		fclose(fp);

	if (path == NULL) {
		_LOGE("no matching backendlib\n");
		return NULL;
	}

	snprintf(temp_path, sizeof(temp_path) - 1, "%slib%s.so", path, type);

	return strdup(temp_path);
}

static int __ps_run_tag_parser(void *lib_handle, xmlDocPtr docPtr, const char *tag,
			   ACTION_TYPE action, const char *pkgid)
{
	int (*plugin_install) (xmlDocPtr, const char *);
	int ret = -1;
	char *ac = NULL;

	switch (action) {
	case ACTION_INSTALL:
		ac = "PKGMGR_PARSER_PLUGIN_INSTALL";
		break;
	case ACTION_UPGRADE:
		ac = "PKGMGR_PARSER_PLUGIN_UPGRADE";
		break;
	case ACTION_UNINSTALL:
		ac = "PKGMGR_PARSER_PLUGIN_UNINSTALL";
		break;
	default:
		goto END;
	}

	if ((plugin_install =
		dlsym(lib_handle, ac)) == NULL || dlerror() != NULL) {
		_LOGE("can not find symbol[%s] \n", ac);
		goto END;
	}

	ret = plugin_install(docPtr, pkgid);
	_LOGD("tag parser[%s, %s] ACTION_TYPE[%d] result[%d]\n", pkgid, tag, action, ret);

END:
	return ret;
}

static int __ps_run_metadata_parser(GList *md_list, const char *tag,
				ACTION_TYPE action, const char *pkgid, const char *appid)
{
	char *lib_path = NULL;
	void *lib_handle = NULL;
	int (*metadata_parser_plugin) (const char *, const char *, GList *);
	int ret = -1;
	char *ac = NULL;

	switch (action) {
	case ACTION_INSTALL:
		ac = "PKGMGR_MDPARSER_PLUGIN_INSTALL";
		break;
	case ACTION_UPGRADE:
		ac = "PKGMGR_MDPARSER_PLUGIN_UPGRADE";
		break;
	case ACTION_UNINSTALL:
		ac = "PKGMGR_MDPARSER_PLUGIN_UNINSTALL";
		break;
	default:
		goto END;
	}

	lib_path = __get_metadata_parser_plugin(tag);
	if (!lib_path) {
		_LOGE("get %s parser fail\n", tag);
		goto END;
	}

	if ((lib_handle = dlopen(lib_path, RTLD_LAZY)) == NULL) {
		_LOGE("dlopen is failed lib_path[%s]\n", lib_path);
		goto END;
	}

	if ((metadata_parser_plugin =
		dlsym(lib_handle, ac)) == NULL || dlerror() != NULL) {
		_LOGE("can not find symbol[%s] \n",ac);
		goto END;
	}

	ret = metadata_parser_plugin(pkgid, appid, md_list);
	if (ret < 0)
		_LOGD("[appid = %s, libpath = %s plugin fail\n", appid, lib_path);
	else
		_LOGD("[appid = %s, libpath = %s plugin success\n", appid, lib_path);

END:
	if (lib_path)
		free(lib_path);
	if (lib_handle)
		dlclose(lib_handle);
	return ret;
}

static int __ps_run_category_parser(GList *category_list, const char *tag,
				ACTION_TYPE action, const char *pkgid, const char *appid)
{
	char *lib_path = NULL;
	void *lib_handle = NULL;
	int (*category_parser_plugin) (const char *, const char *, GList *);
	int ret = -1;
	char *ac = NULL;

	switch (action) {
	case ACTION_INSTALL:
		ac = "PKGMGR_CATEGORY_PARSER_PLUGIN_INSTALL";
		break;
	case ACTION_UPGRADE:
		ac = "PKGMGR_CATEGORY_PARSER_PLUGIN_UPGRADE";
		break;
	case ACTION_UNINSTALL:
		ac = "PKGMGR_CATEGORY_PARSER_PLUGIN_UNINSTALL";
		break;
	default:
		goto END;
	}

	lib_path = __get_category_parser_plugin(tag);
	if (!lib_path) {
		_LOGE("get %s parser fail\n", tag);
		goto END;
	}

	if ((lib_handle = dlopen(lib_path, RTLD_LAZY)) == NULL) {
		_LOGE("dlopen is failed lib_path[%s]\n", lib_path);
		goto END;
	}

	if ((category_parser_plugin =
		dlsym(lib_handle, ac)) == NULL || dlerror() != NULL) {
		_LOGE("can not find symbol[%s] \n",ac);
		goto END;
	}

	ret = category_parser_plugin(pkgid, appid, category_list);
	if (ret < 0)
		_LOGD("[appid = %s, libpath = %s plugin fail\n", appid, lib_path);
	else
		_LOGD("[appid = %s, libpath = %s plugin success\n", appid, lib_path);

END:
	if (lib_path)
		free(lib_path);
	if (lib_handle)
		dlclose(lib_handle);
	return ret;
}

static int __ps_run_parser(xmlDocPtr docPtr, const char *tag,
			   ACTION_TYPE action, const char *pkgid)
{
	char *lib_path = NULL;
	void *lib_handle = NULL;
	int (*plugin_install) (xmlDocPtr, const char *);
	int ret = -1;
	char *ac = NULL;

	switch (action) {
	case ACTION_INSTALL:
		ac = "PKGMGR_PARSER_PLUGIN_INSTALL";
		break;
	case ACTION_UPGRADE:
		ac = "PKGMGR_PARSER_PLUGIN_UPGRADE";
		break;
	case ACTION_UNINSTALL:
		ac = "PKGMGR_PARSER_PLUGIN_UNINSTALL";
		break;
	default:
		goto END;
	}

	lib_path = __get_parser_plugin(tag);
	if (!lib_path) {
		goto END;
	}

	if ((lib_handle = dlopen(lib_path, RTLD_LAZY)) == NULL) {
		_LOGE("dlopen is failed lib_path[%s]\n", lib_path);
		goto END;
	}
	if ((plugin_install =
		dlsym(lib_handle, ac)) == NULL || dlerror() != NULL) {
		_LOGE("can not find symbol[%s] \n", ac);
		goto END;
	}

	ret = plugin_install(docPtr, pkgid);
	if (ret < 0)
		_LOGD("[pkgid = %s, libpath = %s plugin fail\n", pkgid, lib_path);
	else
		_LOGD("[pkgid = %s, libpath = %s plugin success\n", pkgid, lib_path);

END:
	if (lib_path)
		free(lib_path);
	if (lib_handle)
		dlclose(lib_handle);
	return ret;
}

static char *__pkgid_to_manifest(const char *pkgid, uid_t uid)
{
	char *manifest;
	int size;

	if (pkgid == NULL) {
		_LOGE("pkgid is NULL");
		return NULL;
	}

	size = strlen(getUserManifestPath(uid)) + strlen(pkgid) + 10;
	manifest = malloc(size);
	if (manifest == NULL) {
		_LOGE("No memory");
		return NULL;
	}
	memset(manifest, '\0', size);
	snprintf(manifest, size, "%s%s.xml", getUserManifestPath(uid), pkgid);

	if (access(manifest, F_OK)) {
		snprintf(manifest, size, "%s%s.xml", getUserManifestPath(uid), pkgid);
	}

	return manifest;
}

static void __metadata_parser_clear_dir_list(GList* dir_list)
{
	GList *list = NULL;
	__metadata_t* detail = NULL;

	if (dir_list) {
		list = g_list_first(dir_list);
		while (list) {
			detail = (__metadata_t *)list->data;
			if (detail) {
				if (detail->key)
					free(detail->key);
				if (detail->value)
					free(detail->value);
				free(detail);
			}
			list = g_list_next(list);
		}
		g_list_free(dir_list);
	}
}

static void __category_parser_clear_dir_list(GList* dir_list)
{
	GList *list = NULL;
	__category_t* detail = NULL;

	if (dir_list) {
		list = g_list_first(dir_list);
		while (list) {
			detail = (__category_t *)list->data;
			if (detail) {
				if (detail->name)
					free(detail->name);

				free(detail);
			}
			list = g_list_next(list);
		}
		g_list_free(dir_list);
	}
}

static int __run_tag_parser_prestep(void *lib_handle, xmlTextReaderPtr reader, ACTION_TYPE action, const char *pkgid)
{
	int ret = -1;
	const xmlChar *name;

	if (xmlTextReaderDepth(reader) != 1) {
		_LOGE("Node depth is not 1");
		goto END;
	}

	if (xmlTextReaderNodeType(reader) != 1) {
		_LOGE("Node type is not 1");
		goto END;
	}

	const xmlChar *value;
	name = xmlTextReaderConstName(reader);
	if (name == NULL) {
		_LOGE("TEST TEST TES\n");
		name = BAD_CAST "--";
	}

	value = xmlTextReaderConstValue(reader);
	if (value != NULL) {
		if (xmlStrlen(value) > 40) {
			_LOGD(" %.40s...", value);
		} else {
			_LOGD(" %s", value);
		}
	}

	name = xmlTextReaderConstName(reader);
	if (name == NULL) {
		_LOGE("TEST TEST TES\n");
		name = BAD_CAST "--";
	}

	xmlDocPtr docPtr = xmlTextReaderCurrentDoc(reader);
	xmlDocPtr copyDocPtr = xmlCopyDoc(docPtr, 1);
	if (copyDocPtr == NULL)
		return -1;
	xmlNode *rootElement = xmlDocGetRootElement(copyDocPtr);
	if (rootElement == NULL)
		return -1;
	xmlNode *cur_node = xmlFirstElementChild(rootElement);
	if (cur_node == NULL)
		return -1;
	xmlNode *temp = xmlTextReaderExpand(reader);
	if (temp == NULL)
		return -1;
	xmlNode *next_node = NULL;
	while(cur_node != NULL) {
		if ( (strcmp(ASCII(temp->name), ASCII(cur_node->name)) == 0) &&
			(temp->line == cur_node->line) ) {
			break;
		}
		else {
			next_node = xmlNextElementSibling(cur_node);
			xmlUnlinkNode(cur_node);
			xmlFreeNode(cur_node);
			cur_node = next_node;
		}
	}
	if (cur_node == NULL)
		return -1;
	next_node = xmlNextElementSibling(cur_node);
	if (next_node) {
		cur_node->next = NULL;
		next_node->prev = NULL;
		xmlFreeNodeList(next_node);
		xmlSetTreeDoc(cur_node, copyDocPtr);
	} else {
		xmlSetTreeDoc(cur_node, copyDocPtr);
	}

	ret = __ps_run_tag_parser(lib_handle, copyDocPtr, ASCII(name), action, pkgid);
 END:

	return ret;
}

static int __run_metadata_parser_prestep (manifest_x *mfx, char *md_key, ACTION_TYPE action)
{
	int ret = -1;
	int tag_exist = 0;
	char buffer[1024] = { 0, };
	uiapplication_x *up = mfx->uiapplication;
	metadata_x *md = NULL;
	char *md_tag = NULL;

	GList *md_list = NULL;
	__metadata_t *md_detail = NULL;

	md_tag = __get_tag_by_key(md_key);
	if (md_tag == NULL) {
		_LOGD("md_tag is NULL\n");
		return -1;
	}

	while(up != NULL)
	{
		md = up->metadata;
		while (md != NULL)
		{
			//get glist of metadata key and value combination
			memset(buffer, 0x00, 1024);
			snprintf(buffer, 1024, "%s/", md_key);
			if ((md->key && md->value) && (strncmp(md->key, md_key, strlen(md_key)) == 0) && (strncmp(buffer, md->key, strlen(buffer)) == 0)) {
				md_detail = (__metadata_t*) calloc(1, sizeof(__metadata_t));
				if (md_detail == NULL) {
					_LOGD("Memory allocation failed\n");
					goto END;
				}

				md_detail->key = (char*) calloc(1, sizeof(char)*(strlen(md->key)+2));
				if (md_detail->key == NULL) {
					_LOGD("Memory allocation failed\n");
					free(md_detail);
					goto END;
				}
				snprintf(md_detail->key, (strlen(md->key)+1), "%s", md->key);

				md_detail->value = (char*) calloc(1, sizeof(char)*(strlen(md->value)+2));
				if (md_detail->value == NULL) {
					_LOGD("Memory allocation failed\n");
					free(md_detail->key);
					free(md_detail);
					goto END;
				}
				snprintf(md_detail->value, (strlen(md->value)+1), "%s", md->value);

				md_list = g_list_append(md_list, (gpointer)md_detail);
				tag_exist = 1;
			}
			md = md->next;
		}

		//send glist to parser when tags for metadata plugin parser exist.
		if (tag_exist) {
			ret = __ps_run_metadata_parser(md_list, md_tag, action, mfx->package, up->appid);
			if (ret < 0){
				_LOGD("metadata_parser failed[%d] for tag[%s]\n", ret, md_tag);
			}
			else{
				_LOGD("metadata_parser success for tag[%s]\n", md_tag);
			}
		}
		__metadata_parser_clear_dir_list(md_list);
		md_list = NULL;
		tag_exist = 0;
		up = up->next;
	}

	return 0;
END:
	__metadata_parser_clear_dir_list(md_list);

	if (md_tag)
		free(md_tag);

	return ret;
}

static int __run_category_parser_prestep (manifest_x *mfx, char *category_key, ACTION_TYPE action)
{
	int ret = -1;
	int tag_exist = 0;
	char buffer[1024] = { 0, };
	uiapplication_x *up = mfx->uiapplication;
	category_x *category = NULL;
	char *category_tag = NULL;

	GList *category_list = NULL;
	__category_t *category_detail = NULL;

	category_tag = __get_tag_by_key(category_key);
	if (category_tag == NULL) {
		_LOGD("md_tag is NULL\n");
		return -1;
	}

	while(up != NULL)
	{
		category = up->category;
		while (category != NULL)
		{
			//get glist of category key and value combination
			memset(buffer, 0x00, 1024);
			snprintf(buffer, 1024, "%s/", category_key);
			if ((category->name) && (strncmp(category->name, category_key, strlen(category_key)) == 0)) {
				category_detail = (__category_t*) calloc(1, sizeof(__category_t));
				if (category_detail == NULL) {
					_LOGD("Memory allocation failed\n");
					goto END;
				}

				category_detail->name = (char*) calloc(1, sizeof(char)*(strlen(category->name)+2));
				if (category_detail->name == NULL) {
					_LOGD("Memory allocation failed\n");
					free(category_detail);
					goto END;
				}
				snprintf(category_detail->name, (strlen(category->name)+1), "%s", category->name);

				category_list = g_list_append(category_list, (gpointer)category_detail);
				tag_exist = 1;
			}
			category = category->next;
		}

		//send glist to parser when tags for metadata plugin parser exist.
		if (tag_exist) {
			ret = __ps_run_category_parser(category_list, category_tag, action, mfx->package, up->appid);
			if (ret < 0)
				_LOGD("category_parser failed[%d] for tag[%s]\n", ret, category_tag);
			else
				_LOGD("category_parser success for tag[%s]\n", category_tag);
		}
		__category_parser_clear_dir_list(category_list);
		category_list = NULL;
		tag_exist = 0;
		up = up->next;
	}

	return 0;
END:
	__category_parser_clear_dir_list(category_list);

	if (category_tag)
		free(category_tag);

	return ret;
}

static int __run_parser_prestep(xmlTextReaderPtr reader, ACTION_TYPE action, const char *pkgid)
{
	int ret = -1;
	const xmlChar *name;

//	_LOGD("__run_parser_prestep");

	if (xmlTextReaderDepth(reader) != 1) {
		_LOGE("Node depth is not 1");
		goto END;
	}

	if (xmlTextReaderNodeType(reader) != 1) {
		_LOGE("Node type is not 1");
		goto END;
	}

	const xmlChar *value;
	name = xmlTextReaderConstName(reader);
	if (name == NULL) {
		_LOGE("TEST TEST TES\n");
		name = BAD_CAST "--";
	}

	value = xmlTextReaderConstValue(reader);
	_LOGD("%d %d %s %d %d",
	    xmlTextReaderDepth(reader),
	    xmlTextReaderNodeType(reader),
	    name,
	    xmlTextReaderIsEmptyElement(reader), xmlTextReaderHasValue(reader));

	if (value != NULL) {
		if (xmlStrlen(value) > 40) {
			_LOGD(" %.40s...", value);
		} else {
			_LOGD(" %s", value);
		}
	}

	name = xmlTextReaderConstName(reader);
	if (name == NULL) {
		_LOGE("TEST TEST TES\n");
		name = BAD_CAST "--";
	}

	xmlDocPtr docPtr = xmlTextReaderCurrentDoc(reader);
	_LOGD("docPtr->URL %s\n", (char *)docPtr->URL);
	xmlDocPtr copyDocPtr = xmlCopyDoc(docPtr, 1);
	if (copyDocPtr == NULL)
		return -1;
	xmlNode *rootElement = xmlDocGetRootElement(copyDocPtr);
	if (rootElement == NULL)
		return -1;
	xmlNode *cur_node = xmlFirstElementChild(rootElement);
	if (cur_node == NULL)
		return -1;
	xmlNode *temp = xmlTextReaderExpand(reader);
	if (temp == NULL)
		return -1;
	xmlNode *next_node = NULL;
	while(cur_node != NULL) {
		if ( (strcmp(ASCII(temp->name), ASCII(cur_node->name)) == 0) &&
			(temp->line == cur_node->line) ) {
			break;
		}
		else {
			next_node = xmlNextElementSibling(cur_node);
			xmlUnlinkNode(cur_node);
			xmlFreeNode(cur_node);
			cur_node = next_node;
		}
	}
	if (cur_node == NULL)
		return -1;
	next_node = xmlNextElementSibling(cur_node);
	if (next_node) {
		cur_node->next = NULL;
		next_node->prev = NULL;
		xmlFreeNodeList(next_node);
		xmlSetTreeDoc(cur_node, copyDocPtr);
	} else {
		xmlSetTreeDoc(cur_node, copyDocPtr);
	}

#ifdef __DEBUG__

//#else
	_LOGD("node type: %d, name: %s children->name: %s last->name: %s\n"
	    "parent->name: %s next->name: %s prev->name: %s\n",
	    cur_node->type, cur_node->name,
	    cur_node->children ? cur_node->children->name : "NULL",
	    cur_node->last ? cur_node->last->name : "NULL",
	    cur_node->parent ? cur_node->parent->name : "NULL",
	    cur_node->next ? cur_node->next->name : "NULL",
	    cur_node->prev ? cur_node->prev->name : "NULL");

	FILE *fp = fopen(tzplatform_mkpath(TZ_SYS_SHARE, "test.xml"), "a");
	xmlDocDump(fp, copyDocPtr);
	fclose(fp);
#endif

	ret = __ps_run_parser(copyDocPtr, ASCII(name), action, pkgid);
 END:

	return ret;
}

static void
__processNode(xmlTextReaderPtr reader, ACTION_TYPE action, char *const tagv[], const char *pkgid)
{
	char *tag = NULL;
	int i = 0;

	switch (xmlTextReaderNodeType(reader)) {
	case XML_READER_TYPE_END_ELEMENT:
		{
			//            _LOGD("XML_READER_TYPE_END_ELEMENT");
			break;
		}

	case XML_READER_TYPE_ELEMENT:
		{
			// Elements without closing tag don't receive
			// XML_READER_TYPE_END_ELEMENT event.

			const xmlChar *elementName =
			    xmlTextReaderLocalName(reader);
			if (elementName == NULL) {
//				_LOGD("elementName %s\n", (char *)elementName);
				break;
			}

			const xmlChar *nameSpace =
			    xmlTextReaderConstNamespaceUri(reader);
			if (nameSpace) {
//				_LOGD("nameSpace %s\n", (char *)nameSpace);
			}
/*
			_LOGD("XML_READER_TYPE_ELEMENT %s, %s\n",
			    elementName ? elementName : "NULL",
			    nameSpace ? nameSpace : "NULL");
*/
			if (tagv == NULL) {
				_LOGD("__run_parser_prestep pkgid[%s]\n", pkgid);
				__run_parser_prestep(reader, action, pkgid);
			}
			else {
				i = 0;
				for (tag = tagv[0]; tag; tag = tagv[++i])
					if (strcmp(tag, ASCII(elementName)) == 0) {
						_LOGD("__run_parser_prestep tag[%s] pkgid[%s]\n", tag, pkgid);
						__run_parser_prestep(reader,
								     action, pkgid);
						break;
					}
			}

			break;
		}
	case XML_READER_TYPE_TEXT:
	case XML_READER_TYPE_CDATA:
		{
			const xmlChar *value = xmlTextReaderConstValue(reader);
			if (value) {
//				_LOGD("value %s\n", value);
			}

			const xmlChar *lang = xmlTextReaderConstXmlLang(reader);
			if (lang) {
//				_LOGD("lang\n", lang);
			}

/*			_LOGD("XML_READER_TYPE_TEXT %s, %s\n",
			    value ? value : "NULL", lang ? lang : "NULL");
*/
			break;
		}
	default:
//		_LOGD("Ignoring Node of Type: %d", xmlTextReaderNodeType(reader));
		break;
	}
}

static void
__processTag(void *lib_handle, xmlTextReaderPtr reader, ACTION_TYPE action, char *tag, const char *pkgid)
{
	switch (xmlTextReaderNodeType(reader)) {
	case XML_READER_TYPE_END_ELEMENT:
		{
			break;
		}
	case XML_READER_TYPE_ELEMENT:
		{
			// Elements without closing tag don't receive
			const xmlChar *elementName =
			    xmlTextReaderLocalName(reader);
			if (elementName == NULL) {
				break;
			}

			if (strcmp(tag, ASCII(elementName)) == 0) {
				_LOGD("find : tag[%s] ACTION_TYPE[%d] pkg[%s]\n", tag, action, pkgid);
				__run_tag_parser_prestep(lib_handle, reader, action, pkgid);
				break;
			}
			break;
		}

	default:
		break;
	}
}

static int __parser_send_tag(void *lib_handle, ACTION_TYPE action, PLUGIN_PROCESS_TYPE process, const char *pkgid)
{
	int (*plugin_install) (const char *);
	int ret = -1;
	char *ac = NULL;

	if (process == PLUGIN_PRE_PROCESS) {
		switch (action) {
		case ACTION_INSTALL:
			ac = "PKGMGR_PARSER_PLUGIN_PRE_INSTALL";
			break;
		case ACTION_UPGRADE:
			ac = "PKGMGR_PARSER_PLUGIN_PRE_UPGRADE";
			break;
		case ACTION_UNINSTALL:
			ac = "PKGMGR_PARSER_PLUGIN_PRE_UNINSTALL";
			break;
		default:
			return -1;
		}
	} else if (process == PLUGIN_POST_PROCESS) {
		switch (action) {
		case ACTION_INSTALL:
			ac = "PKGMGR_PARSER_PLUGIN_POST_INSTALL";
			break;
		case ACTION_UPGRADE:
			ac = "PKGMGR_PARSER_PLUGIN_POST_UPGRADE";
			break;
		case ACTION_UNINSTALL:
			ac = "PKGMGR_PARSER_PLUGIN_POST_UNINSTALL";
			break;
		default:
			return -1;
		}
	} else
		return -1;

	if ((plugin_install =
		dlsym(lib_handle, ac)) == NULL || dlerror() != NULL) {
		return -1;
	}

	ret = plugin_install(pkgid);
	return ret;
}

static void __plugin_send_tag(const char *tag, ACTION_TYPE action, PLUGIN_PROCESS_TYPE process, const char *pkgid)
{
	char *lib_path = NULL;
	void *lib_handle = NULL;
	int (*plugin_install) (const char *);
	int ret = -1;
	char *ac = NULL;

	if (process == PLUGIN_PRE_PROCESS) {
		switch (action) {
		case ACTION_INSTALL:
			ac = "PKGMGR_PARSER_PLUGIN_PRE_INSTALL";
			break;
		case ACTION_UPGRADE:
			ac = "PKGMGR_PARSER_PLUGIN_PRE_UPGRADE";
			break;
		case ACTION_UNINSTALL:
			ac = "PKGMGR_PARSER_PLUGIN_PRE_UNINSTALL";
			break;
		default:
			goto END;
		}
	} else if (process == PLUGIN_POST_PROCESS) {
		switch (action) {
		case ACTION_INSTALL:
			ac = "PKGMGR_PARSER_PLUGIN_POST_INSTALL";
			break;
		case ACTION_UPGRADE:
			ac = "PKGMGR_PARSER_PLUGIN_POST_UPGRADE";
			break;
		case ACTION_UNINSTALL:
			ac = "PKGMGR_PARSER_PLUGIN_POST_UNINSTALL";
			break;
		default:
			goto END;
		}
	} else
		goto END;

	lib_path = __get_parser_plugin(tag);
	if (!lib_path) {
		goto END;
	}

	if ((lib_handle = dlopen(lib_path, RTLD_LAZY)) == NULL) {
		_LOGE("dlopen is failed lib_path[%s] for tag[%s]\n", lib_path, tag);
		goto END;
	}
	if ((plugin_install =
		dlsym(lib_handle, ac)) == NULL || dlerror() != NULL) {
//		_LOGE("can not find symbol[%s] for tag[%s] \n", ac, tag);
		goto END;
	}

	ret = plugin_install(pkgid);
	if (ret < 0)
		_LOGD("[PLUGIN_PROCESS_TYPE[%d] pkgid=%s, tag=%s plugin fail\n", process, pkgid, tag);
	else
		_LOGD("[PLUGIN_PROCESS_TYPE[%d] pkgid=%s, tag=%s plugin success\n", process, pkgid, tag);

END:
	if (lib_path)
		free(lib_path);
	if (lib_handle)
		dlclose(lib_handle);
}

static void
__plugin_process_tag(char *const tag_list[], ACTION_TYPE action, PLUGIN_PROCESS_TYPE process, const char *pkgid)
{
	char *tag = NULL;
	int i = 0;

	for (tag = tag_list[0]; tag; tag = tag_list[++i])
		__plugin_send_tag(tag, action, process, pkgid);

}

static void
__plugin_save_tag(xmlTextReaderPtr reader, char *const tagv[], char *tag_list[])
{
	char *tag = NULL;
	int i = 0;
	static int pre_cnt=0;

	switch (xmlTextReaderNodeType(reader)) {
	case XML_READER_TYPE_ELEMENT:
		{
			const xmlChar *elementName = xmlTextReaderLocalName(reader);
			if (elementName == NULL) {
				break;
			}
			i = 0;
			for (tag = tag_list[0]; tag; tag = tag_list[++i])
				if (strcmp(ASCII(elementName), tag) == 0) {
					return;
				}
			i = 0;
			for (tag = tagv[0]; tag; tag = tagv[++i])
				if (strcmp(tag, ASCII(elementName)) == 0) {
					tag_list[pre_cnt++] = tag;
					break;
				}
			break;
		}
	default:
//		_LOGD("Ignoring Node of Type: %d", xmlTextReaderNodeType(reader));
		break;
	}
}

static void
__streamFile(const char *filename, ACTION_TYPE action, char *const tagv[], const char *pkgid)
{
	xmlTextReaderPtr reader;
	xmlDocPtr docPtr;
	int ret;
	__plugin_process_tag(tagv, action, PLUGIN_PRE_PROCESS, pkgid);

	docPtr = xmlReadFile(filename, NULL, 0);
	reader = xmlReaderWalker(docPtr);
	if (reader != NULL) {
		ret = xmlTextReaderRead(reader);
		while (ret == 1) {
			__processNode(reader, action, tagv, pkgid);
			ret = xmlTextReaderRead(reader);
		}
		xmlFreeTextReader(reader);

		if (ret != 0) {
			_LOGD("%s : failed to parse", filename);
		}
	} else {
		_LOGD("Unable to open %s", filename);
	}

	__plugin_process_tag(tagv, action, PLUGIN_POST_PROCESS, pkgid);
}

static int __next_child_element(xmlTextReaderPtr reader, int depth)
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

static bool __check_action_fota(char *const tagv[])
{
	int i = 0;
	char delims[] = "=";
	char *ret_result = NULL;
	char *tag = NULL;
	int ret = false;

	if (tagv == NULL)
		return ret;

	for (tag = strdup(tagv[0]); tag != NULL; ) {
		ret_result = strtok(tag, delims);

		/*check tag :  fota is true */
		if (strcmp(ret_result, "fota") == 0) {
			ret_result = strtok(NULL, delims);
			if (strcmp(ret_result, "true") == 0) {
				ret = true;
			}
		} else
			_LOGD("tag process [%s]is not defined\n", ret_result);

		free(tag);

		/*check next value*/
		if (tagv[++i] != NULL)
			tag = strdup(tagv[i]);
		else {
			_LOGD("tag process success...%d\n" , ret);
			return ret;
		}
	}

	return ret;
}

static void __ps_free_category(category_x *category)
{
	if (category == NULL)
		return;
	if (category->name) {
		free((void *)category->name);
		category->name = NULL;
	}
	free((void*)category);
	category = NULL;
}

static void __ps_free_privilege(privilege_x *privilege)
{
	if (privilege == NULL)
		return;
	if (privilege->text) {
		free((void *)privilege->text);
		privilege->text = NULL;
	}
	free((void*)privilege);
	privilege = NULL;
}

static void __ps_free_privileges(privileges_x *privileges)
{
	if (privileges == NULL)
		return;
	/*Free Privilege*/
	if (privileges->privilege) {
		privilege_x *privilege = privileges->privilege;
		privilege_x *tmp = NULL;
		while(privilege != NULL) {
			tmp = privilege->next;
			__ps_free_privilege(privilege);
			privilege = tmp;
		}
	}
	free((void*)privileges);
	privileges = NULL;
}

static void __ps_free_metadata(metadata_x *metadata)
{
	if (metadata == NULL)
		return;
	if (metadata->key) {
		free((void *)metadata->key);
		metadata->key = NULL;
	}
	if (metadata->value) {
		free((void *)metadata->value);
		metadata->value = NULL;
	}
	free((void*)metadata);
	metadata = NULL;
}

static void __ps_free_permission(permission_x *permission)
{
	if (permission == NULL)
		return;
	if (permission->type) {
		free((void *)permission->type);
		permission->type = NULL;
	}
	if (permission->value) {
		free((void *)permission->value);
		permission->value = NULL;
	}
	free((void*)permission);
	permission = NULL;
}

static void __ps_free_icon(icon_x *icon)
{
	if (icon == NULL)
		return;
	if (icon->text) {
		free((void *)icon->text);
		icon->text = NULL;
	}
	if (icon->lang) {
		free((void *)icon->lang);
		icon->lang = NULL;
	}
	if (icon->name) {
		free((void *)icon->name);
		icon->name= NULL;
	}
	if (icon->section) {
		free((void *)icon->section);
		icon->section = NULL;
	}
	if (icon->size) {
		free((void *)icon->size);
		icon->size = NULL;
	}
	if (icon->resolution) {
		free((void *)icon->resolution);
		icon->resolution = NULL;
	}
	free((void*)icon);
	icon = NULL;
}

static void __ps_free_image(image_x *image)
{
	if (image == NULL)
		return;
	if (image->text) {
		free((void *)image->text);
		image->text = NULL;
	}
	if (image->lang) {
		free((void *)image->lang);
		image->lang = NULL;
	}
	if (image->name) {
		free((void *)image->name);
		image->name= NULL;
	}
	if (image->section) {
		free((void *)image->section);
		image->section = NULL;
	}
	free((void*)image);
	image = NULL;
}

static void __ps_free_operation(operation_x *operation)
{
	if (operation == NULL)
		return;
	if (operation->text) {
		free((void *)operation->text);
		operation->text = NULL;
	}
	free((void*)operation);
	operation = NULL;
}

static void __ps_free_uri(uri_x *uri)
{
	if (uri == NULL)
		return;
	if (uri->text) {
		free((void *)uri->text);
		uri->text = NULL;
	}
	free((void*)uri);
	uri = NULL;
}

static void __ps_free_mime(mime_x *mime)
{
	if (mime == NULL)
		return;
	if (mime->text) {
		free((void *)mime->text);
		mime->text = NULL;
	}
	free((void*)mime);
	mime = NULL;
}

static void __ps_free_subapp(subapp_x *subapp)
{
	if (subapp == NULL)
		return;
	if (subapp->text) {
		free((void *)subapp->text);
		subapp->text = NULL;
	}
	free((void*)subapp);
	subapp = NULL;
}

static void __ps_free_condition(condition_x *condition)
{
	if (condition == NULL)
		return;
	if (condition->text) {
		free((void *)condition->text);
		condition->text = NULL;
	}
	if (condition->name) {
		free((void *)condition->name);
		condition->name = NULL;
	}
	free((void*)condition);
	condition = NULL;
}

static void __ps_free_notification(notification_x *notification)
{
	if (notification == NULL)
		return;
	if (notification->text) {
		free((void *)notification->text);
		notification->text = NULL;
	}
	if (notification->name) {
		free((void *)notification->name);
		notification->name = NULL;
	}
	free((void*)notification);
	notification = NULL;
}

static void __ps_free_compatibility(compatibility_x *compatibility)
{
	if (compatibility == NULL)
		return;
	if (compatibility->text) {
		free((void *)compatibility->text);
		compatibility->text = NULL;
	}
	if (compatibility->name) {
		free((void *)compatibility->name);
		compatibility->name = NULL;
	}
	free((void*)compatibility);
	compatibility = NULL;
}

static void __ps_free_resolution(resolution_x *resolution)
{
	if (resolution == NULL)
		return;
	if (resolution->mimetype) {
		free((void *)resolution->mimetype);
		resolution->mimetype = NULL;
	}
	if (resolution->urischeme) {
		free((void *)resolution->urischeme);
		resolution->urischeme = NULL;
	}
	free((void*)resolution);
	resolution = NULL;
}

static void __ps_free_capability(capability_x *capability)
{
	if (capability == NULL)
		return;
	if (capability->operationid) {
		free((void *)capability->operationid);
		capability->operationid = NULL;
	}
	/*Free Resolution*/
	if (capability->resolution) {
		resolution_x *resolution = capability->resolution;
		resolution_x *tmp = NULL;
		while(resolution != NULL) {
			tmp = resolution->next;
			__ps_free_resolution(resolution);
			resolution = tmp;
		}
	}
	free((void*)capability);
	capability = NULL;
}

static void __ps_free_allowed(allowed_x *allowed)
{
	if (allowed == NULL)
		return;
	if (allowed->name) {
		free((void *)allowed->name);
		allowed->name = NULL;
	}
	if (allowed->text) {
		free((void *)allowed->text);
		allowed->text = NULL;
	}
	free((void*)allowed);
	allowed = NULL;
}

static void __ps_free_request(request_x *request)
{
	if (request == NULL)
		return;
	if (request->text) {
		free((void *)request->text);
		request->text = NULL;
	}
	free((void*)request);
	request = NULL;
}

static void __ps_free_datacontrol(datacontrol_x *datacontrol)
{
	if (datacontrol == NULL)
		return;
	if (datacontrol->providerid) {
		free((void *)datacontrol->providerid);
		datacontrol->providerid = NULL;
	}
	/*Free Capability*/
	if (datacontrol->capability) {
		capability_x *capability = datacontrol->capability;
		capability_x *tmp = NULL;
		while(capability != NULL) {
			tmp = capability->next;
			__ps_free_capability(capability);
			capability = tmp;
		}
	}
	free((void*)datacontrol);
	datacontrol = NULL;
}

static void __ps_free_launchconditions(launchconditions_x *launchconditions)
{
	if (launchconditions == NULL)
		return;
	if (launchconditions->text) {
		free((void *)launchconditions->text);
		launchconditions->text = NULL;
	}
	/*Free Condition*/
	if (launchconditions->condition) {
		condition_x *condition = launchconditions->condition;
		condition_x *tmp = NULL;
		while(condition != NULL) {
			tmp = condition->next;
			__ps_free_condition(condition);
			condition = tmp;
		}
	}
	free((void*)launchconditions);
	launchconditions = NULL;
}

static void __ps_free_appcontrol(appcontrol_x *appcontrol)
{
	if (appcontrol == NULL)
		return;
	if (appcontrol->text) {
		free((void *)appcontrol->text);
		appcontrol->text = NULL;
	}
	/*Free Operation*/
	if (appcontrol->operation) {
		operation_x *operation = appcontrol->operation;
		operation_x *tmp = NULL;
		while(operation != NULL) {
			tmp = operation->next;
			__ps_free_operation(operation);
			operation = tmp;
		}
	}
	/*Free Uri*/
	if (appcontrol->uri) {
		uri_x *uri = appcontrol->uri;
		uri_x *tmp = NULL;
		while(uri != NULL) {
			tmp = uri->next;
			__ps_free_uri(uri);
			uri = tmp;
		}
	}
	/*Free Mime*/
	if (appcontrol->mime) {
		mime_x *mime = appcontrol->mime;
		mime_x *tmp = NULL;
		while(mime != NULL) {
			tmp = mime->next;
			__ps_free_mime(mime);
			mime = tmp;
		}
	}
	/*Free subapp*/
	if (appcontrol->subapp) {
		subapp_x *subapp = appcontrol->subapp;
		subapp_x *tmp = NULL;
		while(subapp != NULL) {
			tmp = subapp->next;
			__ps_free_subapp(subapp);
			subapp = tmp;
		}
	}
	free((void*)appcontrol);
	appcontrol = NULL;
}

static void __ps_free_appsvc(appsvc_x *appsvc)
{
	if (appsvc == NULL)
		return;
	if (appsvc->text) {
		free((void *)appsvc->text);
		appsvc->text = NULL;
	}
	/*Free Operation*/
	if (appsvc->operation) {
		operation_x *operation = appsvc->operation;
		operation_x *tmp = NULL;
		while(operation != NULL) {
			tmp = operation->next;
			__ps_free_operation(operation);
			operation = tmp;
		}
	}
	/*Free Uri*/
	if (appsvc->uri) {
		uri_x *uri = appsvc->uri;
		uri_x *tmp = NULL;
		while(uri != NULL) {
			tmp = uri->next;
			__ps_free_uri(uri);
			uri = tmp;
		}
	}
	/*Free Mime*/
	if (appsvc->mime) {
		mime_x *mime = appsvc->mime;
		mime_x *tmp = NULL;
		while(mime != NULL) {
			tmp = mime->next;
			__ps_free_mime(mime);
			mime = tmp;
		}
	}
	/*Free subapp*/
	if (appsvc->subapp) {
		subapp_x *subapp = appsvc->subapp;
		subapp_x *tmp = NULL;
		while(subapp != NULL) {
			tmp = subapp->next;
			__ps_free_subapp(subapp);
			subapp = tmp;
		}
	}
	free((void*)appsvc);
	appsvc = NULL;
}

static void __ps_free_deviceprofile(deviceprofile_x *deviceprofile)
{
	return;
}

static void __ps_free_define(define_x *define)
{
	if (define == NULL)
		return;
	if (define->path) {
		free((void *)define->path);
		define->path = NULL;
	}
	/*Free Request*/
	if (define->request) {
		request_x *request = define->request;
		request_x *tmp = NULL;
		while(request != NULL) {
			tmp = request->next;
			__ps_free_request(request);
			request = tmp;
		}
	}
	/*Free Allowed*/
	if (define->allowed) {
		allowed_x *allowed = define->allowed;
		allowed_x *tmp = NULL;
		while(allowed != NULL) {
			tmp = allowed->next;
			__ps_free_allowed(allowed);
			allowed = tmp;
		}
	}
	free((void*)define);
	define = NULL;
}

static void __ps_free_datashare(datashare_x *datashare)
{
	if (datashare == NULL)
		return;
	/*Free Define*/
	if (datashare->define) {
		define_x *define =  datashare->define;
		define_x *tmp = NULL;
		while(define != NULL) {
			tmp = define->next;
			__ps_free_define(define);
			define = tmp;
		}
	}
	/*Free Request*/
	if (datashare->request) {
		request_x *request = datashare->request;
		request_x *tmp = NULL;
		while(request != NULL) {
			tmp = request->next;
			__ps_free_request(request);
			request = tmp;
		}
	}
	free((void*)datashare);
	datashare = NULL;
}

static void __ps_free_label(label_x *label)
{
	if (label == NULL)
		return;
	if (label->name) {
		free((void *)label->name);
		label->name = NULL;
	}
	if (label->text) {
		free((void *)label->text);
		label->text = NULL;
	}
	if (label->lang) {
		free((void *)label->lang);
		label->lang= NULL;
	}
	free((void*)label);
	label = NULL;
}

static void __ps_free_author(author_x *author)
{
	if (author == NULL)
		return;
	if (author->email) {
		free((void *)author->email);
		author->email = NULL;
	}
	if (author->text) {
		free((void *)author->text);
		author->text = NULL;
	}
	if (author->href) {
		free((void *)author->href);
		author->href = NULL;
	}
	if (author->lang) {
		free((void *)author->lang);
		author->lang = NULL;
	}
	free((void*)author);
	author = NULL;
}

static void __ps_free_description(description_x *description)
{
	if (description == NULL)
		return;
	if (description->name) {
		free((void *)description->name);
		description->name = NULL;
	}
	if (description->text) {
		free((void *)description->text);
		description->text = NULL;
	}
	if (description->lang) {
		free((void *)description->lang);
		description->lang = NULL;
	}
	free((void*)description);
	description = NULL;
}

static void __ps_free_license(license_x *license)
{
	if (license == NULL)
		return;
	if (license->text) {
		free((void *)license->text);
		license->text = NULL;
	}
	if (license->lang) {
		free((void *)license->lang);
		license->lang = NULL;
	}
	free((void*)license);
	license = NULL;
}

static void __ps_free_uiapplication(uiapplication_x *uiapplication)
{
	if (uiapplication == NULL)
		return;
	if (uiapplication->exec) {
		free((void *)uiapplication->exec);
		uiapplication->exec = NULL;
	}
	if (uiapplication->appid) {
		free((void *)uiapplication->appid);
		uiapplication->appid = NULL;
	}
	if (uiapplication->nodisplay) {
		free((void *)uiapplication->nodisplay);
		uiapplication->nodisplay = NULL;
	}
	if (uiapplication->multiple) {
		free((void *)uiapplication->multiple);
		uiapplication->multiple = NULL;
	}
	if (uiapplication->type) {
		free((void *)uiapplication->type);
		uiapplication->type = NULL;
	}
	if (uiapplication->categories) {
		free((void *)uiapplication->categories);
		uiapplication->categories = NULL;
	}
	if (uiapplication->extraid) {
		free((void *)uiapplication->extraid);
		uiapplication->extraid = NULL;
	}
	if (uiapplication->taskmanage) {
		free((void *)uiapplication->taskmanage);
		uiapplication->taskmanage = NULL;
	}
	if (uiapplication->enabled) {
		free((void *)uiapplication->enabled);
		uiapplication->enabled = NULL;
	}
	if (uiapplication->hwacceleration) {
		free((void *)uiapplication->hwacceleration);
		uiapplication->hwacceleration = NULL;
	}
	if (uiapplication->screenreader) {
		free((void *)uiapplication->screenreader);
		uiapplication->screenreader = NULL;
	}
	if (uiapplication->mainapp) {
		free((void *)uiapplication->mainapp);
		uiapplication->mainapp = NULL;
	}
	if (uiapplication->recentimage) {
		free((void *)uiapplication->recentimage);
		uiapplication->recentimage = NULL;
	}
	if (uiapplication->package) {
		free((void *)uiapplication->package);
		uiapplication->package = NULL;
	}
	if (uiapplication->launchcondition) {
		free((void *)uiapplication->launchcondition);
		uiapplication->launchcondition = NULL;
	}
	/*Free Label*/
	if (uiapplication->label) {
		label_x *label = uiapplication->label;
		label_x *tmp = NULL;
		while(label != NULL) {
			tmp = label->next;
			__ps_free_label(label);
			label = tmp;
		}
	}
	/*Free Icon*/
	if (uiapplication->icon) {
		icon_x *icon = uiapplication->icon;
		icon_x *tmp = NULL;
		while(icon != NULL) {
			tmp = icon->next;
			__ps_free_icon(icon);
			icon = tmp;
		}
	}
	/*Free image*/
	if (uiapplication->image) {
		image_x *image = uiapplication->image;
		image_x *tmp = NULL;
		while(image != NULL) {
			tmp = image->next;
			__ps_free_image(image);
			image = tmp;
		}
	}
	/*Free AppControl*/
	if (uiapplication->appcontrol) {
		appcontrol_x *appcontrol = uiapplication->appcontrol;
		appcontrol_x *tmp = NULL;
		while(appcontrol != NULL) {
			tmp = appcontrol->next;
			__ps_free_appcontrol(appcontrol);
			appcontrol = tmp;
		}
	}
	/*Free LaunchConditions*/
	if (uiapplication->launchconditions) {
		launchconditions_x *launchconditions = uiapplication->launchconditions;
		launchconditions_x *tmp = NULL;
		while(launchconditions != NULL) {
			tmp = launchconditions->next;
			__ps_free_launchconditions(launchconditions);
			launchconditions = tmp;
		}
	}
	/*Free Notification*/
	if (uiapplication->notification) {
		notification_x *notification = uiapplication->notification;
		notification_x *tmp = NULL;
		while(notification != NULL) {
			tmp = notification->next;
			__ps_free_notification(notification);
			notification = tmp;
		}
	}
	/*Free DataShare*/
	if (uiapplication->datashare) {
		datashare_x *datashare = uiapplication->datashare;
		datashare_x *tmp = NULL;
		while(datashare != NULL) {
			tmp = datashare->next;
			__ps_free_datashare(datashare);
			datashare = tmp;
		}
	}
	/*Free AppSvc*/
	if (uiapplication->appsvc) {
		appsvc_x *appsvc = uiapplication->appsvc;
		appsvc_x *tmp = NULL;
		while(appsvc != NULL) {
			tmp = appsvc->next;
			__ps_free_appsvc(appsvc);
			appsvc = tmp;
		}
	}
	/*Free Category*/
	if (uiapplication->category) {
		category_x *category = uiapplication->category;
		category_x *tmp = NULL;
		while(category != NULL) {
			tmp = category->next;
			__ps_free_category(category);
			category = tmp;
		}
	}
	/*Free Metadata*/
	if (uiapplication->metadata) {
		metadata_x *metadata = uiapplication->metadata;
		metadata_x *tmp = NULL;
		while(metadata != NULL) {
			tmp = metadata->next;
			__ps_free_metadata(metadata);
			metadata = tmp;
		}
	}
	/*Free permission*/
	if (uiapplication->permission) {
		permission_x *permission = uiapplication->permission;
		permission_x *tmp = NULL;
		while(permission != NULL) {
			tmp = permission->next;
			__ps_free_permission(permission);
			permission = tmp;
		}
	}
	/* _PRODUCT_LAUNCHING_ENHANCED_ START */
	if (uiapplication->indicatordisplay) {
		free((void *)uiapplication->indicatordisplay);
		uiapplication->indicatordisplay = NULL;
	}
	if (uiapplication->portraitimg) {
		free((void *)uiapplication->portraitimg);
		uiapplication->portraitimg = NULL;
	}
	if (uiapplication->landscapeimg) {
		free((void *)uiapplication->landscapeimg);
		uiapplication->landscapeimg = NULL;
	}
	/* _PRODUCT_LAUNCHING_ENHANCED_ END */
	if (uiapplication->guestmode_visibility) {
		free((void *)uiapplication->guestmode_visibility);
		uiapplication->guestmode_visibility = NULL;
	}
	if (uiapplication->app_component) {
		free((void *)uiapplication->app_component);
		uiapplication->app_component = NULL;
	}
	if (uiapplication->permission_type) {
		free((void *)uiapplication->permission_type);
		uiapplication->permission_type = NULL;
	}
	if (uiapplication->component_type) {
		free((void *)uiapplication->component_type);
		uiapplication->component_type = NULL;
	}
	if (uiapplication->preload) {
		free((void *)uiapplication->preload);
		uiapplication->preload = NULL;
	}
	if (uiapplication->submode) {
		free((void *)uiapplication->submode);
		uiapplication->submode = NULL;
	}
	if (uiapplication->submode_mainid) {
		free((void *)uiapplication->submode_mainid);
		uiapplication->submode_mainid = NULL;
	}

	free((void*)uiapplication);
	uiapplication = NULL;
}

static void __ps_free_serviceapplication(serviceapplication_x *serviceapplication)
{
	if (serviceapplication == NULL)
		return;
	if (serviceapplication->exec) {
		free((void *)serviceapplication->exec);
		serviceapplication->exec = NULL;
	}
	if (serviceapplication->appid) {
		free((void *)serviceapplication->appid);
		serviceapplication->appid = NULL;
	}
	if (serviceapplication->onboot) {
		free((void *)serviceapplication->onboot);
		serviceapplication->onboot = NULL;
	}
	if (serviceapplication->autorestart) {
		free((void *)serviceapplication->autorestart);
		serviceapplication->autorestart = NULL;
	}
	if (serviceapplication->type) {
		free((void *)serviceapplication->type);
		serviceapplication->type = NULL;
	}
	if (serviceapplication->enabled) {
		free((void *)serviceapplication->enabled);
		serviceapplication->enabled = NULL;
	}
	if (serviceapplication->package) {
		free((void *)serviceapplication->package);
		serviceapplication->package = NULL;
	}
	if (serviceapplication->permission_type) {
		free((void *)serviceapplication->permission_type);
		serviceapplication->permission_type = NULL;
	}
	/*Free Label*/
	if (serviceapplication->label) {
		label_x *label = serviceapplication->label;
		label_x *tmp = NULL;
		while(label != NULL) {
			tmp = label->next;
			__ps_free_label(label);
			label = tmp;
		}
	}
	/*Free Icon*/
	if (serviceapplication->icon) {
		icon_x *icon = serviceapplication->icon;
		icon_x *tmp = NULL;
		while(icon != NULL) {
			tmp = icon->next;
			__ps_free_icon(icon);
			icon = tmp;
		}
	}
	/*Free AppControl*/
	if (serviceapplication->appcontrol) {
		appcontrol_x *appcontrol = serviceapplication->appcontrol;
		appcontrol_x *tmp = NULL;
		while(appcontrol != NULL) {
			tmp = appcontrol->next;
			__ps_free_appcontrol(appcontrol);
			appcontrol = tmp;
		}
	}
	/*Free DataControl*/
	if (serviceapplication->datacontrol) {
		datacontrol_x *datacontrol = serviceapplication->datacontrol;
		datacontrol_x *tmp = NULL;
		while(datacontrol != NULL) {
			tmp = datacontrol->next;
			__ps_free_datacontrol(datacontrol);
			datacontrol = tmp;
		}
	}
	/*Free LaunchConditions*/
	if (serviceapplication->launchconditions) {
		launchconditions_x *launchconditions = serviceapplication->launchconditions;
		launchconditions_x *tmp = NULL;
		while(launchconditions != NULL) {
			tmp = launchconditions->next;
			__ps_free_launchconditions(launchconditions);
			launchconditions = tmp;
		}
	}
	/*Free Notification*/
	if (serviceapplication->notification) {
		notification_x *notification = serviceapplication->notification;
		notification_x *tmp = NULL;
		while(notification != NULL) {
			tmp = notification->next;
			__ps_free_notification(notification);
			notification = tmp;
		}
	}
	/*Free DataShare*/
	if (serviceapplication->datashare) {
		datashare_x *datashare = serviceapplication->datashare;
		datashare_x *tmp = NULL;
		while(datashare != NULL) {
			tmp = datashare->next;
			__ps_free_datashare(datashare);
			datashare = tmp;
		}
	}
	/*Free AppSvc*/
	if (serviceapplication->appsvc) {
		appsvc_x *appsvc = serviceapplication->appsvc;
		appsvc_x *tmp = NULL;
		while(appsvc != NULL) {
			tmp = appsvc->next;
			__ps_free_appsvc(appsvc);
			appsvc = tmp;
		}
	}
	/*Free Category*/
	if (serviceapplication->category) {
		category_x *category = serviceapplication->category;
		category_x *tmp = NULL;
		while(category != NULL) {
			tmp = category->next;
			__ps_free_category(category);
			category = tmp;
		}
	}
	/*Free Metadata*/
	if (serviceapplication->metadata) {
		metadata_x *metadata = serviceapplication->metadata;
		metadata_x *tmp = NULL;
		while(metadata != NULL) {
			tmp = metadata->next;
			__ps_free_metadata(metadata);
			metadata = tmp;
		}
	}
	/*Free permission*/
	if (serviceapplication->permission) {
		permission_x *permission = serviceapplication->permission;
		permission_x *tmp = NULL;
		while(permission != NULL) {
			tmp = permission->next;
			__ps_free_permission(permission);
			permission = tmp;
		}
	}
	free((void*)serviceapplication);
	serviceapplication = NULL;
}

static void __ps_free_font(font_x *font)
{
	if (font == NULL)
		return;
	if (font->name) {
		free((void *)font->name);
		font->name = NULL;
	}
	if (font->text) {
		free((void *)font->text);
		font->text = NULL;
	}
	free((void*)font);
	font = NULL;
}

static void __ps_free_theme(theme_x *theme)
{
	if (theme == NULL)
		return;
	if (theme->name) {
		free((void *)theme->name);
		theme->name = NULL;
	}
	if (theme->text) {
		free((void *)theme->text);
		theme->text = NULL;
	}
	free((void*)theme);
	theme = NULL;
}

static void __ps_free_daemon(daemon_x *daemon)
{
	if (daemon == NULL)
		return;
	if (daemon->name) {
		free((void *)daemon->name);
		daemon->name = NULL;
	}
	if (daemon->text) {
		free((void *)daemon->text);
		daemon->text = NULL;
	}
	free((void*)daemon);
	daemon = NULL;
}

static void __ps_free_ime(ime_x *ime)
{
	if (ime == NULL)
		return;
	if (ime->name) {
		free((void *)ime->name);
		ime->name = NULL;
	}
	if (ime->text) {
		free((void *)ime->text);
		ime->text = NULL;
	}
	free((void*)ime);
	ime = NULL;
}

int __ps_process_tag_parser(manifest_x *mfx, const char *filename, ACTION_TYPE action)
{
	xmlTextReaderPtr reader;
	xmlDocPtr docPtr;
	int ret = -1;
	FILE *fp = NULL;
	void *lib_handle = NULL;
	char tag[PKG_STRING_LEN_MAX] = { 0 };

	fp = fopen(TAG_PARSER_LIST, "r");
	retvm_if(fp == NULL, PMINFO_R_ERROR, "no preload list");

	while (fgets(tag, sizeof(tag), fp) != NULL) {
		__str_trim(tag);

		lib_handle = __open_lib_handle(tag);
		if (lib_handle == NULL)
			continue;

		ret = __parser_send_tag(lib_handle, action, PLUGIN_PRE_PROCESS, mfx->package);
		_LOGD("PLUGIN_PRE_PROCESS[%s, %s] ACTION_TYPE[%d] result[%d]\n", mfx->package, tag, action, ret);

		docPtr = xmlReadFile(filename, NULL, 0);
		reader = xmlReaderWalker(docPtr);
		if (reader != NULL) {
			ret = xmlTextReaderRead(reader);
			while (ret == 1) {
				__processTag(lib_handle, reader, action, tag, mfx->package);
				ret = xmlTextReaderRead(reader);
			}
			xmlFreeTextReader(reader);

			if (ret != 0) {
				_LOGD("%s : failed to parse", filename);
			}
		} else {
			_LOGD("Unable to open %s", filename);
		}

		ret = __parser_send_tag(lib_handle, action, PLUGIN_POST_PROCESS, mfx->package);
		_LOGD("PLUGIN_POST_PROCESS[%s, %s] ACTION_TYPE[%d] result[%d]\n", mfx->package, tag, action, ret);

		__close_lib_handle(lib_handle);

		memset(tag, 0x00, sizeof(tag));
	}

	if (fp != NULL)
		fclose(fp);

	return 0;
}

int __ps_process_metadata_parser(manifest_x *mfx, ACTION_TYPE action)
{
	fprintf(stdout,"__ps_process_metadata_parser\n");
	int ret = -1;
	FILE *fp = NULL;
	char md_key[PKG_STRING_LEN_MAX] = { 0 };

	fp = fopen(METADATA_PARSER_LIST, "r");
	if (fp == NULL) {
		_LOGD("no preload list\n");
		return -1;
	}
	
	while (fgets(md_key, sizeof(md_key), fp) != NULL) {
		__str_trim(md_key);
		ret = __run_metadata_parser_prestep(mfx, md_key, action);

		memset(md_key, 0x00, sizeof(md_key));
	}

	if (fp != NULL)
		fclose(fp);

	return 0;
}

int __ps_process_category_parser(manifest_x *mfx, ACTION_TYPE action)
{
	int ret = -1;
	FILE *fp = NULL;
	char category_key[PKG_STRING_LEN_MAX] = { 0 };

	fp = fopen(CATEGORY_PARSER_LIST, "r");
	if (fp == NULL) {
		_LOGD("no category parser list\n");
		return -1;
	}

	while (fgets(category_key, sizeof(category_key), fp) != NULL) {
		__str_trim(category_key);
		ret = __run_category_parser_prestep(mfx, category_key, action);

		memset(category_key, 0x00, sizeof(category_key));
	}

	if (fp != NULL)
		fclose(fp);

	return 0;
}

static int __ps_process_allowed(xmlTextReaderPtr reader, allowed_x *allowed)
{
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		allowed->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_operation(xmlTextReaderPtr reader, operation_x *operation)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		operation->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
/* Text does not exist. Only attribute exists
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		operation->text = ASCII(xmlTextReaderValue(reader));
*/
	return 0;
}

static int __ps_process_uri(xmlTextReaderPtr reader, uri_x *uri)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		uri->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
/* Text does not exist. Only attribute exists
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		uri->text = ASCII(xmlTextReaderValue(reader));
*/
	return 0;
}

static int __ps_process_mime(xmlTextReaderPtr reader, mime_x *mime)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		mime->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
/* Text does not exist. Only attribute exists
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		mime->text = ASCII(xmlTextReaderValue(reader));
*/
	return 0;
}

static int __ps_process_subapp(xmlTextReaderPtr reader, subapp_x *subapp)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		subapp->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
/* Text does not exist. Only attribute exists
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		mime->text = ASCII(xmlTextReaderValue(reader));
*/
	return 0;
}

static int __ps_process_condition(xmlTextReaderPtr reader, condition_x *condition)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		condition->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		condition->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_notification(xmlTextReaderPtr reader, notification_x *notification)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		notification->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		notification->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_category(xmlTextReaderPtr reader, category_x *category)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		category->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
	return 0;
}

static int __ps_process_privilege(xmlTextReaderPtr reader, privilege_x *privilege)
{
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader)) {
		privilege->text = ASCII(xmlTextReaderValue(reader));
	}
	return 0;
}

static int __ps_process_metadata(xmlTextReaderPtr reader, metadata_x *metadata)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("key")))
		metadata->key = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("key")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("value")))
		metadata->value = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("value")));
	return 0;
}

static int __ps_process_permission(xmlTextReaderPtr reader, permission_x *permission)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("type")))
		permission->type = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("type")));

	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		permission->value = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_compatibility(xmlTextReaderPtr reader, compatibility_x *compatibility)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		compatibility->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		compatibility->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_resolution(xmlTextReaderPtr reader, resolution_x *resolution)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("mime-type")))
		resolution->mimetype = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("mime-type")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("uri-scheme")))
		resolution->urischeme = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("uri-scheme")));
	return 0;
}

static int __ps_process_request(xmlTextReaderPtr reader, request_x *request)
{
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		request->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_define(xmlTextReaderPtr reader, define_x *define)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	allowed_x *tmp1 = NULL;
	request_x *tmp2 = NULL;

	if (xmlTextReaderGetAttribute(reader, XMLCHAR("path")))
		define->path = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("path")));

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "allowed")) {
			allowed_x *allowed= malloc(sizeof(allowed_x));
			if (allowed == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(allowed, '\0', sizeof(allowed_x));
			LISTADD(define->allowed, allowed);
			ret = __ps_process_allowed(reader, allowed);
		} else if (!strcmp(ASCII(node), "request")) {
			request_x *request = malloc(sizeof(request_x));
			if (request == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(request, '\0', sizeof(request_x));
			LISTADD(define->request, request);
			ret = __ps_process_request(reader, request);
		} else
			return -1;
		if (ret < 0) {
			_LOGD("Processing define failed\n");
			return ret;
		}
	}
	if (define->allowed) {
		LISTHEAD(define->allowed, tmp1);
		define->allowed = tmp1;
	}
	if (define->request) {
		LISTHEAD(define->request, tmp2);
		define->request = tmp2;
	}
	return ret;
}

static int __ps_process_appcontrol(xmlTextReaderPtr reader, appcontrol_x *appcontrol)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	operation_x *tmp1 = NULL;
	uri_x *tmp2 = NULL;
	mime_x *tmp3 = NULL;
	subapp_x *tmp4 = NULL;

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "operation")) {
			operation_x *operation = malloc(sizeof(operation_x));
			if (operation == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(operation, '\0', sizeof(operation_x));
			LISTADD(appcontrol->operation, operation);
			ret = __ps_process_operation(reader, operation);
			_LOGD("operation processing\n");
		} else if (!strcmp(ASCII(node), "uri")) {
			uri_x *uri= malloc(sizeof(uri_x));
			if (uri == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(uri, '\0', sizeof(uri_x));
			LISTADD(appcontrol->uri, uri);
			ret = __ps_process_uri(reader, uri);
			_LOGD("uri processing\n");
		} else if (!strcmp(ASCII(node), "mime")) {
			mime_x *mime = malloc(sizeof(mime_x));
			if (mime == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(mime, '\0', sizeof(mime_x));
			LISTADD(appcontrol->mime, mime);
			ret = __ps_process_mime(reader, mime);
			_LOGD("mime processing\n");
		} else if (!strcmp(ASCII(node), "subapp")) {
			subapp_x *subapp = malloc(sizeof(subapp_x));
			if (subapp == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(subapp, '\0', sizeof(subapp_x));
			LISTADD(appcontrol->subapp, subapp);
			ret = __ps_process_subapp(reader, subapp);
			_LOGD("subapp processing\n");
		} else
			return -1;
		if (ret < 0) {
			_LOGD("Processing appcontrol failed\n");
			return ret;
		}
	}
	if (appcontrol->operation) {
		LISTHEAD(appcontrol->operation, tmp1);
		appcontrol->operation = tmp1;
	}
	if (appcontrol->uri) {
		LISTHEAD(appcontrol->uri, tmp2);
		appcontrol->uri = tmp2;
	}
	if (appcontrol->mime) {
		LISTHEAD(appcontrol->mime, tmp3);
		appcontrol->mime = tmp3;
	}
	if (appcontrol->subapp) {
		LISTHEAD(appcontrol->subapp, tmp4);
		appcontrol->subapp = tmp4;
	}

	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		appcontrol->text = ASCII(xmlTextReaderValue(reader));

	return ret;
}

static int __ps_process_appsvc(xmlTextReaderPtr reader, appsvc_x *appsvc)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	operation_x *tmp1 = NULL;
	uri_x *tmp2 = NULL;
	mime_x *tmp3 = NULL;
	subapp_x *tmp4 = NULL;

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "operation")) {
			operation_x *operation = malloc(sizeof(operation_x));
			if (operation == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(operation, '\0', sizeof(operation_x));
			LISTADD(appsvc->operation, operation);
			ret = __ps_process_operation(reader, operation);
			_LOGD("operation processing\n");
		} else if (!strcmp(ASCII(node), "uri")) {
			uri_x *uri= malloc(sizeof(uri_x));
			if (uri == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(uri, '\0', sizeof(uri_x));
			LISTADD(appsvc->uri, uri);
			ret = __ps_process_uri(reader, uri);
			_LOGD("uri processing\n");
		} else if (!strcmp(ASCII(node), "mime")) {
			mime_x *mime = malloc(sizeof(mime_x));
			if (mime == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(mime, '\0', sizeof(mime_x));
			LISTADD(appsvc->mime, mime);
			ret = __ps_process_mime(reader, mime);
			_LOGD("mime processing\n");
		} else if (!strcmp(ASCII(node), "subapp")) {
			subapp_x *subapp = malloc(sizeof(subapp_x));
			if (subapp == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(subapp, '\0', sizeof(subapp_x));
			LISTADD(appsvc->subapp, subapp);
			ret = __ps_process_subapp(reader, subapp);
			_LOGD("subapp processing\n");
		} else
			return -1;
		if (ret < 0) {
			_LOGD("Processing appsvc failed\n");
			return ret;
		}
	}
	if (appsvc->operation) {
		LISTHEAD(appsvc->operation, tmp1);
		appsvc->operation = tmp1;
	}
	if (appsvc->uri) {
		LISTHEAD(appsvc->uri, tmp2);
		appsvc->uri = tmp2;
	}
	if (appsvc->mime) {
		LISTHEAD(appsvc->mime, tmp3);
		appsvc->mime = tmp3;
	}
	if (appsvc->subapp) {
		LISTHEAD(appsvc->subapp, tmp4);
		appsvc->subapp = tmp4;
	}

	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		appsvc->text = ASCII(xmlTextReaderValue(reader));

	return ret;
}


static int __ps_process_privileges(xmlTextReaderPtr reader, privileges_x *privileges)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	privilege_x *tmp1 = NULL;

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (strcmp(ASCII(node), "privilege") == 0) {
			privilege_x *privilege = malloc(sizeof(privilege_x));
			if (privilege == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(privilege, '\0', sizeof(privilege_x));
			LISTADD(privileges->privilege, privilege);
			ret = __ps_process_privilege(reader, privilege);
		} else
			return -1;
		if (ret < 0) {
			_LOGD("Processing privileges failed\n");
			return ret;
		}
	}
	if (privileges->privilege) {
		LISTHEAD(privileges->privilege, tmp1);
		privileges->privilege = tmp1;
	}
	return ret;
}

static int __ps_process_launchconditions(xmlTextReaderPtr reader, launchconditions_x *launchconditions)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	condition_x *tmp1 = NULL;

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (strcmp(ASCII(node), "condition") == 0) {
			condition_x *condition = malloc(sizeof(condition_x));
			if (condition == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(condition, '\0', sizeof(condition_x));
			LISTADD(launchconditions->condition, condition);
			ret = __ps_process_condition(reader, condition);
		} else
			return -1;
		if (ret < 0) {
			_LOGD("Processing launchconditions failed\n");
			return ret;
		}
	}
	if (launchconditions->condition) {
		LISTHEAD(launchconditions->condition, tmp1);
		launchconditions->condition = tmp1;
	}

	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		launchconditions->text = ASCII(xmlTextReaderValue(reader));

	return ret;
}

static int __ps_process_datashare(xmlTextReaderPtr reader, datashare_x *datashare)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	define_x *tmp1 = NULL;
	request_x *tmp2 = NULL;
	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "define")) {
			define_x *define= malloc(sizeof(define_x));
			if (define == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(define, '\0', sizeof(define_x));
			LISTADD(datashare->define, define);
			ret = __ps_process_define(reader, define);
		} else if (!strcmp(ASCII(node), "request")) {
			request_x *request= malloc(sizeof(request_x));
			if (request == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(request, '\0', sizeof(request_x));
			LISTADD(datashare->request, request);
			ret = __ps_process_request(reader, request);
		} else
			return -1;
		if (ret < 0) {
			_LOGD("Processing data-share failed\n");
			return ret;
		}
	}
	if (datashare->define) {
		LISTHEAD(datashare->define, tmp1);
		datashare->define = tmp1;
	}
	if (datashare->request) {
		LISTHEAD(datashare->request, tmp2);
		datashare->request = tmp2;
	}
	return ret;
}

static char*
__get_icon_with_path(const char* icon, uid_t uid)
{
	if (!icon)
		return NULL;

	if (index(icon, '/') == NULL) {
		char* theme = NULL;
		char* iconPath = NULL;
		char* icon_with_path = NULL;
		char *app_path = NULL;
		int len;

		if (!package)
			return NULL;

/* "db/setting/theme" is not exist */
#if 0
		theme = vconf_get_str("db/setting/theme");
		if (!theme) {
			theme = strdup("default");
			if(!theme) {
				return NULL;
			}
		}
#else
		theme = strdup("default");
#endif

		len = (0x01 << 7) + strlen(icon) + strlen(package) + strlen(theme);
		icon_with_path = malloc(len);
		if(icon_with_path == NULL) {
			_LOGD("(icon_with_path == NULL) return\n");
			free(theme);
			return NULL;
		}

		memset(icon_with_path, 0, len);
		if (uid != GLOBAL_USER)
			snprintf(icon_with_path, len, "%s%s", getIconPath(uid), icon);
		else {
			snprintf(icon_with_path, len, "%s%s/small/%s", getIconPath(GLOBAL_USER), theme, icon);
			if (access (icon_with_path, F_OK)) { //If doesn't exist in case of Global app, try to get icon directly into app's directory
				app_path = tzplatform_getenv(TZ_SYS_RW_APP);
				if (app_path)
					snprintf( len, icon_with_path, "%s/%q/res/icons/%q/small/%q", app_path  , package, theme, icon);
				if (access (icon_with_path, F_OK))
					_LOGE("Cannot find icon path");
			}
		}
		free(theme);
		_LOGD("Icon path : %s ---> %s", icon, icon_with_path);
		return icon_with_path;
	} else {
		char* confirmed_icon = NULL;

		confirmed_icon = strdup(icon);
		if (!confirmed_icon)
			return NULL;
		return confirmed_icon;
	}
}

static void __ps_process_tag(manifest_x * mfx, char *const tagv[])
{
	int i = 0;
	char delims[] = "=";
	char *ret_result = NULL;
	char *tag = NULL;

	if (tagv == NULL)
		return;

	for (tag = strdup(tagv[0]); tag != NULL; ) {
		ret_result = strtok(tag, delims);

		/*check tag :  preload */
		if (strcmp(ret_result, "preload") == 0) {
			ret_result = strtok(NULL, delims);
			if (strcmp(ret_result, "true") == 0) {
				free((void *)mfx->preload);
				mfx->preload = strdup("true");
			} else if (strcmp(ret_result, "false") == 0) {
				free((void *)mfx->preload);
				mfx->preload = strdup("false");
			}
		/*check tag :  removable*/
		} else if (strcmp(ret_result, "removable") == 0) {
			ret_result = strtok(NULL, delims);
			if (strcmp(ret_result, "true") == 0){
				free((void *)mfx->removable);
				mfx->removable = strdup("true");
			} else if (strcmp(ret_result, "false") == 0) {
				free((void *)mfx->removable);
				mfx->removable = strdup("false");
			}
		/*check tag :  not matched*/
		} else
			_LOGD("tag process [%s]is not defined\n", ret_result);

		free(tag);

		/*check next value*/
		if (tagv[++i] != NULL)
			tag = strdup(tagv[i]);
		else {
			_LOGD("tag process success...\n");
			return;
		}
	}
}

static int __ps_process_icon(xmlTextReaderPtr reader, icon_x *icon, uid_t uid)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		icon->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
	if (xmlTextReaderConstXmlLang(reader)) {
		icon->lang = strdup(ASCII(xmlTextReaderConstXmlLang(reader)));
		if (icon->lang == NULL)
			icon->lang = strdup(DEFAULT_LOCALE);
	} else {
		icon->lang = strdup(DEFAULT_LOCALE);
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("section")))
		icon->section = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("section")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("size")))
		icon->size = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("size")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("resolution")))
		icon->resolution = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("resolution")));
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader)) {
		const char *text  = ASCII(xmlTextReaderValue(reader));
		if(text) {
			icon->text = (const char *)__get_icon_with_path(text, uid);
			free((void *)text);
		}
	}

	return 0;
}

static int __ps_process_image(xmlTextReaderPtr reader, image_x *image)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		image->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
	if (xmlTextReaderConstXmlLang(reader)) {
		image->lang = strdup(ASCII(xmlTextReaderConstXmlLang(reader)));
		if (image->lang == NULL)
			image->lang = strdup(DEFAULT_LOCALE);
	} else {
		image->lang = strdup(DEFAULT_LOCALE);
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("section")))
		image->section = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("section")));
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		image->text = ASCII(xmlTextReaderValue(reader));

	return 0;
}

static int __ps_process_label(xmlTextReaderPtr reader, label_x *label)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("name")))
		label->name = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("name")));
	if (xmlTextReaderConstXmlLang(reader)) {
		label->lang = strdup(ASCII(xmlTextReaderConstXmlLang(reader)));
		if (label->lang == NULL)
			label->lang = strdup(DEFAULT_LOCALE);
	} else 
		label->lang = strdup(DEFAULT_LOCALE);
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		label->text = ASCII(xmlTextReaderValue(reader));


/*	_LOGD("lable name %s\n", label->name);
	_LOGD("lable lang %s\n", label->lang);
	_LOGD("lable text %s\n", label->text);
*/
	return 0;

}

static int __ps_process_author(xmlTextReaderPtr reader, author_x *author)
{
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("email")))
		author->email = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("email")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("href")))
		author->href = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("href")));
	if (xmlTextReaderConstXmlLang(reader)) {
		author->lang = strdup(ASCII(xmlTextReaderConstXmlLang(reader)));
		if (author->lang == NULL)
			author->lang = strdup(DEFAULT_LOCALE);
	} else {
		author->lang = strdup(DEFAULT_LOCALE);
	}
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader)) {
		const char *text  = ASCII(xmlTextReaderValue(reader));
		if (*text == '\n') {
			author->text = NULL;
			free((void *)text);
			return 0;
		}
		author->text = ASCII(xmlTextReaderValue(reader));
	}
	return 0;
}

static int __ps_process_description(xmlTextReaderPtr reader, description_x *description)
{
	if (xmlTextReaderConstXmlLang(reader)) {
		description->lang = strdup(ASCII(xmlTextReaderConstXmlLang(reader)));
		if (description->lang == NULL)
			description->lang = strdup(DEFAULT_LOCALE);
	} else {
		description->lang = strdup(DEFAULT_LOCALE);
	}
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader)) {
		const char *text  = ASCII(xmlTextReaderValue(reader));
		if (*text == '\n') {
			description->text = NULL;
			free((void *)text);
			return 0;
		}
		description->text = ASCII(xmlTextReaderValue(reader));
	}
	return 0;
}

static int __ps_process_license(xmlTextReaderPtr reader, license_x *license)
{
	if (xmlTextReaderConstXmlLang(reader)) {
		license->lang = strdup(ASCII(xmlTextReaderConstXmlLang(reader)));
		if (license->lang == NULL)
			license->lang = strdup(DEFAULT_LOCALE);
	} else {
		license->lang = strdup(DEFAULT_LOCALE);
	}
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		license->text = ASCII(xmlTextReaderValue(reader));
	return 0;
}

static int __ps_process_capability(xmlTextReaderPtr reader, capability_x *capability)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	resolution_x *tmp1 = NULL;

	if (xmlTextReaderGetAttribute(reader, XMLCHAR("operation-id")))
		capability->operationid = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("operation-id")));

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "resolution")) {
			resolution_x *resolution = malloc(sizeof(resolution_x));
			if (resolution == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(resolution, '\0', sizeof(resolution_x));
			LISTADD(capability->resolution, resolution);
			ret = __ps_process_resolution(reader, resolution);
		} else
			return -1;
		if (ret < 0) {
			_LOGD("Processing capability failed\n");
			return ret;
		}
	}

	if (capability->resolution) {
		LISTHEAD(capability->resolution, tmp1);
		capability->resolution = tmp1;
	}

	return ret;
}

static int __ps_process_datacontrol(xmlTextReaderPtr reader, datacontrol_x *datacontrol)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	capability_x *tmp1 = NULL;

	if (xmlTextReaderGetAttribute(reader, XMLCHAR("provider-id")))
		datacontrol->providerid = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("provider-id")));

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "capability")) {
			capability_x *capability = malloc(sizeof(capability_x));
			if (capability == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(capability, '\0', sizeof(capability_x));
			LISTADD(datacontrol->capability, capability);
			ret = __ps_process_capability(reader, capability);
		} else
			return -1;
		if (ret < 0) {
			_LOGD("Processing datacontrol failed\n");
			return ret;
		}
	}

	if (datacontrol->capability) {
		LISTHEAD(datacontrol->capability, tmp1);
		datacontrol->capability = tmp1;
	}

	return ret;
}

static int __ps_process_uiapplication(xmlTextReaderPtr reader, uiapplication_x *uiapplication, uid_t uid)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	char *newappid = NULL;
	label_x *tmp1 = NULL;
	icon_x *tmp2 = NULL;
	appsvc_x *tmp3 = NULL;
	appcontrol_x *tmp4 = NULL;
	launchconditions_x *tmp5 = NULL;
	notification_x *tmp6 = NULL;
	datashare_x *tmp7 = NULL;
	category_x *tmp8 = NULL;
	metadata_x *tmp9 = NULL;
	image_x *tmp10 = NULL;
	permission_x *tmp11 = NULL;

	if (xmlTextReaderGetAttribute(reader, XMLCHAR("appid"))) {
		uiapplication->appid = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("appid")));
		if (uiapplication->appid == NULL) {
			_LOGD("appid cant be NULL\n");
			return -1;
		}
	} else {
		_LOGD("appid is mandatory\n");
		return -1;
	}
	/*check appid*/
	ret = __validate_appid(package, uiapplication->appid, &newappid);
	if (ret == -1) {
		_LOGD("appid is not proper\n");
		return -1;
	} else {
		if (newappid) {
			if (uiapplication->appid)
				free((void *)uiapplication->appid);
			uiapplication->appid = newappid;
		}
		uiapplication->package= strdup(package);
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("exec")))
		uiapplication->exec = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("exec")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("nodisplay"))) {
		uiapplication->nodisplay = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("nodisplay")));
		if (uiapplication->nodisplay == NULL)
			uiapplication->nodisplay = strdup("false");
	} else {
		uiapplication->nodisplay = strdup("false");
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("multiple"))) {
		uiapplication->multiple = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("multiple")));
		if (uiapplication->multiple == NULL)
			uiapplication->multiple = strdup("false");
	} else {
		uiapplication->multiple = strdup("false");
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("type")))
		uiapplication->type = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("type")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("categories")))
		uiapplication->categories = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("categories")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("extraid")))
		uiapplication->extraid = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("extraid")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("taskmanage"))) {
		uiapplication->taskmanage = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("taskmanage")));
		if (uiapplication->taskmanage == NULL)
			uiapplication->taskmanage = strdup("true");
	} else {
		uiapplication->taskmanage = strdup("true");
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("enabled"))) {
		uiapplication->enabled = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("enabled")));
		if (uiapplication->enabled == NULL)
			uiapplication->enabled = strdup("true");
	} else {
		uiapplication->enabled = strdup("true");
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("hw-acceleration"))) {
		uiapplication->hwacceleration = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("hw-acceleration")));
		if (uiapplication->hwacceleration == NULL)
			uiapplication->hwacceleration = strdup("use-system-setting");
	} else {
		uiapplication->hwacceleration = strdup("use-system-setting");
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("screen-reader"))) {
		uiapplication->screenreader = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("screen-reader")));
		if (uiapplication->screenreader == NULL)
			uiapplication->screenreader = strdup("use-system-setting");
	} else {
		uiapplication->screenreader = strdup("use-system-setting");
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("recentimage")))
		uiapplication->recentimage = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("recentimage")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("mainapp"))) {
		uiapplication->mainapp = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("mainapp")));
		if (uiapplication->mainapp == NULL)
			uiapplication->mainapp = strdup("false");
	} else {
		uiapplication->mainapp = strdup("false");
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("launchcondition"))) {
		uiapplication->launchcondition = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("launchcondition")));
		if (uiapplication->launchcondition == NULL)
			uiapplication->launchcondition = strdup("false");
	} else {
		uiapplication->launchcondition = strdup("false");
	}

	if (xmlTextReaderGetAttribute(reader, XMLCHAR("indicatordisplay"))) {
		uiapplication->indicatordisplay = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("indicatordisplay")));
		if (uiapplication->indicatordisplay == NULL)
			uiapplication->indicatordisplay = strdup("true");
	} else {
		uiapplication->indicatordisplay = strdup("true");
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("portrait-effectimage")))
		uiapplication->portraitimg = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("portrait-effectimage")));
	else
		uiapplication->portraitimg = NULL;
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("landscape-effectimage")))
		uiapplication->landscapeimg = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("landscape-effectimage")));
	else
		uiapplication->landscapeimg = NULL;
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("guestmode-visibility"))) {
		uiapplication->guestmode_visibility = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("guestmode-visibility")));
		if (uiapplication->guestmode_visibility == NULL)
			uiapplication->guestmode_visibility = strdup("true");
	} else {
		uiapplication->guestmode_visibility = strdup("true");
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("permission-type"))) {
		uiapplication->permission_type = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("permission-type")));
		if (uiapplication->permission_type == NULL)
			uiapplication->permission_type = strdup("normal");
	} else {
		uiapplication->permission_type = strdup("normal");
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("component-type"))) {
		uiapplication->component_type = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("component-type")));
		if (uiapplication->component_type == NULL)
			uiapplication->component_type = strdup("uiapp");
	} else {
		uiapplication->component_type = strdup("uiapp");
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("submode"))) {
		uiapplication->submode = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("submode")));
		if (uiapplication->submode == NULL)
			uiapplication->submode = strdup("false");
	} else {
		uiapplication->submode = strdup("false");
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("submode-mainid")))
		uiapplication->submode_mainid = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("submode-mainid")));

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}
		if (!strcmp(ASCII(node), "label")) {
			label_x *label = malloc(sizeof(label_x));
			if (label == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(label, '\0', sizeof(label_x));
			LISTADD(uiapplication->label, label);
			ret = __ps_process_label(reader, label);
		} else if (!strcmp(ASCII(node), "icon")) {
			icon_x *icon = malloc(sizeof(icon_x));
			if (icon == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(icon, '\0', sizeof(icon_x));
			LISTADD(uiapplication->icon, icon);
			ret = __ps_process_icon(reader, icon, uid);
		} else if (!strcmp(ASCII(node), "image")) {
			image_x *image = malloc(sizeof(image_x));
			if (image == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(image, '\0', sizeof(image_x));
			LISTADD(uiapplication->image, image);
			ret = __ps_process_image(reader, image);
		} else if (!strcmp(ASCII(node), "category")) {
			category_x *category = malloc(sizeof(category_x));
			if (category == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(category, '\0', sizeof(category_x));
			LISTADD(uiapplication->category, category);
			ret = __ps_process_category(reader, category);
		} else if (!strcmp(ASCII(node), "metadata")) {
			metadata_x *metadata = malloc(sizeof(metadata_x));
			if (metadata == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(metadata, '\0', sizeof(metadata_x));
			LISTADD(uiapplication->metadata, metadata);
			ret = __ps_process_metadata(reader, metadata);
		} else if (!strcmp(ASCII(node), "permission")) {
			permission_x *permission = malloc(sizeof(permission_x));
			if (permission == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(permission, '\0', sizeof(permission_x));
			LISTADD(uiapplication->permission, permission);
			ret = __ps_process_permission(reader, permission);
		} else if (!strcmp(ASCII(node), "app-control")) {
			appcontrol_x *appcontrol = malloc(sizeof(appcontrol_x));
			if (appcontrol == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(appcontrol, '\0', sizeof(appcontrol_x));
			LISTADD(uiapplication->appcontrol, appcontrol);
			ret = __ps_process_appcontrol(reader, appcontrol);
		} else if (!strcmp(ASCII(node), "application-service")) {
			appsvc_x *appsvc = malloc(sizeof(appsvc_x));
			if (appsvc == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(appsvc, '\0', sizeof(appsvc_x));
			LISTADD(uiapplication->appsvc, appsvc);
			ret = __ps_process_appsvc(reader, appsvc);
		} else if (!strcmp(ASCII(node), "data-share")) {
			datashare_x *datashare = malloc(sizeof(datashare_x));
			if (datashare == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(datashare, '\0', sizeof(datashare_x));
			LISTADD(uiapplication->datashare, datashare);
			ret = __ps_process_datashare(reader, datashare);
		} else if (!strcmp(ASCII(node), "launch-conditions")) {
			launchconditions_x *launchconditions = malloc(sizeof(launchconditions_x));
			if (launchconditions == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(launchconditions, '\0', sizeof(launchconditions_x));
			LISTADD(uiapplication->launchconditions, launchconditions);
			ret = __ps_process_launchconditions(reader, launchconditions);
		} else if (!strcmp(ASCII(node), "notification")) {
			notification_x *notification = malloc(sizeof(notification_x));
			if (notification == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(notification, '\0', sizeof(notification_x));
			LISTADD(uiapplication->notification, notification);
			ret = __ps_process_notification(reader, notification);
		} else
			return -1;
		if (ret < 0) {
			_LOGD("Processing uiapplication failed\n");
			return ret;
		}
	}

	if (uiapplication->label) {
		LISTHEAD(uiapplication->label, tmp1);
		uiapplication->label = tmp1;
	}
	if (uiapplication->icon) {
		LISTHEAD(uiapplication->icon, tmp2);
		uiapplication->icon = tmp2;
	}
	if (uiapplication->appsvc) {
		LISTHEAD(uiapplication->appsvc, tmp3);
		uiapplication->appsvc = tmp3;
	}
	if (uiapplication->appcontrol) {
		LISTHEAD(uiapplication->appcontrol, tmp4);
		uiapplication->appcontrol = tmp4;
	}
	if (uiapplication->launchconditions) {
		LISTHEAD(uiapplication->launchconditions, tmp5);
		uiapplication->launchconditions = tmp5;
	}
	if (uiapplication->notification) {
		LISTHEAD(uiapplication->notification, tmp6);
		uiapplication->notification = tmp6;
	}
	if (uiapplication->datashare) {
		LISTHEAD(uiapplication->datashare, tmp7);
		uiapplication->datashare = tmp7;
	}
	if (uiapplication->category) {
		LISTHEAD(uiapplication->category, tmp8);
		uiapplication->category = tmp8;
	}
	if (uiapplication->metadata) {
		LISTHEAD(uiapplication->metadata, tmp9);
		uiapplication->metadata = tmp9;
	}
	if (uiapplication->image) {
		LISTHEAD(uiapplication->image, tmp10);
		uiapplication->image = tmp10;
	}
	if (uiapplication->permission) {
		LISTHEAD(uiapplication->permission, tmp11);
		uiapplication->permission = tmp11;
	}

	return ret;
}

static int __ps_process_serviceapplication(xmlTextReaderPtr reader, serviceapplication_x *serviceapplication, uid_t uid)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	char *newappid = NULL;
	label_x *tmp1 = NULL;
	icon_x *tmp2 = NULL;
	appsvc_x *tmp3 = NULL;
	appcontrol_x *tmp4 = NULL;
	datacontrol_x *tmp5 = NULL;
	launchconditions_x *tmp6 = NULL;
	notification_x *tmp7 = NULL;
	datashare_x *tmp8 = NULL;
	category_x *tmp9 = NULL;
	metadata_x *tmp10 = NULL;
	permission_x *tmp11 = NULL;

	if (xmlTextReaderGetAttribute(reader, XMLCHAR("appid"))) {
		serviceapplication->appid = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("appid")));
		if (serviceapplication->appid == NULL) {
			_LOGD("appid cant be NULL\n");
			return -1;
		}
	} else {
		_LOGD("appid is mandatory\n");
		return -1;
	}
	/*check appid*/
	ret = __validate_appid(package, serviceapplication->appid, &newappid);
	if (ret == -1) {
		_LOGD("appid is not proper\n");
		return -1;
	} else {
		if (newappid) {
			if (serviceapplication->appid)
				free((void *)serviceapplication->appid);
			serviceapplication->appid = newappid;
		}
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("exec")))
		serviceapplication->exec = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("exec")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("type")))
		serviceapplication->type = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("type")));
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("on-boot"))) {
		serviceapplication->onboot = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("on-boot")));
		if (serviceapplication->onboot == NULL)
			serviceapplication->onboot = strdup("false");
	} else {
		serviceapplication->onboot = strdup("false");
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("auto-restart"))) {
		serviceapplication->autorestart = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("auto-restart")));
		if (serviceapplication->autorestart == NULL)
			serviceapplication->autorestart = strdup("false");
	} else {
		serviceapplication->autorestart = strdup("false");
	}
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("permission-type"))) {
		serviceapplication->permission_type = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("permission-type")));
		if (serviceapplication->permission_type == NULL)
			serviceapplication->permission_type = strdup("normal");
	} else {
		serviceapplication->permission_type = strdup("normal");
	}

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "label")) {
			label_x *label = malloc(sizeof(label_x));
			if (label == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(label, '\0', sizeof(label_x));
			LISTADD(serviceapplication->label, label);
			ret = __ps_process_label(reader, label);
		} else if (!strcmp(ASCII(node), "icon")) {
			icon_x *icon = malloc(sizeof(icon_x));
			if (icon == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(icon, '\0', sizeof(icon_x));
			LISTADD(serviceapplication->icon, icon);
			ret = __ps_process_icon(reader, icon, uid);
		} else if (!strcmp(ASCII(node), "category")) {
			category_x *category = malloc(sizeof(category_x));
			if (category == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(category, '\0', sizeof(category_x));
			LISTADD(serviceapplication->category, category);
			ret = __ps_process_category(reader, category);
		} else if (!strcmp(ASCII(node), "metadata")) {
			metadata_x *metadata = malloc(sizeof(metadata_x));
			if (metadata == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(metadata, '\0', sizeof(metadata_x));
			LISTADD(serviceapplication->metadata, metadata);
			ret = __ps_process_metadata(reader, metadata);
		} else if (!strcmp(ASCII(node), "permission")) {
			permission_x *permission = malloc(sizeof(permission_x));
			if (permission == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(permission, '\0', sizeof(permission_x));
			LISTADD(serviceapplication->permission, permission);
			ret = __ps_process_permission(reader, permission);
		} else if (!strcmp(ASCII(node), "app-control")) {
			appcontrol_x *appcontrol = malloc(sizeof(appcontrol_x));
			if (appcontrol == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(appcontrol, '\0', sizeof(appcontrol_x));
			LISTADD(serviceapplication->appcontrol, appcontrol);
			ret = __ps_process_appcontrol(reader, appcontrol);
		} else if (!strcmp(ASCII(node), "application-service")) {
			appsvc_x *appsvc = malloc(sizeof(appsvc_x));
			if (appsvc == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(appsvc, '\0', sizeof(appsvc_x));
			LISTADD(serviceapplication->appsvc, appsvc);
			ret = __ps_process_appsvc(reader, appsvc);
		} else if (!strcmp(ASCII(node), "data-share")) {
			datashare_x *datashare = malloc(sizeof(datashare_x));
			if (datashare == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(datashare, '\0', sizeof(datashare_x));
			LISTADD(serviceapplication->datashare, datashare);
			ret = __ps_process_datashare(reader, datashare);
		} else if (!strcmp(ASCII(node), "launch-conditions")) {
			launchconditions_x *launchconditions = malloc(sizeof(launchconditions_x));
			if (launchconditions == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(launchconditions, '\0', sizeof(launchconditions_x));
			LISTADD(serviceapplication->launchconditions, launchconditions);
			ret = __ps_process_launchconditions(reader, launchconditions);
		} else if (!strcmp(ASCII(node), "notification")) {
			notification_x *notification = malloc(sizeof(notification_x));
			if (notification == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(notification, '\0', sizeof(notification_x));
			LISTADD(serviceapplication->notification, notification);
			ret = __ps_process_notification(reader, notification);
		} else if (!strcmp(ASCII(node), "data-control")) {
			datacontrol_x *datacontrol = malloc(sizeof(datacontrol_x));
			if (datacontrol == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(datacontrol, '\0', sizeof(datacontrol_x));
			LISTADD(serviceapplication->datacontrol, datacontrol);
			ret = __ps_process_datacontrol(reader, datacontrol);
		} else
			return -1;
		if (ret < 0) {
			_LOGD("Processing serviceapplication failed\n");
			return ret;
		}
	}

	if (serviceapplication->label) {
		LISTHEAD(serviceapplication->label, tmp1);
		serviceapplication->label = tmp1;
	}
	if (serviceapplication->icon) {
		LISTHEAD(serviceapplication->icon, tmp2);
		serviceapplication->icon = tmp2;
	}
	if (serviceapplication->appsvc) {
		LISTHEAD(serviceapplication->appsvc, tmp3);
		serviceapplication->appsvc = tmp3;
	}
	if (serviceapplication->appcontrol) {
		LISTHEAD(serviceapplication->appcontrol, tmp4);
		serviceapplication->appcontrol = tmp4;
	}
	if (serviceapplication->datacontrol) {
		LISTHEAD(serviceapplication->datacontrol, tmp5);
		serviceapplication->datacontrol = tmp5;
	}
	if (serviceapplication->launchconditions) {
		LISTHEAD(serviceapplication->launchconditions, tmp6);
		serviceapplication->launchconditions = tmp6;
	}
	if (serviceapplication->notification) {
		LISTHEAD(serviceapplication->notification, tmp7);
		serviceapplication->notification = tmp7;
	}
	if (serviceapplication->datashare) {
		LISTHEAD(serviceapplication->datashare, tmp8);
		serviceapplication->datashare = tmp8;
	}
	if (serviceapplication->category) {
		LISTHEAD(serviceapplication->category, tmp9);
		serviceapplication->category = tmp9;
	}
	if (serviceapplication->metadata) {
		LISTHEAD(serviceapplication->metadata, tmp10);
		serviceapplication->metadata = tmp10;
	}
	if (serviceapplication->permission) {
		LISTHEAD(serviceapplication->permission, tmp11);
		serviceapplication->permission = tmp11;
	}

	return ret;
}

static int __ps_process_deviceprofile(xmlTextReaderPtr reader, deviceprofile_x *deviceprofile)
{
	/*TODO: once policy is set*/
	return 0;
}

static int __ps_process_font(xmlTextReaderPtr reader, font_x *font)
{
	/*TODO: once policy is set*/
	return 0;
}

static int __ps_process_theme(xmlTextReaderPtr reader, theme_x *theme)
{
	/*TODO: once policy is set*/
	return 0;
}

static int __ps_process_daemon(xmlTextReaderPtr reader, daemon_x *daemon)
{
	/*TODO: once policy is set*/
	return 0;
}

static int __ps_process_ime(xmlTextReaderPtr reader, ime_x *ime)
{
	/*TODO: once policy is set*/
	return 0;
}

static int __start_process(xmlTextReaderPtr reader, manifest_x * mfx, uid_t uid)
{
	_LOGD("__start_process\n");
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	label_x *tmp1 = NULL;
	author_x *tmp2 = NULL;
	description_x *tmp3 = NULL;
	license_x *tmp4 = NULL;
	uiapplication_x *tmp5 = NULL;
	serviceapplication_x *tmp6 = NULL;
	daemon_x *tmp7 = NULL;
	theme_x *tmp8 = NULL;
	font_x *tmp9 = NULL;
	ime_x *tmp10 = NULL;
	icon_x *tmp11 = NULL;
	compatibility_x *tmp12 = NULL;
	deviceprofile_x *tmp13 = NULL;
	privileges_x *tmp14 = NULL;

	depth = xmlTextReaderDepth(reader);
	int  i =0;
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "label")) {
			label_x *label = malloc(sizeof(label_x));
			if (label == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(label, '\0', sizeof(label_x));
			LISTADD(mfx->label, label);
			ret = __ps_process_label(reader, label);
		} else if (!strcmp(ASCII(node), "author")) {
			author_x *author = malloc(sizeof(author_x));
			if (author == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(author, '\0', sizeof(author_x));
			LISTADD(mfx->author, author);
			ret = __ps_process_author(reader, author);
		} else if (!strcmp(ASCII(node), "description")) {
			description_x *description = malloc(sizeof(description_x));
			if (description == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(description, '\0', sizeof(description_x));
			LISTADD(mfx->description, description);
			ret = __ps_process_description(reader, description);
		} else if (!strcmp(ASCII(node), "license")) {
			license_x *license = malloc(sizeof(license_x));
			if (license == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(license, '\0', sizeof(license_x));
			LISTADD(mfx->license, license);
			ret = __ps_process_license(reader, license);
		} else if (!strcmp(ASCII(node), "privileges")) {
			privileges_x *privileges = malloc(sizeof(privileges_x));
			if (privileges == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(privileges, '\0', sizeof(privileges_x));
			LISTADD(mfx->privileges, privileges);
			ret = __ps_process_privileges(reader, privileges);
		} else if (!strcmp(ASCII(node), "ui-application")) {
			uiapplication_x *uiapplication = malloc(sizeof(uiapplication_x));
			if (uiapplication == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(uiapplication, '\0', sizeof(uiapplication_x));
			LISTADD(mfx->uiapplication, uiapplication);
			ret = __ps_process_uiapplication(reader, uiapplication, uid);
		} else if (!strcmp(ASCII(node), "service-application")) {
			serviceapplication_x *serviceapplication = malloc(sizeof(serviceapplication_x));
			if (serviceapplication == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(serviceapplication, '\0', sizeof(serviceapplication_x));
			LISTADD(mfx->serviceapplication, serviceapplication);
			ret = __ps_process_serviceapplication(reader, serviceapplication, uid);
		} else if (!strcmp(ASCII(node), "daemon")) {
			daemon_x *daemon = malloc(sizeof(daemon_x));
			if (daemon == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(daemon, '\0', sizeof(daemon_x));
			LISTADD(mfx->daemon, daemon);
			ret = __ps_process_daemon(reader, daemon);
		} else if (!strcmp(ASCII(node), "theme")) {
			theme_x *theme = malloc(sizeof(theme_x));
			if (theme == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(theme, '\0', sizeof(theme_x));
			LISTADD(mfx->theme, theme);
			ret = __ps_process_theme(reader, theme);
		} else if (!strcmp(ASCII(node), "font")) {
			font_x *font = malloc(sizeof(font_x));
			if (font == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(font, '\0', sizeof(font_x));
			LISTADD(mfx->font, font);
			ret = __ps_process_font(reader, font);
		} else if (!strcmp(ASCII(node), "ime")) {
			ime_x *ime = malloc(sizeof(ime_x));
			if (ime == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(ime, '\0', sizeof(ime_x));
			LISTADD(mfx->ime, ime);
			ret = __ps_process_ime(reader, ime);
		} else if (!strcmp(ASCII(node), "icon")) {
			icon_x *icon = malloc(sizeof(icon_x));
			if (icon == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(icon, '\0', sizeof(icon_x));
			LISTADD(mfx->icon, icon);
			ret = __ps_process_icon(reader, icon, uid);
		} else if (!strcmp(ASCII(node), "device-profile")) {
			deviceprofile_x *deviceprofile = malloc(sizeof(deviceprofile_x));
			if (deviceprofile == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(deviceprofile, '\0', sizeof(deviceprofile_x));
			LISTADD(mfx->deviceprofile, deviceprofile);
			ret = __ps_process_deviceprofile(reader, deviceprofile);
		} else if (!strcmp(ASCII(node), "compatibility")) {
			compatibility_x *compatibility = malloc(sizeof(compatibility_x));
			if (compatibility == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			memset(compatibility, '\0', sizeof(compatibility_x));
			LISTADD(mfx->compatibility, compatibility);
			ret = __ps_process_compatibility(reader, compatibility);
		} else if (!strcmp(ASCII(node), "shortcut-list")) {
			continue;
		} else if (!strcmp(ASCII(node), "livebox")) {
			continue;
		} else if (!strcmp(ASCII(node), "account")) {
			continue;
		} else if (!strcmp(ASCII(node), "notifications")) {
			continue;
		} else if (!strcmp(ASCII(node), "ime")) {
			continue;
		} else
			return -1;

		if (ret < 0) {
			_LOGD("Processing manifest failed\n");
			return ret;
		}
	}
	if (mfx->label) {
		LISTHEAD(mfx->label, tmp1);
		mfx->label = tmp1;
	}
	if (mfx->author) {
		LISTHEAD(mfx->author, tmp2);
		mfx->author = tmp2;
	}
	if (mfx->description) {
		LISTHEAD(mfx->description, tmp3);
		mfx->description= tmp3;
	}
	if (mfx->license) {
		LISTHEAD(mfx->license, tmp4);
		mfx->license= tmp4;
	}
	if (mfx->uiapplication) {
		LISTHEAD(mfx->uiapplication, tmp5);
		mfx->uiapplication = tmp5;
	}
	if (mfx->serviceapplication) {
		LISTHEAD(mfx->serviceapplication, tmp6);
		mfx->serviceapplication = tmp6;
	}
	if (mfx->daemon) {
		LISTHEAD(mfx->daemon, tmp7);
		mfx->daemon= tmp7;
	}
	if (mfx->theme) {
		LISTHEAD(mfx->theme, tmp8);
		mfx->theme= tmp8;
	}
	if (mfx->font) {
		LISTHEAD(mfx->font, tmp9);
		mfx->font= tmp9;
	}
	if (mfx->ime) {
		LISTHEAD(mfx->ime, tmp10);
		mfx->ime= tmp10;
	}
	if (mfx->icon) {
		LISTHEAD(mfx->icon, tmp11);
		mfx->icon= tmp11;
	}
	if (mfx->compatibility) {
		LISTHEAD(mfx->compatibility, tmp12);
		mfx->compatibility= tmp12;
	}
	if (mfx->deviceprofile) {
		LISTHEAD(mfx->deviceprofile, tmp13);
		mfx->deviceprofile= tmp13;
	}
	if (mfx->privileges) {
		LISTHEAD(mfx->privileges, tmp14);
		mfx->privileges = tmp14;
	}
	return ret;
}

static int __process_manifest(xmlTextReaderPtr reader, manifest_x * mfx, uid_t uid)
{
	const xmlChar *node;
	int ret = -1;

	if ((ret = __next_child_element(reader, -1))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "manifest")) {
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("xmlns"))){
				mfx->ns = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("xmlns")));
			}
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("package"))) {
				mfx->package= ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("package")));
				if (mfx->package == NULL) {
					_LOGD("package cant be NULL\n");
					return -1;
				}
			} else {
				_LOGD("package field is mandatory\n");
				return -1;
			}
			package = mfx->package;
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("version")))
				mfx->version= ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("version")));
			/*app2ext needs package size for external installation*/
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("size")))
				mfx->package_size = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("size")));
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("install-location")))
				mfx->installlocation = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("install-location")));
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("type")))
				mfx->type = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("type")));
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("root_path")))
				mfx->root_path = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("root_path")));
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("csc_path")))
				mfx->csc_path = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("csc_path")));
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("main_package")))
				mfx->main_package = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("main_package")));
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("appsetting"))) {
				mfx->appsetting = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("appsetting")));
				if (mfx->appsetting == NULL)
					mfx->appsetting = strdup("false");
			} else {
				mfx->appsetting = strdup("false");
			}
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("storeclient-id")))
				mfx->storeclient_id= ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("storeclient-id")));
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("nodisplay-setting"))) {
				mfx->nodisplay_setting = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("nodisplay-setting")));
				if (mfx->nodisplay_setting == NULL)
					mfx->nodisplay_setting = strdup("false");
			} else {
				mfx->nodisplay_setting = strdup("false");
			}
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("url")))
				mfx->package_url= ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("url")));
			/*Assign default values. If required it will be overwritten in __add_preload_info()*/
			mfx->preload = strdup("False");
			mfx->removable = strdup("True");
			mfx->readonly = strdup("False");
			mfx->update = strdup("False");
			mfx->system = strdup("False");
			char buf[PKG_STRING_LEN_MAX] = {'\0'};
			char *val = NULL;
			time_t current_time;
			time(&current_time);
			snprintf(buf, PKG_STRING_LEN_MAX - 1, "%d", current_time);
			val = strndup(buf, PKG_STRING_LEN_MAX - 1);
			mfx->installed_time = val;
			mfx->installed_storage= strdup("installed_internal");

			ret = __start_process(reader, mfx, uid);
		} else {
			_LOGD("No Manifest element found\n");
			return -1;
		}
	}
	return ret;
}

static char* __convert_to_system_locale(const char *mlocale)
{
	if (mlocale == NULL)
		return NULL;
	char *locale = NULL;
	locale = (char *)calloc(1, 6);
	if (!locale) {
		_LOGE("Malloc Failed\n");
		return NULL;
	}

	strncpy(locale, mlocale, 2);
	strncat(locale, "_", 1);
	locale[3] = toupper(mlocale[3]);
	locale[4] = toupper(mlocale[4]);
	return locale;
}

#define LIBAIL_PATH LIB_PATH "/libail.so.0"

/* operation_type */
typedef enum {
	AIL_INSTALL = 0,
	AIL_UPDATE,
	AIL_REMOVE,
	AIL_CLEAN,
	AIL_FOTA,
	AIL_MAX
} AIL_TYPE;

static int __ail_change_info(int op, const char *appid, uid_t uid)
{
	void *lib_handle = NULL;
	char *aop = NULL;
	int ret = 0;

	if ((lib_handle = dlopen(LIBAIL_PATH, RTLD_LAZY)) == NULL) {
		_LOGE("dlopen is failed LIBAIL_PATH[%s]\n", LIBAIL_PATH);
		goto END;
	}
//is_admin
	if(uid != GLOBAL_USER)
	{
		int (*ail_desktop_operation) (const char *, uid_t uid);
		switch (op) {
			case 0:
				aop  = "ail_usr_desktop_add";
				break;
			case 1:
				aop  = "ail_usr_desktop_update";
				break;
			case 2:
				aop  = "ail_usr_desktop_remove";
				break;
			case 3:
				aop  = "ail_usr_desktop_clean";
				break;
			case 4:
				aop  = "ail_usr_desktop_fota";
				break;
			default:
				goto END;
				break;
		}

		if ((ail_desktop_operation =
			dlsym(lib_handle, aop)) == NULL || dlerror() != NULL) {
			_LOGE("can not find symbol \n");
			goto END;
		}

		ret = ail_desktop_operation(appid, uid);
	}else{
		int (*ail_desktop_operation) (const char *);
		switch (op) {
			case 0:
				aop  = "ail_desktop_add";
				break;
			case 1:
				aop  = "ail_desktop_update";
				break;
			case 2:
				aop  = "ail_desktop_remove";
				break;
			case 3:
				aop  = "ail_desktop_clean";
				break;
			case 4:
				aop  = "ail_desktop_fota";
				break;
			default:
				goto END;
				break;
		}

		if ((ail_desktop_operation =
			dlsym(lib_handle, aop)) == NULL || dlerror() != NULL) {
			_LOGE("can not find symbol \n");
			goto END;
		}

		ret = ail_desktop_operation(appid);

	}
END:
	if (lib_handle)
		dlclose(lib_handle);

	return ret;
}

/* desktop shoud be generated automatically based on manifest */
/* Currently removable, taskmanage, etc fields are not considerd. it will be decided soon.*/
#define BUFMAX 1024*128
static int __ps_make_nativeapp_desktop(manifest_x * mfx, const char *manifest, ACTION_TYPE action, uid_t uid)
{
        FILE* file = NULL;
        int fd = 0;
        char filepath[PKG_STRING_LEN_MAX] = "";
        char *buf = NULL;
	char *buftemp = NULL;
	char *locale = NULL;

	buf = (char *)calloc(1, BUFMAX);
	if (!buf) {
		_LOGE("Malloc Failed\n");
		return -1;
	}

	buftemp = (char *)calloc(1, BUFMAX);
	if (!buftemp) {
		_LOGE("Malloc Failed\n");
		free(buf);
		return -1;
	}

	if (action == ACTION_UPGRADE)
		__ail_change_info(AIL_CLEAN, mfx->package, uid);

	for(; mfx->uiapplication; mfx->uiapplication=mfx->uiapplication->next) {

		if (manifest != NULL) {
			/* skip making a deskfile and update ail, if preload app is updated */
			if(strstr(manifest, getUserManifestPath(uid))) {
				__ail_change_info(AIL_INSTALL, mfx->uiapplication->appid, uid);
	            _LOGE("preload app is update : skip and update ail : %s", manifest);
				continue;
			}
		}

		snprintf(filepath, sizeof(filepath),"%s%s.desktop", getUserDesktopPath(uid), mfx->uiapplication->appid);

		/* skip if desktop exists
		if (access(filepath, R_OK) == 0)
			continue;
		*/

	        file = fopen(filepath, "w");
	        if(file == NULL)
	        {
	            _LOGD("Can't open %s", filepath);
		    free(buf);
		    free(buftemp);
	            return -1;
	        }

	        snprintf(buf, BUFMAX, "[Desktop Entry]\n");
	        fwrite(buf, 1, strlen(buf), file);

		for( ; mfx->uiapplication->label ; mfx->uiapplication->label = mfx->uiapplication->label->next) {
			if(!strcmp(mfx->uiapplication->label->lang, DEFAULT_LOCALE)) {
				snprintf(buf, BUFMAX, "Name=%s\n",	mfx->uiapplication->label->text);
			} else {
				locale = __convert_to_system_locale(mfx->uiapplication->label->lang);
				snprintf(buf, BUFMAX, "Name[%s]=%s\n", locale,
					mfx->uiapplication->label->text);
				free(locale);
			}
	        	fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->label && mfx->uiapplication->label->text) {
		        snprintf(buf, BUFMAX, "Name=%s\n", mfx->uiapplication->label->text);
	        	fwrite(buf, 1, strlen(buf), file);
		}
/*
		else if(mfx->label && mfx->label->text) {
			snprintf(buf, BUFMAX, "Name=%s\n", mfx->label->text);
	        	fwrite(buf, 1, strlen(buf), file);
		} else {
			snprintf(buf, BUFMAX, "Name=%s\n", mfx->package);
			fwrite(buf, 1, strlen(buf), file);
		}
*/


	        snprintf(buf, BUFMAX, "Type=Application\n");
	        fwrite(buf, 1, strlen(buf), file);

		if(mfx->uiapplication->exec) {
		        snprintf(buf, BUFMAX, "Exec=%s\n", mfx->uiapplication->exec);
		        fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->icon && mfx->uiapplication->icon->text) {
		        snprintf(buf, BUFMAX, "Icon=%s\n", mfx->uiapplication->icon->text);
		        fwrite(buf, 1, strlen(buf), file);
		} else if(mfx->icon && mfx->icon->text) {
		        snprintf(buf, BUFMAX, "Icon=%s\n", mfx->icon->text);
		        fwrite(buf, 1, strlen(buf), file);
		}

		// MIME types
		if(mfx->uiapplication && mfx->uiapplication->appsvc) {
			appsvc_x *asvc = mfx->uiapplication->appsvc;
			mime_x *mi = NULL;
			const char *mime = NULL;
			const char *mime_delim = "; ";
			int mime_count = 0;

			strncpy(buf, "MimeType=", BUFMAX-1);
			while (asvc) {
				mi = asvc->mime;
				while (mi) {
					mime_count++;
					mime = mi->name;
					_LOGD("MIME type: %s\n", mime);
					strncat(buf, mime, BUFMAX-strlen(buf)-1);
					if(mi->next) {
						strncat(buf, mime_delim, BUFMAX-strlen(buf)-1);
					}

					mi = mi->next;
					mime = NULL;
				}
				asvc = asvc->next;
			}
			_LOGD("MIME types: buf[%s]\n", buf);
			_LOGD("MIME count: %d\n", mime_count);
			if(mime_count)
				fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->version) {
		        snprintf(buf, BUFMAX, "Version=%s\n", mfx->version);
		        fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->nodisplay) {
			snprintf(buf, BUFMAX, "NoDisplay=%s\n", mfx->uiapplication->nodisplay);
			fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->categories) {
			snprintf(buf, BUFMAX, "Categories=%s\n", mfx->uiapplication->categories);
			fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->taskmanage && !strcasecmp(mfx->uiapplication->taskmanage, "False")) {
		        snprintf(buf, BUFMAX, "X-TIZEN-TaskManage=False\n");
		        fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->enabled && !strcasecmp(mfx->uiapplication->enabled, "False")) {
		        snprintf(buf, BUFMAX, "X-TIZEN-Enabled=False\n");
		        fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->hwacceleration) {
			snprintf(buf, BUFMAX, "Hw-Acceleration=%s\n", mfx->uiapplication->hwacceleration);
			fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->multiple && !strcasecmp(mfx->uiapplication->multiple, "True")) {
			snprintf(buf, BUFMAX, "X-TIZEN-Multiple=True\n");
			fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->extraid) {
			snprintf(buf, BUFMAX, "X-TIZEN-PackageID=%s\n", mfx->uiapplication->extraid);
			fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->removable && !strcasecmp(mfx->removable, "False")) {
			snprintf(buf, BUFMAX, "X-TIZEN-Removable=False\n");
			fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->type) {
			snprintf(buf, BUFMAX, "X-TIZEN-PackageType=%s\n", mfx->type);
			fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->submode && !strcasecmp(mfx->uiapplication->submode, "True")) {
			snprintf(buf, BUFMAX, "X-TIZEN-Submode=%s\n", mfx->uiapplication->submode);
			fwrite(buf, 1, strlen(buf), file);
			snprintf(buf, BUFMAX, "X-TIZEN-SubmodeMainid=%s\n", mfx->uiapplication->submode_mainid);
			fwrite(buf, 1, strlen(buf), file);
		}

		snprintf(buf, BUFMAX, "X-TIZEN-PkgID=%s\n", mfx->package);
		fwrite(buf, 1, strlen(buf), file);


//		snprintf(buf, BUFMAX, "X-TIZEN-PackageType=rpm\n");
//		fwrite(buf, 1, strlen(buf), file);


		if(mfx->uiapplication->appsvc) {
			snprintf(buf, BUFMAX, "X-TIZEN-Svc=");
			_LOGD("buf[%s]\n", buf);


			uiapplication_x *up = mfx->uiapplication;
			appsvc_x *asvc = NULL;
			operation_x *op = NULL;
			mime_x *mi = NULL;
			uri_x *ui = NULL;
			subapp_x *sub = NULL;
			const char *operation = NULL;
			const char *mime = NULL;
			const char *uri = NULL;
			const char *subapp = NULL;
			int i = 0;


			asvc = up->appsvc;
			while(asvc != NULL) {
				op = asvc->operation;
				while(op != NULL) {
					if (op)
						operation = op->name;
					mi = asvc->mime;

					do
					{
						if (mi)
							mime = mi->name;
						sub = asvc->subapp;
						do
						{
							if (sub)
								subapp = sub->name;
							ui = asvc->uri;
							do
							{
								if (ui)
									uri = ui->name;

								if(i++ > 0) {
									strncpy(buftemp, buf, BUFMAX);
									snprintf(buf, BUFMAX, "%s;", buftemp);
								}


								strncpy(buftemp, buf, BUFMAX);
								snprintf(buf, BUFMAX, "%s%s|%s|%s|%s", buftemp, operation?operation:"NULL", uri?uri:"NULL", mime?mime:"NULL", subapp?subapp:"NULL");
								_LOGD("buf[%s]\n", buf);

								if (ui)
									ui = ui->next;
								uri = NULL;
							} while(ui != NULL);
						if (sub)
								sub = sub->next;
							subapp = NULL;
						}while(sub != NULL);
						if (mi)
							mi = mi->next;
						mime = NULL;
					}while(mi != NULL);
					if (op)
						op = op->next;
					operation = NULL;
				}
				asvc = asvc->next;
			}


			fwrite(buf, 1, strlen(buf), file);

//			strncpy(buftemp, buf, BUFMAX);
//			snprintf(buf, BUFMAX, "%s\n", buftemp);
//			fwrite(buf, 1, strlen(buf), file);
		}

		if(mfx->uiapplication->appcontrol) {
			snprintf(buf, BUFMAX, "X-TIZEN-Svc=");
			_LOGD("buf[%s]\n", buf);

			uiapplication_x *up = mfx->uiapplication;
			appcontrol_x *acontrol = NULL;
			operation_x *op = NULL;
			mime_x *mi = NULL;
			uri_x *ui = NULL;
			subapp_x *sub = NULL;
			const char *operation = NULL;
			const char *mime = NULL;
			const char *uri = NULL;
			const char *subapp = NULL;
			int i = 0;

			acontrol = up->appcontrol;
			while(acontrol != NULL) {
				op = acontrol->operation;
				while(op != NULL) {
					if (op)
						operation = op->name;
					mi = acontrol->mime;

					do
					{
						if (mi)
							mime = mi->name;
						sub = acontrol->subapp;
						do
						{
							if (sub)
								subapp = sub->name;
							ui = acontrol->uri;
							do
							{
								if (ui)
									uri = ui->name;

								if(i++ > 0) {
									strncpy(buftemp, buf, BUFMAX);
									snprintf(buf, BUFMAX, "%s;", buftemp);
								}

								strncpy(buftemp, buf, BUFMAX);
								snprintf(buf, BUFMAX, "%s%s|%s|%s|%s", buftemp, operation?operation:"NULL", uri?uri:"NULL", mime?mime:"NULL", subapp?subapp:"NULL");
								_LOGD("buf[%s]\n", buf);

								if (ui)
									ui = ui->next;
								uri = NULL;
							} while(ui != NULL);
						if (sub)
								sub = sub->next;
							subapp = NULL;
						}while(sub != NULL);
						if (mi)
							mi = mi->next;
						mime = NULL;
					}while(mi != NULL);
					if (op)
						op = op->next;
					operation = NULL;
				}
				acontrol = acontrol->next;
			}


			fwrite(buf, 1, strlen(buf), file);

//			strncpy(buftemp, buf, BUFMAX);
//			snprintf(buf, BUFMAX, "%s\n", buftemp);
//			fwrite(buf, 1, strlen(buf), file);
		}

		fflush(file);
	        fd = fileno(file);
	        fsync(fd);
	        fclose(file);
		if (action == ACTION_FOTA)
			__ail_change_info(AIL_FOTA, mfx->uiapplication->appid, uid);
		else
			__ail_change_info(AIL_INSTALL, mfx->uiapplication->appid, uid);
	}

	free(buf);
	free(buftemp);

        return 0;
}

static int __ps_remove_nativeapp_desktop(manifest_x *mfx, uid_t uid)
{
	char filepath[PKG_STRING_LEN_MAX] = "";
	int ret = 0;
	uiapplication_x *uiapplication = mfx->uiapplication;

	for(; uiapplication; uiapplication=uiapplication->next) {
	        snprintf(filepath, sizeof(filepath),"%s%s.desktop", getUserDesktopPath(uid), uiapplication->appid);

		__ail_change_info(AIL_REMOVE, uiapplication->appid, uid);

		ret = remove(filepath);
		if (ret <0)
			return -1;
	}

        return 0;
}

#define LIBAPPSVC_PATH LIB_PATH "/libappsvc.so.0"

static int __ps_remove_appsvc_db(manifest_x *mfx)
{
	void *lib_handle = NULL;
	int (*appsvc_operation) (const char *);
	int ret = 0;
	uiapplication_x *uiapplication = mfx->uiapplication;

	if ((lib_handle = dlopen(LIBAPPSVC_PATH, RTLD_LAZY)) == NULL) {
		_LOGE("dlopen is failed LIBAIL_PATH[%s]\n", LIBAPPSVC_PATH);
		goto END;
	}

	if ((appsvc_operation =
		 dlsym(lib_handle, "appsvc_unset_defapp")) == NULL || dlerror() != NULL) {
		_LOGE("can not find symbol \n");
		goto END;
	}

	for(; uiapplication; uiapplication=uiapplication->next) {
		ret = appsvc_operation(uiapplication->appid);
		if (ret <0)
			_LOGE("can not operation  symbol \n");
	}

END:
	if (lib_handle)
		dlclose(lib_handle);

	return ret;
}

#define PRELOAD_PACKAGE_LIST SYSCONFDIR "/package-manager/preload/preload_list.txt"
static int __add_preload_info(manifest_x * mfx, const char *manifest, uid_t uid)
{
	FILE *fp = NULL;
	char buffer[1024] = { 0 };
	int state = 0;

	if(strstr(manifest, getUserManifestPath(uid))) {
		free((void *)mfx->readonly);
		mfx->readonly = strdup("True");

		free((void *)mfx->preload);
		mfx->preload = strdup("True");

		free((void *)mfx->removable);
		mfx->removable = strdup("False");

		free((void *)mfx->system);
		mfx->system = strdup("True");

		return 0;
	}

	fp = fopen(PRELOAD_PACKAGE_LIST, "r");
	if (fp == NULL) {
		_LOGE("no preload list\n");
		return -1;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (buffer[0] == '#') {
			if(strcasestr(buffer, "RW_NORM"))
				state = 2;
			else if(strcasestr(buffer, "RW_RM"))
				state = 3;
			else
				continue;
		}

		__str_trim(buffer);

		if(!strcmp(mfx->package, buffer)) {
			free((void *)mfx->preload);
			mfx->preload = strdup("True");
			if(state == 2){
				free((void *)mfx->readonly);
				mfx->readonly = strdup("False");
				free((void *)mfx->removable);
				mfx->removable = strdup("False");
			} else if(state == 3){
				free((void *)mfx->readonly);
				mfx->readonly = strdup("False");
				free((void *)mfx->removable);
				mfx->removable = strdup("True");
			}
		}

		memset(buffer, 0x00, sizeof(buffer));
	}

	if (fp != NULL)
		fclose(fp);

	return 0;
}

static int __check_preload_updated(manifest_x * mfx, const char *manifest, uid_t uid)
{
	char filepath[PKG_STRING_LEN_MAX] = "";
	int ret = 0;
	uiapplication_x *uiapplication = mfx->uiapplication;

	if(strstr(manifest, getUserManifestPath(uid))) {
		/* if preload app is updated, then remove previous desktop file on RW*/
		for(; uiapplication; uiapplication=uiapplication->next) {
				snprintf(filepath, sizeof(filepath),"%s%s.desktop", getUserDesktopPath(uid), uiapplication->appid);
			ret = remove(filepath);
			if (ret <0)
				return -1;
		}
	} else {
		/* if downloaded app is updated, then update tag set true*/
		free((void *)mfx->update);
		mfx->update = strdup("true");
	}

	return 0;
}


API int pkgmgr_parser_create_desktop_file(manifest_x *mfx)
{
        int ret = 0;
	if (mfx == NULL) {
		_LOGD("Manifest pointer is NULL\n");
		return -1;
	}
        ret = __ps_make_nativeapp_desktop(mfx, NULL, ACTION_INSTALL, GLOBAL_USER);
        if (ret == -1)
                _LOGD("Creating desktop file failed\n");
        else
                _LOGD("Creating desktop file Success\n");
        return ret;
}

API int pkgmgr_parser_create_usr_desktop_file(manifest_x *mfx, uid_t uid)
{
        int ret = 0;
	if (mfx == NULL) {
		_LOGD("Manifest pointer is NULL\n");
		return -1;
	}
        ret = __ps_make_nativeapp_desktop(mfx, NULL, ACTION_INSTALL, uid);
        if (ret == -1)
                _LOGD("Creating desktop file failed\n");
        else
                _LOGD("Creating desktop file Success\n");
        return ret;
}


API void pkgmgr_parser_free_manifest_xml(manifest_x *mfx)
{
	if (mfx == NULL)
		return;
	if (mfx->ns) {
		free((void *)mfx->ns);
		mfx->ns = NULL;
	}
	if (mfx->package) {
		free((void *)mfx->package);
		mfx->package = NULL;
	}
	if (mfx->version) {
		free((void *)mfx->version);
		mfx->version = NULL;
	}
	if (mfx->installlocation) {
		free((void *)mfx->installlocation);
		mfx->installlocation = NULL;
	}
	if (mfx->preload) {
		free((void *)mfx->preload);
		mfx->preload = NULL;
	}
	if (mfx->readonly) {
		free((void *)mfx->readonly);
		mfx->readonly = NULL;
	}
	if (mfx->removable) {
		free((void *)mfx->removable);
		mfx->removable = NULL;
	}
	if (mfx->update) {
		free((void *)mfx->update);
		mfx->update = NULL;
	}
	if (mfx->system) {
		free((void *)mfx->system);
		mfx->system = NULL;
	}
	if (mfx->type) {
		free((void *)mfx->type);
		mfx->type = NULL;
	}
	if (mfx->package_size) {
		free((void *)mfx->package_size);
		mfx->package_size = NULL;
	}
	if (mfx->installed_time) {
		free((void *)mfx->installed_time);
		mfx->installed_time = NULL;
	}
	if (mfx->installed_storage) {
		free((void *)mfx->installed_storage);
		mfx->installed_storage = NULL;
	}
	if (mfx->storeclient_id) {
		free((void *)mfx->storeclient_id);
		mfx->storeclient_id = NULL;
	}
	if (mfx->mainapp_id) {
		free((void *)mfx->mainapp_id);
		mfx->mainapp_id = NULL;
	}
	if (mfx->package_url) {
		free((void *)mfx->package_url);
		mfx->package_url = NULL;
	}
	if (mfx->root_path) {
		free((void *)mfx->root_path);
		mfx->root_path = NULL;
	}
	if (mfx->csc_path) {
		free((void *)mfx->csc_path);
		mfx->csc_path = NULL;
	}
	if (mfx->appsetting) {
		free((void *)mfx->appsetting);
		mfx->appsetting = NULL;
	}
	if (mfx->nodisplay_setting) {
		free((void *)mfx->nodisplay_setting);
		mfx->nodisplay_setting = NULL;
	}
	if (mfx->main_package) {
		free((void *)mfx->main_package);
		mfx->main_package = NULL;
	}

	/*Free Icon*/
	if (mfx->icon) {
		icon_x *icon = mfx->icon;
		icon_x *tmp = NULL;
		while(icon != NULL) {
			tmp = icon->next;
			__ps_free_icon(icon);
			icon = tmp;
		}
	}
	/*Free Label*/
	if (mfx->label) {
		label_x *label = mfx->label;
		label_x *tmp = NULL;
		while(label != NULL) {
			tmp = label->next;
			__ps_free_label(label);
			label = tmp;
		}
	}
	/*Free Author*/
	if (mfx->author) {
		author_x *author = mfx->author;
		author_x *tmp = NULL;
		while(author != NULL) {
			tmp = author->next;
			__ps_free_author(author);
			author = tmp;
		}
	}
	/*Free Description*/
	if (mfx->description) {
		description_x *description = mfx->description;
		description_x *tmp = NULL;
		while(description != NULL) {
			tmp = description->next;
			__ps_free_description(description);
			description = tmp;
		}
	}
	/*Free License*/
	if (mfx->license) {
		license_x *license = mfx->license;
		license_x *tmp = NULL;
		while(license != NULL) {
			tmp = license->next;
			__ps_free_license(license);
			license = tmp;
		}
	}
	/*Free Privileges*/
	if (mfx->privileges) {
		privileges_x *privileges = mfx->privileges;
		privileges_x *tmp = NULL;
		while(privileges != NULL) {
			tmp = privileges->next;
			__ps_free_privileges(privileges);
			privileges = tmp;
		}
	}
	/*Free UiApplication*/
	if (mfx->uiapplication) {
		uiapplication_x *uiapplication = mfx->uiapplication;
		uiapplication_x *tmp = NULL;
		while(uiapplication != NULL) {
			tmp = uiapplication->next;
			__ps_free_uiapplication(uiapplication);
			uiapplication = tmp;
		}
	}
	/*Free ServiceApplication*/
	if (mfx->serviceapplication) {
		serviceapplication_x *serviceapplication = mfx->serviceapplication;
		serviceapplication_x *tmp = NULL;
		while(serviceapplication != NULL) {
			tmp = serviceapplication->next;
			__ps_free_serviceapplication(serviceapplication);
			serviceapplication = tmp;
		}
	}
	/*Free Daemon*/
	if (mfx->daemon) {
		daemon_x *daemon = mfx->daemon;
		daemon_x *tmp = NULL;
		while(daemon != NULL) {
			tmp = daemon->next;
			__ps_free_daemon(daemon);
			daemon = tmp;
		}
	}
	/*Free Theme*/
	if (mfx->theme) {
		theme_x *theme = mfx->theme;
		theme_x *tmp = NULL;
		while(theme != NULL) {
			tmp = theme->next;
			__ps_free_theme(theme);
			theme = tmp;
		}
	}
	/*Free Font*/
	if (mfx->font) {
		font_x *font = mfx->font;
		font_x *tmp = NULL;
		while(font != NULL) {
			tmp = font->next;
			__ps_free_font(font);
			font = tmp;
		}
	}
	/*Free Ime*/
	if (mfx->ime) {
		ime_x *ime = mfx->ime;
		ime_x *tmp = NULL;
		while(ime != NULL) {
			tmp = ime->next;
			__ps_free_ime(ime);
			ime = tmp;
		}
	}
	/*Free Compatibility*/
	if (mfx->compatibility) {
		compatibility_x *compatibility = mfx->compatibility;
		compatibility_x *tmp = NULL;
		while(compatibility != NULL) {
			tmp = compatibility->next;
			__ps_free_compatibility(compatibility);
			compatibility = tmp;
		}
	}
	/*Free DeviceProfile*/
	if (mfx->deviceprofile) {
		deviceprofile_x *deviceprofile = mfx->deviceprofile;
		deviceprofile_x *tmp = NULL;
		while(deviceprofile != NULL) {
			tmp = deviceprofile->next;
			__ps_free_deviceprofile(deviceprofile);
			deviceprofile = tmp;
		}
	}
	free((void*)mfx);
	mfx = NULL;
	return;
}

API manifest_x *pkgmgr_parser_process_manifest_xml(const char *manifest)
{
	_LOGD("parsing start pkgmgr_parser_process_manifest_xml\n");
	xmlTextReaderPtr reader;
	manifest_x *mfx = NULL;

	reader = xmlReaderForFile(manifest, NULL, 0);
	if (reader) {
		mfx = malloc(sizeof(manifest_x));
		if (mfx) {
			memset(mfx, '\0', sizeof(manifest_x));
			if (__process_manifest(reader, mfx, GLOBAL_USER) < 0) {
				_LOGD("Parsing Failed\n");
				pkgmgr_parser_free_manifest_xml(mfx);
				mfx = NULL;
			} else
				_LOGD("Parsing Success\n");
		} else {
			_LOGD("Memory allocation error\n");
		}
		xmlFreeTextReader(reader);
	} else {
		_LOGD("Unable to create xml reader\n");
	}
	return mfx;
}


API manifest_x *pkgmgr_parser_usr_process_manifest_xml(const char *manifest, uid_t uid)
{
	_LOGD("parsing start pkgmgr_parser_usr_process_manifest_xml\n");
	xmlTextReaderPtr reader;
	manifest_x *mfx = NULL;

	reader = xmlReaderForFile(manifest, NULL, 0);
	if (reader) {
		mfx = malloc(sizeof(manifest_x));
		if (mfx) {
			memset(mfx, '\0', sizeof(manifest_x));
			if (__process_manifest(reader, mfx, uid) < 0) {
				_LOGD("Parsing Failed\n");
				pkgmgr_parser_free_manifest_xml(mfx);
				mfx = NULL;
			} else
				_LOGD("Parsing Success\n");
		} else {
			_LOGD("Memory allocation error\n");
		}
		xmlFreeTextReader(reader);
	} else {
		_LOGD("Unable to create xml reader\n");
	}
	return mfx;
}

/* These APIs are intended to call parser directly */

API int pkgmgr_parser_parse_manifest_for_installation(const char *manifest, char *const tagv[])
{
//	char *temp[] = {"shortcut-list", "livebox", "account", "notifications", "privileges", "ime", "font", NULL};
	retvm_if(manifest == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	_LOGD("parsing manifest for installation: %s\n", manifest);

	manifest_x *mfx = NULL;
	int ret = -1;

	xmlInitParser();
	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	retvm_if(mfx == NULL, PMINFO_R_ERROR, "argument supplied is NULL");

	_LOGD("Parsing Finished\n");

//	__streamFile(manifest, ACTION_INSTALL, temp, mfx->package);
	__ps_process_tag_parser(mfx, manifest, ACTION_INSTALL);
	__add_preload_info(mfx, manifest, GLOBAL_USER);

	_LOGD("Added preload infomation\n");

	__ps_process_tag(mfx, tagv);

	ret = pkgmgr_parser_insert_manifest_info_in_db(mfx);
	retvm_if(ret == PMINFO_R_ERROR, PMINFO_R_ERROR, "DB Insert failed");

	_LOGD("DB Insert Success\n");

	ret = __ps_process_metadata_parser(mfx, ACTION_INSTALL);
	if (ret == -1)
		_LOGD("Creating metadata parser failed\n");

	ret = __ps_process_category_parser(mfx, ACTION_INSTALL);
	if (ret == -1)
		_LOGD("Creating category parser failed\n");

	if (__check_action_fota(tagv))
		ret = __ps_make_nativeapp_desktop(mfx, NULL, ACTION_FOTA, GLOBAL_USER);
	else
		ret = __ps_make_nativeapp_desktop(mfx, NULL, ACTION_INSTALL, GLOBAL_USER);

	if (ret == -1)
		_LOGD("Creating desktop file failed\n");
	else
		_LOGD("Creating desktop file Success\n");

	pkgmgr_parser_free_manifest_xml(mfx);
	_LOGD("Free Done\n");
	xmlCleanupParser();

	return PMINFO_R_OK;
}
API int pkgmgr_parser_parse_usr_manifest_for_installation(const char *manifest, uid_t uid, char *const tagv[])
{
//	char *temp[] = {"shortcut-list", "livebox", "account", "notifications", "privileges", "ime", "font", NULL};
	retvm_if(manifest == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	_LOGD("parsing manifest for installation: %s\n", manifest);
	manifest_x *mfx = NULL;
	int ret = -1;

	xmlInitParser();
	mfx = pkgmgr_parser_usr_process_manifest_xml(manifest, uid);
	retvm_if(mfx == NULL, PMINFO_R_ERROR, "argument supplied is NULL");

	_LOGD("Parsing Finished\n");
//	__streamFile(manifest, ACTION_INSTALL, temp, mfx->package);
	__ps_process_tag_parser(mfx, manifest, ACTION_INSTALL);
	__add_preload_info(mfx, manifest, uid);

	_LOGD("Added preload infomation\n");
	__ps_process_tag(mfx, tagv);

	ret = pkgmgr_parser_insert_manifest_info_in_usr_db(mfx, uid);
	retvm_if(ret == PMINFO_R_ERROR, PMINFO_R_ERROR, "DB Insert failed");

	_LOGD("DB Insert Success\n");
	ret = __ps_process_metadata_parser(mfx, ACTION_INSTALL);
	if (ret == -1)
		_LOGD("Creating metadata parser failed\n");
	ret = __ps_process_category_parser(mfx, ACTION_INSTALL);
	if (ret == -1)
		_LOGD("Creating category parser failed\n");

	if (__check_action_fota(tagv))
		ret = __ps_make_nativeapp_desktop(mfx, NULL, ACTION_FOTA, uid);
	else
		ret = __ps_make_nativeapp_desktop(mfx, NULL, ACTION_INSTALL, uid);

	if (ret == -1)
		_LOGD("Creating desktop file failed\n");
	else
		_LOGD("Creating desktop file Success\n");
	pkgmgr_parser_free_manifest_xml(mfx);
	_LOGD("Free Done\n");
	xmlCleanupParser();

	return PMINFO_R_OK;
}

API int pkgmgr_parser_parse_manifest_for_upgrade(const char *manifest, char *const tagv[])
{
//	char *temp[] = {"shortcut-list", "livebox", "account", "notifications", "privileges", "ime", "font", NULL};
	retvm_if(manifest == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	_LOGD("pkgmgr_parser_parse_manifest_for_upgrade  parsing manifest for upgradation: %s\n", manifest);
	manifest_x *mfx = NULL;
	int ret = -1;
	bool preload = false;
	bool system = false;
	char *csc_path = NULL;
	pkgmgrinfo_pkginfo_h handle = NULL;

	xmlInitParser();
	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	retvm_if(mfx == NULL, PMINFO_R_ERROR, "argument supplied is NULL");

	_LOGD("Parsing Finished\n");
//	__streamFile(manifest, ACTION_UPGRADE, temp, mfx->package);
	__ps_process_tag_parser(mfx, manifest, ACTION_UPGRADE);
	__add_preload_info(mfx, manifest, GLOBAL_USER);
	_LOGD("Added preload infomation\n");
	__check_preload_updated(mfx, manifest, GLOBAL_USER);

	ret = pkgmgrinfo_pkginfo_get_pkginfo(mfx->package, &handle);
	if (ret != PMINFO_R_OK)
		_LOGD("pkgmgrinfo_pkginfo_get_pkginfo failed\n");
	ret = pkgmgrinfo_pkginfo_is_preload(handle, &preload);
	if (ret != PMINFO_R_OK)
		_LOGD("pkgmgrinfo_pkginfo_is_preload failed\n");

	if (preload) {
		free((void *)mfx->preload);
		mfx->preload = strdup("true");
	}

	ret = pkgmgrinfo_pkginfo_is_system(handle, &system);
	if (ret != PMINFO_R_OK)
		_LOGD("pkgmgrinfo_pkginfo_is_system failed\n");
	if (system) {
		free((void *)mfx->system);
		mfx->system = strdup("true");
	}

	ret = pkgmgrinfo_pkginfo_get_csc_path(handle, &csc_path);
	if (ret != PMINFO_R_OK)
		_LOGD("pkgmgrinfo_pkginfo_get_csc_path failed\n");
	
	if (csc_path != NULL) {
		if (mfx->csc_path)
			free((void *)mfx->csc_path);
		mfx->csc_path = strdup(csc_path);
	}

	ret = pkgmgr_parser_update_manifest_info_in_db(mfx);
	retvm_if(ret == PMINFO_R_ERROR, PMINFO_R_ERROR, "DB Insert failed");
	_LOGD("DB Update Success\n");
	ret = __ps_process_metadata_parser(mfx, ACTION_UPGRADE);
	if (ret == -1){
		_LOGD("Upgrade metadata parser failed\n");
	}
	ret = __ps_process_category_parser(mfx, ACTION_UPGRADE);
	if (ret == -1)
		_LOGD("Creating category parser failed\n");
	ret = __ps_make_nativeapp_desktop(mfx, manifest, ACTION_UPGRADE, GLOBAL_USER);
	if (ret == -1)
		_LOGD("Creating desktop file failed\n");
	else
		_LOGD("Creating desktop file Success\n");
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	pkgmgr_parser_free_manifest_xml(mfx);
	_LOGD("Free Done\n");
	xmlCleanupParser();

	return PMINFO_R_OK;
}

API int pkgmgr_parser_parse_usr_manifest_for_upgrade(const char *manifest, uid_t uid, char *const tagv[])
{
//	char *temp[] = {"shortcut-list", "livebox", "account", "notifications", "privileges", "ime", "font", NULL};
	retvm_if(manifest == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	_LOGD(" pkgmgr_parser_parse_usr_manifest_for_upgrade parsing manifest for upgradation: %s\n", manifest);
	manifest_x *mfx = NULL;
	int ret = -1;
	bool preload = false;
	bool system = false;
	char *csc_path = NULL;
	pkgmgrinfo_pkginfo_h handle = NULL;

	xmlInitParser();
	mfx = pkgmgr_parser_usr_process_manifest_xml(manifest, uid);
	retvm_if(mfx == NULL, PMINFO_R_ERROR, "argument supplied is NULL");

	_LOGD("Parsing Finished\n");
	//__streamFile(manifest, ACTION_UPGRADE, temp, mfx->package);
	__ps_process_tag_parser(mfx, manifest, ACTION_UPGRADE);
	__add_preload_info(mfx, manifest, uid);
	_LOGD("Added preload infomation\n");
	_LOGE("Added preload infomation\n");
	__check_preload_updated(mfx, manifest, uid);

	ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(mfx->package, uid, &handle);
	if (ret != PMINFO_R_OK)
		_LOGD("pkgmgrinfo_pkginfo_get_pkginfo failed\n");
	ret = pkgmgrinfo_pkginfo_is_preload(handle, &preload);
	if (ret != PMINFO_R_OK)
		_LOGD("pkgmgrinfo_pkginfo_is_preload failed\n");

	if (preload) {
		free((void *)mfx->preload);
		mfx->preload = strdup("true");
	}

	ret = pkgmgrinfo_pkginfo_is_system(handle, &system);
	if (ret != PMINFO_R_OK)
		_LOGD("pkgmgrinfo_pkginfo_is_system failed\n");

	if (system) {
		free((void *)mfx->system);
		mfx->system = strdup("true");
	}

	ret = pkgmgrinfo_pkginfo_get_csc_path(handle, &csc_path);
	if (ret != PMINFO_R_OK)
		_LOGD("pkgmgrinfo_pkginfo_get_csc_path failed\n");
	if (csc_path != NULL) {
		if (mfx->csc_path)
			free((void *)mfx->csc_path);
		mfx->csc_path = strdup(csc_path);
	}

	ret = pkgmgr_parser_update_manifest_info_in_usr_db(mfx, uid);
	retvm_if(ret == PMINFO_R_ERROR, PMINFO_R_ERROR, "DB Insert failed");
	_LOGD("DB Update Success\n");
	_LOGE("DB Update Success\n" );
	ret = __ps_process_metadata_parser(mfx, ACTION_UPGRADE);
	if (ret == -1)
		_LOGD("Upgrade metadata parser failed\n");
	ret = __ps_process_category_parser(mfx, ACTION_UPGRADE);
	if (ret == -1)
		_LOGD("Creating category parser failed\n");
	ret = __ps_make_nativeapp_desktop(mfx, manifest, ACTION_UPGRADE, uid);
	if (ret == -1)
		_LOGD("Creating desktop file failed\n");
	else
		_LOGD("Creating desktop file Success\n");
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	pkgmgr_parser_free_manifest_xml(mfx);
	_LOGD("Free Done\n");
	xmlCleanupParser();

	return PMINFO_R_OK;
}

API int pkgmgr_parser_parse_manifest_for_uninstallation(const char *manifest, char *const tagv[])
{
//	char *temp[] = {"shortcut-list", "livebox", "account", "notifications", "privileges", "ime", "font", NULL};
	retvm_if(manifest == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	_LOGD("parsing manifest for uninstallation: %s\n", manifest);

	manifest_x *mfx = NULL;
	int ret = -1;
	xmlInitParser();
	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	retvm_if(mfx == NULL, PMINFO_R_ERROR, "argument supplied is NULL");

	_LOGD("Parsing Finished\n");

//	__streamFile(manifest, ACTION_UNINSTALL, temp, mfx->package);
	__ps_process_tag_parser(mfx, manifest, ACTION_UNINSTALL);

	__add_preload_info(mfx, manifest, GLOBAL_USER);
	_LOGD("Added preload infomation\n");

	ret = __ps_process_metadata_parser(mfx, ACTION_UNINSTALL);
	if (ret == -1)
		_LOGD("Removing metadata parser failed\n");

	ret = __ps_process_category_parser(mfx, ACTION_UNINSTALL);
	if (ret == -1)
		_LOGD("Creating category parser failed\n");

	ret = pkgmgr_parser_delete_manifest_info_from_db(mfx);
	if (ret == -1)
		_LOGD("DB Delete failed\n");
	else
		_LOGD("DB Delete Success\n");

	ret = __ps_remove_nativeapp_desktop(mfx, GLOBAL_USER);
	if (ret == -1)
		_LOGD("Removing desktop file failed\n");
	else
		_LOGD("Removing desktop file Success\n");

	ret = __ps_remove_appsvc_db(mfx);
	if (ret == -1)
		_LOGD("Removing appsvc_db failed\n");
	else
		_LOGD("Removing appsvc_db Success\n");

	pkgmgr_parser_free_manifest_xml(mfx);
	_LOGD("Free Done\n");
	xmlCleanupParser();

	return PMINFO_R_OK;
}


API int pkgmgr_parser_parse_usr_manifest_for_uninstallation(const char *manifest, uid_t uid, char *const tagv[])
{
//	char *temp[] = {"shortcut-list", "livebox", "account", "notifications", "privileges", "ime", "font", NULL};
	retvm_if(manifest == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	_LOGD("parsing manifest for uninstallation: %s\n", manifest);

	manifest_x *mfx = NULL;
	int ret = -1;
	xmlInitParser();
	mfx = pkgmgr_parser_usr_process_manifest_xml(manifest, uid);
	retvm_if(mfx == NULL, PMINFO_R_ERROR, "argument supplied is NULL");

	_LOGD("Parsing Finished\n");

//	__streamFile(manifest, ACTION_UNINSTALL, temp, mfx->package);
	__ps_process_tag_parser(mfx, manifest, ACTION_UNINSTALL);

	__add_preload_info(mfx, manifest, uid);
	_LOGD("Added preload infomation\n");

	ret = __ps_process_metadata_parser(mfx, ACTION_UNINSTALL);
	if (ret == -1)
		_LOGD("Removing metadata parser failed\n");

	ret = __ps_process_category_parser(mfx, ACTION_UNINSTALL);
	if (ret == -1)
		_LOGD("Creating category parser failed\n");

	ret = pkgmgr_parser_delete_manifest_info_from_usr_db(mfx, uid);
	if (ret == -1)
		_LOGD("DB Delete failed\n");
	else
		_LOGD("DB Delete Success\n");

	ret = __ps_remove_nativeapp_desktop(mfx, uid);
	if (ret == -1)
		_LOGD("Removing desktop file failed\n");
	else
		_LOGD("Removing desktop file Success\n");

	ret = __ps_remove_appsvc_db(mfx);
	if (ret == -1)
		_LOGD("Removing appsvc_db failed\n");
	else
		_LOGD("Removing appsvc_db Success\n");

	pkgmgr_parser_free_manifest_xml(mfx);
	_LOGD("Free Done\n");
	xmlCleanupParser();

	return PMINFO_R_OK;
}

API int pkgmgr_parser_parse_manifest_for_preload()
{
	return pkgmgr_parser_update_preload_info_in_db();
}

API int pkgmgr_parser_parse_usr_manifest_for_preload(uid_t uid)
{
	return pkgmgr_parser_update_preload_info_in_usr_db(uid);
}


API char *pkgmgr_parser_get_usr_manifest_file(const char *pkgid, uid_t uid)
{
	return __pkgid_to_manifest(pkgid, uid);
}

API char *pkgmgr_parser_get_manifest_file(const char *pkgid)
{
	return __pkgid_to_manifest(pkgid, GLOBAL_USER);
}

API int pkgmgr_parser_run_parser_for_installation(xmlDocPtr docPtr, const char *tag, const char *pkgid)
{
	return __ps_run_parser(docPtr, tag, ACTION_INSTALL, pkgid);
}

API int pkgmgr_parser_run_parser_for_upgrade(xmlDocPtr docPtr, const char *tag, const char *pkgid)
{
	return __ps_run_parser(docPtr, tag, ACTION_UPGRADE, pkgid);
}

API int pkgmgr_parser_run_parser_for_uninstallation(xmlDocPtr docPtr, const char *tag, const char *pkgid)
{
	return __ps_run_parser(docPtr, tag, ACTION_UNINSTALL, pkgid);
}

#define SCHEMA_FILE SYSCONFDIR "/package-manager/preload/manifest.xsd"
#if 1
API int pkgmgr_parser_check_manifest_validation(const char *manifest)
{
	if (manifest == NULL) {
		_LOGE("manifest file is NULL\n");
		return PMINFO_R_EINVAL;
	}
	int ret = -1;
	xmlSchemaParserCtxtPtr ctx;
	xmlSchemaValidCtxtPtr vctx;
	xmlSchemaPtr xschema;
	ctx = xmlSchemaNewParserCtxt(SCHEMA_FILE);
	if (ctx == NULL) {
		_LOGE("xmlSchemaNewParserCtxt() Failed\n");
		return PMINFO_R_ERROR;
	}
	xschema = xmlSchemaParse(ctx);
	if (xschema == NULL) {
		_LOGE("xmlSchemaParse() Failed\n");
		return PMINFO_R_ERROR;
	}
	vctx = xmlSchemaNewValidCtxt(xschema);
	if (vctx == NULL) {
		_LOGE("xmlSchemaNewValidCtxt() Failed\n");
		return PMINFO_R_ERROR;
	}
	xmlSchemaSetValidErrors(vctx, (xmlSchemaValidityErrorFunc) fprintf, (xmlSchemaValidityWarningFunc) fprintf, stderr);
	ret = xmlSchemaValidateFile(vctx, manifest, 0);
	if (ret == -1) {
		_LOGE("xmlSchemaValidateFile() failed\n");
		return PMINFO_R_ERROR;
	} else if (ret == 0) {
		_LOGE("Manifest is Valid\n");
		return PMINFO_R_OK;
	} else {
		_LOGE("Manifest Validation Failed with error code %d\n", ret);
		return PMINFO_R_ERROR;
	}
	return PMINFO_R_OK;
}

#else
API int pkgmgr_parser_check_manifest_validation(const char *manifest)
{
	int err = 0;
	int status = 0;
	pid_t pid;

	pid = fork();

	switch (pid) {
	case -1:
		_LOGE("fork failed\n");
		return -1;
	case 0:
		/* child */
		{
			int dev_null_fd = open ("/dev/null", O_RDWR);
			if (dev_null_fd >= 0)
			{
			        dup2 (dev_null_fd, 0);/*stdin*/
			        dup2 (dev_null_fd, 1);/*stdout*/
			        dup2 (dev_null_fd, 2);/*stderr*/
			}

			if (execl("/usr/bin/xmllint", "xmllint", manifest, "--schema",
				SCHEMA_FILE, NULL) < 0) {
				_LOGE("execl error\n");
			}

			_exit(100);
		}
	default:
		/* parent */
		break;
	}

	while ((err = waitpid(pid, &status, WNOHANG)) != pid) {
		if (err < 0) {
			if (errno == EINTR)
				continue;
			_LOGE("waitpid failed\n");
			return -1;
		}
	}


	if(WIFEXITED(status) && !WEXITSTATUS(status))
		return 0;
	else
		return -1;
}
#endif
