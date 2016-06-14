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

#include "pkgmgr-info.h"
#include "pkgmgrinfo_basic.h"
#include "pkgmgrinfo_debug.h"

#include "pkgmgr_parser.h"
#include "pkgmgr_parser_internal.h"
#include "pkgmgr_parser_db.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "PKGMGR_PARSER"

#define ASCII(s) (char *)s
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

/* plugin process_type */
typedef enum {
	PLUGIN_PRE_PROCESS = 0,
	PLUGIN_POST_PROCESS
} PLUGIN_PROCESS_TYPE;

const char *package;

static int __ps_process_label(xmlTextReaderPtr reader, label_x *label);
static int __ps_process_privilege(xmlTextReaderPtr reader, char **privilege);
static int __ps_process_privileges(xmlTextReaderPtr reader, GList **privileges);
static int __ps_process_allowed(xmlTextReaderPtr reader, char **allowed);
static int __ps_process_condition(xmlTextReaderPtr reader, char **condition);
static int __ps_process_notification(xmlTextReaderPtr reader, notification_x *notifiation);
static int __ps_process_category(xmlTextReaderPtr reader, char **category);
static int __ps_process_metadata(xmlTextReaderPtr reader, metadata_x *metadata);
static int __ps_process_permission(xmlTextReaderPtr reader, permission_x *permission);
static int __ps_process_compatibility(xmlTextReaderPtr reader, compatibility_x *compatibility);
static int __ps_process_request(xmlTextReaderPtr reader, char **request);
static int __ps_process_define(xmlTextReaderPtr reader, define_x *define);
static int __ps_process_launchconditions(xmlTextReaderPtr reader, GList **launchconditions);
static int __ps_process_datashare(xmlTextReaderPtr reader, datashare_x *datashare);
static int __ps_process_icon(xmlTextReaderPtr reader, icon_x *icon, uid_t uid);
static int __ps_process_author(xmlTextReaderPtr reader, author_x *author);
static int __ps_process_description(xmlTextReaderPtr reader, description_x *description);
static int __ps_process_license(xmlTextReaderPtr reader, license_x *license);
static int __ps_process_appcontrol(xmlTextReaderPtr reader, GList **appcontrol);
static int __ps_process_datacontrol(xmlTextReaderPtr reader, datacontrol_x *datacontrol);
static int __ps_process_application(xmlTextReaderPtr reader, application_x *application, int type, uid_t uid);
static int __next_child_element(xmlTextReaderPtr reader, int depth);
static int __start_process(xmlTextReaderPtr reader, manifest_x * mfx, uid_t uid);
static int __process_manifest(xmlTextReaderPtr reader, manifest_x * mfx, uid_t uid);
static void __str_trim(char *input);
static char *__get_parser_plugin(const char *type);
API int __is_admin();

static void __save_xml_attribute(xmlTextReaderPtr reader, char *attribute, char **xml_attribute, char *default_value)
{
	xmlChar *attrib_val = xmlTextReaderGetAttribute(reader, XMLCHAR(attribute));
	if (attrib_val) {
		*xml_attribute = strdup((const char *)attrib_val);
		xmlFree(attrib_val);
	} else {
		if (default_value != NULL) {
			*xml_attribute = strdup(default_value);
		}
	}
}

static void __save_xml_lang(xmlTextReaderPtr reader, char **xml_attribute)
{
	const xmlChar *attrib_val = xmlTextReaderConstXmlLang(reader);
	if (attrib_val != NULL)
		*xml_attribute = strdup(ASCII(attrib_val));
	else
		*xml_attribute = strdup(DEFAULT_LOCALE);
}

static void __save_xml_value(xmlTextReaderPtr reader, char **xml_attribute)
{
	xmlTextReaderRead(reader);
	const xmlChar *attrib_val = xmlTextReaderConstValue(reader);

	if (attrib_val)
		*xml_attribute = strdup((const char *)attrib_val);
}

static void __save_xml_installed_time(manifest_x *mfx)
{
	char buf[PKG_STRING_LEN_MAX] = {'\0'};
	char *val = NULL;
	time_t current_time;
	time(&current_time);
	snprintf(buf, PKG_STRING_LEN_MAX - 1, "%d", (int)current_time);
	val = strndup(buf, PKG_STRING_LEN_MAX - 1);
	mfx->installed_time = val;
}

static void __save_xml_root_path(manifest_x *mfx, uid_t uid)
{
	char root[PKG_STRING_LEN_MAX] = { '\0' };
	const char *path;

	if (mfx->root_path)
		return;

	tzplatform_set_user(uid);
	path = tzplatform_getenv((uid == OWNER_ROOT || uid == GLOBAL_USER) ? TZ_SYS_RO_APP : TZ_USER_APP);
	snprintf(root, PKG_STRING_LEN_MAX - 1, "%s/%s", path, mfx->package);

	mfx->root_path = strdup(root);

	tzplatform_reset_user();
}

static void __save_xml_default_value(manifest_x * mfx)
{
	mfx->preload = strdup("False");
	mfx->removable = strdup("True");
	mfx->readonly = strdup("False");
	mfx->update = strdup("False");
	mfx->system = strdup("False");
	mfx->installed_storage= strdup("installed_internal");
	package = mfx->package;
}

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
					free((void *)detail->key);
				if (detail->value)
					free((void *)detail->value);
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
					free((void *)detail->name);

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
	GList *app_tmp;
	application_x *app;
	GList *md_tmp = NULL;
	metadata_x *md;
	char *md_tag = NULL;

	GList *md_list = NULL;
	__metadata_t *md_detail = NULL;

	md_tag = __get_tag_by_key(md_key);
	if (md_tag == NULL) {
		_LOGD("md_tag is NULL\n");
		return -1;
	}

	for (app_tmp = mfx->application; app_tmp; app_tmp = app_tmp->next) {
		app = (application_x *)app_tmp->data;
		if (app == NULL)
			continue;
		for (md_tmp = app->metadata; md_tmp; md_tmp = md_tmp->next) {
			md = (metadata_x *)md_tmp->data;
			if (md == NULL)
				continue;
			//get glist of metadata key and value combination
			memset(buffer, 0x00, 1024);
			snprintf(buffer, 1024, "%s/", md_key);
			if ((md->key && md->value) && (strncmp(md->key, md_key, strlen(md_key)) == 0) && (strncmp(buffer, md->key, strlen(buffer)) == 0)) {
				md_detail = (__metadata_t*) calloc(1, sizeof(__metadata_t));
				if (md_detail == NULL) {
					_LOGD("Memory allocation failed\n");
					goto END;
				}

				md_detail->key = strdup(md->key);
				if (md_detail->key == NULL) {
					_LOGD("Memory allocation failed\n");
					free(md_detail);
					goto END;
				}

				md_detail->value = strdup(md->value);
				if (md_detail->value == NULL) {
					_LOGD("Memory allocation failed\n");
					free((void *)md_detail->key);
					free(md_detail);
					goto END;
				}

				md_list = g_list_append(md_list, (gpointer)md_detail);
				tag_exist = 1;
			}
		}

		//send glist to parser when tags for metadata plugin parser exist.
		if (tag_exist) {
			ret = __ps_run_metadata_parser(md_list, md_tag, action, mfx->package, app->appid);
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
	GList *app_tmp;
	application_x *app;
	GList *category_tmp;
	const char *category;
	char *category_tag = NULL;

	GList *category_list = NULL;
	__category_t *category_detail = NULL;

	category_tag = __get_tag_by_key(category_key);
	if (category_tag == NULL) {
		_LOGD("md_tag is NULL\n");
		return -1;
	}

	for (app_tmp = mfx->application; app_tmp; app_tmp = app_tmp->next) {
		app = (application_x *)app_tmp->data;
		if (app == NULL)
			continue;
		for (category_tmp = app->category; category_tmp; category_tmp = category_tmp->next) {
			category = (const char *)category_tmp->data;
			//get glist of category key and value combination
			memset(buffer, 0x00, 1024);
			snprintf(buffer, 1024, "%s/", category_key);
			if ((category) && (strncmp(category, category_key, strlen(category_key)) == 0)) {
				category_detail = (__category_t*) calloc(1, sizeof(__category_t));
				if (category_detail == NULL) {
					_LOGD("Memory allocation failed\n");
					goto END;
				}

				category_detail->name = strdup(category);
				if (category_detail->name == NULL) {
					_LOGD("Memory allocation failed\n");
					free(category_detail);
					goto END;
				}

				category_list = g_list_append(category_list, (gpointer)category_detail);
				tag_exist = 1;
			}
		}

		//send glist to parser when tags for metadata plugin parser exist.
		if (tag_exist) {
			ret = __ps_run_category_parser(category_list, category_tag, action, mfx->package, app->appid);
			if (ret < 0)
				_LOGD("category_parser failed[%d] for tag[%s]\n", ret, category_tag);
			else
				_LOGD("category_parser success for tag[%s]\n", category_tag);
		}
		__category_parser_clear_dir_list(category_list);
		category_list = NULL;
		tag_exist = 0;
	}

	return 0;
END:
	__category_parser_clear_dir_list(category_list);

	if (category_tag)
		free(category_tag);

	return ret;
}

static void __process_tag(void *lib_handle, xmlTextReaderPtr reader, ACTION_TYPE action, char *tag, const char *pkgid)
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
				__process_tag(lib_handle, reader, action, tag, mfx->package);
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
	int ret = 0;
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
		if (ret < 0)
			break;
	}

	if (fp != NULL)
		fclose(fp);

	return ret;
}

int __ps_process_category_parser(manifest_x *mfx, ACTION_TYPE action)
{
	int ret = 0;
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
		if (ret < 0)
			break;
	}

	if (fp != NULL)
		fclose(fp);

	return ret;
}

static int __ps_process_allowed(xmlTextReaderPtr reader, char **allowed)
{
	__save_xml_value(reader, allowed);
	return 0;
}

static int __ps_process_condition(xmlTextReaderPtr reader, char **condition)
{
	__save_xml_attribute(reader, "name", condition, NULL);
	return 0;
}

static int __ps_process_notification(xmlTextReaderPtr reader, notification_x *notification)
{
	__save_xml_attribute(reader, "name", &notification->name, NULL);
	__save_xml_value(reader, &notification->text);
	return 0;
}

static int __ps_process_category(xmlTextReaderPtr reader, char **category)
{
	__save_xml_attribute(reader, "name", category, NULL);
	return 0;
}

static int __ps_process_privilege(xmlTextReaderPtr reader, char **privilege)
{
	__save_xml_value(reader, privilege);
	return 0;
}

static int __ps_process_metadata(xmlTextReaderPtr reader, metadata_x *metadata)
{
	__save_xml_attribute(reader, "key", &metadata->key, NULL);
	__save_xml_attribute(reader, "value", &metadata->value, NULL);
	return 0;
}

static int __ps_process_permission(xmlTextReaderPtr reader, permission_x *permission)
{
	__save_xml_attribute(reader, "type", &permission->type, NULL);
	__save_xml_value(reader, &permission->value);
	return 0;
}

static int __ps_process_compatibility(xmlTextReaderPtr reader, compatibility_x *compatibility)
{
	__save_xml_attribute(reader, "name", &compatibility->name, NULL);
	__save_xml_value(reader, &compatibility->text);
	return 0;
}

static int __ps_process_request(xmlTextReaderPtr reader, char **request)
{
	__save_xml_value(reader, request);
	return 0;
}

static int __ps_process_define(xmlTextReaderPtr reader, define_x *define)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	char *val;

	__save_xml_attribute(reader, "path", &define->path, NULL);

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "allowed")) {
			val = NULL;
			ret = __ps_process_allowed(reader, &val);
			if (val)
				define->allowed = g_list_append(define->allowed, (gpointer)val);
		} else if (!strcmp(ASCII(node), "request")) {
			val = NULL;
			ret = __ps_process_request(reader, &val);
			if (val)
				define->request = g_list_append(define->request, (gpointer)val);
		} else {
			return -1;
		}
		if (ret < 0) {
			_LOGD("Processing define failed\n");
			return ret;
		}
	}
	return ret;
}

struct appcontrol_data {
	GList *operations;
	GList *uris;
	GList *mimes;
	GList *appcontrols;
	char operation[BUFSIZE];
	char uri[BUFSIZE];
	char mime[BUFSIZE];
};

static void __ps_process_mime(gpointer data, gpointer user_data)
{
	char *mime = (char *)data;
	struct appcontrol_data *ad = (struct appcontrol_data *)user_data;
	appcontrol_x *appcontrol;

	snprintf(ad->mime, sizeof(ad->mime), "%s", mime);

	appcontrol = calloc(1, sizeof(appcontrol_x));
	if (strlen(ad->operation))
		appcontrol->operation = strdup(ad->operation);
	if (strlen(ad->uri))
		appcontrol->uri = strdup(ad->uri);
	appcontrol->mime = strdup(ad->mime);
	ad->appcontrols = g_list_append(ad->appcontrols, appcontrol);
}

static void __ps_process_uri(gpointer data, gpointer user_data)
{
	char *uri = (char *)data;
	struct appcontrol_data *ad = (struct appcontrol_data *)user_data;
	appcontrol_x *appcontrol;

	snprintf(ad->uri, sizeof(ad->uri), "%s", uri);

	if (ad->mimes != NULL) {
		g_list_foreach(ad->mimes, __ps_process_mime, user_data);
	} else {
		appcontrol = calloc(1, sizeof(appcontrol_x));
		if (strlen(ad->operation))
			appcontrol->operation = strdup(ad->operation);
		appcontrol->uri = strdup(ad->uri);
		ad->appcontrols = g_list_append(ad->appcontrols, appcontrol);
	}
}

static void __ps_process_operation(gpointer data, gpointer user_data)
{
	char *operation = (char *)data;
	struct appcontrol_data *ad = (struct appcontrol_data *)user_data;
	appcontrol_x *appcontrol;

	snprintf(ad->operation, sizeof(ad->operation), "%s", operation);

	if (ad->uris != NULL) {
		g_list_foreach(ad->uris, __ps_process_uri, user_data);
	} else if (ad->mimes != NULL) {
		g_list_foreach(ad->mimes, __ps_process_mime, user_data);
	} else {
		appcontrol = calloc(1, sizeof(appcontrol_x));
		appcontrol->operation = strdup(ad->operation);
		ad->appcontrols = g_list_append(ad->appcontrols, appcontrol);
	}
}

static GList *__make_appcontrol_list(GList *operations, GList *uris, GList *mimes)
{
	struct appcontrol_data ad = {0, };

	ad.operations = operations;
	ad.uris = uris;
	ad.mimes = mimes;

	if (ad.operations == NULL)
		return NULL;

	g_list_foreach(ad.operations, __ps_process_operation, (gpointer)&ad);

	return ad.appcontrols;
}

static int __ps_process_appcontrol(xmlTextReaderPtr reader, GList **appcontrol)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	char *val;
	GList *operations = NULL;
	GList *uris = NULL;
	GList *mimes = NULL;
	GList *result;

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth)) > 0) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		val = NULL;
		if (!strcmp(ASCII(node), "operation")) {
			__save_xml_attribute(reader, "name", &val, NULL);
			if (val)
				operations = g_list_append(operations, (gpointer)val);
			_LOGD("operation processing\n");
		} else if (!strcmp(ASCII(node), "uri")) {
			__save_xml_attribute(reader, "name", &val, NULL);
			if (val)
				uris = g_list_append(uris, (gpointer)val);
			_LOGD("uri processing\n");
		} else if (!strcmp(ASCII(node), "mime")) {
			__save_xml_attribute(reader, "name", &val, NULL);
			if (val)
				mimes = g_list_append(mimes, (gpointer)val);
			_LOGD("mime processing\n");
		} else if (!strcmp(ASCII(node), "subapp")) {
			continue;
		} else {
			ret = -1;
		}
	}

	if (ret < 0) {
		_LOGD("Processing appcontrol failed\n");
		g_list_free_full(operations, free);
		g_list_free_full(uris, free);
		g_list_free_full(mimes, free);
		return ret;
	}

	result = __make_appcontrol_list(operations, uris, mimes);
	if (result)
		*appcontrol = g_list_concat(*appcontrol, result);
	else
		ret = -1;

	g_list_free_full(operations, free);
	g_list_free_full(uris, free);
	g_list_free_full(mimes, free);

	return ret;
}

static int __ps_process_privileges(xmlTextReaderPtr reader, GList **privileges)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	char *val;

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (strcmp(ASCII(node), "privilege") == 0) {
			val = NULL;
			ret = __ps_process_privilege(reader, &val);
			if (val)
				*privileges = g_list_append(*privileges, (gpointer)val);
		} else
			return -1;
		if (ret < 0) {
			_LOGD("Processing privileges failed\n");
			return ret;
		}
	}
	return ret;
}

static int __ps_process_launchconditions(xmlTextReaderPtr reader, GList **launchconditions)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	char *val;

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (strcmp(ASCII(node), "condition") == 0) {
			val = NULL;
			ret = __ps_process_condition(reader, &val);
			if (val)
				*launchconditions = g_list_append(*launchconditions, (gpointer)val);
		} else
			return -1;
		if (ret < 0) {
			_LOGD("Processing launchconditions failed\n");
			return ret;
		}
	}

	return ret;
}

static int __ps_process_datashare(xmlTextReaderPtr reader, datashare_x *datashare)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	char *val;
	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "define")) {
			define_x *define = calloc(1, sizeof(define_x));
			if (define == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			datashare->define = g_list_append(datashare->define, define);
			ret = __ps_process_define(reader, define);
		} else if (!strcmp(ASCII(node), "request")) {
			val = NULL;
			ret = __ps_process_request(reader, &val);
			if (val)
				datashare->request = g_list_append(datashare->request, (gpointer)val);
		} else
			return -1;
		if (ret < 0) {
			_LOGD("Processing data-share failed\n");
			return ret;
		}
	}
	return ret;
}

static char *__get_icon_with_path(const char *icon, uid_t uid)
{
	char icon_with_path[BUFSIZE];
	const char *app_path;

	if (!icon || !package)
		return NULL;

	/* just use absolute path */
	if (index(icon, '/'))
		return strdup(icon);

	do {
		if (uid == GLOBAL_USER || uid == OWNER_ROOT) {
			snprintf(icon_with_path, sizeof(icon_with_path),
				"%s%s", getIconPath(uid, true), icon);
			if (access(icon_with_path, F_OK) == 0)
				break;

			snprintf(icon_with_path, sizeof(icon_with_path),
				"%s%s", getIconPath(uid, false), icon);
			if (access(icon_with_path, F_OK) == 0)
				break;

			/* for backward compatibility (.../default/small/...)
			 * this should be removed
			 */
			snprintf(icon_with_path, sizeof(icon_with_path),
				"%sdefault/small/%s",
				getIconPath(uid, true), icon);
			if (access(icon_with_path, F_OK) == 0)
				break;

			snprintf(icon_with_path, sizeof(icon_with_path),
				"%sdefault/small/%s",
				getIconPath(uid, false), icon);
			if (access(icon_with_path, F_OK) == 0)
				break;

			/* If doesn't exist in case of Global app,
			 * try to get icon directly into app's directory
			 */
			app_path = tzplatform_getenv(TZ_SYS_RO_APP);

			snprintf(icon_with_path, sizeof(icon_with_path),
				"%s/%s/%s", app_path, package, icon);
			if (access(icon_with_path, F_OK) == 0)
				break;

			app_path = tzplatform_getenv(TZ_SYS_RW_APP);

			snprintf(icon_with_path, sizeof(icon_with_path),
				"%s/%s/%s", app_path, package, icon);
			if (access(icon_with_path, F_OK) == 0)
				break;
		} else {
			tzplatform_set_user(uid);
			app_path = tzplatform_getenv(TZ_USER_APP);
			tzplatform_reset_user();

			snprintf(icon_with_path, sizeof(icon_with_path),
				"%s/%s/%s", app_path, package, icon);
			if (access(icon_with_path, F_OK) == 0)
				break;
		}

		/* some preload package has icons at below path */
		snprintf(icon_with_path, sizeof(icon_with_path),
				"%s/%s/res/icons/%s", app_path, package, icon);
		if (access(icon_with_path, F_OK) == 0)
			break;

		/* since 2.3 tpk package */
		snprintf(icon_with_path, sizeof(icon_with_path),
				"%s/%s/shared/res/%s", app_path, package, icon);
		if (access(icon_with_path, F_OK) == 0)
			break;

		_LOGE("cannot find icon path for [%s]", icon);
		return NULL;
	} while (0);

	_LOGD("Icon path : %s ---> %s", icon, icon_with_path);

	return strdup(icon_with_path);
}

static void __ps_process_tag(manifest_x * mfx, char *const tagv[])
{
	int i = 0;
	char delims[] = "=";
	char *ret_result = NULL;
	char *tag = NULL;
	char *ptr = NULL;

	if (tagv == NULL)
		return;

	for (tag = strdup(tagv[0]); tag != NULL; ) {
		ret_result = strtok_r(tag, delims, &ptr);

		/*check tag :  preload */
		if (strcmp(ret_result, "preload") == 0) {
			ret_result = strtok_r(NULL, delims, &ptr);
			if (strcmp(ret_result, "true") == 0) {
				free((void *)mfx->preload);
				mfx->preload = strdup("true");
			} else if (strcmp(ret_result, "false") == 0) {
				free((void *)mfx->preload);
				mfx->preload = strdup("false");
			}
		/*check tag :  removable*/
		} else if (strcmp(ret_result, "removable") == 0) {
			ret_result = strtok_r(NULL, delims, &ptr);
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
	__save_xml_attribute(reader, "section", &icon->section, NULL);
	__save_xml_attribute(reader, "size", &icon->size, NULL);
	__save_xml_attribute(reader, "resolution", &icon->resolution, NULL);
	__save_xml_lang(reader, &icon->lang);

	xmlTextReaderRead(reader);
	char *text  = ASCII(xmlTextReaderValue(reader));
	if (text) {
		icon->text = __get_icon_with_path(text, uid);
		free(text);
	}

	return 0;
}

static int __ps_process_image(xmlTextReaderPtr reader, image_x *image)
{
	__save_xml_attribute(reader, "section", &image->section, NULL);
	__save_xml_lang(reader, &image->lang);
	__save_xml_value(reader, &image->text);
	return 0;
}

static int __ps_process_label(xmlTextReaderPtr reader, label_x *label)
{
	__save_xml_attribute(reader, "name", &label->name, NULL);
	__save_xml_lang(reader, &label->lang);
	__save_xml_value(reader, &label->text);
	return 0;

}

static int __ps_process_author(xmlTextReaderPtr reader, author_x *author)
{
	__save_xml_attribute(reader, "email", &author->email, NULL);
	__save_xml_attribute(reader, "href", &author->href, NULL);
	__save_xml_value(reader, &author->text);
	return 0;
}

static int __ps_process_description(xmlTextReaderPtr reader, description_x *description)
{
	__save_xml_lang(reader, &description->lang);
	__save_xml_value(reader, &description->text);
	return 0;
}

static int __ps_process_license(xmlTextReaderPtr reader, license_x *license)
{
	__save_xml_lang(reader, &license->lang);
	__save_xml_value(reader, &license->text);
	return 0;
}

static int __ps_process_datacontrol(xmlTextReaderPtr reader, datacontrol_x *datacontrol)
{
	__save_xml_attribute(reader, "providerid", &datacontrol->providerid, NULL);
	__save_xml_attribute(reader, "access", &datacontrol->access, NULL);
	__save_xml_attribute(reader, "type", &datacontrol->type, NULL);
	return 0;
}

static int __ps_process_splashscreen(xmlTextReaderPtr reader, splashscreen_x *splashscreen)
{
	__save_xml_attribute(reader, "src", &splashscreen->src, NULL);
	__save_xml_attribute(reader, "type", &splashscreen->type, NULL);
	__save_xml_attribute(reader, "dpi", &splashscreen->dpi, NULL);
	__save_xml_attribute(reader, "orientation", &splashscreen->orientation, NULL);
	__save_xml_attribute(reader, "indicator-display", &splashscreen->indicatordisplay, NULL);
	__save_xml_attribute(reader, "app-control-operation", &splashscreen->operation, NULL);
	__save_xml_attribute(reader, "color-depth", &splashscreen->color_depth, NULL);
	return 0;
}

static int __ps_process_splashscreens(xmlTextReaderPtr reader, GList **splashscreens)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	splashscreen_x *splashscreen;

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (strcmp(ASCII(node), "splash-screen") == 0) {
			splashscreen = calloc(1, sizeof(splashscreen_x));
			if (splashscreen == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			*splashscreens = g_list_append(*splashscreens, splashscreen);
			ret = __ps_process_splashscreen(reader, splashscreen);
		} else {
			return -1;
		}

		if (ret < 0) {
			_LOGD("Processing splash-screen failed\n");
			return ret;
		}
	}
	return 0;
}

static int __ps_process_application(xmlTextReaderPtr reader, application_x *application, int type, uid_t uid)
{
	const xmlChar *node;
	int ret = -1;
	int depth = -1;
	char *val;

	__save_xml_attribute(reader, "appid", &application->appid, NULL);
	retvm_if(application->appid == NULL, PM_PARSER_R_ERROR, "appid cant be NULL, appid field is mandatory\n");
	__save_xml_attribute(reader, "exec", &application->exec, NULL);
	__save_xml_attribute(reader, "nodisplay", &application->nodisplay, "false");
	__save_xml_attribute(reader, "multiple", &application->multiple, "false");
	__save_xml_attribute(reader, "type", &application->type, NULL);
	__save_xml_attribute(reader, "categories", &application->categories, NULL);
	__save_xml_attribute(reader, "extraid", &application->extraid, NULL);
	__save_xml_attribute(reader, "taskmanage", &application->taskmanage, "true");
	__save_xml_attribute(reader, "enabled", &application->enabled, "true");
	__save_xml_attribute(reader, "hw-acceleration", &application->hwacceleration, "default");
	__save_xml_attribute(reader, "screen-reader", &application->screenreader, "use-system-setting");
	__save_xml_attribute(reader, "mainapp", &application->mainapp, "false");
	__save_xml_attribute(reader, "recentimage", &application->recentimage, "false");
	__save_xml_attribute(reader, "launchcondition", &application->launchcondition, "false");
	__save_xml_attribute(reader, "indicatordisplay", &application->indicatordisplay, "true");
	__save_xml_attribute(reader, "portrait-effectimage", &application->portraitimg, NULL);
	__save_xml_attribute(reader, "landscape-effectimage", &application->landscapeimg, NULL);
	__save_xml_attribute(reader, "guestmode-visibility", &application->guestmode_visibility, "true");
	__save_xml_attribute(reader, "permission-type", &application->permission_type, "normal");
	__save_xml_attribute(reader, "component-type", &application->component_type, type == PMINFO_UI_APP ? "uiapp" : type == PMINFO_SVC_APP ? "svcapp" : "widgetapp");
	/*component_type has "svcapp" or "uiapp", if it is not, parsing manifest is fail*/
	retvm_if(((strcmp(application->component_type, "svcapp") != 0) && (strcmp(application->component_type, "uiapp") != 0) && (strcmp(application->component_type, "widgetapp") != 0)), PM_PARSER_R_ERROR, "invalid component_type[%s]", application->component_type);
	__save_xml_attribute(reader, "submode", &application->submode, "false");
	__save_xml_attribute(reader, "submode-mainid", &application->submode_mainid, NULL);
	__save_xml_attribute(reader, "process-pool", &application->process_pool, "false");
	__save_xml_attribute(reader, "launch_mode", &application->launch_mode, "caller");
	__save_xml_attribute(reader, "ui-gadget", &application->ui_gadget, "false");
	__save_xml_attribute(reader, "auto-restart", &application->autorestart, "false");
	__save_xml_attribute(reader, "on-boot", &application->onboot, "false");
	__save_xml_attribute(reader, "splash-screen-display", &application->splash_screen_display, "true");

	application->package= strdup(package);
	/* overwrite some attributes if the app is widgetapp */
	if (type == PMINFO_WIDGET_APP || type == PMINFO_WATCH_APP) {
		free((void *)application->nodisplay);
		application->nodisplay = strdup("true");
		free((void *)application->multiple);
		application->multiple = strdup("true");
		free((void *)application->type);
		application->type = strdup("capp");
		free((void *)application->taskmanage);
		application->taskmanage = strdup("false");
		free((void *)application->indicatordisplay);
		application->indicatordisplay = strdup("false");
	}

	/* hw-acceleration values are changed from use-GL/not-use-GL/use-system-setting to on/off/default */
	if (strcmp(application->hwacceleration, "use-GL") == 0) {
		free((void *)application->hwacceleration);
		application->hwacceleration = strdup("on");
	} else if (strcmp(application->hwacceleration, "not-use-GL") == 0) {
		free((void *)application->hwacceleration);
		application->hwacceleration = strdup("off");
	} else if (strcmp(application->hwacceleration, "use-system-setting") == 0) {
		free((void *)application->hwacceleration);
		application->hwacceleration = strdup("default");
	}

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}
		if (!strcmp(ASCII(node), "label")) {
			label_x *label = calloc(1, sizeof(label_x));
			if (label == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			application->label = g_list_append(application->label, label);
			ret = __ps_process_label(reader, label);
		} else if (!strcmp(ASCII(node), "icon")) {
			icon_x *icon = calloc(1, sizeof(icon_x));
			if (icon == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			application->icon = g_list_append(application->icon, icon);
			ret = __ps_process_icon(reader, icon, uid);
		} else if (!strcmp(ASCII(node), "image")) {
			image_x *image = calloc(1, sizeof(image_x));
			if (image == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			application->image = g_list_append(application->image, image);
			ret = __ps_process_image(reader, image);
		} else if (!strcmp(ASCII(node), "category")) {
			val = NULL;
			ret = __ps_process_category(reader, &val);
			if (val)
				application->category = g_list_append(application->category, (gpointer)val);
		} else if (!strcmp(ASCII(node), "metadata")) {
			metadata_x *metadata = calloc(1, sizeof(metadata_x));
			if (metadata == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			application->metadata = g_list_append(application->metadata, metadata);
			ret = __ps_process_metadata(reader, metadata);
		} else if (!strcmp(ASCII(node), "permission")) {
			permission_x *permission = calloc(1, sizeof(permission_x));
			if (permission == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			application->permission = g_list_append(application->permission, permission);
			ret = __ps_process_permission(reader, permission);
		} else if (!strcmp(ASCII(node), "app-control")) {
			ret = __ps_process_appcontrol(reader, &application->appcontrol);
		} else if (!strcmp(ASCII(node), "application-service")) {
			ret = __ps_process_appcontrol(reader, &application->appcontrol);
		} else if (!strcmp(ASCII(node), "data-share")) {
			datashare_x *datashare = calloc(1, sizeof(datashare_x));
			if (datashare == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			application->datashare = g_list_append(application->datashare, datashare);
			ret = __ps_process_datashare(reader, datashare);
		} else if (!strcmp(ASCII(node), "launch-conditions")) {
			ret = __ps_process_launchconditions(reader, &application->launchconditions);
		} else if (!strcmp(ASCII(node), "notification")) {
			notification_x *notification = calloc(1, sizeof(notification_x));
			if (notification == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			application->notification = g_list_append(application->notification, notification);
			ret = __ps_process_notification(reader, notification);
		} else if (!strcmp(ASCII(node), "datacontrol")) {
			datacontrol_x *datacontrol = calloc(1, sizeof(datacontrol_x));
			if (datacontrol == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			application->datacontrol = g_list_append(application->datacontrol, datacontrol);
			ret = __ps_process_datacontrol(reader, datacontrol);
		} else if (!strcmp(ASCII(node), "splash-screens") == 0) {
			ret = __ps_process_splashscreens(reader, &application->splashscreens);
		} else
			continue;
		if (ret < 0) {
			_LOGD("Processing application failed\n");
			return ret;
		}
	}

	return ret;
}

static int __start_process(xmlTextReaderPtr reader, manifest_x * mfx, uid_t uid)
{
	_LOGD("__start_process\n");
	const xmlChar *node;
	int ret = -1;
	int depth = -1;

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGD("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "label")) {
			label_x *label = calloc(1, sizeof(label_x));
			if (label == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			mfx->label = g_list_append(mfx->label, label);
			ret = __ps_process_label(reader, label);
		} else if (!strcmp(ASCII(node), "author")) {
			author_x *author = calloc(1, sizeof(author_x));
			if (author == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			mfx->author = g_list_append(mfx->author, author);
			ret = __ps_process_author(reader, author);
		} else if (!strcmp(ASCII(node), "description")) {
			description_x *description = calloc(1, sizeof(description_x));
			if (description == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			mfx->description = g_list_append(mfx->description, description);
			ret = __ps_process_description(reader, description);
		} else if (!strcmp(ASCII(node), "license")) {
			license_x *license = calloc(1, sizeof(license_x));
			if (license == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			mfx->license = g_list_append(mfx->license, license);
			ret = __ps_process_license(reader, license);
		} else if (!strcmp(ASCII(node), "privileges")) {
			ret = __ps_process_privileges(reader, &mfx->privileges);
		} else if (!strcmp(ASCII(node), "ui-application")) {
			application_x *application = calloc(1, sizeof(application_x));
			if (application == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			mfx->application = g_list_append(mfx->application, application);
			ret = __ps_process_application(reader, application, PMINFO_UI_APP, uid);
		} else if (!strcmp(ASCII(node), "service-application")) {
			application_x *application = calloc(1, sizeof(application_x));
			if (application == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			mfx->application = g_list_append(mfx->application, application);
			ret = __ps_process_application(reader, application, PMINFO_SVC_APP, uid);
		} else if (!strcmp(ASCII(node), "widget-application")) {
			application_x *application = calloc(1, sizeof(application_x));
			if (application == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			mfx->application = g_list_append(mfx->application, application);
			ret = __ps_process_application(reader, application, PMINFO_WIDGET_APP, uid);
		} else if (!strcmp(ASCII(node), "watch-application")) {
			application_x *application = calloc(1, sizeof(application_x));
			if (application == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			mfx->application = g_list_append(mfx->application, application);
			ret = __ps_process_application(reader, application, PMINFO_WATCH_APP, uid);
		} else if (!strcmp(ASCII(node), "icon")) {
			icon_x *icon = calloc(1, sizeof(icon_x));
			if (icon == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			mfx->icon = g_list_append(mfx->icon, icon);
			ret = __ps_process_icon(reader, icon, uid);
		} else if (!strcmp(ASCII(node), "compatibility")) {
			compatibility_x *compatibility = calloc(1, sizeof(compatibility_x));
			if (compatibility == NULL) {
				_LOGD("Malloc Failed\n");
				return -1;
			}
			mfx->compatibility = g_list_append(mfx->compatibility, compatibility);
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
		} else if (!strcmp(ASCII(node), "feature")) {
			continue;
		} else {
			_LOGI("Unknown element: %s", ASCII(node));
			continue;
		}

		if (ret < 0) {
			_LOGD("Processing manifest failed\n");
			return ret;
		}
	}
	return ret;
}

static int __process_manifest(xmlTextReaderPtr reader, manifest_x *mfx, uid_t uid)
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
			__save_xml_attribute(reader, "xmlns", &mfx->ns, NULL);
			__save_xml_attribute(reader, "package", &mfx->package, NULL);
			retvm_if(mfx->package == NULL, PM_PARSER_R_ERROR, "package cant be NULL, package field is mandatory\n");
			__save_xml_attribute(reader, "version", &mfx->version, NULL);
			__save_xml_attribute(reader, "size", &mfx->package_size, NULL);
			__save_xml_attribute(reader, "install-location", &mfx->installlocation, "internal-only");
			__save_xml_attribute(reader, "type", &mfx->type, "tpk");
			__save_xml_attribute(reader, "root_path", &mfx->root_path, NULL);
			__save_xml_attribute(reader, "csc_path", &mfx->csc_path, NULL);
			__save_xml_attribute(reader, "appsetting", &mfx->appsetting, "false");
			__save_xml_attribute(reader, "storeclient-id", &mfx->storeclient_id, NULL);
			__save_xml_attribute(reader, "nodisplay-setting", &mfx->nodisplay_setting, "false");
			__save_xml_attribute(reader, "url", &mfx->package_url, NULL);
			__save_xml_attribute(reader, "api-version", &mfx->api_version, NULL);
			__save_xml_attribute(reader, "support-disable", &mfx->support_disable, "false");

			__save_xml_installed_time(mfx);
			__save_xml_root_path(mfx, uid);
			/*Assign default values. If required it will be overwritten in __add_preload_info()*/
			__save_xml_default_value(mfx);

			ret = __start_process(reader, mfx, uid);
		} else {
			_LOGD("No Manifest element found\n");
			return -1;
		}
	}
	return ret;
}

#define LIBAPPSVC_PATH LIB_PATH "/libappsvc.so.0"

static int __ps_remove_appsvc_db(manifest_x *mfx, uid_t uid)
{
	void *lib_handle = NULL;
	int (*appsvc_operation) (const char *, uid_t);
	int ret = 0;
	GList *tmp;
	application_x *application;

	if ((lib_handle = dlopen(LIBAPPSVC_PATH, RTLD_LAZY)) == NULL) {
		_LOGE("dlopen is failed LIBAPPSVC_PATH[%s]\n", LIBAPPSVC_PATH);
		goto END;
	}

	if ((appsvc_operation =
		 dlsym(lib_handle, "appsvc_unset_defapp")) == NULL || dlerror() != NULL) {
		_LOGE("can not find symbol \n");
		goto END;
	}

	for (tmp = mfx->application; tmp; tmp = tmp->next) {
		application = (application_x *)tmp->data;
		if (application == NULL)
			continue;
		ret = appsvc_operation(application->appid, uid);
		if (ret <0)
			_LOGE("can not operation  symbol \n");
	}

END:
	if (lib_handle)
		dlclose(lib_handle);

	return ret;
}

static int __check_preload_updated(manifest_x * mfx, const char *manifest, uid_t uid)
{
	if (!strstr(manifest, getUserManifestPath(uid,
		strcmp(mfx->preload, "true") == 0))) {
		/* if downloaded app is updated, then update tag set true*/
		if (mfx->update)
			free((void *)mfx->update);
		mfx->update = strdup("true");
	}

	return 0;
}

API void pkgmgr_parser_free_manifest_xml(manifest_x *mfx)
{
	pkgmgrinfo_basic_free_package((package_x *)mfx);
}

DEPRECATED API manifest_x *pkgmgr_parser_process_manifest_xml(const char *manifest)
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


DEPRECATED API manifest_x *pkgmgr_parser_usr_process_manifest_xml(const char *manifest, uid_t uid)
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

API int pkgmgr_parser_usr_update_tep(const char *pkgid, const char *tep_path, uid_t uid)
{
	return pkgmgr_parser_update_tep_info_in_usr_db(pkgid, tep_path, uid);
}

API int pkgmgr_parser_update_tep(const char *pkgid, const char *tep_path)
{
	return pkgmgr_parser_update_tep_info_in_db(pkgid, tep_path);
}

DEPRECATED API int pkgmgr_parser_parse_manifest_for_installation(const char *manifest, char *const tagv[])
{
	retvm_if(manifest == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	_LOGD("parsing manifest for installation: %s\n", manifest);

	manifest_x *mfx = NULL;
	int ret = -1;

	xmlInitParser();
	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	retvm_if(mfx == NULL, PMINFO_R_ERROR, "argument supplied is NULL");

	_LOGD("Parsing Finished\n");

	__ps_process_tag(mfx, tagv);

	ret = pkgmgr_parser_insert_manifest_info_in_db(mfx);
	retvm_if(ret == PMINFO_R_ERROR, PMINFO_R_ERROR, "DB Insert failed");

	_LOGD("DB Insert Success\n");

	__ps_process_tag_parser(mfx, manifest, ACTION_INSTALL);
	ret = __ps_process_metadata_parser(mfx, ACTION_INSTALL);
	if (ret == -1)
		_LOGD("Creating metadata parser failed\n");

	ret = __ps_process_category_parser(mfx, ACTION_INSTALL);
	if (ret == -1)
		_LOGD("Creating category parser failed\n");

	pkgmgr_parser_free_manifest_xml(mfx);
	_LOGD("Free Done\n");
	xmlCleanupParser();

	return PMINFO_R_OK;
}

DEPRECATED API int pkgmgr_parser_parse_usr_manifest_for_installation(const char *manifest, uid_t uid, char *const tagv[])
{
	retvm_if(manifest == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	_LOGD("parsing manifest for installation: %s\n", manifest);
	manifest_x *mfx = NULL;
	int ret = -1;

	xmlInitParser();
	mfx = pkgmgr_parser_usr_process_manifest_xml(manifest, uid);
	retvm_if(mfx == NULL, PMINFO_R_ERROR, "argument supplied is NULL");

	_LOGD("Parsing Finished\n");

	__ps_process_tag(mfx, tagv);

	ret = pkgmgr_parser_insert_manifest_info_in_usr_db(mfx, uid);
	retvm_if(ret == PMINFO_R_ERROR, PMINFO_R_ERROR, "DB Insert failed");

	_LOGD("DB Insert Success\n");

	__ps_process_tag_parser(mfx, manifest, ACTION_INSTALL);
	ret = __ps_process_metadata_parser(mfx, ACTION_INSTALL);
	if (ret == -1)
		_LOGD("Creating metadata parser failed\n");
	ret = __ps_process_category_parser(mfx, ACTION_INSTALL);
	if (ret == -1)
		_LOGD("Creating category parser failed\n");

	pkgmgr_parser_free_manifest_xml(mfx);
	_LOGD("Free Done\n");
	xmlCleanupParser();

	return PMINFO_R_OK;
}

API int pkgmgr_parser_process_manifest_x_for_installation(manifest_x* mfx, const char *manifest) {
	retvm_if(mfx == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	retvm_if(manifest == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	_LOGD("processing manifest_x for installation: %s\n", manifest);
	int ret = -1;

	ret = pkgmgr_parser_insert_manifest_info_in_db(mfx);
	retvm_if(ret == PMINFO_R_ERROR, PMINFO_R_ERROR, "DB Insert failed");
	_LOGD("DB Insert Success\n");

	return PMINFO_R_OK;
}

API int pkgmgr_parser_process_usr_manifest_x_for_installation(manifest_x* mfx, const char *manifest, uid_t uid) {
	retvm_if(mfx == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	retvm_if(manifest == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	_LOGD("processing manifest_x for installation: %s\n", manifest);
	int ret = -1;

	ret = pkgmgr_parser_insert_manifest_info_in_usr_db(mfx, uid);
	retvm_if(ret == PMINFO_R_ERROR, PMINFO_R_ERROR, "DB Insert failed");
	_LOGD("DB Insert Success\n");

	return PMINFO_R_OK;
}

DEPRECATED API int pkgmgr_parser_parse_manifest_for_upgrade(const char *manifest, char *const tagv[])
{
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

	/*Delete from cert table*/
	ret = pkgmgrinfo_delete_certinfo(mfx->package);
	if (ret) {
		_LOGD("Cert Info  DB Delete Failed\n");
		return -1;
	}

	ret = pkgmgr_parser_update_manifest_info_in_db(mfx);
	retvm_if(ret == PMINFO_R_ERROR, PMINFO_R_ERROR, "DB Insert failed");

	_LOGD("DB Update Success\n");

	__ps_process_tag_parser(mfx, manifest, ACTION_UPGRADE);
	ret = __ps_process_metadata_parser(mfx, ACTION_UPGRADE);
	if (ret == -1){
		_LOGD("Upgrade metadata parser failed\n");
	}
	ret = __ps_process_category_parser(mfx, ACTION_UPGRADE);
	if (ret == -1)
		_LOGD("Creating category parser failed\n");
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	pkgmgr_parser_free_manifest_xml(mfx);
	_LOGD("Free Done\n");
	xmlCleanupParser();

	return PMINFO_R_OK;
}

DEPRECATED API int pkgmgr_parser_parse_usr_manifest_for_upgrade(const char *manifest, uid_t uid, char *const tagv[])
{
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

	/*Delete from cert table*/
	ret = pkgmgrinfo_delete_certinfo(mfx->package);
	if (ret) {
		_LOGD("Cert Info  DB Delete Failed\n");
		return -1;
	}

	ret = pkgmgr_parser_update_manifest_info_in_usr_db(mfx, uid);
	retvm_if(ret == PMINFO_R_ERROR, PMINFO_R_ERROR, "DB Insert failed");
	_LOGD("DB Update Success\n");

	__ps_process_tag_parser(mfx, manifest, ACTION_UPGRADE);
	ret = __ps_process_metadata_parser(mfx, ACTION_UPGRADE);
	if (ret == -1)
		_LOGD("Upgrade metadata parser failed\n");
	ret = __ps_process_category_parser(mfx, ACTION_UPGRADE);
	if (ret == -1)
		_LOGD("Creating category parser failed\n");
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	pkgmgr_parser_free_manifest_xml(mfx);
	_LOGD("Free Done\n");
	xmlCleanupParser();

	return PMINFO_R_OK;
}

API int pkgmgr_parser_process_manifest_x_for_upgrade(manifest_x* mfx, const char *manifest) {
	retvm_if(mfx == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	retvm_if(manifest == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	_LOGD("pkgmgr_parser_process_manifest_x_for_upgrade  parsing manifest for upgradation: %s\n", manifest);
	int ret = -1;

	ret = pkgmgr_parser_update_manifest_info_in_db(mfx);
	retvm_if(ret == PMINFO_R_ERROR, PMINFO_R_ERROR, "DB Insert failed");
	_LOGD("DB Update Success\n");

	return PMINFO_R_OK;
}

API int pkgmgr_parser_process_usr_manifest_x_for_upgrade(manifest_x* mfx, const char *manifest, uid_t uid) {
	retvm_if(mfx == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	retvm_if(manifest == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	_LOGD(" pkgmgr_parser_process_usr_manifest_x_for_upgrade parsing manifest for upgradation: %s\n", manifest);
	int ret = -1;

	ret = pkgmgr_parser_update_manifest_info_in_usr_db(mfx, uid);
	retvm_if(ret == PMINFO_R_ERROR, PMINFO_R_ERROR, "DB Insert failed");
	_LOGD("DB Update Success\n");

	return PMINFO_R_OK;
}

API int pkgmgr_parser_parse_manifest_for_uninstallation(const char *manifest, char *const tagv[])
{
	retvm_if(manifest == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	_LOGD("parsing manifest for uninstallation: %s\n", manifest);

	manifest_x *mfx = NULL;
	int ret = -1;
	xmlInitParser();
	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	retvm_if(mfx == NULL, PMINFO_R_ERROR, "argument supplied is NULL");

	_LOGD("Parsing Finished\n");

	__ps_process_tag_parser(mfx, manifest, ACTION_UNINSTALL);

	ret = __ps_process_metadata_parser(mfx, ACTION_UNINSTALL);
	if (ret == -1)
		_LOGD("Removing metadata parser failed\n");

	ret = __ps_process_category_parser(mfx, ACTION_UNINSTALL);
	if (ret == -1)
		_LOGD("Creating category parser failed\n");

	/*Delete from cert table*/
	ret = pkgmgrinfo_delete_certinfo(mfx->package);
	if (ret) {
		_LOGD("Cert Info  DB Delete Failed\n");
		return -1;
	}

	ret = pkgmgr_parser_delete_manifest_info_from_db(mfx);
	if (ret == -1)
		_LOGD("DB Delete failed\n");
	else
		_LOGD("DB Delete Success\n");

	pkgmgr_parser_free_manifest_xml(mfx);
	_LOGD("Free Done\n");
	xmlCleanupParser();

	return PMINFO_R_OK;
}


API int pkgmgr_parser_parse_usr_manifest_for_uninstallation(const char *manifest, uid_t uid, char *const tagv[])
{
	retvm_if(manifest == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	_LOGD("parsing manifest for uninstallation: %s\n", manifest);

	manifest_x *mfx = NULL;
	int ret = -1;
	xmlInitParser();
	mfx = pkgmgr_parser_usr_process_manifest_xml(manifest, uid);
	retvm_if(mfx == NULL, PMINFO_R_ERROR, "argument supplied is NULL");

	_LOGD("Parsing Finished\n");

	__ps_process_tag_parser(mfx, manifest, ACTION_UNINSTALL);

	ret = __ps_process_metadata_parser(mfx, ACTION_UNINSTALL);
	if (ret == -1)
		_LOGD("Removing metadata parser failed\n");

	ret = __ps_process_category_parser(mfx, ACTION_UNINSTALL);
	if (ret == -1)
		_LOGD("Creating category parser failed\n");

	/*Delete from cert table*/
	ret = pkgmgrinfo_delete_certinfo(mfx->package);
	if (ret) {
		_LOGD("Cert Info  DB Delete Failed\n");
		return -1;
	}

	ret = pkgmgr_parser_delete_manifest_info_from_usr_db(mfx, uid);
	if (ret == -1)
		_LOGD("DB Delete failed\n");
	else
		_LOGD("DB Delete Success\n");

	ret = __ps_remove_appsvc_db(mfx, uid);
	if (ret == -1)
		_LOGD("Removing appsvc_db failed\n");
	else
		_LOGD("Removing appsvc_db Success\n");

	pkgmgr_parser_free_manifest_xml(mfx);
	_LOGD("Free Done\n");
	xmlCleanupParser();

	return PMINFO_R_OK;
}

API int pkgmgr_parser_process_manifest_x_for_uninstallation(manifest_x* mfx, const char *manifest) {
	retvm_if(mfx == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	retvm_if(manifest == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	_LOGD("processing manifest_x for uninstallation: %s\n", manifest);

	int ret = -1;
	ret = pkgmgr_parser_delete_manifest_info_from_db(mfx);
	if (ret == -1)
		_LOGD("DB Delete failed\n");
	else
		_LOGD("DB Delete Success\n");

	return PMINFO_R_OK;
}

API int pkgmgr_parser_process_usr_manifest_x_for_uninstallation(manifest_x* mfx, const char *manifest, uid_t uid) {
	retvm_if(mfx == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	retvm_if(manifest == NULL, PMINFO_R_ERROR, "argument supplied is NULL");
	_LOGD("processing manifest_x for uninstallation: %s\n", manifest);

	int ret = -1;

	ret = pkgmgr_parser_delete_manifest_info_from_usr_db(mfx, uid);
	if (ret == -1)
		_LOGD("DB Delete failed\n");
	else
		_LOGD("DB Delete Success\n");

	ret = __ps_remove_appsvc_db(mfx, uid);
	if (ret == -1)
		_LOGD("Removing appsvc_db failed\n");
	else
		_LOGD("Removing appsvc_db Success\n");

	return PMINFO_R_OK;
}

#define SCHEMA_FILE SYSCONFDIR "/package-manager/preload/manifest.xsd"
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
		_LOGD("Manifest is Valid\n");
		return PMINFO_R_OK;
	} else {
		_LOGE("Manifest Validation Failed with error code %d\n", ret);
		return PMINFO_R_ERROR;
	}
	return PMINFO_R_OK;
}

