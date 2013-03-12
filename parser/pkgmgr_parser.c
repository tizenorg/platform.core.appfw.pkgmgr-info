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

#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlschemas.h>
#include <vconf.h>


#include "pkgmgr_parser.h"
#include "pkgmgr_parser_internal.h"
#include "pkgmgr_parser_db.h"
#include "pkgmgr-info.h"

#define MANIFEST_RW_DIRECTORY "/opt/share/packages"
#define MANIFEST_RO_DIRECTORY "/usr/share/packages"
#define ASCII(s) (const char *)s
#define XMLCHAR(s) (const xmlChar *)s

/* operation_type */
typedef enum {
	ACTION_INSTALL = 0,
	ACTION_UPGRADE,
	ACTION_UNINSTALL,
	ACTION_MAX
} ACTION_TYPE;

char *package;

static int __ps_process_label(xmlTextReaderPtr reader, label_x *label);
static int __ps_process_deviceprofile(xmlTextReaderPtr reader, deviceprofile_x *deviceprofile);
static int __ps_process_allowed(xmlTextReaderPtr reader, allowed_x *allowed);
static int __ps_process_operation(xmlTextReaderPtr reader, operation_x *operation);
static int __ps_process_uri(xmlTextReaderPtr reader, uri_x *uri);
static int __ps_process_mime(xmlTextReaderPtr reader, mime_x *mime);
static int __ps_process_subapp(xmlTextReaderPtr reader, subapp_x *subapp);
static int __ps_process_condition(xmlTextReaderPtr reader, condition_x *condition);
static int __ps_process_notification(xmlTextReaderPtr reader, notification_x *notifiation);
static int __ps_process_category(xmlTextReaderPtr reader, category_x *category);
static int __ps_process_compatibility(xmlTextReaderPtr reader, compatibility_x *compatibility);
static int __ps_process_resolution(xmlTextReaderPtr reader, resolution_x *resolution);
static int __ps_process_request(xmlTextReaderPtr reader, request_x *request);
static int __ps_process_define(xmlTextReaderPtr reader, define_x *define);
static int __ps_process_registry(xmlTextReaderPtr reader, registry_x *registry);
static int __ps_process_database(xmlTextReaderPtr reader, database_x *database);
static int __ps_process_appsvc(xmlTextReaderPtr reader, appsvc_x *appsvc);
static int __ps_process_launchconditions(xmlTextReaderPtr reader, launchconditions_x *launchconditions);
static int __ps_process_datashare(xmlTextReaderPtr reader, datashare_x *datashare);
static int __ps_process_layout(xmlTextReaderPtr reader, layout_x *layout);
static int __ps_process_icon(xmlTextReaderPtr reader, icon_x *icon);
static int __ps_process_author(xmlTextReaderPtr reader, author_x *author);
static int __ps_process_description(xmlTextReaderPtr reader, description_x *description);
static int __ps_process_capability(xmlTextReaderPtr reader, capability_x *capability);
static int __ps_process_license(xmlTextReaderPtr reader, license_x *license);
static int __ps_process_appcontrol(xmlTextReaderPtr reader, appcontrol_x *appcontrol);
static int __ps_process_datacontrol(xmlTextReaderPtr reader, datacontrol_x *datacontrol);
static int __ps_process_uiapplication(xmlTextReaderPtr reader, uiapplication_x *uiapplication);
static int __ps_process_serviceapplication(xmlTextReaderPtr reader, serviceapplication_x *serviceapplication);
static int __ps_process_font(xmlTextReaderPtr reader, font_x *font);
static int __ps_process_theme(xmlTextReaderPtr reader, theme_x *theme);
static int __ps_process_daemon(xmlTextReaderPtr reader, daemon_x *daemon);
static int __ps_process_ime(xmlTextReaderPtr reader, ime_x *ime);
static void __ps_free_label(label_x *label);
static void __ps_free_deviceprofile(deviceprofile_x * deviceprofile);
static void __ps_free_allowed(allowed_x *allowed);
static void __ps_free_operation(operation_x *operation);
static void __ps_free_uri(uri_x *uri);
static void __ps_free_mime(mime_x *mime);
static void __ps_free_subapp(subapp_x *subapp);
static void __ps_free_condition(condition_x *condition);
static void __ps_free_notification(notification_x *notifiation);
static void __ps_free_category(category_x *category);
static void __ps_free_compatibility(compatibility_x *compatibility);
static void __ps_free_resolution(resolution_x *resolution);
static void __ps_free_request(request_x *request);
static void __ps_free_define(define_x *define);
static void __ps_free_registry(registry_x *registry);
static void __ps_free_database(database_x *database);
static void __ps_free_appsvc(appsvc_x *appsvc);
static void __ps_free_launchconditions(launchconditions_x *launchconditions);
static void __ps_free_datashare(datashare_x *datashare);
static void __ps_free_layout(layout_x *layout);
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
static char *__pkgid_to_manifest(const char *pkgid);
static int __next_child_element(xmlTextReaderPtr reader, int depth);
static int __start_process(xmlTextReaderPtr reader, manifest_x * mfx);
static int __process_manifest(xmlTextReaderPtr reader, manifest_x * mfx);
static void __str_trim(char *input);
static char *__get_parser_plugin(const char *type);
static int __ps_run_parser(xmlDocPtr docPtr, const char *tag, ACTION_TYPE action, const char *pkgid);
static int __run_parser_prestep(xmlTextReaderPtr reader, ACTION_TYPE action, const char *pkgid);
static void __processNode(xmlTextReaderPtr reader, ACTION_TYPE action, char *const tagv[], const char *pkgid);
static void __streamFile(const char *filename, ACTION_TYPE action, char *const tagv[], const char *pkgid);
static int __validate_appid(const char *pkgid, const char *appid, char **newappid);

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

static int __validate_appid(const char *pkgid, const char *appid, char **newappid)
{
	if (!pkgid || !appid || !newappid) {
		DBG("Arg supplied is NULL\n");
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
			DBG("Malloc failed\n");
			return -1;
		}
		strncpy(newapp, pkgid, pkglen);
		strncat(newapp, appid, applen);
		DBG("new appid is %s\n", newapp);
		*newappid = newapp;
		return 0;
	}
	if (applen < pkglen) {
		DBG("app id is not proper\n");
		*newappid = NULL;
#ifdef _VALIDATE_APPID_
		return -1;
#else
		return 0;
#endif
	}
	if (!strcmp(appid, pkgid)) {
		DBG("appid is proper\n");
		*newappid = NULL;
		return 0;
	}
	else if (strncmp(appid, pkgid, pkglen) == 0) {
		ptr = strstr(appid, pkgid);
		ptr = ptr + pkglen;
		if (strncmp(ptr, ".", 1) == 0) {
			DBG("appid is proper\n");
			*newappid = NULL;
			return 0;
		}
		else {
			DBG("appid is not proper\n");
			*newappid = NULL;
#ifdef _VALIDATE_APPID_
			return -1;
#else
			return 0;
#endif
		}
	} else {
		DBG("appid is not proper\n");
		*newappid = NULL;
#ifdef _VALIDATE_APPID_
		return -1;
#else
		return 0;
#endif
	}
	return 0;
}


static char *__get_parser_plugin(const char *type)
{
	FILE *fp = NULL;
	char buffer[1024] = { 0 };
	char temp_path[1024] = { 0 };
	char *lib_path = NULL;
	char *path = NULL;

	if (type == NULL) {
		DBGE("invalid argument\n");
		return NULL;
	}

	fp = fopen(PKG_PARSER_CONF_PATH, "r");
	if (fp == NULL) {
		DBGE("no matching backendlib\n");
		return NULL;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (buffer[0] == '#')
			continue;

		__str_trim(buffer);

		if ((path = strstr(buffer, PKG_PARSERLIB)) != NULL) {
			DBG("[%s]\n", path);
			path = path + strlen(PKG_PARSERLIB);
			DBG("[%s]\n", path);

			break;
		}

		memset(buffer, 0x00, 1024);
	}

	if (fp != NULL)
		fclose(fp);

	if (path == NULL) {
		DBGE("no matching backendlib\n");
		return NULL;
	}

	snprintf(temp_path, sizeof(temp_path) - 1, "%slib%s.so", path, type);

	return strdup(temp_path);
}

static int __ps_run_parser(xmlDocPtr docPtr, const char *tag,
			   ACTION_TYPE action, const char *pkgid)
{
	char *lib_path = NULL;
	void *lib_handle = NULL;
	int (*plugin_install) (xmlDocPtr, const char *);
	int ret = -1;
	char *ac;

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
		DBGE("dlopen is failed lib_path[%s]\n", lib_path);
		goto END;
	}

	if ((plugin_install =
	     dlsym(lib_handle, ac)) == NULL || dlerror() != NULL) {
		DBGE("can not find symbol \n");
		goto END;
	}

	ret = plugin_install(docPtr, pkgid);

 END:
	if (lib_path)
		free(lib_path);
	if (lib_handle)
		dlclose(lib_handle);
	return ret;
}

static char *__pkgid_to_manifest(const char *pkgid)
{
	char *manifest;
	int size;

	if (pkgid == NULL) {
		DBGE("pkgid is NULL");
		return NULL;
	}

	size = strlen(MANIFEST_RW_DIRECTORY) + strlen(pkgid) + 10;
	manifest = malloc(size);
	if (manifest == NULL) {
		DBGE("No memory");
		return NULL;
	}
	memset(manifest, '\0', size);
	snprintf(manifest, size, MANIFEST_RW_DIRECTORY "/%s.xml", pkgid);

	if (access(manifest, F_OK)) {
		snprintf(manifest, size, MANIFEST_RO_DIRECTORY "/%s.xml", pkgid);
	}

	return manifest;
}

static int __run_parser_prestep(xmlTextReaderPtr reader, ACTION_TYPE action, const char *pkgid)
{
	int nLoop = 0;
	int pid = 0;
	char *parser_cmd = NULL;
	int ret = -1;
	const xmlChar *name;
	char *lib_path = NULL;
	void *lib_handle = NULL;
	int (*plugin_install) (xmlDocPtr);

	DBG("__run_parser_prestep");

	if (xmlTextReaderDepth(reader) != 1) {
		DBGE("Node depth is not 1");
		goto END;
	}

	if (xmlTextReaderNodeType(reader) != 1) {
		DBGE("Node type is not 1");
		goto END;
	}

	const xmlChar *value;
	name = xmlTextReaderConstName(reader);
	if (name == NULL) {
		DBGE("TEST TEST TES\n");
		name = BAD_CAST "--";
	}

	value = xmlTextReaderConstValue(reader);
	DBG("%d %d %s %d %d",
	    xmlTextReaderDepth(reader),
	    xmlTextReaderNodeType(reader),
	    name,
	    xmlTextReaderIsEmptyElement(reader), xmlTextReaderHasValue(reader));

	if (value == NULL) {
		DBG("ConstValue NULL");
	} else {
		if (xmlStrlen(value) > 40) {
			DBG(" %.40s...", value);
		} else {
			DBG(" %s", value);
		}
	}

	name = xmlTextReaderConstName(reader);
	if (name == NULL) {
		DBGE("TEST TEST TES\n");
		name = BAD_CAST "--";
	}

	xmlDocPtr docPtr = xmlTextReaderCurrentDoc(reader);
	DBG("docPtr->URL %s\n", (char *)docPtr->URL);
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
	while(cur_node != NULL)
	{
		if ( (strcmp(temp->name, cur_node->name) == 0) &&
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
	DBG("node type: %d, name: %s children->name: %s last->name: %s\n"
	    "parent->name: %s next->name: %s prev->name: %s\n",
	    cur_node->type, cur_node->name,
	    cur_node->children ? cur_node->children->name : "NULL",
	    cur_node->last ? cur_node->last->name : "NULL",
	    cur_node->parent ? cur_node->parent->name : "NULL",
	    cur_node->next ? cur_node->next->name : "NULL",
	    cur_node->prev ? cur_node->prev->name : "NULL");

	FILE *fp = fopen("/opt/share/test.xml", "a");
	xmlDocDump(fp, copyDocPtr);
	fprintf(fp, "\n");
	fclose(fp);
#endif

	ret = __ps_run_parser(copyDocPtr, name, action, pkgid);
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
			//            DBG("XML_READER_TYPE_END_ELEMENT");
			break;
		}

	case XML_READER_TYPE_ELEMENT:
		{
			// Elements without closing tag don't receive
			// XML_READER_TYPE_END_ELEMENT event.

			const xmlChar *elementName =
			    xmlTextReaderLocalName(reader);
			if (elementName == NULL) {
//				DBG("elementName %s\n", (char *)elementName);
				break;
			}

			const xmlChar *nameSpace =
			    xmlTextReaderConstNamespaceUri(reader);
			if (nameSpace) {
//				DBG("nameSpace %s\n", (char *)nameSpace);
			}
/*
			DBG("XML_READER_TYPE_ELEMENT %s, %s\n",
			    elementName ? elementName : "NULL",
			    nameSpace ? nameSpace : "NULL");
*/
			if (tagv == NULL) {
				DBG("__run_parser_prestep pkgid[%s]\n", pkgid);
				__run_parser_prestep(reader, action, pkgid);
			}
			else {
				i = 0;
				for (tag = tagv[0]; tag; tag = tagv[++i])
					if (strcmp(tag, elementName) == 0) {
						DBG("__run_parser_prestep tag[%s] pkgid[%s]\n", tag, pkgid);
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
//				DBG("value %s\n", value);
			}

			const xmlChar *lang = xmlTextReaderConstXmlLang(reader);
			if (lang) {
//				DBG("lang\n", lang);
			}

/*			DBG("XML_READER_TYPE_TEXT %s, %s\n",
			    value ? value : "NULL", lang ? lang : "NULL");
*/
			break;
		}
	default:
//		DBG("Ignoring Node of Type: %d", xmlTextReaderNodeType(reader));
		break;
	}
}

static void
__streamFile(const char *filename, ACTION_TYPE action, char *const tagv[], const char *pkgid)
{
	xmlTextReaderPtr reader;
	xmlDocPtr docPtr;
	int ret;

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
			DBGE("%s : failed to parse", filename);
		}
	} else {
		DBGE("Unable to open %s", filename);
	}
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
		while(resolution != NULL)
		{
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
		while(capability != NULL)
		{
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
		while(condition != NULL)
		{
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
		while(operation != NULL)
		{
			tmp = operation->next;
			__ps_free_operation(operation);
			operation = tmp;
		}
	}
	/*Free Uri*/
	if (appcontrol->uri) {
		uri_x *uri = appcontrol->uri;
		uri_x *tmp = NULL;
		while(uri != NULL)
		{
			tmp = uri->next;
			__ps_free_uri(uri);
			uri = tmp;
		}
	}
	/*Free Mime*/
	if (appcontrol->mime) {
		mime_x *mime = appcontrol->mime;
		mime_x *tmp = NULL;
		while(mime != NULL)
		{
			tmp = mime->next;
			__ps_free_mime(mime);
			mime = tmp;
		}
	}
	/*Free subapp*/
	if (appcontrol->subapp) {
		subapp_x *subapp = appcontrol->subapp;
		subapp_x *tmp = NULL;
		while(subapp != NULL)
		{
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
		while(operation != NULL)
		{
			tmp = operation->next;
			__ps_free_operation(operation);
			operation = tmp;
		}
	}
	/*Free Uri*/
	if (appsvc->uri) {
		uri_x *uri = appsvc->uri;
		uri_x *tmp = NULL;
		while(uri != NULL)
		{
			tmp = uri->next;
			__ps_free_uri(uri);
			uri = tmp;
		}
	}
	/*Free Mime*/
	if (appsvc->mime) {
		mime_x *mime = appsvc->mime;
		mime_x *tmp = NULL;
		while(mime != NULL)
		{
			tmp = mime->next;
			__ps_free_mime(mime);
			mime = tmp;
		}
	}
	/*Free subapp*/
	if (appsvc->subapp) {
		subapp_x *subapp = appsvc->subapp;
		subapp_x *tmp = NULL;
		while(subapp != NULL)
		{
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
		while(request != NULL)
		{
			tmp = request->next;
			__ps_free_request(request);
			request = tmp;
		}
	}
	/*Free Allowed*/
	if (define->allowed) {
		allowed_x *allowed = define->allowed;
		allowed_x *tmp = NULL;
		while(allowed != NULL)
		{
			tmp = allowed->next;
			__ps_free_allowed(allowed);
			allowed = tmp;
		}
	}
	free((void*)define);
	define = NULL;
}

static void __ps_free_registry(registry_x *registry)
{
	if (registry == NULL)
		return;
	if (registry->name) {
		free((void *)registry->name);
		registry->name = NULL;
	}
	if (registry->text) {
		free((void *)registry->text);
		registry->text = NULL;
	}
	free((void*)registry);
	registry = NULL;
}

static void __ps_free_database(database_x *database)
{
	if (database == NULL)
		return;
	if (database->name) {
		free((void *)database->name);
		database->name = NULL;
	}
	if (database->text) {
		free((void *)database->text);
		database->text = NULL;
	}
	free((void*)database);
	database = NULL;
}

static void __ps_free_datashare(datashare_x *datashare)
{
	if (datashare == NULL)
		return;
	/*Free Define*/
	if (datashare->define) {
		define_x *define =  datashare->define;
		define_x *tmp = NULL;
		while(define != NULL)
		{
			tmp = define->next;
			__ps_free_define(define);
			define = tmp;
		}
	}
	/*Free Request*/
	if (datashare->request) {
		request_x *request = datashare->request;
		request_x *tmp = NULL;
		while(request != NULL)
		{
			tmp = request->next;
			__ps_free_request(request);
			request = tmp;
		}
	}
	free((void*)datashare);
	datashare = NULL;
}

static void __ps_free_layout(layout_x *layout)
{
	if (layout == NULL)
		return;
	if (layout->name) {
		free((void *)layout->name);
		layout->name = NULL;
	}
	if (layout->text) {
		free((void *)layout->text);
		layout->text = NULL;
	}
	free((void*)layout);
	layout = NULL;
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
	if (uiapplication->hwacceleration) {
		free((void *)uiapplication->hwacceleration);
		uiapplication->hwacceleration = NULL;
	}
	if (uiapplication->mainapp) {
		free((void *)uiapplication->mainapp);
		uiapplication->mainapp = NULL;
	}
	if (uiapplication->recentimage) {
		free((void *)uiapplication->recentimage);
		uiapplication->recentimage = NULL;
	}
	/*Free Label*/
	if (uiapplication->label) {
		label_x *label = uiapplication->label;
		label_x *tmp = NULL;
		while(label != NULL)
		{
			tmp = label->next;
			__ps_free_label(label);
			label = tmp;
		}
	}
	/*Free Icon*/
	if (uiapplication->icon) {
		icon_x *icon = uiapplication->icon;
		icon_x *tmp = NULL;
		while(icon != NULL)
		{
			tmp = icon->next;
			__ps_free_icon(icon);
			icon = tmp;
		}
	}
	/*Free AppControl*/
	if (uiapplication->appcontrol) {
		appcontrol_x *appcontrol = uiapplication->appcontrol;
		appcontrol_x *tmp = NULL;
		while(appcontrol != NULL)
		{
			tmp = appcontrol->next;
			__ps_free_appcontrol(appcontrol);
			appcontrol = tmp;
		}
	}
	/*Free LaunchConditions*/
	if (uiapplication->launchconditions) {
		launchconditions_x *launchconditions = uiapplication->launchconditions;
		launchconditions_x *tmp = NULL;
		while(launchconditions != NULL)
		{
			tmp = launchconditions->next;
			__ps_free_launchconditions(launchconditions);
			launchconditions = tmp;
		}
	}
	/*Free Notification*/
	if (uiapplication->notification) {
		notification_x *notification = uiapplication->notification;
		notification_x *tmp = NULL;
		while(notification != NULL)
		{
			tmp = notification->next;
			__ps_free_notification(notification);
			notification = tmp;
		}
	}
	/*Free DataShare*/
	if (uiapplication->datashare) {
		datashare_x *datashare = uiapplication->datashare;
		datashare_x *tmp = NULL;
		while(datashare != NULL)
		{
			tmp = datashare->next;
			__ps_free_datashare(datashare);
			datashare = tmp;
		}
	}
	/*Free AppSvc*/
	if (uiapplication->appsvc) {
		appsvc_x *appsvc = uiapplication->appsvc;
		appsvc_x *tmp = NULL;
		while(appsvc != NULL)
		{
			tmp = appsvc->next;
			__ps_free_appsvc(appsvc);
			appsvc = tmp;
		}
	}
	/*Free Category*/
	if (uiapplication->category) {
		category_x *category = uiapplication->category;
		category_x *tmp = NULL;
		while(category != NULL)
		{
			tmp = category->next;
			__ps_free_category(category);
			category = tmp;
		}
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
	/*Free Label*/
	if (serviceapplication->label) {
		label_x *label = serviceapplication->label;
		label_x *tmp = NULL;
		while(label != NULL)
		{
			tmp = label->next;
			__ps_free_label(label);
			label = tmp;
		}
	}
	/*Free Icon*/
	if (serviceapplication->icon) {
		icon_x *icon = serviceapplication->icon;
		icon_x *tmp = NULL;
		while(icon != NULL)
		{
			tmp = icon->next;
			__ps_free_icon(icon);
			icon = tmp;
		}
	}
	/*Free AppControl*/
	if (serviceapplication->appcontrol) {
		appcontrol_x *appcontrol = serviceapplication->appcontrol;
		appcontrol_x *tmp = NULL;
		while(appcontrol != NULL)
		{
			tmp = appcontrol->next;
			__ps_free_appcontrol(appcontrol);
			appcontrol = tmp;
		}
	}
	/*Free DataControl*/
	if (serviceapplication->datacontrol) {
		datacontrol_x *datacontrol = serviceapplication->datacontrol;
		datacontrol_x *tmp = NULL;
		while(datacontrol != NULL)
		{
			tmp = datacontrol->next;
			__ps_free_datacontrol(datacontrol);
			datacontrol = tmp;
		}
	}
	/*Free LaunchConditions*/
	if (serviceapplication->launchconditions) {
		launchconditions_x *launchconditions = serviceapplication->launchconditions;
		launchconditions_x *tmp = NULL;
		while(launchconditions != NULL)
		{
			tmp = launchconditions->next;
			__ps_free_launchconditions(launchconditions);
			launchconditions = tmp;
		}
	}
	/*Free Notification*/
	if (serviceapplication->notification) {
		notification_x *notification = serviceapplication->notification;
		notification_x *tmp = NULL;
		while(notification != NULL)
		{
			tmp = notification->next;
			__ps_free_notification(notification);
			notification = tmp;
		}
	}
	/*Free DataShare*/
	if (serviceapplication->datashare) {
		datashare_x *datashare = serviceapplication->datashare;
		datashare_x *tmp = NULL;
		while(datashare != NULL)
		{
			tmp = datashare->next;
			__ps_free_datashare(datashare);
			datashare = tmp;
		}
	}
	/*Free AppSvc*/
	if (serviceapplication->appsvc) {
		appsvc_x *appsvc = serviceapplication->appsvc;
		appsvc_x *tmp = NULL;
		while(appsvc != NULL)
		{
			tmp = appsvc->next;
			__ps_free_appsvc(appsvc);
			appsvc = tmp;
		}
	}
	/*Free Category*/
	if (serviceapplication->category) {
		category_x *category = serviceapplication->category;
		category_x *tmp = NULL;
		while(category != NULL)
		{
			tmp = category->next;
			__ps_free_category(category);
			category = tmp;
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
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "allowed")) {
			allowed_x *allowed= malloc(sizeof(allowed_x));
			if (allowed == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(allowed, '\0', sizeof(allowed_x));
			LISTADD(define->allowed, allowed);
			ret = __ps_process_allowed(reader, allowed);
		} else if (!strcmp(ASCII(node), "request")) {
			request_x *request = malloc(sizeof(request_x));
			if (request == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(request, '\0', sizeof(request_x));
			LISTADD(define->request, request);
			ret = __ps_process_request(reader, request);
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing define failed\n");
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

static int __ps_process_registry(xmlTextReaderPtr reader, registry_x *registry)
{
	/*TODO: once policy is set*/
	return 0;
}

static int __ps_process_database(xmlTextReaderPtr reader, database_x *database)
{
	/*TODO: once policy is set*/
	return 0;
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
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "operation")) {
			operation_x *operation = malloc(sizeof(operation_x));
			if (operation == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(operation, '\0', sizeof(operation_x));
			LISTADD(appcontrol->operation, operation);
			ret = __ps_process_operation(reader, operation);
			DBG("operation processing\n");
		} else if (!strcmp(ASCII(node), "uri")) {
			uri_x *uri= malloc(sizeof(uri_x));
			if (uri == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(uri, '\0', sizeof(uri_x));
			LISTADD(appcontrol->uri, uri);
			ret = __ps_process_uri(reader, uri);
			DBG("uri processing\n");
		} else if (!strcmp(ASCII(node), "mime")) {
			mime_x *mime = malloc(sizeof(mime_x));
			if (mime == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(mime, '\0', sizeof(mime_x));
			LISTADD(appcontrol->mime, mime);
			ret = __ps_process_mime(reader, mime);
			DBG("mime processing\n");
		} else if (!strcmp(ASCII(node), "subapp")) {
			subapp_x *subapp = malloc(sizeof(subapp_x));
			if (subapp == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(subapp, '\0', sizeof(subapp_x));
			LISTADD(appcontrol->subapp, subapp);
			ret = __ps_process_subapp(reader, subapp);
			DBG("subapp processing\n");
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing appcontrol failed\n");
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
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "operation")) {
			operation_x *operation = malloc(sizeof(operation_x));
			if (operation == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(operation, '\0', sizeof(operation_x));
			LISTADD(appsvc->operation, operation);
			ret = __ps_process_operation(reader, operation);
			DBG("operation processing\n");
		} else if (!strcmp(ASCII(node), "uri")) {
			uri_x *uri= malloc(sizeof(uri_x));
			if (uri == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(uri, '\0', sizeof(uri_x));
			LISTADD(appsvc->uri, uri);
			ret = __ps_process_uri(reader, uri);
			DBG("uri processing\n");
		} else if (!strcmp(ASCII(node), "mime")) {
			mime_x *mime = malloc(sizeof(mime_x));
			if (mime == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(mime, '\0', sizeof(mime_x));
			LISTADD(appsvc->mime, mime);
			ret = __ps_process_mime(reader, mime);
			DBG("mime processing\n");
		} else if (!strcmp(ASCII(node), "subapp")) {
			subapp_x *subapp = malloc(sizeof(subapp_x));
			if (subapp == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(subapp, '\0', sizeof(subapp_x));
			LISTADD(appsvc->subapp, subapp);
			ret = __ps_process_subapp(reader, subapp);
			DBG("subapp processing\n");
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing appsvc failed\n");
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
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (strcmp(ASCII(node), "condition") == 0) {
			condition_x *condition = malloc(sizeof(condition_x));
			if (condition == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(condition, '\0', sizeof(condition_x));
			LISTADD(launchconditions->condition, condition);
			ret = __ps_process_condition(reader, condition);
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing launchconditions failed\n");
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
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "define")) {
			define_x *define= malloc(sizeof(define_x));
			if (define == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(define, '\0', sizeof(define_x));
			LISTADD(datashare->define, define);
			ret = __ps_process_define(reader, define);
		} else if (!strcmp(ASCII(node), "request")) {
			request_x *request= malloc(sizeof(request_x));
			if (request == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(request, '\0', sizeof(request_x));
			LISTADD(datashare->request, request);
			ret = __ps_process_request(reader, request);
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing data-share failed\n");
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

static int __ps_process_layout(xmlTextReaderPtr reader, layout_x *layout)
{
	/*TODO: once policy is set*/
	return 0;
}

static char*
__get_icon_with_path(char* icon)
{
	if (!icon)
		return NULL;

	if (index(icon, '/') == NULL) {
		char* theme = NULL;
		char* icon_with_path = NULL;
		int len;

		if (!package)
			return NULL;

		theme = vconf_get_str("db/setting/theme");
		if (!theme) {
			theme = strdup("default");
			if(!theme) {
				return NULL;
			}
		}

		len = (0x01 << 7) + strlen(icon) + strlen(package) + strlen(theme);
		icon_with_path = malloc(len);
		if(icon_with_path == NULL) {
			DBG("(icon_with_path == NULL) return\n");
			free(theme);
			return NULL;
		}

		memset(icon_with_path, 0, len);

		snprintf(icon_with_path, len, "/opt/share/icons/%s/small/%s", theme, icon);
		do {
			if (access(icon_with_path, R_OK) == 0) break;
			snprintf(icon_with_path, len, "/usr/share/icons/%s/small/%s", theme, icon);
			if (access(icon_with_path, R_OK) == 0) break;
			DBG("cannot find icon %s", icon_with_path);
			snprintf(icon_with_path, len,"/opt/share/icons/default/small/%s", icon);
			if (access(icon_with_path, R_OK) == 0) break;
			snprintf(icon_with_path, len, "/usr/share/icons/default/small/%s", icon);
			if (access(icon_with_path, R_OK) == 0) break;

			/* icon path is going to be moved intto the app directory */
			DBGE("icon file must be moved to %s", icon_with_path);
			snprintf(icon_with_path, len, "/opt/apps/%s/res/icons/%s/small/%s", package, theme, icon);
			if (access(icon_with_path, R_OK) == 0) break;
			snprintf(icon_with_path, len, "/usr/apps/%s/res/icons/%s/small/%s", package, theme, icon);
			if (access(icon_with_path, R_OK) == 0) break;
			DBG("cannot find icon %s", icon_with_path);
			snprintf(icon_with_path, len, "/opt/apps/%s/res/icons/default/small/%s", package, icon);
			if (access(icon_with_path, R_OK) == 0) break;
			snprintf(icon_with_path, len, "/usr/apps/%s/res/icons/default/small/%s", package, icon);
			if (access(icon_with_path, R_OK) == 0) break;
		} while (0);

		free(theme);

		DBG("Icon path : %s ---> %s", icon, icon_with_path);

		return icon_with_path;
	} else {
		char* confirmed_icon = NULL;

		confirmed_icon = strdup(icon);
		if (!confirmed_icon)
			return NULL;
		return confirmed_icon;
	}
}


static int __ps_process_icon(xmlTextReaderPtr reader, icon_x *icon)
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
		char *text  = ASCII(xmlTextReaderValue(reader));
		if(text) {
			icon->text = __get_icon_with_path(text);
			free(text);
		}
	}

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
	} else {
		label->lang = strdup(DEFAULT_LOCALE);
	}
	xmlTextReaderRead(reader);
	if (xmlTextReaderValue(reader))
		label->text = ASCII(xmlTextReaderValue(reader));

/*	DBG("lable name %s\n", label->name);
	DBG("lable lang %s\n", label->lang);
	DBG("lable text %s\n", label->text);
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
	if (xmlTextReaderValue(reader))
		author->text = ASCII(xmlTextReaderValue(reader));
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
	if (xmlTextReaderValue(reader))
		description->text = ASCII(xmlTextReaderValue(reader));
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
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "resolution")) {
			resolution_x *resolution = malloc(sizeof(resolution_x));
			if (resolution == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(resolution, '\0', sizeof(resolution_x));
			LISTADD(capability->resolution, resolution);
			ret = __ps_process_resolution(reader, resolution);
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing capability failed\n");
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
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "capability")) {
			capability_x *capability = malloc(sizeof(capability_x));
			if (capability == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(capability, '\0', sizeof(capability_x));
			LISTADD(datacontrol->capability, capability);
			ret = __ps_process_capability(reader, capability);
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing datacontrol failed\n");
			return ret;
		}
	}

	if (datacontrol->capability) {
		LISTHEAD(datacontrol->capability, tmp1);
		datacontrol->capability = tmp1;
	}

	return ret;
}

static int __ps_process_uiapplication(xmlTextReaderPtr reader, uiapplication_x *uiapplication)
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

	if (xmlTextReaderGetAttribute(reader, XMLCHAR("appid"))) {
		uiapplication->appid = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("appid")));
		if (uiapplication->appid == NULL) {
			DBG("appid cant be NULL\n");
			return -1;
		}
	} else {
		DBG("appid is mandatory\n");
		return -1;
	}
	/*check appid*/
	ret = __validate_appid(package, uiapplication->appid, &newappid);
	if (ret == -1) {
		DBG("appid is not proper\n");
		return -1;
	} else {
		if (newappid) {
			if (uiapplication->appid)
				free((void *)uiapplication->appid);
			uiapplication->appid = newappid;
		}
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
	if (xmlTextReaderGetAttribute(reader, XMLCHAR("hw-acceleration"))) {
		uiapplication->hwacceleration = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("hw-acceleration")));
		if (uiapplication->hwacceleration == NULL)
			uiapplication->hwacceleration = strdup("use-system-setting");
	} else {
		uiapplication->hwacceleration = strdup("use-system-setting");
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

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}
		if (!strcmp(ASCII(node), "label")) {
			label_x *label = malloc(sizeof(label_x));
			if (label == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(label, '\0', sizeof(label_x));
			LISTADD(uiapplication->label, label);
			ret = __ps_process_label(reader, label);
		} else if (!strcmp(ASCII(node), "icon")) {
			icon_x *icon = malloc(sizeof(icon_x));
			if (icon == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(icon, '\0', sizeof(icon_x));
			LISTADD(uiapplication->icon, icon);
			ret = __ps_process_icon(reader, icon);
		} else if (!strcmp(ASCII(node), "category")) {
			category_x *category = malloc(sizeof(category_x));
			if (category == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(category, '\0', sizeof(category_x));
			LISTADD(uiapplication->category, category);
			ret = __ps_process_category(reader, category);
		} else if (!strcmp(ASCII(node), "app-control")) {
			appcontrol_x *appcontrol = malloc(sizeof(appcontrol_x));
			if (appcontrol == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(appcontrol, '\0', sizeof(appcontrol_x));
			LISTADD(uiapplication->appcontrol, appcontrol);
			ret = __ps_process_appcontrol(reader, appcontrol);
		} else if (!strcmp(ASCII(node), "application-service")) {
			appsvc_x *appsvc = malloc(sizeof(appsvc_x));
			if (appsvc == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(appsvc, '\0', sizeof(appsvc_x));
			LISTADD(uiapplication->appsvc, appsvc);
			ret = __ps_process_appsvc(reader, appsvc);
		} else if (!strcmp(ASCII(node), "data-share")) {
			datashare_x *datashare = malloc(sizeof(datashare_x));
			if (datashare == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(datashare, '\0', sizeof(datashare_x));
			LISTADD(uiapplication->datashare, datashare);
			ret = __ps_process_datashare(reader, datashare);
		} else if (!strcmp(ASCII(node), "launch-conditions")) {
			launchconditions_x *launchconditions = malloc(sizeof(launchconditions_x));
			if (launchconditions == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(launchconditions, '\0', sizeof(launchconditions_x));
			LISTADD(uiapplication->launchconditions, launchconditions);
			ret = __ps_process_launchconditions(reader, launchconditions);
		} else if (!strcmp(ASCII(node), "notification")) {
			notification_x *notification = malloc(sizeof(notification_x));
			if (notification == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(notification, '\0', sizeof(notification_x));
			LISTADD(uiapplication->notification, notification);
			ret = __ps_process_notification(reader, notification);
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing uiapplication failed\n");
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

	return ret;
}

static int __ps_process_serviceapplication(xmlTextReaderPtr reader, serviceapplication_x *serviceapplication)
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

	if (xmlTextReaderGetAttribute(reader, XMLCHAR("appid"))) {
		serviceapplication->appid = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("appid")));
		if (serviceapplication->appid == NULL) {
			DBG("appid cant be NULL\n");
			return -1;
		}
	} else {
		DBG("appid is mandatory\n");
		return -1;
	}
	/*check appid*/
	ret = __validate_appid(package, serviceapplication->appid, &newappid);
	if (ret == -1) {
		DBG("appid is not proper\n");
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

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "label")) {
			label_x *label = malloc(sizeof(label_x));
			if (label == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(label, '\0', sizeof(label_x));
			LISTADD(serviceapplication->label, label);
			ret = __ps_process_label(reader, label);
		} else if (!strcmp(ASCII(node), "icon")) {
			icon_x *icon = malloc(sizeof(icon_x));
			if (icon == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(icon, '\0', sizeof(icon_x));
			LISTADD(serviceapplication->icon, icon);
			ret = __ps_process_icon(reader, icon);
		} else if (!strcmp(ASCII(node), "category")) {
			category_x *category = malloc(sizeof(category_x));
			if (category == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(category, '\0', sizeof(category_x));
			LISTADD(serviceapplication->category, category);
			ret = __ps_process_category(reader, category);
		} else if (!strcmp(ASCII(node), "app-control")) {
			appcontrol_x *appcontrol = malloc(sizeof(appcontrol_x));
			if (appcontrol == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(appcontrol, '\0', sizeof(appcontrol_x));
			LISTADD(serviceapplication->appcontrol, appcontrol);
			ret = __ps_process_appcontrol(reader, appcontrol);
		} else if (!strcmp(ASCII(node), "application-service")) {
			appsvc_x *appsvc = malloc(sizeof(appsvc_x));
			if (appsvc == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(appsvc, '\0', sizeof(appsvc_x));
			LISTADD(serviceapplication->appsvc, appsvc);
			ret = __ps_process_appsvc(reader, appsvc);
		} else if (!strcmp(ASCII(node), "data-share")) {
			datashare_x *datashare = malloc(sizeof(datashare_x));
			if (datashare == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(datashare, '\0', sizeof(datashare_x));
			LISTADD(serviceapplication->datashare, datashare);
			ret = __ps_process_datashare(reader, datashare);
		} else if (!strcmp(ASCII(node), "launch-conditions")) {
			launchconditions_x *launchconditions = malloc(sizeof(launchconditions_x));
			if (launchconditions == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(launchconditions, '\0', sizeof(launchconditions_x));
			LISTADD(serviceapplication->launchconditions, launchconditions);
			ret = __ps_process_launchconditions(reader, launchconditions);
		} else if (!strcmp(ASCII(node), "notification")) {
			notification_x *notification = malloc(sizeof(notification_x));
			if (notification == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(notification, '\0', sizeof(notification_x));
			LISTADD(serviceapplication->notification, notification);
			ret = __ps_process_notification(reader, notification);
		} else if (!strcmp(ASCII(node), "data-control")) {
			datacontrol_x *datacontrol = malloc(sizeof(datacontrol_x));
			if (datacontrol == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(datacontrol, '\0', sizeof(datacontrol_x));
			LISTADD(serviceapplication->datacontrol, datacontrol);
			ret = __ps_process_datacontrol(reader, datacontrol);
		} else
			return -1;
		if (ret < 0) {
			DBG("Processing serviceapplication failed\n");
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

static int __start_process(xmlTextReaderPtr reader, manifest_x * mfx)
{
	DBG("__start_process\n");
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

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "label")) {
			label_x *label = malloc(sizeof(label_x));
			if (label == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(label, '\0', sizeof(label_x));
			LISTADD(mfx->label, label);
			ret = __ps_process_label(reader, label);
		} else if (!strcmp(ASCII(node), "author")) {
			author_x *author = malloc(sizeof(author_x));
			if (author == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(author, '\0', sizeof(author_x));
			LISTADD(mfx->author, author);
			ret = __ps_process_author(reader, author);
		} else if (!strcmp(ASCII(node), "description")) {
			description_x *description = malloc(sizeof(description_x));
			if (description == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(description, '\0', sizeof(description_x));
			LISTADD(mfx->description, description);
			ret = __ps_process_description(reader, description);
		} else if (!strcmp(ASCII(node), "license")) {
			license_x *license = malloc(sizeof(license_x));
			if (license == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(license, '\0', sizeof(license_x));
			LISTADD(mfx->license, license);
			ret = __ps_process_license(reader, license);
		} else if (!strcmp(ASCII(node), "ui-application")) {
			uiapplication_x *uiapplication = malloc(sizeof(uiapplication_x));
			if (uiapplication == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(uiapplication, '\0', sizeof(uiapplication_x));
			LISTADD(mfx->uiapplication, uiapplication);
			ret = __ps_process_uiapplication(reader, uiapplication);
		} else if (!strcmp(ASCII(node), "service-application")) {
			serviceapplication_x *serviceapplication = malloc(sizeof(serviceapplication_x));
			if (serviceapplication == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(serviceapplication, '\0', sizeof(serviceapplication_x));
			LISTADD(mfx->serviceapplication, serviceapplication);
			ret = __ps_process_serviceapplication(reader, serviceapplication);
		} else if (!strcmp(ASCII(node), "daemon")) {
			daemon_x *daemon = malloc(sizeof(daemon_x));
			if (daemon == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(daemon, '\0', sizeof(daemon_x));
			LISTADD(mfx->daemon, daemon);
			ret = __ps_process_daemon(reader, daemon);
		} else if (!strcmp(ASCII(node), "theme")) {
			theme_x *theme = malloc(sizeof(theme_x));
			if (theme == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(theme, '\0', sizeof(theme_x));
			LISTADD(mfx->theme, theme);
			ret = __ps_process_theme(reader, theme);
		} else if (!strcmp(ASCII(node), "font")) {
			font_x *font = malloc(sizeof(font_x));
			if (font == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(font, '\0', sizeof(font_x));
			LISTADD(mfx->font, font);
			ret = __ps_process_font(reader, font);
		} else if (!strcmp(ASCII(node), "ime")) {
			ime_x *ime = malloc(sizeof(ime_x));
			if (ime == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(ime, '\0', sizeof(ime_x));
			LISTADD(mfx->ime, ime);
			ret = __ps_process_ime(reader, ime);
		} else if (!strcmp(ASCII(node), "icon")) {
			icon_x *icon = malloc(sizeof(icon_x));
			if (icon == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(icon, '\0', sizeof(icon_x));
			LISTADD(mfx->icon, icon);
			ret = __ps_process_icon(reader, icon);
		} else if (!strcmp(ASCII(node), "device-profile")) {
			deviceprofile_x *deviceprofile = malloc(sizeof(deviceprofile_x));
			if (deviceprofile == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(deviceprofile, '\0', sizeof(deviceprofile_x));
			LISTADD(mfx->deviceprofile, deviceprofile);
			ret = __ps_process_deviceprofile(reader, deviceprofile);
		} else if (!strcmp(ASCII(node), "compatibility")) {
			compatibility_x *compatibility = malloc(sizeof(compatibility_x));
			if (compatibility == NULL) {
				DBG("Malloc Failed\n");
				return -1;
			}
			memset(compatibility, '\0', sizeof(compatibility_x));
			LISTADD(mfx->compatibility, compatibility);
			ret = __ps_process_compatibility(reader, compatibility);
		} else if (!strcmp(ASCII(node), "shortcut-list")) {
			continue;
		} else if (!strcmp(ASCII(node), "livebox")) {
			continue;
		} else if (!strcmp(ASCII(node), "Accounts")) {
			continue;
		} else if (!strcmp(ASCII(node), "account")) {
			continue;
		} else
			return -1;

		if (ret < 0) {
			DBG("Processing manifest failed\n");
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

	return ret;
}

static int __process_manifest(xmlTextReaderPtr reader, manifest_x * mfx)
{
	const xmlChar *node;
	int ret = -1;

	if ((ret = __next_child_element(reader, -1))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			DBG("xmlTextReaderConstName value is NULL\n");
			return -1;
		}

		if (!strcmp(ASCII(node), "manifest")) {
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("xmlns")))
				mfx->ns = ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("xmlns")));
			if (xmlTextReaderGetAttribute(reader, XMLCHAR("package"))) {
				mfx->package= ASCII(xmlTextReaderGetAttribute(reader, XMLCHAR("package")));
				if (mfx->package == NULL) {
					DBG("package cant be NULL\n");
					return -1;
				}
			} else {
				DBG("package field is mandatory\n");
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
			/*Assign default values. If required it will be overwritten in __add_preload_info()*/
			mfx->preload = strdup("False");
			mfx->removable = strdup("True");
			mfx->readonly = strdup("False");
			char buf[PKG_STRING_LEN_MAX] = {'\0'};
			char *val = NULL;
			time_t current_time;
			time(&current_time);
			snprintf(buf, PKG_STRING_LEN_MAX - 1, "%d", current_time);
			val = strndup(buf, PKG_STRING_LEN_MAX - 1);
			mfx->installed_time = val;

			ret = __start_process(reader, mfx);
		} else {
			DBG("No Manifest element found\n");
			return -1;
		}
	}
	return ret;
}

#define DESKTOP_RW_PATH "/opt/share/applications/"
#define DESKTOP_RO_PATH "/usr/share/applications/"

static char* __convert_to_system_locale(const char *mlocale)
{
	if (mlocale == NULL)
		return NULL;
	char *locale = NULL;
	locale = (char *)calloc(1, 6);
	if (!locale) {
		DBGE("Malloc Failed\n");
		return NULL;
	}

	strncpy(locale, mlocale, 2);
	strncat(locale, "_", 1);
	locale[3] = toupper(mlocale[3]);
	locale[4] = toupper(mlocale[4]);
	return locale;
}


/* desktop shoud be generated automatically based on manifest */
/* Currently removable, taskmanage, etc fields are not considerd. it will be decided soon.*/
#define BUFMAX 1024*128
static int __ps_make_nativeapp_desktop(manifest_x * mfx)
{
        FILE* file = NULL;
        int fd = 0;
        char filepath[PKG_STRING_LEN_MAX] = "";
        char *buf = NULL;
	char *buftemp = NULL;
	char *locale = NULL;

	buf = (char *)calloc(1, BUFMAX);
	if (!buf) {
		DBGE("Malloc Failed\n");
		return -1;
	}

	buftemp = (char *)calloc(1, BUFMAX);
	if (!buftemp) {
		DBGE("Malloc Failed\n");
		free(buf);
		return -1;
	}

	for(; mfx->uiapplication; mfx->uiapplication=mfx->uiapplication->next) {

		if(mfx->readonly && !strcasecmp(mfx->readonly, "True"))
		        snprintf(filepath, sizeof(filepath),"%s%s.desktop", DESKTOP_RO_PATH, mfx->uiapplication->appid);
		else
			snprintf(filepath, sizeof(filepath),"%s%s.desktop", DESKTOP_RW_PATH, mfx->uiapplication->appid);

		/* skip if desktop exists
		if (access(filepath, R_OK) == 0)
			continue;
		*/

	        file = fopen(filepath, "w");
	        if(file == NULL)
	        {
	            DBGE("Can't open %s", filepath);
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

		snprintf(buf, BUFMAX, "X-TIZEN-PkgID=%s\n", mfx->package);
		fwrite(buf, 1, strlen(buf), file);


//		snprintf(buf, BUFMAX, "X-TIZEN-PackageType=rpm\n");
//		fwrite(buf, 1, strlen(buf), file);


		if(mfx->uiapplication->appsvc) {
			snprintf(buf, BUFMAX, "X-TIZEN-Svc=");
			DBG("buf[%s]\n", buf);


			uiapplication_x *up = mfx->uiapplication;
			appsvc_x *asvc = NULL;
			operation_x *op = NULL;
			mime_x *mi = NULL;
			uri_x *ui = NULL;
			subapp_x *sub = NULL;
			int ret = -1;
			char query[PKG_STRING_LEN_MAX] = {'\0'};
			char *operation = NULL;
			char *mime = NULL;
			char *uri = NULL;
			char *subapp = NULL;
			int i = 0;


			asvc = up->appsvc;
			while(asvc != NULL)
			{
				op = asvc->operation;
				while(op != NULL)
				{
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
								DBG("buf[%s]\n", buf);

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
			DBG("buf[%s]\n", buf);

			uiapplication_x *up = mfx->uiapplication;
			appcontrol_x *acontrol = NULL;
			operation_x *op = NULL;
			mime_x *mi = NULL;
			uri_x *ui = NULL;
			subapp_x *sub = NULL;
			int ret = -1;
			char query[PKG_STRING_LEN_MAX] = {'\0'};
			char *operation = NULL;
			char *mime = NULL;
			char *uri = NULL;
			char *subapp = NULL;
			int i = 0;

			acontrol = up->appcontrol;
			while(acontrol != NULL)
			{
				op = acontrol->operation;
				while(op != NULL)
				{
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
								DBG("buf[%s]\n", buf);

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
	}

	free(buf);
	free(buftemp);

        return 0;
}

static int __ps_remove_nativeapp_desktop(manifest_x *mfx)
{
    char filepath[PKG_STRING_LEN_MAX] = "";
	int ret = 0;

	for(; mfx->uiapplication; mfx->uiapplication=mfx->uiapplication->next) {
	        snprintf(filepath, sizeof(filepath),"%s%s.desktop", DESKTOP_RW_PATH, mfx->uiapplication->appid);

		ret = remove(filepath);
		if (ret <0)
			return -1;
	}

        return 0;
}

#define MANIFEST_RO_PREFIX "/usr/share/packages/"
#define PRELOAD_PACKAGE_LIST "/usr/etc/package-manager/preload/preload_list.txt"
static int __add_preload_info(manifest_x * mfx, const char *manifest)
{
	FILE *fp = NULL;
	char buffer[1024] = { 0 };
	int state = 0;

	if(strstr(manifest, MANIFEST_RO_PREFIX)) {
		free(mfx->readonly);
		mfx->readonly = strdup("True");

		free(mfx->preload);
		mfx->preload = strdup("True");

		free(mfx->removable);
		mfx->removable = strdup("False");

		return 0;
	}

	fp = fopen(PRELOAD_PACKAGE_LIST, "r");
	if (fp == NULL) {
		DBGE("no preload list\n");
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
			free(mfx->preload);
			mfx->preload = strdup("True");
			if(state == 2){
				free(mfx->readonly);
				mfx->readonly = strdup("False");
				free(mfx->removable);
				mfx->removable = strdup("False");
			} else if(state == 3){
				free(mfx->readonly);
				mfx->readonly = strdup("False");
				free(mfx->removable);
				mfx->removable = strdup("True");
			}
		}

		memset(buffer, 0x00, sizeof(buffer));
	}

	if (fp != NULL)
		fclose(fp);

	return 0;
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
	if (mfx->type) {
		free((void *)mfx->type);
		mfx->type = NULL;
	}
	if (mfx->installed_time) {
		free((void *)mfx->installed_time);
		mfx->installed_time = NULL;
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

	/*Free Icon*/
	if (mfx->icon) {
		icon_x *icon = mfx->icon;
		icon_x *tmp = NULL;
		while(icon != NULL)
		{
			tmp = icon->next;
			__ps_free_icon(icon);
			icon = tmp;
		}
	}
	/*Free Label*/
	if (mfx->label) {
		label_x *label = mfx->label;
		label_x *tmp = NULL;
		while(label != NULL)
		{
			tmp = label->next;
			__ps_free_label(label);
			label = tmp;
		}
	}
	/*Free Author*/
	if (mfx->author) {
		author_x *author = mfx->author;
		author_x *tmp = NULL;
		while(author != NULL)
		{
			tmp = author->next;
			__ps_free_author(author);
			author = tmp;
		}
	}
	/*Free Description*/
	if (mfx->description) {
		description_x *description = mfx->description;
		description_x *tmp = NULL;
		while(description != NULL)
		{
			tmp = description->next;
			__ps_free_description(description);
			description = tmp;
		}
	}
	/*Free License*/
	if (mfx->license) {
		license_x *license = mfx->license;
		license_x *tmp = NULL;
		while(license != NULL)
		{
			tmp = license->next;
			__ps_free_license(license);
			license = tmp;
		}
	}
	/*Free UiApplication*/
	if (mfx->uiapplication) {
		uiapplication_x *uiapplication = mfx->uiapplication;
		uiapplication_x *tmp = NULL;
		while(uiapplication != NULL)
		{
			tmp = uiapplication->next;
			__ps_free_uiapplication(uiapplication);
			uiapplication = tmp;
		}
	}
	/*Free ServiceApplication*/
	if (mfx->serviceapplication) {
		serviceapplication_x *serviceapplication = mfx->serviceapplication;
		serviceapplication_x *tmp = NULL;
		while(serviceapplication != NULL)
		{
			tmp = serviceapplication->next;
			__ps_free_serviceapplication(serviceapplication);
			serviceapplication = tmp;
		}
	}
	/*Free Daemon*/
	if (mfx->daemon) {
		daemon_x *daemon = mfx->daemon;
		daemon_x *tmp = NULL;
		while(daemon != NULL)
		{
			tmp = daemon->next;
			__ps_free_daemon(daemon);
			daemon = tmp;
		}
	}
	/*Free Theme*/
	if (mfx->theme) {
		theme_x *theme = mfx->theme;
		theme_x *tmp = NULL;
		while(theme != NULL)
		{
			tmp = theme->next;
			__ps_free_theme(theme);
			theme = tmp;
		}
	}
	/*Free Font*/
	if (mfx->font) {
		font_x *font = mfx->font;
		font_x *tmp = NULL;
		while(font != NULL)
		{
			tmp = font->next;
			__ps_free_font(font);
			font = tmp;
		}
	}
	/*Free Ime*/
	if (mfx->ime) {
		ime_x *ime = mfx->ime;
		ime_x *tmp = NULL;
		while(ime != NULL)
		{
			tmp = ime->next;
			__ps_free_ime(ime);
			ime = tmp;
		}
	}
	/*Free Compatibility*/
	if (mfx->compatibility) {
		compatibility_x *compatibility = mfx->compatibility;
		compatibility_x *tmp = NULL;
		while(compatibility != NULL)
		{
			tmp = compatibility->next;
			__ps_free_compatibility(compatibility);
			compatibility = tmp;
		}
	}
	/*Free DeviceProfile*/
	if (mfx->deviceprofile) {
		deviceprofile_x *deviceprofile = mfx->deviceprofile;
		deviceprofile_x *tmp = NULL;
		while(deviceprofile != NULL)
		{
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
	DBG("parsing start\n");
	xmlTextReaderPtr reader;
	manifest_x *mfx = NULL;

	reader = xmlReaderForFile(manifest, NULL, 0);
	if (reader) {
		mfx = malloc(sizeof(manifest_x));
		if (mfx) {
			memset(mfx, '\0', sizeof(manifest_x));
			if (__process_manifest(reader, mfx) < 0) {
				DBG("Parsing Failed\n");
				pkgmgr_parser_free_manifest_xml(mfx);
				mfx = NULL;
			} else
				DBG("Parsing Success\n");
		} else {
			DBG("Memory allocation error\n");
		}
		xmlFreeTextReader(reader);
	} else {
		DBG("Unable to create xml reader\n");
	}
	return mfx;
}

/* These APIs are intended to call parser directly */

API int pkgmgr_parser_parse_manifest_for_installation(const char *manifest, char *const tagv[])
{
	char *temp[] = {"shortcut-list", "livebox", "Accounts", "account", NULL};
	if (manifest == NULL) {
		DBG("argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	DBG("parsing manifest for installation: %s\n", manifest);
	manifest_x *mfx = NULL;
	int ret = -1;
	xmlInitParser();
	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	DBG("Parsing Finished\n");
	if (mfx == NULL)
		return PMINFO_R_ERROR;
	
	__streamFile(manifest, ACTION_INSTALL, temp, mfx->package);
	__add_preload_info(mfx, manifest);
	DBG("Added preload infomation\n");
	ret = pkgmgr_parser_insert_manifest_info_in_db(mfx);
	if (ret == -1)
		DBG("DB Insert failed\n");
	else
		DBG("DB Insert Success\n");

	ret = __ps_make_nativeapp_desktop(mfx);
	if (ret == -1)
		DBG("Creating desktop file failed\n");
	else
		DBG("Creating desktop file Success\n");

	pkgmgr_parser_free_manifest_xml(mfx);
	DBG("Free Done\n");
	xmlCleanupParser();

	return PMINFO_R_OK;
}

API int pkgmgr_parser_parse_manifest_for_upgrade(const char *manifest, char *const tagv[])
{
	char *temp[] = {"shortcut-list", "livebox", "Accounts", "account", NULL};
	if (manifest == NULL) {
		DBG("argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	DBG("parsing manifest for upgradation: %s\n", manifest);
	manifest_x *mfx = NULL;
	int ret = -1;
	xmlInitParser();
	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	DBG("Parsing Finished\n");
	if (mfx == NULL)
		return PMINFO_R_ERROR;
	
	__streamFile(manifest, ACTION_UPGRADE, temp, mfx->package);
	__add_preload_info(mfx, manifest);
	DBG("Added preload infomation\n");
	ret = pkgmgr_parser_update_manifest_info_in_db(mfx);
	if (ret == -1)
		DBG("DB Update failed\n");
	else
		DBG("DB Update Success\n");

	ret = __ps_make_nativeapp_desktop(mfx);
	if (ret == -1)
		DBG("Creating desktop file failed\n");
	else
		DBG("Creating desktop file Success\n");

	pkgmgr_parser_free_manifest_xml(mfx);
	DBG("Free Done\n");
	xmlCleanupParser();

	return PMINFO_R_OK;
}

API int pkgmgr_parser_parse_manifest_for_uninstallation(const char *manifest, char *const tagv[])
{
	char *temp[] = {"shortcut-list", "livebox", "Accounts", "account", NULL};
	if (manifest == NULL) {
		DBG("argument supplied is NULL\n");
		return PMINFO_R_EINVAL;
	}
	DBG("parsing manifest for uninstallation: %s\n", manifest);
	manifest_x *mfx = NULL;
	int ret = -1;
	xmlInitParser();
	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	DBG("Parsing Finished\n");
	if (mfx == NULL)
		return PMINFO_R_ERROR;
	
	__streamFile(manifest, ACTION_UNINSTALL, temp, mfx->package);
	__add_preload_info(mfx, manifest);
	DBG("Added preload infomation\n");

	ret = pkgmgr_parser_delete_manifest_info_from_db(mfx);
	if (ret == -1)
		DBG("DB Delete failed\n");
	else
		DBG("DB Delete Success\n");

	ret = __ps_remove_nativeapp_desktop(mfx);
	if (ret == -1)
		DBG("Removing desktop file failed\n");
	else
		DBG("Removing desktop file Success\n");

	pkgmgr_parser_free_manifest_xml(mfx);
	DBG("Free Done\n");
	xmlCleanupParser();

	return PMINFO_R_OK;
}

API char *pkgmgr_parser_get_manifest_file(const char *pkgid)
{
	return __pkgid_to_manifest(pkgid);
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

#define SCHEMA_FILE "/usr/etc/package-manager/preload/manifest.xsd"
#if 1
API int pkgmgr_parser_check_manifest_validation(const char *manifest)
{
	if (manifest == NULL) {
		DBGE("manifest file is NULL\n");
		return PMINFO_R_EINVAL;
	}
	int ret = -1;
	xmlSchemaParserCtxtPtr ctx;
	xmlSchemaValidCtxtPtr vctx;
	xmlSchemaPtr xschema;
	ctx = xmlSchemaNewParserCtxt(SCHEMA_FILE);
	if (ctx == NULL) {
		DBGE("xmlSchemaNewParserCtxt() Failed\n");
		return PMINFO_R_ERROR;
	}
	xschema = xmlSchemaParse(ctx);
	if (xschema == NULL) {
		DBGE("xmlSchemaParse() Failed\n");
		return PMINFO_R_ERROR;
	}
	vctx = xmlSchemaNewValidCtxt(xschema);
	if (vctx == NULL) {
		DBGE("xmlSchemaNewValidCtxt() Failed\n");
		return PMINFO_R_ERROR;
	}
	xmlSchemaSetValidErrors(vctx, (xmlSchemaValidityErrorFunc) fprintf, (xmlSchemaValidityWarningFunc) fprintf, stderr);
	ret = xmlSchemaValidateFile(vctx, manifest, 0);
	if (ret == -1) {
		DBGE("xmlSchemaValidateFile() failed\n");
		return PMINFO_R_ERROR;
	} else if (ret == 0) {
		DBGE("Manifest is Valid\n");
		return PMINFO_R_OK;
	} else {
		DBGE("Manifest Validation Failed with error code %d\n", ret);
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
		DBGE("fork failed\n");
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
				DBGE("execl error\n");
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
			DBGE("waitpid failed\n");
			return -1;
		}
	}


	if(WIFEXITED(status) && !WEXITSTATUS(status))
		return 0;
	else
		return -1;
}
#endif
