/*
 * pkgmgr-info
 *
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <db-util.h>
#include <glib.h>
#include <dlfcn.h>
#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlschemas.h>
#include <bundle.h>
#include "pkgmgr-info.h"
#include "pkgmgr-info-debug.h"
#include "pkgmgr_parser_resource.h"
#include "pkgmgr_parser_resource_db.h"
#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "PKGMGR_PARSER"

#define XMLCHAR(s) (const xmlChar *)s
#define ASCII(s) (char *)s

#define FREE_AND_NULL(ptr) do { \
		if (ptr) { \
			free((void *)ptr); \
			ptr = NULL; \
		} \
	} while (0)


#define RSC_XML_QUALIFIER "res"
#define RSC_GROUP_NAME_SEPERATOR '-'
#define RSC_GROUP "group"
#define RSC_GROUP_ATTR_FOLDER "folder"
#define RSC_GROUP_ATTR_TYPE "type"
#define RSC_NODE "node"
#define RSC_MANIFEST_SCHEMA_FILE "/etc/package-manager/preload/res.xsd"

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

static void _free_node_list(void *data, void *user_data)
{
	resource_node_t *tmp_node = (resource_node_t *)data;

	if (tmp_node == NULL) {
		_LOGE("node list's element is NULL");
		return;
	}

	FREE_AND_NULL(tmp_node->folder);
	if (tmp_node->attr != NULL) {
		bundle_free(tmp_node->attr);
		tmp_node->attr = NULL;
	}
}

static void _free_group_list(void *data, void *user_data)
{
	resource_group_t *tmp_group = (resource_group_t *)data;

	if (tmp_group == NULL) {
		_LOGE("group list's element is NULL");
		return;
	}

	FREE_AND_NULL(tmp_group->folder);
	FREE_AND_NULL(tmp_group->type);

	g_list_free_full(tmp_group->node_list, (GDestroyNotify)_free_node_list);
}

static void __save_resource_attribute_into_bundle(xmlTextReaderPtr reader, char *attribute, bundle **b)
{
	xmlChar *attr_val = xmlTextReaderGetAttribute(reader, XMLCHAR(attribute));

	if (attr_val)
		bundle_add_str(*b, attribute, (char *)attr_val);
}

static void __save_resource_attribute(xmlTextReaderPtr reader, char *attribute, char **xml_attribute, char *default_value)
{
	xmlChar *attrib_val = xmlTextReaderGetAttribute(reader, XMLCHAR(attribute));

	if (attrib_val)
		*xml_attribute = strdup(ASCII(attrib_val));
	else {
		if (default_value != NULL)
			*xml_attribute = strdup(default_value);
	}
}


static void __psp_process_node(xmlTextReaderPtr reader, resource_node_t **res_node)
{
	char *node_folder = NULL;

	__save_resource_attribute(reader, "folder", &node_folder, NULL);
	bundle *b = NULL;
	(*res_node)->folder = node_folder;

	/*retrieve node's attribute and put it into bundle*/
	b = bundle_create();

	__save_resource_attribute_into_bundle(reader, RSC_NODE_ATTR_SCREEN_DPI, &b);
	__save_resource_attribute_into_bundle(reader, RSC_NODE_ATTR_SCREEN_DPI_RANGE, &b);
	__save_resource_attribute_into_bundle(reader, RSC_NODE_ATTR_SCREEN_WIDTH_RANGE, &b);
	__save_resource_attribute_into_bundle(reader, RSC_NODE_ATTR_SCREEN_LARGE, &b);
	__save_resource_attribute_into_bundle(reader, RSC_NODE_ATTR_SCREEN_BPP, &b);
	__save_resource_attribute_into_bundle(reader, RSC_NODE_ATTR_PLATFORM_VER, &b);
	__save_resource_attribute_into_bundle(reader, RSC_NODE_ATTR_LANGUAGE, &b);

	(*res_node)->attr = b;
}

static int __psp_process_group(xmlTextReaderPtr reader, resource_group_t **res_group, char *group_type)
{
	int depth = -1;
	int ret = -1;
	resource_group_t *tmp_group = NULL;
	resource_node_t *res_node = NULL;
	const xmlChar *node;
	char *folder = NULL;

	if (reader == NULL || *res_group == NULL || group_type == NULL) {
		_LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	tmp_group = *res_group;
	/*handle group's own attribute*/
	__save_resource_attribute(reader, RSC_GROUP_ATTR_FOLDER, &folder, NULL);
	tmp_group->folder = folder;
	tmp_group->type = group_type;

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGE("xmlTextReaderConstName value is NULL");
			return PMINFO_R_ERROR;
		}

		res_node = NULL;
		if (!strcmp(ASCII(node), RSC_NODE)) {
			res_node = malloc(sizeof(resource_node_t));
			if (res_node == NULL) {
				_LOGE("malloc failed");
				return -1;
			}
			tmp_group->node_list = g_list_append(tmp_group->node_list, res_node);
			__psp_process_node(reader, &res_node);
		} else {
			_LOGE("unidentified node has found[%s]", ASCII(node));
			return PMINFO_R_ERROR;
		}
	}
	return ret;
}

static int __is_group(char *node, char **type)
{
	char *tmp = NULL;

	if (node == NULL) {
		_LOGE("node is null");
		return PMINFO_R_EINVAL;
	}

	tmp = strchr(node, RSC_GROUP_NAME_SEPERATOR);
	tmp = tmp + 1; /*remove dash seperator*/
	if (!strcmp(tmp, PKGMGR_RSC_GROUP_TYPE_IMAGE))
		*type = strdup(tmp);
	else if (!strcmp(tmp, PKGMGR_RSC_GROUP_TYPE_LAYOUT))
		*type = strdup(tmp);
	else if (!strcmp(tmp, PKGMGR_RSC_GROUP_TYPE_SOUND))
		*type = strdup(tmp);
	else if (!strcmp(tmp, PKGMGR_RSC_GROUP_TYPE_BIN))
		*type = strdup(tmp);
	else
		return PMINFO_R_ERROR;

	if (*type == NULL) {
		_LOGE("strdup failed with node[%s]", node);
		return PMINFO_R_ERROR;
	}

	return PMINFO_R_OK;
}

static int __start_resource_process(xmlTextReaderPtr reader, GList **list)
{
	GList *tmp_list = NULL;
	const xmlChar *node;
	char *group_type = NULL;
	int ret = -1;
	int depth = -1;
	resource_group_t *res_group = NULL;

	if (reader == NULL) {
		_LOGE("reader is null");
		return PMINFO_R_EINVAL;
	}

	depth = xmlTextReaderDepth(reader);
	while ((ret = __next_child_element(reader, depth))) {
		node = xmlTextReaderConstName(reader);
		if (!node) {
			_LOGE("xmlTextReaderConstName value is null");
			return -1;
		}

		group_type = NULL;
		ret = __is_group(ASCII(node), &group_type);
		if (ret) {
			_LOGE("unidentified node[%s] has found with error[%d]", ASCII(node), ret);
			goto err;
		}
		res_group = NULL;
		res_group = malloc(sizeof(resource_group_t));
		if (res_group == NULL) {
			_LOGE("malloc failed");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		memset(res_group, '\0', sizeof(resource_group_t));
		tmp_list = g_list_append(tmp_list, res_group);
		ret = __psp_process_group(reader, &res_group, group_type);
		if (ret != 0) {
			_LOGE("resource group processing failed");
			ret = PMINFO_R_ERROR;
			goto err;
		}
	}

	*list = g_list_first(tmp_list);
	return ret;

err:
	FREE_AND_NULL(group_type);
	FREE_AND_NULL(res_group);
	g_list_free_full(tmp_list, _free_group_list);

	return ret;
}

static int __process_resource_manifest(xmlTextReaderPtr reader, resource_data_t *data)
{
	const xmlChar *node;
	int ret = PMINFO_R_ERROR;

	if (reader == NULL)
		return PMINFO_R_ERROR;

	ret = __next_child_element(reader, -1);
	if (ret) {
		node = xmlTextReaderConstName(reader);
		retvm_if(!node, PMINFO_R_ERROR, "xmlTextReaderConstName value is NULL\n");

		if (!strcmp(ASCII(node), RSC_XML_QUALIFIER)) {
			ret = __start_resource_process(reader, &data->group_list);
			if (data->group_list == NULL)
				_LOGE("__process_resource_manifest about to end but group list is null[%d]", ret);
		} else {
			_LOGE("no manifest element[res] has found");
			return PMINFO_R_ERROR;
		}
	}
	return ret;
}

static resource_data_t *_pkgmgr_resource_parser_process_manifest_xml(const char *manifest)
{
	xmlTextReaderPtr reader;
	resource_data_t *rsc_data = NULL;

	reader = xmlReaderForFile(manifest, NULL, 0);
	if (reader) {
		rsc_data = malloc(sizeof(resource_data_t));
		if (rsc_data == NULL) {
			_LOGE("memory allocation failed");
			return NULL;
		}

		memset(rsc_data, '\0', sizeof(resource_data_t));
		if (__process_resource_manifest(reader, rsc_data) < 0) {
			_LOGE("parsing failed with given manifest[%s]", manifest);
			if (pkgmgr_resource_parser_close(rsc_data) != 0)
				_LOGE("closing failed");
			rsc_data = NULL;
		} else
			_LOGE("parsing succeed");

		xmlFreeTextReader(reader);
	} else {
		_LOGE("creating xmlreader failed");
		FREE_AND_NULL(rsc_data);
	}
	return rsc_data;
}

API int pkgmgr_resource_parser_open_from_db(const char *package, resource_data_t **data)
{
	resource_data_t *rsc_data = NULL;
	int ret = -1;

	if (package == NULL || strlen(package) == 0) {
		_LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	ret = pkgmgr_parser_resource_db_load(package, &rsc_data);
	if (ret != 0) {
		_LOGE("get resource data from db failed");
		return ret;
	}

	*data = rsc_data;
	return ret;
}

API int pkgmgr_resource_parser_open(const char *fname, const char *package, resource_data_t **data)
{
	resource_data_t *rsc_data = NULL;
	int ret = PMINFO_R_ERROR;

	if (fname == NULL || access(fname, R_OK) != 0) {
		_LOGE("filename is null or cannot access file");
		return PMINFO_R_EINVAL;
	}
	xmlInitParser();
	rsc_data = _pkgmgr_resource_parser_process_manifest_xml(fname);
	if (rsc_data == NULL) {
		_LOGE("parsing failed");
		goto catch;
	}
	rsc_data->package = strdup(package);

	*data = rsc_data;
	ret = PMINFO_R_OK;
catch:
	xmlCleanupParser();
	return ret;
}

API int pkgmgr_resource_parser_close(resource_data_t *data)
{
	if (data == NULL) {
		_LOGE("parameter is NULL");
		return PMINFO_R_EINVAL;
	}

	FREE_AND_NULL(data->package);
	g_list_free_full(data->group_list, (GDestroyNotify)_free_group_list);

	return PMINFO_R_OK;
}

API int pkgmgr_resource_parser_insert_into_db(resource_data_t *data)
{
	if (data == NULL) {
		_LOGE("parameter is NULL");
		return PMINFO_R_EINVAL;
	}

	return pkgmgr_parser_resource_db_save(data->package, data);
}

API int pkgmgr_resource_parser_delete_from_db(const char *package)
{
	if (package == NULL) {
		_LOGE("parameter is NULL");
		return PMINFO_R_EINVAL;
	}

	return pkgmgr_parser_resource_db_remove(package);
}

API int pkgmgr_resource_parser_check_xml_validation(const char *xmlfile)
{
	if (xmlfile == NULL) {
		_LOGE("manifest file is NULL\n");
		return PM_PARSER_R_EINVAL;
	}
	int ret = PM_PARSER_R_OK;
	xmlSchemaParserCtxtPtr ctx = NULL;
	xmlSchemaValidCtxtPtr vctx = NULL;
	xmlSchemaPtr xschema = NULL;
	ctx = xmlSchemaNewParserCtxt(RSC_MANIFEST_SCHEMA_FILE);
	if (ctx == NULL) {
		_LOGE("xmlSchemaNewParserCtxt() Failed\n");
		return PM_PARSER_R_ERROR;
	}
	xschema = xmlSchemaParse(ctx);
	if (xschema == NULL) {
		_LOGE("xmlSchemaParse() Failed\n");
		ret = PM_PARSER_R_ERROR;
		goto cleanup;
	}
	vctx = xmlSchemaNewValidCtxt(xschema);
	if (vctx == NULL) {
		_LOGE("xmlSchemaNewValidCtxt() Failed\n");
		return PM_PARSER_R_ERROR;
	}
	xmlSchemaSetValidErrors(vctx, (xmlSchemaValidityErrorFunc) fprintf, (xmlSchemaValidityWarningFunc) fprintf, stderr);
	ret = xmlSchemaValidateFile(vctx, xmlfile, 0);
	if (ret == -1) {
		_LOGE("xmlSchemaValidateFile() failed\n");
		ret = PM_PARSER_R_ERROR;
		goto cleanup;
	} else if (ret == 0) {
		_LOGE("Manifest is Valid\n");
		ret = PM_PARSER_R_OK;
		goto cleanup;
	} else {
		_LOGE("Manifest Validation Failed with error code %d\n", ret);
		ret = PM_PARSER_R_ERROR;
		goto cleanup;
	}

cleanup:
	if(vctx != NULL)
		xmlSchemaFreeValidCtxt(vctx);

	if(ctx != NULL)
		xmlSchemaFreeParserCtxt(ctx);

	if(xschema != NULL)
		xmlSchemaFree(xschema);

	return ret;
}
