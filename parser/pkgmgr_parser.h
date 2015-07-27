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

#ifndef __PKGMGR_PARSER_H__
#define __PKGMGR_PARSER_H__

/**
 * @file pkgmgr_parser.h
 * @author Sewook Park <sewook7.park@samsung.com>
 * @author Shobhit Srivastava <shobhit.s@samsung.com>
 * @version 0.1
 * @brief    This file declares API of pkgmgr_parser
 * @addtogroup		APPLICATION_FRAMEWORK
 * @{
 *
 * @defgroup		PackageManagerParser
 * @section		Header Header file to include:
 * @code
 * #include		<pkgmgr_parser.h>
 * @endcode
 *
 * @}
 */

#include <libxml/xmlreader.h>

/* For multi-user support */
#include <tzplatform_config.h>

#ifdef __cplusplus
extern "C" {
#endif
#define DEFAULT_LOCALE		"No Locale"

#define PKG_PARSERLIB	"parserlib:"
#define PKG_PARSER_CONF_PATH	SYSCONFDIR "/package-manager/parser_path.conf"

#define PKG_STRING_LEN_MAX 1024

#define PKGMGR_PARSER_EMPTY_STR		""
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

/**
 * @brief API return values
 */
enum {
	PM_PARSER_R_EINVAL = -2,		/**< Invalid argument */
	PM_PARSER_R_ERROR = -1,		/**< General error */
	PM_PARSER_R_OK = 0			/**< General success */
};

/**
 * @brief List definitions.
 * All lists are doubly-linked, the last element is stored to list pointer,
 * which means that lists must be looped using the prev pointer, or by
 * calling LISTHEAD first to go to start in order to use the next pointer.
 */

 /**
 * @brief Convinience Macro to add node in list
 */

#define LISTADD(list, node)			\
    do {					\
	(node)->prev = (list);			\
	if (list) (node)->next = (list)->next;	\
	else (node)->next = NULL;		\
	if (list) (list)->next = (node);	\
	(list) = (node);			\
    } while (0);

 /**
 * @brief Convinience Macro to add one node to another node
 */
#define NODEADD(node1, node2)					\
    do {							\
	(node2)->prev = (node1);				\
	(node2)->next = (node1)->next;				\
	if ((node1)->next) (node1)->next->prev = (node2);	\
	(node1)->next = (node2);				\
    } while (0);

 /**
 * @brief Convinience Macro to concatenate two lists
 */
#define LISTCAT(list, first, last)		\
    if ((first) && (last)) {			\
	(first)->prev = (list);			\
	(list) = (last);			\
    }

 /**
 * @brief Convinience Macro to delete node from list
 */
#define LISTDEL(list, node)					\
    do {							\
	if ((node)->prev) (node)->prev->next = (node)->next;	\
	if ((node)->next) (node)->next->prev = (node)->prev;	\
	if (!((node)->prev) && !((node)->next)) (list) = NULL;	\
    } while (0);

 /**
 * @brief Convinience Macro to get list head
 */
#define LISTHEAD(list, node)					\
    for ((node) = (list); (node)->prev; (node) = (node)->prev)

 /**
 * @brief Convinience Macro to get list tail
 */
#define LISTTAIL(list, node)					\
    for ((node) = (list); (node)->next; (node) = (node)->next)

typedef struct metadata_x {
	const char *key;
	const char *value;
	struct metadata_x *prev;
	struct metadata_x *next;
} metadata_x;

typedef struct privilege_x {
	const char *text;
	struct privilege_x *prev;
	struct privilege_x *next;
} privilege_x;

typedef struct privileges_x {
	struct privilege_x *privilege;
	struct privileges_x *prev;
	struct privileges_x *next;
} privileges_x;

typedef struct permission_x {
	const char *type;
	const char *value;
	struct permission_x *prev;
	struct permission_x *next;
} permission_x;

typedef struct icon_x {
	const char *name;
	const char *text;
	const char *lang;
	const char *section;
	const char *size;
	const char *resolution;
	struct icon_x *prev;
	struct icon_x *next;
} icon_x;

typedef struct image_x {
	const char *name;
	const char *text;
	const char *lang;
	const char *section;
	struct image_x *prev;
	struct image_x *next;
} image_x;

typedef struct allowed_x {
	const char *name;
	const char *text;
	struct allowed_x *prev;
	struct allowed_x *next;
} allowed_x;

typedef struct request_x {
	const char *text;
	struct request_x *prev;
	struct request_x *next;
} request_x;

typedef struct define_x {
	const char *path;
	struct allowed_x *allowed;
	struct request_x *request;
	struct define_x *prev;
	struct define_x *next;
} define_x;

typedef struct datashare_x {
	struct define_x *define;
	struct request_x *request;
	struct datashare_x *prev;
	struct datashare_x *next;
} datashare_x;

typedef struct description_x {
	const char *name;
	const char *text;
	const char *lang;
	struct description_x *prev;
	struct description_x *next;
} description_x;

typedef struct registry_x {
	const char *name;
	const char *text;
	struct registry_x *prev;
	struct registry_x *next;
} registry_x;

typedef struct database_x {
	const char *name;
	const char *text;
	struct database_x *prev;
	struct database_x *next;
} database_x;

typedef struct layout_x {
	const char *name;
	const char *text;
	struct layout_x *prev;
	struct layout_x *next;
} layout_x;

typedef struct label_x {
	const char *name;
	const char *text;
	const char *lang;
	struct label_x *prev;
	struct label_x *next;
} label_x;

typedef struct author_x {
	const char *email;
	const char *href;
	const char *text;
	const char *lang;
	struct author_x *prev;
	struct author_x *next;
} author_x;

typedef struct license_x {
	const char *text;
	const char *lang;
	struct license_x *prev;
	struct license_x *next;
} license_x;

typedef struct operation_x {
	const char *name;
	const char *text;
	struct operation_x *prev;
	struct operation_x *next;
} operation_x;

typedef struct uri_x {
	const char *name;
	const char *text;
	struct uri_x *prev;
	struct uri_x *next;
} uri_x;

typedef struct mime_x {
	const char *name;
	const char *text;
	struct mime_x *prev;
	struct mime_x *next;
} mime_x;

typedef struct subapp_x {
	const char *name;
	const char *text;
	struct subapp_x *prev;
	struct subapp_x *next;
} subapp_x;

typedef struct condition_x {
	const char *name;
	const char *text;
	struct condition_x *prev;
	struct condition_x *next;
} condition_x;

typedef struct notification_x {
	const char *name;
	const char *text;
	struct notification_x *prev;
	struct notification_x *next;
} notification_x;

typedef struct appsvc_x {
	const char *text;
	struct operation_x *operation;
	struct uri_x *uri;
	struct mime_x *mime;
	struct subapp_x *subapp;
	struct appsvc_x *prev;
	struct appsvc_x *next;
} appsvc_x;

typedef struct appcontrol_x {
	const char *operation;
	const char *uri;
	const char *mime;
	struct appcontrol_x *prev;
	struct appcontrol_x *next;
} appcontrol_x;

typedef struct category_x{
	const char *name;
	struct category_x *prev;
	struct category_x *next;
} category_x;

typedef struct launchconditions_x {
	const char *text;
	struct condition_x *condition;
	struct launchconditions_x *prev;
	struct launchconditions_x *next;
} launchconditions_x;

typedef struct compatibility_x {
	const char *name;
	const char *text;
	struct compatibility_x *prev;
	struct compatibility_x *next;
}compatibility_x;

typedef struct deviceprofile_x {
	const char *name;
	const char *text;
	struct deviceprofile_x *prev;
	struct deviceprofile_x *next;
}deviceprofile_x;

typedef struct datacontrol_x {
	const char *providerid;
	const char *access;
	const char *type;
	struct datacontrol_x *prev;
	struct datacontrol_x *next;
} datacontrol_x;

typedef struct application_x {
	const char *appid;
	const char *component;
	const char *exec;
	const char *nodisplay;
	const char *type;
	const char *onboot;
	const char *multiple;
	const char *autorestart;
	const char *taskmanage;
	const char *enabled;
	const char *hwacceleration;
	const char *screenreader;
	const char *mainapp;
	const char *recentimage;
	const char *launchcondition;
	const char *indicatordisplay;
	const char *portraitimg;
	const char *landscapeimg;
	const char *guestmode_visibility;
	const char *permission_type;
	const char *preload;
	const char *submode;
	const char *submode_mainid;
	const char *launch_mode;
	const char *component_type;
	const char *package;
	struct label_x *label;
	struct icon_x *icon;
	struct image_x *image;
	struct appsvc_x *appsvc;
	struct appcontrol_x *appcontrol;
	struct category_x *category;
	struct metadata_x *metadata;
	struct permission_x *permission;
	struct launchconditions_x *launchconditions;
	struct notification_x *notification;
	struct datashare_x *datashare;
	struct datacontrol_x *datacontrol;
	struct application_x *prev;
	struct application_x *next;
} application_x;

typedef struct uiapplication_x {
	const char *appid;
	const char *exec;
	const char *nodisplay;
	const char *multiple;
	const char *taskmanage;
	const char *enabled;
	const char *type;
	const char *categories;
	const char *extraid;
	const char *hwacceleration;
	const char *screenreader;
	const char *mainapp;
	const char *package;
	const char *recentimage;
	const char *launchcondition;
	const char *indicatordisplay;
	const char *portraitimg;
	const char *landscapeimg;
	const char *guestmode_visibility;
	const char *app_component;
	const char *permission_type;
	const char *component_type;
	const char *preload;
	const char *submode;
	const char *submode_mainid;
	const char *launch_mode;
	struct label_x *label;
	struct icon_x *icon;
	struct image_x *image;
	struct appsvc_x *appsvc;
	struct appcontrol_x *appcontrol;
	struct category_x *category;
	struct metadata_x *metadata;
	struct permission_x *permission;
	struct launchconditions_x *launchconditions;
	struct notification_x *notification;
	struct datashare_x *datashare;
	struct datacontrol_x *datacontrol;
	struct uiapplication_x *prev;
	struct uiapplication_x *next;

} uiapplication_x;

typedef struct serviceapplication_x {
	const char *appid;
	const char *exec;
	const char *onboot;
	const char *autorestart;
	const char *enabled;
	const char *type;
	const char *package;
	const char *permission_type;
	struct label_x *label;
	struct icon_x *icon;
	struct appsvc_x *appsvc;
	struct appcontrol_x *appcontrol;
	struct category_x *category;
	struct metadata_x *metadata;
	struct permission_x *permission;
	struct datacontrol_x *datacontrol;
	struct launchconditions_x *launchconditions;
	struct notification_x *notification;
	struct datashare_x *datashare;
	struct serviceapplication_x *prev;
	struct serviceapplication_x *next;
} serviceapplication_x;

typedef struct daemon_x {
	const char *name;
	const char *text;
	struct daemon_x *prev;
	struct daemon_x *next;
} daemon_x;

typedef struct theme_x {
	const char *name;
	const char *text;
	struct theme_x *prev;
	struct theme_x *next;
} theme_x;

typedef struct font_x {
	const char *name;
	const char *text;
	struct font_x *prev;
	struct font_x *next;
} font_x;

typedef struct ime_x {
	const char *name;
	const char *text;
	struct ime_x *prev;
	struct ime_x *next;
} ime_x;

typedef struct manifest_x {
	const char *for_all_users;		/**< Flag that indicates if the package is available for everyone or for current user only*/
	const char *package;		/**< package name*/
	const char *version;		/**< package version*/
	const char *installlocation;		/**< package install location*/
	const char *ns;		/**<name space*/
	const char *removable;		/**< package removable flag*/
	const char *preload;		/**< package preload flag*/
	const char *readonly;		/**< package readonly flag*/
	const char *update;			/**< package update flag*/
	const char *appsetting;		/**< package app setting flag*/
	const char *system;		/**< package system flag*/
	const char *type;		/**< package type*/
	const char *package_size;		/**< package size for external installation*/
	const char *installed_time;		/**< installed time after finishing of installation*/
	const char *installed_storage;		/**< package currently installed storage*/
	const char *storeclient_id;		/**< id of store client for installed package*/
	const char *mainapp_id;		/**< app id of main application*/
	const char *package_url;		/**< app id of main application*/
	const char *root_path;		/**< package root path*/
	const char *csc_path;		/**< package csc path*/
	const char *nodisplay_setting;		/**< package no display setting menu*/
	const char *api_version;		/**< minimum version of API package using*/
	struct icon_x *icon;		/**< package icon*/
	struct label_x *label;		/**< package label*/
	struct author_x *author;		/**< package author*/
	struct description_x *description;		/**< package description*/
	struct license_x *license;		/**< package license*/
	struct privileges_x *privileges;	/**< package privileges*/
	struct uiapplication_x *uiapplication;		/**< package's ui application*/
	struct serviceapplication_x *serviceapplication;		/**< package's service application*/
	struct daemon_x *daemon;		/**< package daemon*/
	struct theme_x *theme;		/**< package theme*/
	struct font_x *font;		/**< package font*/
	struct ime_x *ime;		/**< package ime*/
	struct compatibility_x *compatibility;		/**< package compatibility*/
	struct deviceprofile_x *deviceprofile;		/**< package device profile*/
} manifest_x;

/*enum uid_value {
	ROOT,
	GLOBAL,
	USER
};*/

/**uid check
 * 
 */
/* int check_uid(uid_t uid)
 {
	 switch(uid)
	 {
		case GLOBAL_USER: return GLOBAL;
		case 0:	return ROOT;
		default: goto user; break;
	}
user:
cf getdbpath
*/
 

/**
 * @fn char *pkgmgr_parser_get_manifest_file(const char *pkgid)
 * @brief	This API gets the manifest file of the package.
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	pkgid	pointer to package ID
 * @return	manifest file path on success, NULL on failure
 * @pre		None
 * @post		Free the manifest file pointer that is returned by API
 * @code
static int get_manifest_file(const char *pkgid)
{
	char *manifest = NULL;
	manifest = pkgmgr_parser_get_manifest_file(pkgid);
	if (manifest == NULL)
		return -1;
	printf("Manifest File Path is %s\n", manifest);
	free(manifest);
	return 0;
}
 * @endcode
 */
char *pkgmgr_parser_get_manifest_file(const char *pkgid);
char *pkgmgr_parser_get_usr_manifest_file(const char *pkgid, uid_t uid);

/**
 * @fn int pkgmgr_parser_parse_manifest_for_installation(const char *manifest, char *const tagv[])
 * @fn int pkgmgr_parser_parse_usr_manifest_for_installation(const char *manifest, uid_t uid, char *const tagv[])
 * @brief	This API parses the manifest file of the package after installation and stores the data in DB.
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	manifest	pointer to package manifest file
 * @param[in]	uid	the addressee user id of the instruction
 * @param[in]	tagv		array of xml tags or NULL
 * @return	0 if success, error code(<0) if fail
 * @retval	PMINFO_R_OK	success
 * @retval	PMINFO_R_EINVAL	invalid argument
 * @retval	PMINFO_R_ERROR	internal error
 * @pre		None
 * @post		None
 * @code
static int parse_manifest_file_for_installation(const char *manifest)
{
	int ret = 0;
	ret = pkgmgr_parser_parse_manifest_for_installation(manifest, NULL);
	if (ret)
		return -1;
	return 0;
}
 * @endcode
 */
int pkgmgr_parser_parse_manifest_for_installation(const char *manifest, char *const tagv[]);
int pkgmgr_parser_parse_usr_manifest_for_installation(const char *manifest, uid_t uid, char *const tagv[]);

/**
 * @fn int pkgmgr_parser_parse_usr_manifest_for_upgrade(const char *manifest,  uid_t uid, char *const tagv[])
 * @fn int pkgmgr_parser_parse_manifest_for_upgrade(const char *manifest, char *const tagv[])
 * @brief	This API parses the manifest file of the package after upgrade and stores the data in DB.
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	manifest	pointer to package manifest file
 * @param[in]	uid	the addressee user id of the instruction
 * @param[in]	tagv		array of xml tags or NULL
 * @return	0 if success, error code(<0) if fail
 * @retval	PMINFO_R_OK	success
 * @retval	PMINFO_R_EINVAL	invalid argument
 * @retval	PMINFO_R_ERROR	internal error
 * @pre		None
 * @post		None
 * @code
static int parse_manifest_file_for_upgrade(const char *manifest)
{
	int ret = 0;
	ret = pkgmgr_parser_parse_manifest_for_upgrade(manifest, NULL);
	if (ret)
		return -1;
	return 0;
}
 * @endcode
 */
int pkgmgr_parser_parse_manifest_for_upgrade(const char *manifest, char *const tagv[]);
int pkgmgr_parser_parse_usr_manifest_for_upgrade(const char *manifest, uid_t uid, char *const tagv[]);
/**
 * @fn int pkgmgr_parser_parse_manifest_for_uninstallation(const char *manifest, char *const tagv[])
 * @fn int pkgmgr_parser_parse_usr_manifest_for_uninstallation(const char *manifest, uid_t uid, char *const tagv[])
 * @brief	This API parses the manifest file of the package after uninstallation and deletes the data from DB.
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	manifest	pointer to package manifest file
 * @param[in]	uid	the addressee user id of the instruction
 * @param[in]	tagv		array of xml tags or NULL
 * @return	0 if success, error code(<0) if fail
 * @retval	PMINFO_R_OK	success
 * @retval	PMINFO_R_EINVAL	invalid argument
 * @retval	PMINFO_R_ERROR	internal error
 * @pre		None
 * @post		None
 * @code
static int parse_manifest_file_for_uninstallation(const char *manifest)
{
	int ret = 0;
	ret = pkgmgr_parser_parse_manifest_for_uninstallation(manifest, NULL);
	if (ret)
		return -1;
	return 0;
}
 * @endcode
 */
int pkgmgr_parser_parse_manifest_for_uninstallation(const char *manifest, char *const tagv[]);
int pkgmgr_parser_parse_usr_manifest_for_uninstallation(const char *manifest, uid_t uid, char *const tagv[]);
/**
 * @fn int pkgmgr_parser_parse_manifest_for_preload()
 * @fn int pkgmgr_parser_parse_usr_manifest_for_preload(uid_t uid)
 * @brief	This API update  preload information to DB.
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @return	0 if success, error code(<0) if fail
 * @retval	PMINFO_R_OK	success
 * @retval	PMINFO_R_EINVAL	invalid argument
 * @retval	PMINFO_R_ERROR	internal error
 * @pre		None
 * @post		None
 * @code
static int parser_parse_manifest_for_preload()
{
	int ret = 0;
	ret = pkgmgr_parser_parse_manifest_for_preload();
	if (ret)
		return -1;
	return 0;
}
 * @endcode
 */
int pkgmgr_parser_parse_manifest_for_preload();
int pkgmgr_parser_parse_usr_manifest_for_preload(uid_t uid);

/**
 * @fn int pkgmgr_parser_check_manifest_validation(const char *manifest)
 * @brief	This API validates the manifest file against the manifest schema.
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	manifest	pointer to package manifest file
 * @return	0 if success, error code(<0) if fail
 * @retval	PMINFO_R_OK	success
 * @retval	PMINFO_R_EINVAL	invalid argument
 * @retval	PMINFO_R_ERROR	internal error
 * @pre		None
 * @post		None
 * @code
static int validate_manifest_file(const char *manifest)
{
	int ret = 0;
	ret = pkgmgr_parser_check_manifest_validation(manifest);
	if (ret)
		return -1;
	return 0;
}
 * @endcode
 */
int pkgmgr_parser_check_manifest_validation(const char *manifest);

/**
 * @fn void pkgmgr_parser_free_manifest_xml(manifest_x *mfx)
 * @brief	This API will free the manifest pointer by recursively freeing all sub elements.
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	mfx	pointer to parsed manifest data
 * @pre		pkgmgr_parser_process_manifest_xml()
 * @post		None
 * @code
static int parse_manifest_file(const char *manifest)
{
	manifest_x *mfx = NULL
	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	if (mfx == NULL)
		return -1;
	printf("Parsing Manifest Success\n");
	pkgmgr_parser_free_manifest_xml(mfx);
	return 0;
}
 * @endcode
 */
void pkgmgr_parser_free_manifest_xml(manifest_x *mfx);

/**
 * @fn manifest_x *pkgmgr_parser_process_manifest_xml(const char *manifest)
 * @fn manifest_x *pkgmgr_parser_usr_process_manifest_xml(const char *manifest, uid_t uid)
 * @brief	This API parses the manifest file and stores all the data in the manifest structure.
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	manifest	pointer to package manifest file
 * @param[in]	uid	the addressee user id of the instruction
 * @return	manifest pointer on success, NULL on failure
 * @pre		None
 * @post		pkgmgr_parser_free_manifest_xml()
 * @code
static int parse_manifest_file(const char *manifest)
{
	manifest_x *mfx = NULL
	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	if (mfx == NULL)
		return -1;
	printf("Parsing Manifest Success\n");
	pkgmgr_parser_free_manifest_xml(mfx);
	return 0;
}
 * @endcode
 */
manifest_x *pkgmgr_parser_process_manifest_xml(const char *manifest);
manifest_x *pkgmgr_parser_usr_process_manifest_xml(const char *manifest, uid_t uid);

/**
 * @fn int pkgmgr_parser_run_parser_for_installation(xmlDocPtr docPtr, const char *tag, const char *pkgid)
 * @brief	This API calls the parser directly by supplying the xml docptr. It is used during package installation
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	docPtr	XML doxument pointer
 * @param[in]	tag		the xml tag corresponding to the parser that will parse the docPtr
 * @param[in]	pkgid		the package id
 * @return	0 if success, error code(<0) if fail
 * @retval	PMINFO_R_OK	success
 * @retval	PMINFO_R_EINVAL	invalid argument
 * @retval	PMINFO_R_ERROR	internal error
 * @pre		None
 * @post		None
 * @code
static int parse_docptr_for_installation(xmlDocPtr docPtr)
{
	int ret = 0;
	ret = pkgmgr_parser_run_parser_for_installation(docPtr, "theme", "com.samsung.test");
	if (ret)
		return -1;
	return 0;
}
 * @endcode
 */
int pkgmgr_parser_run_parser_for_installation(xmlDocPtr docPtr, const char *tag, const char *pkgid);

/**
 * @fn int pkgmgr_parser_run_parser_for_upgrade(xmlDocPtr docPtr, const char *tag, const char *pkgid)
 * @brief	This API calls the parser directly by supplying the xml docptr. It is used during package upgrade
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	docPtr	XML doxument pointer
 * @param[in]	tag		the xml tag corresponding to the parser that will parse the docPtr
 * @param[in]	pkgid		the package id
 * @return	0 if success, error code(<0) if fail
 * @retval	PMINFO_R_OK	success
 * @retval	PMINFO_R_EINVAL	invalid argument
 * @retval	PMINFO_R_ERROR	internal error
 * @pre		None
 * @post		None
 * @code
static int parse_docptr_for_upgrade(xmlDocPtr docPtr)
{
	int ret = 0;
	ret = pkgmgr_parser_run_parser_for_upgrade(docPtr, "theme", "com.samsung.test");
	if (ret)
		return -1;
	return 0;
}
 * @endcode
 */
int pkgmgr_parser_run_parser_for_upgrade(xmlDocPtr docPtr, const char *tag, const char *pkgid);

/**
 * @fn int pkgmgr_parser_run_parser_for_uninstallation(xmlDocPtr docPtr, const char *tag, const char *pkgid)
 * @brief	This API calls the parser directly by supplying the xml docptr. It is used during package uninstallation
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	docPtr	XML doxument pointer
 * @param[in]	tag		the xml tag corresponding to the parser that will parse the docPtr
 * @param[in]	pkgid		the package id
 * @return	0 if success, error code(<0) if fail
 * @retval	PMINFO_R_OK	success
 * @retval	PMINFO_R_EINVAL	invalid argument
 * @retval	PMINFO_R_ERROR	internal error
 * @pre		None
 * @post		None
 * @code
static int parse_docptr_for_uninstallation(xmlDocPtr docPtr)
{
	int ret = 0;
	ret = pkgmgr_parser_run_parser_for_uninstallation(docPtr, "theme", "com.samsung.test");
	if (ret)
		return -1;
	return 0;
}
 * @endcode
 */
int pkgmgr_parser_run_parser_for_uninstallation(xmlDocPtr docPtr, const char *tag, const char *pkgid);



/**
 * @fn int pkgmgr_parser_create_desktop_file(manifest_x *mfx)
 * @fn int pkgmgr_parser_create_usr_desktop_file(manifest_x *mfx, uid_t uid)
 * @brief	This API generates the application desktop file
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	mfx	manifest pointer
 * @param[in]	uid	the addressee user id of the instruction
 * @return	0 if success, error code(<0) if fail
 * @retval	PMINFO_R_OK	success
 * @retval	PMINFO_R_EINVAL	invalid argument
 * @retval	PMINFO_R_ERROR	internal error
 * @pre		pkgmgr_parser_process_manifest_xml()
 * @post	pkgmgr_parser_free_manifest_xml()
 * @code
static int create_desktop_file(char *manifest)
{
	int ret = 0;
	manifest_x *mfx = NULL;
	mfx = pkgmgr_parser_process_manifest_xml(manifest);
	ret = pkgmgr_parser_create_desktop_file(mfx);
	if (ret)
		return -1;
	pkgmgr_parser_free_manifest_xml(mfx);
	return 0;
}
 * @endcode
 */
int pkgmgr_parser_create_desktop_file(manifest_x *mfx);
int pkgmgr_parser_create_usr_desktop_file(manifest_x *mfx, uid_t uid);

/** @} */
#ifdef __cplusplus
}
#endif
#endif				/* __PKGMGR_PARSER_H__ */
