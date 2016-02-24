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
#include "pkgmgrinfo_basic.h"

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
int pkgmgr_parser_process_manifest_x_for_installation(manifest_x* mfx, const char *manifest);
int pkgmgr_parser_process_usr_manifest_x_for_installation(manifest_x* mfx, const char *manifest, uid_t uid);

/**
 * @fn int pkgmgr_parser_update_tep(const char* pkgid, const char * tep_path)
 * @fn int pkgmgr_parser_usr_update_tep(const char* pkgid, const char* tep_path, uid_t uid)
 * @brief	This API updates tep path information stored in DB.
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	pkgid	pointer to package ID
  * @param[in]tep_path	pointer to path of TEP file
 * @param[in]	uid	the addressee user id of the instruction
 * @return	0 if success, error code(<0) if fail
 * @retval	PMINFO_R_OK	success
 * @retval	PMINFO_R_EINVAL	invalid argument
 * @retval	PMINFO_R_ERROR	internal error
 * @pre		None
 * @post		None
 * @code
static int update_tep_info_for_upgrade(const char *pkgid, const char *tep_path)
{
	int ret = 0;
	ret = pkgmgr_parser_update_tep(pkgid, tep_path);
	if (ret)
		return -1;
	return 0;
}
 * @endcode
 */
int pkgmgr_parser_update_tep(const char* pkgid, const char* tep_path);
int pkgmgr_parser_usr_update_tep(const char* pkgid, const char* tep_path, uid_t uid);

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
int pkgmgr_parser_process_manifest_x_for_upgrade(manifest_x* mfx, const char *manifest);
int pkgmgr_parser_process_usr_manifest_x_for_upgrade(manifest_x* mfx, const char *manifest, uid_t uid);

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
int pkgmgr_parser_process_manifest_x_for_uninstallation(manifest_x* mfx, const char *manifest);
int pkgmgr_parser_process_usr_manifest_x_for_uninstallation(manifest_x* mfx, const char *manifest, uid_t uid);

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
