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


/**
 * @file		pkgmgr_parser_db.h
 * @author	Shobhit Srivastava <shobhit.s@samsung.com>
 * @version	0.1
 * @brief		This file declares API to store/retrieve manifest data in DB
 *
 * @addtogroup APPLICATION_FRAMEWORK
 * @{
 *
  * @defgroup	PackageManagerParserDB
 * @section	Header Header file to include:
 * @code
 * #include <pkgmgr_parser_db.h>
 * @endcode
 *
 * @}
 */

#ifndef __PKGMGR_PARSER_DB_H__
#define __PKGMGR_PARSER_DB_H__

#ifdef __cplusplus
extern "C" {
#endif
#include "pkgmgr_parser.h"
/**
 * @fn int pkgmgr_parser_insert_manifest_info_in_usr_db(manifest_x *mfx, uid_t uid)
 * @fn int pkgmgr_parser_insert_manifest_info_in_db(manifest_x *mfx)
 * @brief	This API inserts the parsed manifest info in db
 *
 * @par		This API is for package-manager installer backends
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	mfx	pointer to manifest info
 * @param[in]	uid	the addressee user id of the instruction
 * @return	0 if success, error code(<0) if fail
 * @pre		None
 * @post		None
 * @see		pkgmgr_parser_update_manifest_info_in_db()
 * @see		pkgmgr_parser_delete_manifest_info_from_db()
 * @code
static int insert_manifest_data(manifest_x *mfx)
{
	int ret = 0;
	ret = pkgmgr_parser_insert_manifest_info_in_db(mfx);
	if (ret < 0)
		return -1;
	return 0;
}
 * @endcode
 */
int pkgmgr_parser_insert_manifest_info_in_db(manifest_x *mfx);
int pkgmgr_parser_insert_manifest_info_in_usr_db(manifest_x *mfx, uid_t uid);

/**
 * @fn int pkgmgr_parser_update_manifest_info_in_db(manifest_x *mfx)
 * @fn int pkgmgr_parser_update_manifest_info_in_db(manifest_x *mfx)
 * @brief	This API updates the manifest info in db
 *
 * @par		This API is for package-manager installer backends
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	mfx	pointer to manifest info
 * @param[in]	uid	the addressee user id of the instruction
 * @return	0 if success, error code(<0) if fail
 * @pre		None
 * @post		None
 * @see		pkgmgr_parser_insert_manifest_info_in_db()
 * @see		pkgmgr_parser_delete_manifest_info_from_db()
 * @code
static int update_manifest_data(manifest_x *mfx)
{
	int ret = 0;
	ret = pkgmgr_parser_update_manifest_info_in_db(mfx);
	if (ret < 0)
		return -1;
	return 0;
}
 * @endcode
 */
int pkgmgr_parser_update_manifest_info_in_db(manifest_x *mfx);
int pkgmgr_parser_update_manifest_info_in_usr_db(manifest_x *mfx, uid_t uid);

/**
 * @fn int pkgmgr_parser_update_tep_info_in_db(const char * pkgid, const char * tep_path)
 * @fn int pkgmgr_parser_update_tep_info_in_usr_db(const char * pkgid, const char * tep_path,uid_t uid)
 * @brief	This API updates the tep info in db
 *
 * @par		This API is for package-manager installer backends
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	pkgid	pointer to pkgid
 * @param[in]	tep_path	path of tep file
 * @return	0 if success, error code(<0) if fail
 * @pre		None
 * @post		None
 * @code
static int update_tep_data(const char *pkgid, *tep_path)
{
	int ret = 0;
	ret = pkgmgr_parser_update_tep_info_in_db(pkgid, tep_path);
	if (ret < 0)
		return -1;
	return 0;
}
 * @endcode
 */
int pkgmgr_parser_update_tep_info_in_db(const char *pkgid, const char *tep_path);
int pkgmgr_parser_update_tep_info_in_usr_db(const char *pkgid, const char *tep_path, uid_t uid);

/**
 * @fn int pkgmgr_parser_delete_manifest_info_from_usr_db(manifest_x *mfx, uid_t uid)
 * @fn int pkgmgr_parser_delete_manifest_info_from_db(manifest_x *mfx)
 * @brief	This API deletes the parsed manifest info from db
 *
 * @par		This API is for package-manager installer backends
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	mfx	pointer to manifest info
 * @param[in]	uid	the addressee user id of the instruction
 * @return	0 if success, error code(<0) if fail
 * @pre		None
 * @post		None
 * @see		pkgmgr_parser_update_manifest_info_in_db()
 * @see		pkgmgr_parser_insert_manifest_info_in_db()
 * @code
static int delete_manifest_data(manifest_x *mfx)
{
	int ret = 0;
	ret = pkgmgr_parser_delete_manifest_info_from_db(mfx);
	if (ret < 0)
		return -1;
	return 0;
}
 * @endcode
 */
int pkgmgr_parser_delete_manifest_info_from_db(manifest_x *mfx);
int pkgmgr_parser_delete_manifest_info_from_usr_db(manifest_x *mfx, uid_t uid);

int pkgmgr_parser_update_preload_info_in_db();
int pkgmgr_parser_update_preload_info_in_usr_db(uid_t uid);
int pkgmgr_parser_update_global_app_disable_info_in_db(const char *appid, uid_t uid, int is_disable);

int pkgmgr_parser_create_and_initialize_db(uid_t uid);


/** @} */
#ifdef __cplusplus
}
#endif
#endif				/* __PKGMGR_PARSER_DB_H__ */
/**
 * @}
 * @}
 */
