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

#ifndef __PKGMGRINFO_TYPE_H__
#define __PKGMGRINFO_TYPE_H__

#include <sys/types.h>

/**
 * @brief A type to retrieve uid information from the manifest handle
 */
typedef struct {
	uid_t uid;
} pkgmgrinfo_uidinfo_t;

/**
 * @brief A handle to insert certificate information
 */
typedef void* pkgmgrinfo_instcertinfo_h;

/**
 * @brief Certificate Types to be used for setting information
 */
typedef enum {
	PMINFO_SET_AUTHOR_ROOT_CERT = 0,		/**< Author Root Certificate*/
	PMINFO_SET_AUTHOR_INTERMEDIATE_CERT = 1,		/**< Author Intermediate Certificate*/
	PMINFO_SET_AUTHOR_SIGNER_CERT = 2,		/**< Author Signer Certificate*/
	PMINFO_SET_DISTRIBUTOR_ROOT_CERT = 3,		/**< Distributor Root Certificate*/
	PMINFO_SET_DISTRIBUTOR_INTERMEDIATE_CERT = 4,		/**< Distributor Intermediate Certificate*/
	PMINFO_SET_DISTRIBUTOR_SIGNER_CERT = 5,		/**< Distributor Signer Certificate*/
	PMINFO_SET_DISTRIBUTOR2_ROOT_CERT = 6,		/**< End Entity Root Certificate*/
	PMINFO_SET_DISTRIBUTOR2_INTERMEDIATE_CERT = 7,		/**< End Entity Intermediate Certificate*/
	PMINFO_SET_DISTRIBUTOR2_SIGNER_CERT = 8,		/**< End Entity Signer Certificate*/
}pkgmgrinfo_instcert_type;

typedef enum {
	PMINFO_CERT_COMPARE_MATCH,
	PMINFO_CERT_COMPARE_MISMATCH,
	PMINFO_CERT_COMPARE_LHS_NO_CERT,
	PMINFO_CERT_COMPARE_RHS_NO_CERT,
	PMINFO_CERT_COMPARE_BOTH_NO_CERT,
	PMINFO_CERT_COMPARE_ERROR,
} pkgmgrinfo_cert_compare_result_type_e;

/**
 * @brief API return values
 */
enum {
	PMINFO_R_ENOENT = -3,		/**< No result */
	PMINFO_R_EINVAL = -2,		/**< Invalid argument */
	PMINFO_R_ERROR = -1,		/**< General error */
	PMINFO_R_OK = 0			/**< General success */
};

/**
 * @brief Value to be used when filtering based on install location
 */
#define	PMINFO_PKGINFO_INSTALL_LOCATION_AUTO		"LOCATION_AUTO"

/**
 * @brief Value to be used when filtering based on install location
 */
#define	PMINFO_PKGINFO_INSTALL_LOCATION_INTERNAL	"LOCATION_INTERNAL"

/**
 * @brief Value to be used when filtering based on install location
 */
#define	PMINFO_PKGINFO_INSTALL_LOCATION_EXTERNAL	"LOCATION_EXTERNAL"

/**
 * @brief Value to be used when filtering based on app-component
 */
#define	PMINFO_APPINFO_UI_APP				"UI_APP"

/**
 * @brief Value to be used when filtering based on app-component
 */
#define	PMINFO_APPINFO_SVC_APP				"SVC_APP"

typedef enum {
	PMINFO_HWACCELERATION_NOT_USE_GL = 0,		/**< Don't use hardware acceleration*/
	PMINFO_HWACCELERATION_USE_GL = 1,		/**< Use hardware acceleration*/
	PMINFO_HWACCELERATION_USE_SYSTEM_SETTING = 2		/**< Follow system setting for hardware acceleration */
}pkgmgrinfo_app_hwacceleration;

typedef enum {
	PMINFO_SCREENREADER_OFF = 0,		/**< Don't use screen reader*/
	PMINFO_SCREENREADER_ON = 1,		/**< Use screen reader*/
	PMINFO_SCREENREADER_USE_SYSTEM_SETTING = 2		/**< Follow system setting for screen reader */
}pkgmgrinfo_app_screenreader;

typedef enum {
	PMINFO_RECENTIMAGE_USE_ICON = 0,		/**<Use icon for recent image*/
	PMINFO_RECENTIMAGE_USE_CAPTURE = 1,		/**< Use capture for recent image*/
	PMINFO_RECENTIMAGE_USE_NOTHING = 2		/**< Don't use recent image */
}pkgmgrinfo_app_recentimage;

/**
 * @brief A handle to get package information
 */
typedef void* pkgmgrinfo_pkginfo_h;

/**
 * @brief A handle to get application information
 */
typedef void* pkgmgrinfo_appinfo_h;

/**
 * @brief A handle to get certificate information
 */
typedef void* pkgmgrinfo_certinfo_h;

/**
 * @brief A handle to insert package information
 */
typedef void* pkgmgrinfo_pkgdbinfo_h;

/**
 * @brief A handle to filter package information
 */
typedef void* pkgmgrinfo_pkginfo_filter_h;

/**
 * @brief A handle to filter application information
 */
typedef void* pkgmgrinfo_appinfo_filter_h;

/**
 * @brief A handle to filter application metadata  information
 */
typedef void* pkgmgrinfo_appinfo_metadata_filter_h;

/**
 * @brief A handle to get appcontrol information
 */
typedef void* pkgmgrinfo_appcontrol_h;

/**
 * @brief type definition.
 */
typedef void pkgmgrinfo_client;

/**
 * @fn int (*pkgmgrinfo_pkg_list_cb ) (const pkgmgrinfo_pkginfo_h handle, void *user_data)
 *
 * @brief Specifies the type of function passed to pkgmgrinfo_pkginfo_get_list(), pkgmgrinfo_pkginfo_filter_foreach_pkginfo()
 *
 * @param[in] handle the pkginfo handle
 * @param[in] user_data user data passed to pkgmgrinfo_pkginfo_get_list(), pkgmgrinfo_pkginfo_filter_foreach_pkginfo()
 *
 * @return 0 if success, negative value(<0) if fail. Callback is not called if return value is negative.\n
 *
 * @see  pkgmgrinfo_pkginfo_get_list()
 * @see  pkgmgrinfo_pkginfo_filter_foreach_pkginfo()
 */
typedef int (*pkgmgrinfo_pkg_list_cb ) (const pkgmgrinfo_pkginfo_h handle,
							void *user_data);

/**
 * @fn int (*pkgmgrinfo_app_list_cb ) (const pkgmgrinfo_appinfo_h handle, void *user_data)
 *
 * @brief Specifies the type of function passed to pkgmgrinfo_appinfo_get_list(), pkgmgrinfo_appinfo_filter_foreach_appinfo(), pkgmgrinfo_appinfo_metadata_filter_foreach()
 *
 * @param[in] handle the appinfo handle
 * @param[in] user_data user data passed to pkgmgrinfo_appinfo_get_list(), pkgmgrinfo_appinfo_filter_foreach_appinfo(), pkgmgrinfo_appinfo_metadata_filter_foreach()
 *
 * @return 0 if success, negative value(<0) if fail. Callback is not called if return value is negative.\n
 *
 * @see  pkgmgrinfo_appinfo_get_list()
 * @see  pkgmgrinfo_appinfo_filter_foreach_appinfo()
 * @see  pkgmgrinfo_appinfo_metadata_filter_foreach()
 */
typedef int (*pkgmgrinfo_app_list_cb ) (const pkgmgrinfo_appinfo_h handle,
							void *user_data);

/**
 * @fn int (*pkgmgrinfo_app_category_list_cb ) (const char *category_name, void *user_data)
 *
 * @brief Specifies the type of function passed to pkgmgrinfo_appinfo_foreach_category()
 *
 * @param[in] category_name the name of the category
 * @param[in] user_data user data passed to pkgmgrinfo_appinfo_foreach_category()
 *
 * @return 0 if success, negative value(<0) if fail. Callback is not called if return value is negative.\n
 *
 * @see  pkgmgrinfo_appinfo_foreach_category()
 */
typedef int (*pkgmgrinfo_app_category_list_cb ) (const char *category_name,
							void *user_data);

/**
 * @fn int (*pkgmgrinfo_app_permission_list_cb ) (const char *permission_type, void *user_data)
 *
 * @brief Specifies the type of function passed to pkgmgrinfo_appinfo_foreach_category()
 *
 * @param[in] permission_name the name of the permission
 * @param[in] user_data user data passed to pkgmgrinfo_appinfo_foreach_category()
 *
 * @return 0 if success, negative value(<0) if fail. Callback is not called if return value is negative.\n
 *
 * @see  pkgmgrinfo_appinfo_foreach_category()
 */
typedef int (*pkgmgrinfo_app_permission_list_cb ) (const char *permission_type,
							void *user_data);

/**
 * @fn int (*pkgmgrinfo_pkg_privilege_list_cb ) (const char *privilege_name, void *user_data)
 *
 * @brief Specifies the type of function passed to pkgmgrinfo_pkginfo_foreach_privilege()
 *
 * @param[in] privilege_name the name of the privilege
 * @param[in] user_data user data passed to pkgmgrinfo_pkginfo_foreach_privilege()
 *
 * @return 0 if success, negative value(<0) if fail. Callback is not called if return value is negative.\n
 *
 * @see  pkgmgrinfo_pkginfo_foreach_privilege()
 */
typedef int (*pkgmgrinfo_pkg_privilege_list_cb ) (const char *privilege_name,
							void *user_data);

/**
 * @fn int (*pkgmgrinfo_app_metadata_list_cb ) (const char *metadata_key, const char *metadata_value, void *user_data)
 *
 * @brief Specifies the type of function passed to pkgmgrinfo_appinfo_foreach_metadata()
 *
 * @param[in] metadata_name the name of the metadata
 * @param[in] metadata_value the value of the metadata
 * @param[in] user_data user data passed to pkgmgrinfo_appinfo_foreach_metadata()
 *
 * @return 0 if success, negative value(<0) if fail. Callback is not called if return value is negative.\n
 *
 * @see  pkgmgrinfo_appinfo_foreach_metadata()
 */
typedef int (*pkgmgrinfo_app_metadata_list_cb ) (const char *metadata_key,
							const char *metadata_value, void *user_data);

/**
 * @fn int (*pkgmgrinfo_app_control_list_cb ) (pkgmgrinfo_appcontrol_h handle, void *user_data)
 *
 * @brief Specifies the type of function passed to pkgmgrinfo_appinfo_foreach_appcontrol()
 *
 * @param[in] handle the appcontrol handle to be used to get operation, uri and mime info
 * @param[in] user_data user data passed to pkgmgrinfo_appinfo_foreach_appcontrol()
 *
 * @return 0 if success, negative value(<0) if fail. Callback is not called if return value is negative.\n
 *
 * @see  pkgmgrinfo_appinfo_foreach_appcontrol()
 */
typedef int (*pkgmgrinfo_app_control_list_cb ) (const char *operation, const char *uri, const char *mime,
							void *user_data);

typedef int (*pkgmgrinfo_handler)(uid_t target_uid, int req_id, const char *pkg_type,
				const char *pkgid, const char *key,
				const char *val, const void *pmsg, void *data);


/**
 * @brief Install Location Types
 */
typedef enum {
	PMINFO_INSTALL_LOCATION_AUTO = 0,		/**< Auto*/
	PMINFO_INSTALL_LOCATION_INTERNAL_ONLY,		/**< Internal Installation*/
	PMINFO_INSTALL_LOCATION_PREFER_EXTERNAL,		/**< External Installation*/
}pkgmgrinfo_install_location;

/**
 * @brief Application Component Types
 */
typedef enum {
	PMINFO_ALL_APP = 0,	/**< All Application*/
	PMINFO_UI_APP,		/**< UI Application*/
	PMINFO_SVC_APP,		/**< Service Application*/
}pkgmgrinfo_app_component;

/**
 * @brief Application Storage Types
 */
typedef enum {
	PMINFO_INTERNAL_STORAGE = 0,		/**< Internal Storage*/
	PMINFO_EXTERNAL_STORAGE = 1,		/**< External Storage*/
}pkgmgrinfo_installed_storage;

/**
 * @brief Certificate Types to be used for getting information
 */
typedef enum {
	PMINFO_AUTHOR_ROOT_CERT = 0,		/**< Author Root Certificate*/
	PMINFO_AUTHOR_INTERMEDIATE_CERT = 1,		/**< Author Intermediate Certificate*/
	PMINFO_AUTHOR_SIGNER_CERT = 2,		/**< Author Signer Certificate*/
	PMINFO_DISTRIBUTOR_ROOT_CERT = 3,		/**< Distributor Root Certificate*/
	PMINFO_DISTRIBUTOR_INTERMEDIATE_CERT = 4,		/**< Distributor Intermediate Certificate*/
	PMINFO_DISTRIBUTOR_SIGNER_CERT = 5,		/**< Distributor Signer Certificate*/
	PMINFO_DISTRIBUTOR2_ROOT_CERT = 6,		/**< End Entity Root Certificate*/
	PMINFO_DISTRIBUTOR2_INTERMEDIATE_CERT = 7,		/**< End Entity Intermediate Certificate*/
	PMINFO_DISTRIBUTOR2_SIGNER_CERT = 8,		/**< End Entity Signer Certificate*/
}pkgmgrinfo_cert_type;

/**
 * @brief Install Location Types to be used when setting data in DB
 */
typedef enum {
	INSTALL_INTERNAL = 0,		/**< Internal Installation*/
	INSTALL_EXTERNAL,		/**< External Installation*/
} INSTALL_LOCATION;

 /**
  * @brief permission Types
  */
typedef enum {
	PMINFO_PERMISSION_NORMAL = 0,		 /**< permission normal*/
	PMINFO_PERMISSION_SIGNATURE, 	 /**< permission type is signature*/
	PMINFO_PERMISSION_PRIVILEGE, 	 /**< permission type is privilege*/
} pkgmgrinfo_permission_type;

typedef enum {
	PM_GET_TOTAL_SIZE= 0,
	PM_GET_DATA_SIZE = 1,
	PM_GET_ALL_PKGS = 2,
	PM_GET_SIZE_INFO = 3,
	PM_GET_TOTAL_AND_DATA = 4,
	PM_GET_SIZE_FILE = 5,
	PM_GET_MAX
} pkgmgr_getsize_type;

typedef enum {
	PMINFO_REQUEST = 0,
	PMINFO_LISTENING,
	PMINFO_BROADCAST,
}pkgmgrinfo_client_type;

#endif
