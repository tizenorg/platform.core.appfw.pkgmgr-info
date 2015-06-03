#ifndef __PKGMGR_PARSER_RESOURCE_H_
#define __PKGMGR_PARSER_RESOURCE_H_

#include <bundle.h>
#include <glib.h>
#include "pkgmgr_parser.h"
#include "pkgmgrinfo_resource.h"

#define PKGMGR_RSC_GROUP_TYPE_IMAGE "image"
#define PKGMGR_RSC_GROUP_TYPE_LAYOUT "layout"
#define PKGMGR_RSC_GROUP_TYPE_SOUND "sound"
#define PKGMGR_RSC_GROUP_TYPE_BIN "bin"

#define RSC_NODE_ATTR_SCREEN_DPI "screen-dpi"
#define RSC_NODE_ATTR_SCREEN_DPI_RANGE "screen-dpi-range"
#define RSC_NODE_ATTR_SCREEN_WIDTH_RANGE "screen-width-range"
#define RSC_NODE_ATTR_SCREEN_LARGE "screen-large"
#define RSC_NODE_ATTR_SCREEN_BPP "screen-bpp"
#define RSC_NODE_ATTR_PLATFORM_VER "platform-version"
#define RSC_NODE_ATTR_LANGUAGE "language"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @fn int *pkgmgr_resource_parser_open(const char *fname, const char *package, resource_data_t **data)
 * @brief	This API initialize parses res.xml which identified by fname and package and put it into data.
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	fname		pointer to xml filename
 * @param[in]	pacakage	pointer to packageID
 * @param[out]data		pointer of	pointer to resource_data type structure.
 * @return	0 on succeed and -1 on failure, -2 on invalid parameter
 */
API int pkgmgr_resource_parser_open(const char *fname, const char *package, resource_data_t **data);

/**
 * @fn int pkgmgr_resource_parser_close(resource_data_t data)
 * @brief	This API frees given data and its own variables
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	data	structure of resource_data_t
 * @return	0 on succeed and -1 on failure, -2 on invalid parameter
 */
API int pkgmgr_resource_parser_close(resource_data_t *data);

/**
 * @fn int pkgmgr_resource_parser_insert_into_db(resource_data_t *data)
 * @brief	This API will put given data into db
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	data	structure to be inserted into db
 * @return	0 on succeed and -1 on failure, -2 on invalid parameter
 */
API int pkgmgr_resource_parser_insert_into_db(resource_data_t *data);

/**
 * @fn int pkgmgr_resource_parser_open_from_db(const char *package, resource_data_t **data)
 * @brief	This API will get resource data of specific package from db
 *
 * @par		This API is for applications.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	package	packageID
 * @param[out]data	resource_data type structure. it will filled with resource data
 * @return	0 on succeed and -1 on failure, -2 on invalid parameter
 */
API int pkgmgr_resource_parser_open_from_db(const char *package, resource_data_t **data);

/**
 * @fn int pkgmgr_resource_parser_check_xml_validation(const char *xmlfile)
 * @brief	This API will validates given resource manifest file
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	manifest	manifest filepath to be validated
 * @return	0 on succeed and -1 on failure, -2 on invalid parameter
 */
API int pkgmgr_resource_parser_check_xml_validation(const char *xmlfile);

/**
 * @fn int pkgmgr_resource_parser_delete_from_db(const char *package)
 * @brief	This API will remove resource data from package_resource_info, package_resource_data
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	package	packageID
 * @return	0 on succeed and -1 on failure, -2 on invalid parameter
 */
API int pkgmgr_resource_parser_delete_from_db(const char *package);

#ifdef __cplusplus
}
#endif

#endif

