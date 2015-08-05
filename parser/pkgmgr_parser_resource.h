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
 * @fn int *pkgmgr_resource_parser_open(const char *fname, resource_data_t **data)
 * @brief	This API initialize parses res.xml which identified by fname and package and put it into data.
 *
 * @par		This API is for package-manager installer backends.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	fname		pointer to xml filename
 * @param[out]data		pointer of	pointer to resource_data type structure.
 * @return	0 on succeed and -1 on failure, -2 on invalid parameter
 */
API int pkgmgr_resource_parser_open(const char *fname, resource_data_t **data);

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

#ifdef __cplusplus
}
#endif

#endif

