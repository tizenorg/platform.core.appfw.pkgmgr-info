#ifndef __PKGMGRINFO_RESOURCE_H_
#define __PKGMGRINFO_RESOURCE_H_

#include <glib.h>
#include <bundle.h>

#define RSC_GROUP_TYPE_IMAGE "image"
#define RSC_GROUP_TYPE_LAYOUT "layout"
#define RSC_GROUP_TYPE_SOUND "sound"
#define RSC_GROUP_TYPE_BIN "bin"

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

typedef struct {
	char *folder;
	bundle *attr;
} resource_node_t;

typedef struct {
	char *folder;
	char *type;
	GList *node_list;
} resource_group_t;

typedef struct {
	char *package;
	GList *group_list;
} resource_data_t;

/**
 * @fn int pkgmgrinfo_resource_close(resource_data_t data)
 * @brief	This API frees given data and its own variables
 *
 * @par		This API is for capi-appfw-application.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	data	structure of resource_data_t
 * @return	0 on succeed and -1 on failure, -2 on invalid parameter
 */
int pkgmgrinfo_resource_close(resource_data_t *data);

/**
 * @fn int pkgmgrinfo_resource_open(const char *filepath, resource_data_t **data)
 * @brief	This API will get resource data from specified resource xml
 *
 * @par		This API is for capi-appfw-application.
 * @par Sync (or) Async : Synchronous API
 *
 * @param[in]	filepath	path of resource xml
 * @param[out]data	resource_data type structure. it will filled with resource data
 * @return	0 on succeed and -1 on failure, -2 on invalid parameter
 */
int pkgmgrinfo_resource_open(const char *filepath, resource_data_t **data);

#ifdef __cplusplus
}
#endif

#endif

