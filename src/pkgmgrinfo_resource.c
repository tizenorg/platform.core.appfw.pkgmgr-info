#include "pkgmgr_parser_resource.h"

API int pkgmgrinfo_resource_open(const char *filepath, resource_data_t **data)
{
	return pkgmgr_resource_parser_open(filepath, data);
}

API int pkgmgrinfo_resource_close(resource_data_t *data)
{
	return pkgmgr_resource_parser_close(data);
}

