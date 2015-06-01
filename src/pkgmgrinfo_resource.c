#include "pkgmgr_parser_resource.h"

API int pkgmgrinfo_resource_open(const char *package, resource_data_t **data)
{
	return pkgmgr_resource_parser_open_from_db(package, data);
}

API int pkgmgrinfo_resource_close(resource_data_t *data)
{
	return pkgmgr_resource_parser_close(data);
}

