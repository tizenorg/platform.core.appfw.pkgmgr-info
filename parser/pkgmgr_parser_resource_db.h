#ifndef __PKGMGR_PARSER_RESOURCE_DB_H_
#define __PKGMGR_PARSER_RESOURCE_DB_H_

#include "pkgmgrinfo_resource.h"
#include "pkgmgr_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

int pkgmgr_parser_resource_db_save(const char *package, resource_data_t *data);
int pkgmgr_parser_resource_db_load(const char *package, resource_data_t **data);
int pkgmgr_parser_resource_db_remove(const char *package);

#ifdef __cplusplus
}
#endif

#endif

