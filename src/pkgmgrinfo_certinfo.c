#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>

#include <sqlite3.h>
#include <glib.h>

#include <db-util.h>

#include "pkgmgr-info.h"
#include "pkgmgrinfo_debug.h"
#include "pkgmgrinfo_private.h"
#include "pkgmgr_parser.h"

typedef struct _pkgmgr_certinfo_x {
	int for_all_users;
	char *pkgid;
	char *cert_value;
	char *cert_info[MAX_CERT_TYPE];	/*certificate info*/
	int cert_id[MAX_CERT_TYPE];		/*certificate ID in index table*/
} pkgmgr_certinfo_x;

typedef struct _pkgmgr_instcertinfo_x {
	char *pkgid;
	char *cert_info[MAX_CERT_TYPE];	/*certificate data*/
	int is_new[MAX_CERT_TYPE];		/*whether already exist in table or not*/
	int ref_count[MAX_CERT_TYPE];		/*reference count of certificate data*/
	int cert_id[MAX_CERT_TYPE];		/*certificate ID in index table*/
} pkgmgr_instcertinfo_x;

typedef struct _pkgmgr_certindexinfo_x {
	int cert_id;
	int cert_ref_count;
} pkgmgr_certindexinfo_x;

typedef struct _pkgmgr_cert_x {
	char *pkgid;
	int cert_id;
} pkgmgr_cert_x;

API int pkgmgrinfo_pkginfo_create_certinfo(pkgmgrinfo_certinfo_h *handle)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_certinfo_x *certinfo = NULL;
	certinfo = calloc(1, sizeof(pkgmgr_certinfo_x));
	*handle = NULL;
	retvm_if(certinfo == NULL, PMINFO_R_ERROR, "Malloc Failed\n");
	*handle = (void *)certinfo;
	return PMINFO_R_OK;
}

static int _pkginfo_compare_certinfo(sqlite3 *db, const char *l_pkgid,
		const char *r_pkgid,
		pkgmgrinfo_cert_compare_result_type_e *result)
{
	static const char query[] =
		"SELECT author_signer_cert FROM package_cert_info "
		"WHERE package=?";
	int ret;
	sqlite3_stmt *stmt;
	const char *pkgid[2];
	int certid[2] = {-1, };
	int i;

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("prepare error: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	pkgid[0] = l_pkgid;
	pkgid[1] = r_pkgid;
	for (i = 0; i < 2; i++) {
		ret = sqlite3_bind_text(stmt, 1, pkgid[i], -1, SQLITE_STATIC);
		if (ret != SQLITE_OK) {
			_LOGE("bind error: %s", sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}

		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW) {
			_save_column_int(stmt, 0, &certid[i]);
		} else if (ret != SQLITE_DONE) {
			_LOGE("step error: %s", sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}

		sqlite3_reset(stmt);
		sqlite3_clear_bindings(stmt);
	}

	if (certid[0] == -1 && certid[1] == -1)
		*result = PMINFO_CERT_COMPARE_BOTH_NO_CERT;
	else if (certid[0] == -1)
		*result = PMINFO_CERT_COMPARE_LHS_NO_CERT;
	else if (certid[1] == -1)
		*result = PMINFO_CERT_COMPARE_RHS_NO_CERT;
	else if (certid[0] == certid[1])
		*result = PMINFO_CERT_COMPARE_MATCH;
	else
		*result = PMINFO_CERT_COMPARE_MISMATCH;

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_compare_usr_pkg_cert_info(const char *lhs_package_id,
		const char *rhs_package_id, uid_t uid,
		pkgmgrinfo_cert_compare_result_type_e *compare_result)
{
	int ret;
	sqlite3 *db;
	const char *dbpath;

	if (lhs_package_id == NULL || rhs_package_id == NULL ||
			compare_result == NULL) {
		_LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	/* open unified global cert db */
	dbpath = getUserPkgCertDBPathUID(GLOBAL_USER);
	if (dbpath == NULL)
		return PMINFO_R_ERROR;

	ret = sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("failed to open db: %d", ret);
		return PMINFO_R_ERROR;
	}

	if (_pkginfo_compare_certinfo(db, lhs_package_id, rhs_package_id,
				compare_result)) {
		_LOGE("failed to compare certinfo");
		sqlite3_close_v2(db);
		return PMINFO_R_ERROR;
	}

	sqlite3_close_v2(db);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_compare_pkg_cert_info(const char *lhs_package_id, const char *rhs_package_id, pkgmgrinfo_cert_compare_result_type_e *compare_result)
{
	return pkgmgrinfo_pkginfo_compare_usr_pkg_cert_info(lhs_package_id, rhs_package_id, _getuid(), compare_result);
}

static int _pkginfo_get_pkgid_from_appid(uid_t uid, const char *appid,
		char **pkgid)
{
	static const char query[] =
		"SELECT package FROM package_app_info WHERE app_id=?";
	int ret;
	sqlite3 *db;
	const char *dbpath;
	sqlite3_stmt *stmt;

	dbpath = getUserPkgParserDBPathUID(uid);
	if (dbpath == NULL)
		return PMINFO_R_ERROR;

	ret = sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("failed to open db: %d", ret);
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("prepare error: %s", sqlite3_errmsg(db));
		sqlite3_close_v2(db);
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_bind_text(stmt, 1, appid, -1, SQLITE_STATIC);
	if (ret != SQLITE_OK) {
		_LOGE("bind error: %s", sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		sqlite3_close_v2(db);
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_step(stmt);
	if (ret == SQLITE_ROW) {
		_save_column_str(stmt, 0, pkgid);
		ret = PMINFO_R_OK;
	} else if (ret == SQLITE_DONE) {
		_LOGE("cannot find pkgid of app %s", appid);
		ret = PMINFO_R_ENOENT;
	} else {
		_LOGE("step error: %s", sqlite3_errmsg(db));
		ret = PMINFO_R_ERROR;
	}

	sqlite3_finalize(stmt);
	sqlite3_close_v2(db);

	return ret;
}

API int pkgmgrinfo_pkginfo_compare_usr_app_cert_info(const char *lhs_app_id,
		const char *rhs_app_id, uid_t uid,
		pkgmgrinfo_cert_compare_result_type_e *compare_result)
{
	int ret;
	char *l_pkgid = NULL;
	char *r_pkgid = NULL;

	if (lhs_app_id == NULL || rhs_app_id == NULL ||
			compare_result == NULL) {
		_LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	ret = _pkginfo_get_pkgid_from_appid(uid, lhs_app_id, &l_pkgid);
	if (ret == PMINFO_R_ENOENT && uid != GLOBAL_USER)
		ret = _pkginfo_get_pkgid_from_appid(GLOBAL_USER, lhs_app_id,
				&l_pkgid);

	if (ret != PMINFO_R_OK)
		return ret;

	ret = _pkginfo_get_pkgid_from_appid(uid, rhs_app_id, &r_pkgid);
	if (ret == PMINFO_R_ENOENT && uid != GLOBAL_USER)
		ret = _pkginfo_get_pkgid_from_appid(GLOBAL_USER, rhs_app_id,
				&r_pkgid);

	if (ret != PMINFO_R_OK) {
		free(l_pkgid);
		return ret;
	}

	ret = pkgmgrinfo_pkginfo_compare_usr_pkg_cert_info(l_pkgid, r_pkgid,
			uid, compare_result);

	free(l_pkgid);
	free(r_pkgid);

	return ret;
}

API int pkgmgrinfo_pkginfo_compare_app_cert_info(const char *lhs_app_id,
		const char *rhs_app_id,
		pkgmgrinfo_cert_compare_result_type_e *compare_result)
{
	return pkgmgrinfo_pkginfo_compare_usr_app_cert_info(lhs_app_id,
			rhs_app_id, _getuid(), compare_result);
}

static int _pkginfo_get_cert(sqlite3 *db, int cert_id[],
		char *cert_info[])
{
	static const char query[] =
		"SELECT cert_info FROM package_cert_index_info WHERE cert_id=?";
	int ret;
	sqlite3_stmt *stmt;
	int i;

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("prepare failed: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	for (i = 0; i < MAX_CERT_TYPE; i++) {
		ret = sqlite3_bind_int(stmt, 1, cert_id[i]);
		if (ret != SQLITE_OK) {
			sqlite3_finalize(stmt);
			_LOGE("bind failed: %s", sqlite3_errmsg(db));
			return PMINFO_R_ERROR;
		}

		ret = sqlite3_step(stmt);
		if (ret == SQLITE_DONE) {
			sqlite3_reset(stmt);
			sqlite3_clear_bindings(stmt);
			continue;
		} else if (ret != SQLITE_ROW) {
			_LOGE("step failed: %s", sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}

		_save_column_str(stmt, 0, &cert_info[i]);
		sqlite3_reset(stmt);
		sqlite3_clear_bindings(stmt);
	}

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

static int _pkginfo_get_certid(sqlite3 *db, const char *pkgid, int cert_id[])
{
	static const char query[] =
		"SELECT author_root_cert, author_im_cert, author_signer_cert, "
		"dist_root_cert, dist_im_cert, dist_signer_cert, "
		"dist2_root_cert, dist2_im_cert, dist2_signer_cert "
		"FROM package_cert_info WHERE package=?";
	int ret;
	sqlite3_stmt *stmt;
	int idx;

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("prepare failed: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_bind_text(stmt, 1, pkgid, -1, SQLITE_STATIC);
	if (ret != SQLITE_OK) {
		_LOGE("bind failed: %s", sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_step(stmt);
	if (ret == SQLITE_DONE) {
		sqlite3_finalize(stmt);
		return PMINFO_R_ENOENT;
	} else if (ret != SQLITE_ROW) {
		_LOGE("step failed: %s", sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return PMINFO_R_ERROR;
	}

	idx = 0;
	_save_column_int(stmt, idx++, &cert_id[PMINFO_AUTHOR_ROOT_CERT]);
	_save_column_int(stmt, idx++,
			&cert_id[PMINFO_AUTHOR_INTERMEDIATE_CERT]);
	_save_column_int(stmt, idx++, &cert_id[PMINFO_AUTHOR_SIGNER_CERT]);
	_save_column_int(stmt, idx++, &cert_id[PMINFO_DISTRIBUTOR_ROOT_CERT]);
	_save_column_int(stmt, idx++,
			&cert_id[PMINFO_DISTRIBUTOR_INTERMEDIATE_CERT]);
	_save_column_int(stmt, idx++, &cert_id[PMINFO_DISTRIBUTOR_SIGNER_CERT]);
	_save_column_int(stmt, idx++, &cert_id[PMINFO_DISTRIBUTOR2_ROOT_CERT]);
	_save_column_int(stmt, idx++,
			&cert_id[PMINFO_DISTRIBUTOR2_INTERMEDIATE_CERT]);
	_save_column_int(stmt, idx++,
			&cert_id[PMINFO_DISTRIBUTOR2_SIGNER_CERT]);

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

static int _pkginfo_get_certinfo(const char *pkgid, pkgmgr_certinfo_x *info)
{
	int ret;
	sqlite3 *db;
	const char *dbpath;

	/* open unified global cert db */
	dbpath = getUserPkgCertDBPathUID(GLOBAL_USER);
	if (dbpath == NULL)
		return PMINFO_R_ERROR;

	ret = sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("failed to open db: %d", ret);
		return PMINFO_R_ERROR;
	}

	ret = _pkginfo_get_certid(db, pkgid, info->cert_id);
	if (ret != PMINFO_R_OK) {
		sqlite3_close_v2(db);
		return ret;
	}

	ret = _pkginfo_get_cert(db, info->cert_id, info->cert_info);
	if (ret != PMINFO_R_OK) {
		sqlite3_close_v2(db);
		return ret;
	}

	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_load_certinfo(const char *pkgid, pkgmgrinfo_certinfo_h handle, uid_t uid)
{
	int ret;
	pkgmgr_certinfo_x *info = (pkgmgr_certinfo_x *)handle;

	if (pkgid == NULL || handle == NULL) {
		_LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	ret = _pkginfo_get_certinfo(pkgid, info);
	if (ret != PMINFO_R_OK)
		_LOGE("failed to get certinfo of %s ", pkgid);

	return ret;
}

API int pkgmgrinfo_pkginfo_get_cert_value(pkgmgrinfo_certinfo_h handle, pkgmgrinfo_cert_type cert_type, const char **cert_value)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(cert_value == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(cert_type < PMINFO_AUTHOR_ROOT_CERT, PMINFO_R_EINVAL, "Invalid certificate type\n");
	retvm_if(cert_type > PMINFO_DISTRIBUTOR2_SIGNER_CERT, PMINFO_R_EINVAL, "Invalid certificate type\n");
	pkgmgr_certinfo_x *certinfo = NULL;
	certinfo = (pkgmgr_certinfo_x *)handle;
	if ((certinfo->cert_info)[cert_type])
		*cert_value = (certinfo->cert_info)[cert_type];
	else
		*cert_value = NULL;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_pkginfo_destroy_certinfo(pkgmgrinfo_certinfo_h handle)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	int i = 0;
	pkgmgr_certinfo_x *certinfo = NULL;
	certinfo = (pkgmgr_certinfo_x *)handle;
	if (certinfo->pkgid) {
		free(certinfo->pkgid);
		certinfo->pkgid = NULL;
	}
	for (i = 0; i < MAX_CERT_TYPE; i++) {
		if ((certinfo->cert_info)[i]) {
			free((certinfo->cert_info)[i]);
			(certinfo->cert_info)[i] = NULL;
		}
	}
	free(certinfo);
	certinfo = NULL;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_create_certinfo_set_handle(pkgmgrinfo_instcertinfo_h *handle)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_instcertinfo_x *certinfo = NULL;
	*handle = NULL;
	certinfo = calloc(1, sizeof(pkgmgr_instcertinfo_x));
	retvm_if(certinfo == NULL, PMINFO_R_ERROR, "Malloc Failed\n");
	*handle = (void *)certinfo;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_set_cert_value(pkgmgrinfo_instcertinfo_h handle, pkgmgrinfo_instcert_type cert_type, char *cert_value)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(cert_value == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(cert_type < PMINFO_SET_AUTHOR_ROOT_CERT, PMINFO_R_EINVAL, "Invalid certificate type\n");
	retvm_if(cert_type > PMINFO_SET_DISTRIBUTOR2_SIGNER_CERT, PMINFO_R_EINVAL, "Invalid certificate type\n");
	pkgmgr_instcertinfo_x *certinfo = NULL;
	certinfo = (pkgmgr_instcertinfo_x *)handle;
	(certinfo->cert_info)[cert_type] = strdup(cert_value);
	return PMINFO_R_OK;
}

static int _pkginfo_save_cert_info(sqlite3 *db, const char *pkgid,
		char *cert_info[])
{
	static const char query_insert[] =
		"INSERT INTO package_cert_info (package,"
		" author_root_cert, author_im_cert, author_signer_cert,"
		" dist_root_cert, dist_im_cert, dist_signer_cert,"
		" dist2_root_cert, dist2_im_cert, dist2_signer_cert) "
		"VALUES(?, "
		" (SELECT cert_id FROM package_cert_index_info"
		"  WHERE cert_info=?),"
		" (SELECT cert_id FROM package_cert_index_info"
		"  WHERE cert_info=?),"
		" (SELECT cert_id FROM package_cert_index_info"
		"  WHERE cert_info=?),"
		" (SELECT cert_id FROM package_cert_index_info"
		"  WHERE cert_info=?),"
		" (SELECT cert_id FROM package_cert_index_info"
		"  WHERE cert_info=?),"
		" (SELECT cert_id FROM package_cert_index_info"
		"  WHERE cert_info=?),"
		" (SELECT cert_id FROM package_cert_index_info"
		"  WHERE cert_info=?),"
		" (SELECT cert_id FROM package_cert_index_info"
		"  WHERE cert_info=?),"
		" (SELECT cert_id FROM package_cert_index_info"
		"  WHERE cert_info=?))";
	static const char query_update[] =
		"UPDATE package_cert_info SET "
		" author_root_cert= "
		"  (SELECT cert_id FROM package_cert_index_info"
		"   WHERE cert_info=?),"
		" author_im_cert= "
		"  (SELECT cert_id FROM package_cert_index_info"
		"   WHERE cert_info=?),"
		" author_signer_cert= "
		"  (SELECT cert_id FROM package_cert_index_info"
		"   WHERE cert_info=?),"
		" dist_root_cert= "
		"  (SELECT cert_id FROM package_cert_index_info"
		"   WHERE cert_info=?),"
		" dist_im_cert= "
		"  (SELECT cert_id FROM package_cert_index_info"
		"   WHERE cert_info=?),"
		" dist_signer_cert= "
		"  (SELECT cert_id FROM package_cert_index_info"
		"   WHERE cert_info=?),"
		" dist2_root_cert= "
		"  (SELECT cert_id FROM package_cert_index_info"
		"   WHERE cert_info=?),"
		"dist2_im_cert= "
		"  (SELECT cert_id FROM package_cert_index_info"
		"   WHERE cert_info=?),"
		"dist2_signer_cert= "
		"  (SELECT cert_id FROM package_cert_index_info"
		"   WHERE cert_info=?) "
		"WHERE package=?";
	int ret;
	sqlite3_stmt *stmt;
	int i;
	int idx;

	ret = sqlite3_prepare_v2(db, query_insert, strlen(query_insert),
			&stmt, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("prepare error: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	idx = 1;
	sqlite3_bind_text(stmt, idx++, pkgid, -1, SQLITE_STATIC);
	for (i = 0; i < MAX_CERT_TYPE; i++) {
		if (sqlite3_bind_text(stmt, idx++, cert_info[i], -1,
				SQLITE_STATIC)) {
			_LOGE("bind error: %s", sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}
	}

	ret = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (ret == SQLITE_CONSTRAINT) {
		ret = sqlite3_prepare_v2(db, query_update, strlen(query_update),
				&stmt, NULL);
		if (ret != SQLITE_OK) {
			_LOGE("prepare error: %s", sqlite3_errmsg(db));
			return PMINFO_R_ERROR;
		}
		idx = 1;
		for (i = 0; i < MAX_CERT_TYPE; i++) {
			if (sqlite3_bind_text(stmt, idx++, cert_info[i], -1,
					SQLITE_STATIC)) {
				_LOGE("bind error: %s", sqlite3_errmsg(db));
				sqlite3_finalize(stmt);
				return PMINFO_R_ERROR;
			}
		}
		sqlite3_bind_text(stmt, idx++, pkgid, -1, SQLITE_STATIC);
		ret = sqlite3_step(stmt);
		sqlite3_finalize(stmt);
	}

	if (ret != SQLITE_DONE) {
		_LOGE("step error: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	return PMINFO_R_OK;
}

static int _pkginfo_save_cert_index_info(sqlite3 *db, char *cert_info[])
{
	static const char query[] =
		"INSERT OR REPLACE INTO package_cert_index_info "
		"(cert_info, cert_id, cert_ref_count) "
		"VALUES ( "
		" ?, "
		" (SELECT cert_id FROM package_cert_index_info "
		"  WHERE cert_info=?), "
		" COALESCE( "
		"  ((SELECT cert_ref_count FROM package_cert_index_info "
		"    WHERE cert_info=?) + 1), 1))";
	int ret;
	sqlite3_stmt *stmt;
	int i;
	int idx;

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("prepare error: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	for (i = 0; i < MAX_CERT_TYPE; i++) {
		if (cert_info[i] == NULL)
			continue;
		idx = 1;
		sqlite3_bind_text(stmt, idx++, cert_info[i], -1, SQLITE_STATIC);
		sqlite3_bind_text(stmt, idx++, cert_info[i], -1, SQLITE_STATIC);
		sqlite3_bind_text(stmt, idx++, cert_info[i], -1, SQLITE_STATIC);

		ret = sqlite3_step(stmt);
		if (ret != SQLITE_DONE) {
			_LOGE("step failed: %s", sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}

		sqlite3_reset(stmt);
		sqlite3_clear_bindings(stmt);
	}

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_save_certinfo(const char *pkgid, pkgmgrinfo_instcertinfo_h handle, uid_t uid)
{
	int ret;
	sqlite3 *db;
	const char *dbpath;
	pkgmgr_instcertinfo_x *info = (pkgmgr_instcertinfo_x *)handle;

	if (pkgid == NULL || handle == NULL) {
		_LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	/* open unified global cert db */
	dbpath = getUserPkgCertDBPathUID(GLOBAL_USER);
	if (dbpath == NULL)
		return PMINFO_R_ERROR;

	ret = sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READWRITE, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("failed to open db: %d", ret);
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_exec(db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("failed to begin transaction");
		sqlite3_close_v2(db);
		return PMINFO_R_ERROR;
	}

	_check_create_cert_db(db);

	if (_pkginfo_save_cert_index_info(db, info->cert_info)) {
		_LOGE("failed to save cert index info, rollback now");
		sqlite3_exec(GET_DB(cert_db), "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close_v2(db);
		return PMINFO_R_ERROR;
	}
	if (_pkginfo_save_cert_info(db, pkgid, info->cert_info)) {
		_LOGE("failed to save cert info, rollback now");
		sqlite3_exec(GET_DB(cert_db), "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close_v2(db);
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("failed to commit transaction, rollback now");
		sqlite3_exec(GET_DB(cert_db), "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close_v2(db);
		return PMINFO_R_ERROR;
	}

	sqlite3_close_v2(db);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_destroy_certinfo_set_handle(pkgmgrinfo_instcertinfo_h handle)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	int i = 0;
	pkgmgr_instcertinfo_x *certinfo = NULL;
	certinfo = (pkgmgr_instcertinfo_x *)handle;
	if (certinfo->pkgid) {
		free(certinfo->pkgid);
		certinfo->pkgid = NULL;
	}
	for (i = 0; i < MAX_CERT_TYPE; i++) {
		if ((certinfo->cert_info)[i]) {
			free((certinfo->cert_info)[i]);
			(certinfo->cert_info)[i] = NULL;
		}
	}
	free(certinfo);
	certinfo = NULL;
	return PMINFO_R_OK;
}

static int _pkginfo_delete_certinfo(sqlite3 *db, const char *pkgid)
{
	static const char query[] =
		"DELETE FROM package_cert_info WHERE package=?";
	int ret;
	sqlite3_stmt *stmt;

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("prepare error: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_bind_text(stmt, 1, pkgid, -1, SQLITE_STATIC);
	if (ret != SQLITE_OK) {
		_LOGE("bind error: %s", sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (ret != SQLITE_DONE) {
		_LOGE("step error: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	return PMINFO_R_OK;
}

API int pkgmgrinfo_delete_usr_certinfo(const char *pkgid, uid_t uid)
{
	int ret;
	sqlite3 *db;
	const char *dbpath;

	if (pkgid == NULL) {
		_LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	/* open unified global cert db */
	dbpath = getUserPkgCertDBPathUID(GLOBAL_USER);
	if (dbpath == NULL)
		return PMINFO_R_ERROR;

	ret = sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READWRITE, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("failed to open db: %d", ret);
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_exec(db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("failed to begin transaction");
		sqlite3_close_v2(db);
		return PMINFO_R_ERROR;
	}

	if (_pkginfo_delete_certinfo(db, pkgid)) {
		_LOGE("failed to delete certinfo of %s, rollback now", pkgid);
		sqlite3_exec(GET_DB(cert_db), "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close_v2(db);
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("failed to commit transaction, rollback now");
		sqlite3_exec(GET_DB(cert_db), "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close_v2(db);
		return PMINFO_R_ERROR;
	}

	sqlite3_close_v2(db);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_delete_certinfo(const char *pkgid)
{
	return pkgmgrinfo_delete_usr_certinfo(pkgid, _getuid());
}

