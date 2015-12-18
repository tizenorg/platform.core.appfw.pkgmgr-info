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

static int __cert_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_cert_x *info = (pkgmgr_cert_x *)data;
	int i = 0;

	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "author_signer_cert") == 0) {
			if (coltxt[i])
				info->cert_id = atoi(coltxt[i]);
			else
				info->cert_id = 0;
		} else if (strcmp(colname[i], "package") == 0) {
			if (coltxt[i])
				info->pkgid= strdup(coltxt[i]);
			else
				info->pkgid = NULL;
		} else
			continue;
	}
	return 0;
}

static int __validate_cb(void *data, int ncols, char **coltxt, char **colname)
{
	int *p = (int*)data;
	*p = atoi(coltxt[0]);
	return 0;
}

API int pkgmgrinfo_pkginfo_compare_usr_pkg_cert_info(const char *lhs_package_id, const char *rhs_package_id, uid_t uid, pkgmgrinfo_cert_compare_result_type_e *compare_result)
{
	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message = NULL;
	sqlite3_stmt *stmt = NULL;
	char *lhs_certinfo = NULL;
	char *rhs_certinfo = NULL;
	int lcert;
	int rcert;
	int exist;
	int i;
	int is_global = 0;
	*compare_result = PMINFO_CERT_COMPARE_ERROR;

	retvm_if(lhs_package_id == NULL, PMINFO_R_EINVAL, "lhs package ID is NULL");
	retvm_if(rhs_package_id == NULL, PMINFO_R_EINVAL, "rhs package ID is NULL");
	retvm_if(compare_result == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	ret = __open_cert_db(uid, true);
	if (ret != 0) {
		ret = PMINFO_R_ERROR;
		goto err;
	}
	_check_create_cert_db(GET_DB(cert_db));
	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", lhs_package_id);
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(cert_db), query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}
	lcert = exist;

	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", rhs_package_id);
	if (SQLITE_OK !=
		sqlite3_exec(GET_DB(cert_db), query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
			   error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}
	rcert = exist;

	if (uid == GLOBAL_USER || uid == ROOT_UID) {
		snprintf(query, MAX_QUERY_LEN, "select cert_info from package_cert_index_info where cert_id=(select author_signer_cert from package_cert_info where package=?)");
		is_global = 1;
	} else
		snprintf(query, MAX_QUERY_LEN, "select cert_info from package_cert_index_info where cert_id=(select author_signer_cert from package_cert_info where package=?) and for_all_users=(select for_all_users from package_cert_info where package=?)");
	if (SQLITE_OK != sqlite3_prepare_v2(GET_DB(cert_db), query, strlen(query), &stmt, NULL)) {
		_LOGE("sqlite3_prepare_v2 error: %s", sqlite3_errmsg(GET_DB(cert_db)));
		ret = PMINFO_R_ERROR;
		goto err;
	}

	for (i = 1; i <= 2 - is_global; i++) {
		if (SQLITE_OK != sqlite3_bind_text(stmt, i, lhs_package_id, -1, SQLITE_STATIC)) {
			_LOGE("sqlite3_bind_text error: %s", sqlite3_errmsg(GET_DB(cert_db)));
			ret = PMINFO_R_ERROR;
			goto err;
		}
	}
	if (SQLITE_ROW != sqlite3_step(stmt) || sqlite3_column_text(stmt, 0) == NULL) {
		_LOGE("sqlite3_step error: %s", sqlite3_errmsg(GET_DB(cert_db)));
		ret = PMINFO_R_ERROR;
		goto err;
	}

	lhs_certinfo = strdup((const char *)sqlite3_column_text(stmt, 0));
	sqlite3_reset(stmt);
	sqlite3_clear_bindings(stmt);

	for (i = 1; i <= 2 - is_global; i++) {
		if (SQLITE_OK != sqlite3_bind_text(stmt, i, rhs_package_id, -1, SQLITE_STATIC)) {
			_LOGE("sqlite3_bind_text error: %s", sqlite3_errmsg(GET_DB(cert_db)));
			ret = PMINFO_R_ERROR;
			goto err;
		}
	}
	if (SQLITE_ROW != sqlite3_step(stmt) || sqlite3_column_text(stmt, 0) == NULL) {
		_LOGE("sqlite3_step error: %s", sqlite3_errmsg(GET_DB(cert_db)));
		ret = PMINFO_R_ERROR;
		goto err;
	}

	rhs_certinfo = strdup((const char *)sqlite3_column_text(stmt, 0));

	if ((lcert == 0) || (rcert == 0)) {
		if ((lcert == 0) && (rcert == 0))
			*compare_result = PMINFO_CERT_COMPARE_BOTH_NO_CERT;
		else if (lcert == 0)
			*compare_result = PMINFO_CERT_COMPARE_LHS_NO_CERT;
		else if (rcert == 0)
			*compare_result = PMINFO_CERT_COMPARE_RHS_NO_CERT;
	} else {
		if (lhs_certinfo && rhs_certinfo && !strcmp(lhs_certinfo, rhs_certinfo))
			*compare_result = PMINFO_CERT_COMPARE_MATCH;
		else
			*compare_result = PMINFO_CERT_COMPARE_MISMATCH;
	}

err:
	if (stmt)
		sqlite3_finalize(stmt);
	if (lhs_certinfo)
		free(lhs_certinfo);
	if (rhs_certinfo)
		free(rhs_certinfo);
	sqlite3_free(error_message);
	__close_cert_db();

	return ret;
}

API int pkgmgrinfo_pkginfo_compare_pkg_cert_info(const char *lhs_package_id, const char *rhs_package_id, pkgmgrinfo_cert_compare_result_type_e *compare_result)
{
	return pkgmgrinfo_pkginfo_compare_usr_pkg_cert_info(lhs_package_id, rhs_package_id, GLOBAL_USER, compare_result);
}

API int pkgmgrinfo_pkginfo_compare_app_cert_info(const char *lhs_app_id, const char *rhs_app_id, pkgmgrinfo_cert_compare_result_type_e *compare_result)
{
	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message = NULL;
	pkgmgr_cert_x *info;
 	int exist;
	char *lpkgid = NULL;
	char *rpkgid = NULL;
	const char* user_pkg_parser = getUserPkgParserDBPath();

	retvm_if(lhs_app_id == NULL, PMINFO_R_EINVAL, "lhs app ID is NULL");
	retvm_if(rhs_app_id == NULL, PMINFO_R_EINVAL, "rhs app ID is NULL");
	retvm_if(compare_result == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	info = (pkgmgr_cert_x *)calloc(1, sizeof(pkgmgr_cert_x));
	retvm_if(info == NULL, PMINFO_R_ERROR, "Out of Memory!!!");

	ret = db_util_open_with_options(user_pkg_parser, &GET_DB(manifest_db),
					SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n", user_pkg_parser);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_app_info where app_id='%s')", lhs_app_id);
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(manifest_db), query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	if (exist == 0) {
		lpkgid = NULL;
	} else {
		snprintf(query, MAX_QUERY_LEN, "select package from package_app_info where app_id='%s' ", lhs_app_id);
		if (SQLITE_OK !=
			sqlite3_exec(GET_DB(manifest_db), query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto err;
		}
		lpkgid = strdup(info->pkgid);
		if (lpkgid == NULL) {
			_LOGE("Out of Memory\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		free(info->pkgid);
		info->pkgid = NULL;
	}

	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_app_info where app_id='%s')", rhs_app_id);
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(manifest_db), query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	if (exist == 0) {
		rpkgid = NULL;
	} else {
		snprintf(query, MAX_QUERY_LEN, "select package from package_app_info where app_id='%s' ", rhs_app_id);
		if (SQLITE_OK !=
			sqlite3_exec(GET_DB(manifest_db), query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto err;
		}
		rpkgid = strdup(info->pkgid);
		if (rpkgid == NULL) {
			_LOGE("Out of Memory\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		free(info->pkgid);
		info->pkgid = NULL;
	}
	ret = pkgmgrinfo_pkginfo_compare_pkg_cert_info(lpkgid, rpkgid, compare_result);
 err:
	if (error_message)
		sqlite3_free(error_message);
	__close_manifest_db();
	if (info) {
		if (info->pkgid) {
			free(info->pkgid);
			info->pkgid = NULL;
		}
		free(info);
		info = NULL;
	}
	if (lpkgid) {
		free(lpkgid);
		lpkgid = NULL;
	}
	if (rpkgid) {
		free(rpkgid);
		rpkgid = NULL;
	}
	return ret;
}

API int pkgmgrinfo_pkginfo_compare_usr_app_cert_info(const char *lhs_app_id, const char *rhs_app_id, uid_t uid, pkgmgrinfo_cert_compare_result_type_e *compare_result)
{
	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message = NULL;
	pkgmgr_cert_x *info;
 	int exist;
	char *lpkgid = NULL;
	char *rpkgid = NULL;

	retvm_if(lhs_app_id == NULL, PMINFO_R_EINVAL, "lhs app ID is NULL");
	retvm_if(rhs_app_id == NULL, PMINFO_R_EINVAL, "rhs app ID is NULL");
	retvm_if(compare_result == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	info = (pkgmgr_cert_x *)calloc(1, sizeof(pkgmgr_cert_x));
	retvm_if(info == NULL, PMINFO_R_ERROR, "Out of Memory!!!");

	ret = __open_manifest_db(uid, true);
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n", getUserPkgParserDBPathUID(uid));
		ret = PMINFO_R_ERROR;
		goto err;
	}

	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_app_info where app_id='%s')", lhs_app_id);
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(manifest_db), query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	if (exist == 0) {
		lpkgid = NULL;
	} else {
		snprintf(query, MAX_QUERY_LEN, "select package from package_app_info where app_id='%s' ", lhs_app_id);
		if (SQLITE_OK !=
			sqlite3_exec(GET_DB(manifest_db), query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto err;
		}
		lpkgid = strdup(info->pkgid);
		if (lpkgid == NULL) {
			_LOGE("Out of Memory\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		free(info->pkgid);
		info->pkgid = NULL;
	}

	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_app_info where app_id='%s')", rhs_app_id);
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(manifest_db), query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	if (exist == 0) {
		rpkgid = NULL;
	} else {
		snprintf(query, MAX_QUERY_LEN, "select package from package_app_info where app_id='%s' ", rhs_app_id);
		if (SQLITE_OK !=
			sqlite3_exec(GET_DB(manifest_db), query, __cert_cb, (void *)info, &error_message)) {
			_LOGE("Don't execute query = %s error message = %s\n", query,
				   error_message);
			ret = PMINFO_R_ERROR;
			goto err;
		}
		rpkgid = strdup(info->pkgid);
		if (rpkgid == NULL) {
			_LOGE("Out of Memory\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		free(info->pkgid);
		info->pkgid = NULL;
	}
	ret = pkgmgrinfo_pkginfo_compare_usr_pkg_cert_info(lpkgid, rpkgid, uid, compare_result);
 err:
	if (error_message)
		sqlite3_free(error_message);
	__close_manifest_db();
	if (info) {
		if (info->pkgid) {
			free(info->pkgid);
			info->pkgid = NULL;
		}
		free(info);
		info = NULL;
	}
	if (lpkgid) {
		free(lpkgid);
		lpkgid = NULL;
	}
	if (rpkgid) {
		free(rpkgid);
		rpkgid = NULL;
	}
	return ret;
}

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

		_save_column_str(stmt, 0, (const char **)&cert_info[i]);
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

static int _pkginfo_get_certinfo(const char *pkgid, uid_t uid,
		pkgmgr_certinfo_x *info)
{
	int ret;
	sqlite3 *db;
	const char *dbpath;

	dbpath = getUserPkgCertDBPathUID(uid);
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

	ret = _pkginfo_get_certinfo(pkgid, uid, info);
	if (ret == PMINFO_R_ENOENT && uid != GLOBAL_USER)
		ret = _pkginfo_get_certinfo(pkgid, GLOBAL_USER, info);

	if (ret != PMINFO_R_OK)
		_LOGE("failed to get certinfo of %s for user %d", pkgid, uid);

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
	static const char query[] =
		"INSERT OR REPLACE INTO package_cert_info (package,"
		" author_root_cert, author_im_cert, author_signer_cert,"
		" dist_root_cert, dist_im_cert, dist_signer_cert,"
		" dist2_root_cert, dist2_im_cert, dist2_signer_cert) "
		"VALUES(?, "
		" (COALESCE( "
		"   (SELECT cert_id FROM package_cert_index_info"
		"    WHERE cert_info=?),"
		"   (SELECT author_root_cert FROM package_cert_info"
		"    WHERE package=?))),"
		" (COALESCE( "
		"   (SELECT cert_id FROM package_cert_index_info"
		"    WHERE cert_info=?),"
		"   (SELECT author_im_cert FROM package_cert_info"
		"    WHERE package=?))),"
		" (COALESCE( "
		"   (SELECT cert_id FROM package_cert_index_info"
		"    WHERE cert_info=?),"
		"   (SELECT author_signer_cert FROM package_cert_info"
		"    WHERE package=?))),"
		" (COALESCE( "
		"   (SELECT cert_id FROM package_cert_index_info"
		"    WHERE cert_info=?),"
		"   (SELECT dist_root_cert FROM package_cert_info"
		"    WHERE package=?))),"
		" (COALESCE( "
		"   (SELECT cert_id FROM package_cert_index_info"
		"    WHERE cert_info=?),"
		"   (SELECT dist_im_cert FROM package_cert_info"
		"    WHERE package=?))),"
		" (COALESCE( "
		"   (SELECT cert_id FROM package_cert_index_info"
		"    WHERE cert_info=?),"
		"   (SELECT dist_signer_cert FROM package_cert_info"
		"    WHERE package=?))),"
		" (COALESCE( "
		"   (SELECT cert_id FROM package_cert_index_info"
		"    WHERE cert_info=?),"
		"   (SELECT dist2_root_cert FROM package_cert_info"
		"    WHERE package=?))),"
		" (COALESCE( "
		"   (SELECT cert_id FROM package_cert_index_info"
		"    WHERE cert_info=?),"
		"   (SELECT dist2_im_cert FROM package_cert_info"
		"    WHERE package=?))),"
		" (COALESCE( "
		"   (SELECT cert_id FROM package_cert_index_info"
		"    WHERE cert_info=?),"
		"   (SELECT dist2_signer_cert FROM package_cert_info"
		"    WHERE package=?))))";
	int ret;
	sqlite3_stmt *stmt;
	int i;
	int idx;

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("prepare error: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	idx = 1;
	sqlite3_bind_text(stmt, idx++, pkgid, -1, SQLITE_STATIC);
	for (i = 0; i < MAX_CERT_TYPE; i++) {
		ret = sqlite3_bind_text(stmt, idx++, cert_info[i], -1,
				SQLITE_STATIC);
		if (ret != SQLITE_OK) {
			_LOGE("bind error: %s", sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}
		ret = sqlite3_bind_text(stmt, idx++, pkgid, -1,
				SQLITE_STATIC);
		if (ret != SQLITE_OK) {
			_LOGE("bind error: %s", sqlite3_errmsg(db));
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}
	}
	ret = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
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

	dbpath = getUserPkgCertDBPathUID(uid);
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
		_LOGE("failed to save cert index info");
		sqlite3_close_v2(db);
		return PMINFO_R_ERROR;
	}
	if (_pkginfo_save_cert_info(db, pkgid, info->cert_info)) {
		_LOGE("failed to save cert info");
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

	dbpath = getUserPkgCertDBPathUID(uid);
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

	if (_pkginfo_delete_certinfo(db, pkgid))
		_LOGE("failed to delete certinfo of %s", pkgid);

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
	return pkgmgrinfo_delete_usr_certinfo(pkgid, GLOBAL_USER);
}

