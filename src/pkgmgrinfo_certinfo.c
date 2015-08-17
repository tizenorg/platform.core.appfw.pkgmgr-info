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

static int __certinfo_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_certinfo_x *info = (pkgmgr_certinfo_x *)data;
	int i = 0;
	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "package") == 0) {
			if (coltxt[i])
				info->pkgid = strdup(coltxt[i]);
			else
				info->pkgid = NULL;
		} else if (strcmp(colname[i], "author_signer_cert") == 0) {
			if (coltxt[i])
				(info->cert_id)[PMINFO_AUTHOR_SIGNER_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_AUTHOR_SIGNER_CERT] = 0;
		} else if (strcmp(colname[i], "author_im_cert") == 0) {
			if (coltxt[i])
				(info->cert_id)[PMINFO_AUTHOR_INTERMEDIATE_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_AUTHOR_INTERMEDIATE_CERT] = 0;
		} else if (strcmp(colname[i], "author_root_cert") == 0) {
			if (coltxt[i])
				(info->cert_id)[PMINFO_AUTHOR_ROOT_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_AUTHOR_ROOT_CERT] = 0;
		} else if (strcmp(colname[i], "dist_signer_cert") == 0 ){
			if (coltxt[i])
				(info->cert_id)[PMINFO_DISTRIBUTOR_SIGNER_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_DISTRIBUTOR_SIGNER_CERT] = 0;
		} else if (strcmp(colname[i], "dist_im_cert") == 0 ){
			if (coltxt[i])
				(info->cert_id)[PMINFO_DISTRIBUTOR_INTERMEDIATE_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_DISTRIBUTOR_INTERMEDIATE_CERT] = 0;
		} else if (strcmp(colname[i], "dist_root_cert") == 0 ){
			if (coltxt[i])
				(info->cert_id)[PMINFO_DISTRIBUTOR_ROOT_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_DISTRIBUTOR_ROOT_CERT] = 0;
		} else if (strcmp(colname[i], "dist2_signer_cert") == 0 ){
			if (coltxt[i])
				(info->cert_id)[PMINFO_DISTRIBUTOR2_SIGNER_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_DISTRIBUTOR2_SIGNER_CERT] = 0;
		} else if (strcmp(colname[i], "dist2_im_cert") == 0 ){
			if (coltxt[i])
				(info->cert_id)[PMINFO_DISTRIBUTOR2_INTERMEDIATE_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_DISTRIBUTOR2_INTERMEDIATE_CERT] = 0;
		} else if (strcmp(colname[i], "dist2_root_cert") == 0 ){
			if (coltxt[i])
				(info->cert_id)[PMINFO_DISTRIBUTOR2_ROOT_CERT] = atoi(coltxt[i]);
			else
				(info->cert_id)[PMINFO_DISTRIBUTOR2_ROOT_CERT] = 0;
		} else if (strcmp(colname[i], "cert_info") == 0 ){
			if (coltxt[i])
				info->cert_value = strdup(coltxt[i]);
			else
				info->cert_value = NULL;
		} else if (strcmp(colname[i], "for_all_users") == 0 ){
			if (coltxt[i])
				info->for_all_users = atoi(coltxt[i]);
			else
				info->for_all_users = 0;
		} else
			continue;
	}
	return 0;
}

static int __exec_certinfo_query(char *query, void *data)
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(cert_db), query, __certinfo_cb, data, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __certindexinfo_cb(void *data, int ncols, char **coltxt, char **colname)
{
	pkgmgr_certindexinfo_x *info = (pkgmgr_certindexinfo_x *)data;
	int i = 0;
	for(i = 0; i < ncols; i++) {
		if (strcmp(colname[i], "cert_id") == 0) {
			if (coltxt[i])
				info->cert_id = atoi(coltxt[i]);
			else
				info->cert_id = 0;
		} else if (strcmp(colname[i], "cert_ref_count") == 0) {
			if (coltxt[i])
				info->cert_ref_count = atoi(coltxt[i]);
			else
				info->cert_ref_count = 0;
		} else
			continue;
	}
	return 0;
}

static int __exec_certindexinfo_query(char *query, void *data)
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(cert_db), query, __certindexinfo_cb, data, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __delete_certinfo(const char *pkgid, uid_t uid)
{
	int ret = -1;
	int i = 0;
	int j = 0;
	int c = 0;
	int unique_id[MAX_CERT_TYPE] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
	char *error_message = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	pkgmgr_certinfo_x *certinfo = NULL;
	pkgmgr_certindexinfo_x *indexinfo = NULL;
	certinfo = calloc(1, sizeof(pkgmgr_certinfo_x));
	retvm_if(certinfo == NULL, PMINFO_R_ERROR, "Malloc Failed\n");
	indexinfo = calloc(1, sizeof(pkgmgr_certindexinfo_x));
	if (indexinfo == NULL) {
		_LOGE("Out of Memory!!!");
		ret = PMINFO_R_ERROR;
		goto err;
	}

	__open_cert_db(uid, false);
	/*populate certinfo from DB*/
	snprintf(query, MAX_QUERY_LEN, "select * from package_cert_info where package='%s' ", pkgid);
	ret = __exec_certinfo_query(query, (void *)certinfo);
	if (ret == -1) {
		_LOGE("Package Cert Info DB Information retrieval failed\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	/*Update cert index table*/
	for (i = 0; i < MAX_CERT_TYPE; i++) {
		if ((certinfo->cert_id)[i]) {
			for (j = 0; j < MAX_CERT_TYPE; j++) {
				if ((certinfo->cert_id)[i] == unique_id[j]) {
					/*Ref count has already been updated. Just continue*/
					break;
				}
			}
			if (j == MAX_CERT_TYPE)
				unique_id[c++] = (certinfo->cert_id)[i];
			else
				continue;
			memset(query, '\0', MAX_QUERY_LEN);
			snprintf(query, MAX_QUERY_LEN, "select * from package_cert_index_info where cert_id=%d ", (certinfo->cert_id)[i]);
			ret = __exec_certindexinfo_query(query, (void *)indexinfo);
			if (ret == -1) {
				_LOGE("Cert Info DB Information retrieval failed\n");
				ret = PMINFO_R_ERROR;
				goto err;
			}
			memset(query, '\0', MAX_QUERY_LEN);
			if (indexinfo->cert_ref_count > 1) {
				/*decrease ref count*/
				snprintf(query, MAX_QUERY_LEN, "update package_cert_index_info set cert_ref_count=%d where cert_id=%d ",
				indexinfo->cert_ref_count - 1, (certinfo->cert_id)[i]);
			} else {
				/*delete this certificate as ref count is 1 and it will become 0*/
				snprintf(query, MAX_QUERY_LEN, "delete from  package_cert_index_info where cert_id=%d ", (certinfo->cert_id)[i]);
			}
		        if (SQLITE_OK !=
		            sqlite3_exec(GET_DB(cert_db), query, NULL, NULL, &error_message)) {
		                _LOGE("Don't execute query = %s error message = %s\n", query,
		                       error_message);
				sqlite3_free(error_message);
				ret = PMINFO_R_ERROR;
				goto err;
		        }
		}
	}
	/*Now delete the entry from db*/
	snprintf(query, MAX_QUERY_LEN, "delete from package_cert_info where package='%s'", pkgid);
        if (SQLITE_OK !=
            sqlite3_exec(GET_DB(cert_db), query, NULL, NULL, &error_message)) {
                _LOGE("Don't execute query = %s error message = %s\n", query,
                       error_message);
		sqlite3_free(error_message);
		ret = PMINFO_R_ERROR;
		goto err;
        }
	ret = PMINFO_R_OK;
err:
	if (indexinfo) {
		free(indexinfo);
		indexinfo = NULL;
	}
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
	__close_cert_db();
	free(certinfo);
	certinfo = NULL;
	return ret;
}

static int __validate_cb(void *data, int ncols, char **coltxt, char **colname)
{
	int *p = (int*)data;
	*p = atoi(coltxt[0]);
	return 0;
}

static int __maxid_cb(void *data, int ncols, char **coltxt, char **colname)
{
	int *p = (int*)data;
	if (coltxt[0])
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

API int pkgmgrinfo_pkginfo_load_certinfo(const char *pkgid, pkgmgrinfo_certinfo_h handle, uid_t uid)
{
	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "package ID is NULL\n");
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Certinfo handle is NULL\n");
	pkgmgr_certinfo_x *certinfo = NULL;
	char *error_message = NULL;
	int ret = PMINFO_R_OK;
	char query[MAX_QUERY_LEN] = {'\0'};
	int exist = 0;
	int i = 0;

	/*Open db.*/
	ret = __open_cert_db(uid, true);
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	_check_create_cert_db(GET_DB(cert_db));
	/*validate pkgid*/
	snprintf(query, MAX_QUERY_LEN, "select exists(select * from package_cert_info where package='%s')", pkgid);
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(cert_db), query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}
	if (exist == 0) {
		_LOGE("Package for user[%d] is not found in DB\n", uid);
		ret = PMINFO_R_ERROR;
		goto err;
	}
	certinfo = (pkgmgr_certinfo_x *)handle;
	/*populate certinfo from DB*/
	snprintf(query, MAX_QUERY_LEN, "select * from package_cert_info where package='%s' ", pkgid);
	ret = __exec_certinfo_query(query, (void *)certinfo);
	if (ret == -1) {
		_LOGE("Package Cert Info DB Information retrieval failed\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	for (i = 0; i < MAX_CERT_TYPE; i++) {
		memset(query, '\0', MAX_QUERY_LEN);
		if (uid == GLOBAL_USER || uid == ROOT_UID)
			snprintf(query, MAX_QUERY_LEN, "select cert_info from package_cert_index_info where cert_id=%d", (certinfo->cert_id)[i]);
		else
			snprintf(query, MAX_QUERY_LEN, "select cert_info from package_cert_index_info where cert_id=%d and for_all_users=%d", (certinfo->cert_id)[i], certinfo->for_all_users);
		ret = __exec_certinfo_query(query, (void *)certinfo);
		if (ret == -1) {
			_LOGE("Cert Info DB Information retrieval failed\n");
			ret = PMINFO_R_ERROR;
			goto err;
		}
		if (certinfo->cert_value) {
			(certinfo->cert_info)[i] = strdup(certinfo->cert_value);
			free(certinfo->cert_value);
			certinfo->cert_value = NULL;
		}
	}
err:
	__close_cert_db();
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

API int pkgmgrinfo_save_certinfo(const char *pkgid, pkgmgrinfo_instcertinfo_h handle, uid_t uid)
{
	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "package ID is NULL\n");
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Certinfo handle is NULL\n");
	char *error_message = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	char vquery[MAX_QUERY_LEN] = {'\0'};
	int i = 0;
	int j = 0;
	int c = 0;
	int unique_id[MAX_CERT_TYPE] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
	int newid = 0;
	int is_new = 0;
	int exist = -1;
	int ret = -1;
	int maxid = 0;
	int flag = 0;
	pkgmgr_instcertinfo_x *info = (pkgmgr_instcertinfo_x *)handle;
	pkgmgr_certindexinfo_x *indexinfo = NULL;
	indexinfo = calloc(1, sizeof(pkgmgr_certindexinfo_x));
	if (indexinfo == NULL) {
		_LOGE("Out of Memory!!!");
		return PMINFO_R_ERROR;
	}
	info->pkgid = strdup(pkgid);

	/*Open db.*/
	ret =__open_cert_db(uid, false);
	if (ret != 0) {
		ret = PMINFO_R_ERROR;
		_LOGE("Failed to open cert db \n");
		goto err;
	}
	_check_create_cert_db(GET_DB(cert_db));
	/*Begin Transaction*/
	ret = sqlite3_exec(GET_DB(cert_db), "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret == -1) {
		_LOGE("Failed to begin transaction %s\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}

	/*Check if request is to insert/update*/
	snprintf(query, sizeof(query), "select exists(select * from package_cert_info where package='%s')", pkgid);
	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(cert_db), query, __validate_cb, (void *)&exist, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		ret = PMINFO_R_ERROR;
		goto err;
	}
	if (exist) {
		/*Update request.
		We cant just issue update query directly. We need to manage index table also.
		Hence it is better to delete and insert again in case of update*/
		ret = __delete_certinfo(pkgid, uid);
		if (ret < 0)
			_LOGE("Certificate Deletion Failed\n");
	}
	for (i = 0; i < MAX_CERT_TYPE; i++) {
		if ((info->cert_info)[i]) {
			for (j = 0; j < i; j++) {
				if ( (info->cert_info)[j]) {
					if (strcmp((info->cert_info)[i], (info->cert_info)[j]) == 0) {
						(info->cert_id)[i] = (info->cert_id)[j];
						(info->is_new)[i] = 0;
						(info->ref_count)[i] = (info->ref_count)[j];
						break;
					}
				}
			}
			if (j < i)
				continue;
			snprintf(query, sizeof(query), "select * from package_cert_index_info " \
				"where cert_info='%s'",(info->cert_info)[i]);
			ret = __exec_certindexinfo_query(query, (void *)indexinfo);
			if (ret == -1) {
				_LOGE("Cert Info DB Information retrieval failed\n");
				ret = PMINFO_R_ERROR;
				goto err;
			}
			if (indexinfo->cert_id == 0) {
				/*New certificate. Get newid*/
				snprintf(query, sizeof(query), "select MAX(cert_id) from package_cert_index_info ");
				if (SQLITE_OK !=
				    sqlite3_exec(GET_DB(cert_db), query, __maxid_cb, (void *)&newid, &error_message)) {
					_LOGE("Don't execute query = %s error message = %s\n", query,
					       error_message);
					sqlite3_free(error_message);
					ret = PMINFO_R_ERROR;
					goto err;
				}
				newid = newid + 1;
				if (flag == 0) {
					maxid = newid;
					flag = 1;
				}
				indexinfo->cert_id = maxid;
				indexinfo->cert_ref_count = 1;
				is_new = 1;
				maxid = maxid + 1;
			}
			(info->cert_id)[i] = indexinfo->cert_id;
			(info->is_new)[i] = is_new;
			(info->ref_count)[i] = indexinfo->cert_ref_count;
			indexinfo->cert_id = 0;
			indexinfo->cert_ref_count = 0;
			is_new = 0;
		}
	}
	/*insert*/
	snprintf(vquery, sizeof(vquery),
                 "insert into package_cert_info(package, author_root_cert, author_im_cert, author_signer_cert, dist_root_cert, " \
                "dist_im_cert, dist_signer_cert, dist2_root_cert, dist2_im_cert, dist2_signer_cert) " \
                "values('%s', %d, %d, %d, %d, %d, %d, %d, %d, %d)",\
                 info->pkgid,(info->cert_id)[PMINFO_SET_AUTHOR_ROOT_CERT],(info->cert_id)[PMINFO_SET_AUTHOR_INTERMEDIATE_CERT],
		(info->cert_id)[PMINFO_SET_AUTHOR_SIGNER_CERT], (info->cert_id)[PMINFO_SET_DISTRIBUTOR_ROOT_CERT],
		(info->cert_id)[PMINFO_SET_DISTRIBUTOR_INTERMEDIATE_CERT], (info->cert_id)[PMINFO_SET_DISTRIBUTOR_SIGNER_CERT],
		(info->cert_id)[PMINFO_SET_DISTRIBUTOR2_ROOT_CERT],(info->cert_id)[PMINFO_SET_DISTRIBUTOR2_INTERMEDIATE_CERT],
		(info->cert_id)[PMINFO_SET_DISTRIBUTOR2_SIGNER_CERT]);
        if (SQLITE_OK !=
            sqlite3_exec(GET_DB(cert_db), vquery, NULL, NULL, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", vquery,
		       error_message);
		sqlite3_free(error_message);
		ret = PMINFO_R_ERROR;
		goto err;
        }
	/*Update index table info*/
	/*If cert_id exists and is repeated for current package, ref count should only be increased once*/
	for (i = 0; i < MAX_CERT_TYPE; i++) {
		if ((info->cert_info)[i]) {
			if ((info->is_new)[i]) {
				snprintf(vquery, sizeof(vquery), "insert into package_cert_index_info(cert_info, cert_id, cert_ref_count) " \
				"values('%s', '%d', '%d') ", (info->cert_info)[i], (info->cert_id)[i], 1);
				unique_id[c++] = (info->cert_id)[i];
			} else {
				/*Update*/
				for (j = 0; j < MAX_CERT_TYPE; j++) {
					if ((info->cert_id)[i] == unique_id[j]) {
						/*Ref count has already been increased. Just continue*/
						break;
					}
				}
				if (j == MAX_CERT_TYPE)
					unique_id[c++] = (info->cert_id)[i];
				else
					continue;
				snprintf(vquery, sizeof(vquery), "update package_cert_index_info set cert_ref_count=%d " \
				"where cert_id=%d",  (info->ref_count)[i] + 1, (info->cert_id)[i]);
			}
		        if (SQLITE_OK !=
		            sqlite3_exec(GET_DB(cert_db), vquery, NULL, NULL, &error_message)) {
				_LOGE("Don't execute query = %s error message = %s\n", vquery,
				       error_message);
				sqlite3_free(error_message);
				ret = PMINFO_R_ERROR;
				goto err;
		        }
		}
	}
	/*Commit transaction*/
	ret = sqlite3_exec(GET_DB(cert_db), "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to commit transaction, Rollback now\n");
		sqlite3_exec(GET_DB(cert_db), "ROLLBACK", NULL, NULL, NULL);
		ret = PMINFO_R_ERROR;
		goto err;
	}

	ret =  PMINFO_R_OK;
err:
	__close_cert_db();
	if (indexinfo) {
		free(indexinfo);
		indexinfo = NULL;
	}
	return ret;
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

API int pkgmgrinfo_delete_usr_certinfo(const char *pkgid, uid_t uid)
{
	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	int ret = -1;
	/*Open db.*/
	ret = __open_cert_db(uid, false);
	if (ret != 0) {
		_LOGE("connect db [%s] failed!\n", getUserPkgCertDBPathUID(uid));
		ret = PMINFO_R_ERROR;
		goto err;
	}
	_check_create_cert_db(GET_DB(cert_db));
	/*Begin Transaction*/
	ret = sqlite3_exec(GET_DB(cert_db), "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to begin transaction\n");
		ret = PMINFO_R_ERROR;
		goto err;
	}
	_LOGE("Transaction Begin\n");
	ret = __delete_certinfo(pkgid, uid);
	if (ret < 0) {
		_LOGE("Certificate Deletion Failed\n");
	} else {
		_LOGE("Certificate Deletion Success\n");
	}
	/*Commit transaction*/
	ret = sqlite3_exec(GET_DB(cert_db), "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to commit transaction, Rollback now\n");
		sqlite3_exec(GET_DB(cert_db), "ROLLBACK", NULL, NULL, NULL);
		ret = PMINFO_R_ERROR;
		goto err;
	}
	_LOGE("Transaction Commit and End\n");
	ret = PMINFO_R_OK;
err:
	__close_cert_db();
	return ret;
}


API int pkgmgrinfo_delete_certinfo(const char *pkgid)
{
	return pkgmgrinfo_delete_usr_certinfo(pkgid, GLOBAL_USER);
}

