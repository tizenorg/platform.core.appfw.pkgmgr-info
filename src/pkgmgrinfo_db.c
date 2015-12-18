#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <grp.h>
#include <dirent.h>
#include <libgen.h>

#include <sqlite3.h>

#include <tzplatform_config.h>
#include <db-util.h>

#include "pkgmgr-info.h"
#include "pkgmgrinfo_debug.h"
#include "pkgmgrinfo_private.h"
#include "pkgmgr_parser.h"
#include "pkgmgr_parser_internal.h"

#define QUERY_CREATE_TABLE_PACKAGE_CERT_INDEX_INFO "create table if not exists package_cert_index_info " \
						"(cert_info text not null, " \
						"cert_id integer, " \
						"cert_ref_count integer, " \
						"PRIMARY KEY(cert_id)) "

#define QUERY_CREATE_TABLE_PACKAGE_CERT_INFO "create table if not exists package_cert_info " \
						"(package text not null, " \
						"author_root_cert integer, " \
						"author_im_cert integer, " \
						"author_signer_cert integer, " \
						"dist_root_cert integer, " \
						"dist_im_cert integer, " \
						"dist_signer_cert integer, " \
						"dist2_root_cert integer, " \
						"dist2_im_cert integer, " \
						"dist2_signer_cert integer, " \
						"PRIMARY KEY(package)) "
__thread db_handle manifest_db;
__thread db_handle cert_db;

typedef int (*sqlite_query_callback)(void *data, int ncols, char **coltxt, char **colname);

static int _mkdir_for_user(const char* dir, uid_t uid, gid_t gid)
{
	int ret;
	char *fullpath;
	char *subpath;

	fullpath = strdup(dir);
	if (fullpath == NULL)
		return -1;
	subpath = dirname(fullpath);
	if (strlen(subpath) > 1 && strcmp(subpath, fullpath) != 0) {
		ret = _mkdir_for_user(fullpath, uid, gid);
		if (ret == -1) {
			free(fullpath);
			return ret;
		}
	}

	ret = mkdir(dir, S_IRWXU | S_IRGRP | S_IXGRP | S_IXOTH);
	if (ret && errno != EEXIST) {
		free(fullpath);
		return ret;
	} else if (ret && errno == EEXIST) {
		free(fullpath);
		return 0;
	}

	if (getuid() == ROOT_UID) {
		ret = chown(dir, uid, gid);
		if (ret == -1)
			_LOGE("FAIL : chown %s %d.%d, because %s", dir, uid,
					gid, strerror(errno));
	}

	free(fullpath);

	return 0;
}

static const char *_get_db_path(uid_t uid) {
	const char *db_path = NULL;
	if (uid != GLOBAL_USER && uid != ROOT_UID) {
		tzplatform_set_user(uid);
		db_path = tzplatform_getenv(TZ_USER_DB);
		tzplatform_reset_user();
	} else {
		db_path = tzplatform_getenv(TZ_SYS_DB);
	}
	return db_path;
}

static int __attach_and_create_view(sqlite3 *handle, const char *db, const char *tables[], uid_t uid)
{
	int i;
	char *err;
	char query[MAX_QUERY_LEN];

	if (uid != GLOBAL_USER && uid != ROOT_UID) {
		snprintf(query, sizeof(query), "ATTACH DATABASE '%s' AS Global", db);
		if (SQLITE_OK != sqlite3_exec(handle, query, NULL, NULL, &err)) {
			_LOGD("Don't execute query = %s error message = %s\n", query, err);
			sqlite3_free(err);
			return SQLITE_ERROR;
		}
	}

	for (i = 0; tables[i]; i++) {
		if (uid != GLOBAL_USER && uid != ROOT_UID)
			snprintf(query, sizeof(query), "CREATE TEMP VIEW '%s' AS SELECT * \
					FROM (SELECT *,0 AS for_all_users FROM main.'%s' UNION \
					SELECT *,1 AS for_all_users FROM Global.'%s')",
					tables[i], tables[i], tables[i]);
		else
			snprintf(query, sizeof(query), "CREATE TEMP VIEW '%s' AS SELECT * \
					FROM (SELECT *,1 AS for_all_users FROM main.'%s')",
					tables[i], tables[i]);
		if (SQLITE_OK != sqlite3_exec(handle, query, NULL, NULL, &err)) {
			_LOGD("Don't execute query = %s error message = %s\n", query, err);
			sqlite3_free(err);
		}
	}

	return SQLITE_OK;
}

static int __exec_db_query(sqlite3 *db, char *query, sqlite_query_callback callback, void *data)
{
	char *error_message = NULL;
	int ret = sqlite3_exec(db, query, callback, data, &error_message);
	if (SQLITE_OK != ret) {
		_LOGE("Don't execute query = %s error message = %s   ret = %d\n", query,
		       error_message, ret);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

int _check_create_cert_db(sqlite3 *certdb)
{
	int ret = 0;
	ret = __exec_db_query(certdb, QUERY_CREATE_TABLE_PACKAGE_CERT_INDEX_INFO, NULL, NULL);
	if (ret < 0)
		return ret;
	ret = __exec_db_query(certdb, QUERY_CREATE_TABLE_PACKAGE_CERT_INFO, NULL, NULL);
	return ret;
}
static gid_t _get_gid(const char *name)
{
	char buf[BUFSIZE];
	struct group entry;
	struct group *ge;
	int ret;

	ret = getgrnam_r(name, &entry, buf, sizeof(buf), &ge);
	if (ret || ge == NULL) {
		_LOGE("fail to get gid of %s", name);
		return -1;
	}

	return entry.gr_gid;
}

API const char *getIconPath(uid_t uid)
{
	const char *path = NULL;
	uid_t uid_caller = getuid();
	gid_t gid = ROOT_UID;

	if (uid != GLOBAL_USER && uid != ROOT_UID) {
		tzplatform_set_user(uid);
		path = tzplatform_mkpath(TZ_USER_ICONS, "/");
		gid = _get_gid(tzplatform_getenv(TZ_SYS_USER_GROUP));
		tzplatform_reset_user();
	} else {
		path = tzplatform_mkpath(TZ_SYS_RW_ICONS, "/");
	}

	// just allow certain users to create the icon directory if needed.
	if (uid_caller == ROOT_UID || uid_caller == uid)
		_mkdir_for_user(path, uid, gid);

	return path;
}

API const char *getUserPkgParserDBPath(void)
{
	return getUserPkgParserDBPathUID(GLOBAL_USER);
}

API const char *getUserPkgParserDBPathUID(uid_t uid)
{
	const char *pkgmgr_parser_db = NULL;
	uid_t uid_caller = getuid();
	gid_t gid = ROOT_UID;

	if (uid != GLOBAL_USER && uid != ROOT_UID) {
		tzplatform_set_user(uid);
		pkgmgr_parser_db = tzplatform_mkpath(TZ_USER_DB, ".pkgmgr_parser.db");
		gid = _get_gid(tzplatform_getenv(TZ_SYS_USER_GROUP));
		tzplatform_reset_user();
	} else {
		pkgmgr_parser_db = tzplatform_mkpath(TZ_SYS_DB, ".pkgmgr_parser.db");
	}

	// just allow certain users to create the dbspace directory if needed.
	if (uid_caller == ROOT_UID || uid_caller == uid) {
		const char *db_path = _get_db_path(uid);
		_mkdir_for_user(db_path, uid, gid);
	}

	return pkgmgr_parser_db;
}

API const char *getUserPkgCertDBPath(void)
{
	 return getUserPkgCertDBPathUID(GLOBAL_USER);
}

API const char *getUserPkgCertDBPathUID(uid_t uid)
{
	const char *pkgmgr_cert_db = NULL;
	uid_t uid_caller = getuid();
	gid_t gid = ROOT_UID;

	if (uid != GLOBAL_USER && uid != ROOT_UID) {
		tzplatform_set_user(uid);
		pkgmgr_cert_db = tzplatform_mkpath(TZ_USER_DB, ".pkgmgr_cert.db");
		gid = _get_gid(tzplatform_getenv(TZ_SYS_USER_GROUP));
		tzplatform_reset_user();
	} else {
		pkgmgr_cert_db = tzplatform_mkpath(TZ_SYS_DB, ".pkgmgr_cert.db");
	}

	// just allow certain users to create the dbspace directory if needed.
	if (uid_caller == ROOT_UID || uid_caller == uid) {
		const char *db_path = _get_db_path(uid);
		_mkdir_for_user(db_path, uid, gid);
	}

	return pkgmgr_cert_db;
}

API const char *getUserDesktopPath(uid_t uid)
{
	const char *path = NULL;
	uid_t uid_caller = getuid();
	gid_t gid = ROOT_UID;

	if (uid != GLOBAL_USER && uid != ROOT_UID) {
		tzplatform_set_user(uid);
		path = tzplatform_mkpath(TZ_USER_DESKTOP, "/");
		gid = _get_gid(tzplatform_getenv(TZ_SYS_USER_GROUP));
		tzplatform_reset_user();
	} else {
		path = tzplatform_mkpath(TZ_SYS_RW_DESKTOP_APP, "/");
	}

	// just allow certain users to create the icon directory if needed.
	if (uid_caller == ROOT_UID || uid_caller == uid)
		_mkdir_for_user(path, uid, gid);

	return path;
}

API const char *getUserManifestPath(uid_t uid)
{
	const char *path = NULL;
	uid_t uid_caller = getuid();
	gid_t gid = ROOT_UID;

	if (uid != GLOBAL_USER && uid != ROOT_UID) {
		tzplatform_set_user(uid);
		path = tzplatform_mkpath(TZ_USER_PACKAGES, "/");
		gid = _get_gid(tzplatform_getenv(TZ_SYS_USER_GROUP));
		tzplatform_reset_user();
	} else {
		path = tzplatform_mkpath(TZ_SYS_RW_PACKAGES, "/");
	}

	// just allow certain users to create the icon directory if needed.
	if (uid_caller == ROOT_UID || uid_caller == uid)
		_mkdir_for_user(path, uid, gid);

	return path;
}

int __close_manifest_db(void)
{
	if (manifest_db.ref) {
		if (--manifest_db.ref == 0)
			sqlite3_close(GET_DB(manifest_db));
		return 0;
	}
	return -1;
}

static const char *parserdb_tables[] = {
	"package_app_app_category",
	"package_app_info",
	"package_app_app_control",
	"package_app_localized_info",
	"package_app_app_metadata",
	"package_app_share_allowed",
	"package_app_app_permission",
	"package_app_share_request",
	"package_info",
	"package_app_data_control",
	"package_localized_info",
	"package_app_icon_section_info",
	"package_privilege_info",
	"package_app_image_info",
	NULL
};

int __open_manifest_db(uid_t uid, bool readonly)
{
	int ret;
	const char *user_pkg_parser;
	int flags;

	if (manifest_db.ref) {
		manifest_db.ref ++;
		return 0;
	}

	user_pkg_parser = getUserPkgParserDBPathUID(uid);
	if (access(user_pkg_parser, F_OK) != 0) {
		_LOGE("Manifest DB does not exists !!");
		return -1;
	}

	flags = readonly ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE;
	ret = db_util_open_with_options(user_pkg_parser, &GET_DB(manifest_db),
			flags, NULL);
	retvm_if(ret != SQLITE_OK, -1, "connect db [%s] failed!\n",
			user_pkg_parser);
	manifest_db.ref++;
	if (readonly) {
		ret = __attach_and_create_view(GET_DB(manifest_db), MANIFEST_DB,
				parserdb_tables, uid);
		retvm_if(ret != SQLITE_OK, -1, "attach db [%s] failed!\n",
				user_pkg_parser);
	}
	return 0;
}

int __close_cert_db(void)
{
	if (cert_db.ref) {
		if (--cert_db.ref == 0)
			sqlite3_close_v2(GET_DB(cert_db));
			return 0;
	}
	_LOGE("Certificate DB is already closed !!\n");
	return -1;
}

static const char *certdb_tables[] = {
	"package_cert_index_info",
	"package_cert_info",
	NULL
};

int __open_cert_db(uid_t uid, bool readonly)
{
	int ret;
	const char *user_cert_parser;
	int flags;

	if (cert_db.ref) {
		cert_db.ref ++;
		return 0;
	}

	user_cert_parser = getUserPkgCertDBPathUID(uid);
	if (access(user_cert_parser, F_OK) != 0) {
		_LOGE("Cert DB does not exists !!");
		return -1;
	}

	flags = readonly ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE;
	ret = db_util_open_with_options(user_cert_parser, &GET_DB(cert_db),
			flags, NULL);
	retvm_if(ret != SQLITE_OK, -1, "connect db [%s] failed!",
			user_cert_parser);
	cert_db.ref++;
	if (readonly) {
		ret = __attach_and_create_view(GET_DB(cert_db), CERT_DB,
				certdb_tables, uid);
		retvm_if(ret != SQLITE_OK, -1, "attach db [%s] failed!",
				user_cert_parser);
	}
	return 0;
}

void _save_column_int(sqlite3_stmt *stmt, int idx, int *i)
{
	*i = sqlite3_column_int(stmt, idx);
}

void _save_column_str(sqlite3_stmt *stmt, int idx, const char **str)
{
	const char *val;

	val = (const char *)sqlite3_column_text(stmt, idx);
	if (val)
		*str = strdup(val);
}

API int pkgmgrinfo_pkginfo_set_state_enabled(const char *pkgid, bool enabled)
{
	/* Should be implemented later */
	return 0;
}

API int pkgmgrinfo_appinfo_set_usr_state_enabled(const char *appid, bool enabled, uid_t uid)
{
	int ret;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message;

	retvm_if(appid == NULL, PMINFO_R_EINVAL, "appid is NULL\n");

	/* Open db.*/
	ret = __open_manifest_db(uid, false);
	if (ret != SQLITE_OK) {
		_LOGE("connect db [%s] failed!\n", getUserPkgParserDBPathUID(uid));
		return PMINFO_R_ERROR;
	}

	/*Begin transaction*/
	ret = sqlite3_exec(GET_DB(manifest_db), "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to begin transaction\n");
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}
	_LOGD("Transaction Begin\n");

	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN,
		"update package_app_info set app_enabled='%s' where app_id='%s'", enabled?"true":"false", appid);

	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(manifest_db), query, NULL, NULL, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return PMINFO_R_ERROR;
	}
	sqlite3_free(error_message);

	/*Commit transaction*/
	ret = sqlite3_exec(GET_DB(manifest_db), "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to commit transaction. Rollback now\n");
		sqlite3_exec(GET_DB(manifest_db), "ROLLBACK", NULL, NULL, NULL);
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}
	_LOGD("Transaction Commit and End\n");
	__close_manifest_db();
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_set_state_enabled(const char *appid, bool enabled)
{
	return pkgmgrinfo_appinfo_set_usr_state_enabled(appid, enabled, GLOBAL_USER);
}

API int pkgmgrinfo_appinfo_set_usr_default_label(const char *appid, const char *label, uid_t uid)
{
	int ret;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *error_message;

	retvm_if(appid == NULL, PMINFO_R_EINVAL, "appid is NULL\n");

	ret = __open_manifest_db(uid, false);
	if (ret == -1) {
		_LOGE("Fail to open manifest DB\n");
		return PMINFO_R_ERROR;
	}

	/*Begin transaction*/
	ret = sqlite3_exec(GET_DB(manifest_db), "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to begin transaction\n");
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}
	_LOGD("Transaction Begin\n");

	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN,
		"update package_app_localized_info set app_label='%s' where app_id='%s' and app_locale='No Locale'", label, appid);

	if (SQLITE_OK !=
	    sqlite3_exec(GET_DB(manifest_db), query, NULL, NULL, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return PMINFO_R_ERROR;
	}

	/*Commit transaction*/
	ret = sqlite3_exec(GET_DB(manifest_db), "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to commit transaction. Rollback now\n");
		sqlite3_exec(GET_DB(manifest_db), "ROLLBACK", NULL, NULL, NULL);
		__close_manifest_db();
		return PMINFO_R_ERROR;
	}
	_LOGD("Transaction Commit and End\n");
	__close_manifest_db();
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_set_default_label(const char *appid, const char *label)
{
	return pkgmgrinfo_appinfo_set_usr_default_label(appid, label, GLOBAL_USER);
}

API int pkgmgrinfo_appinfo_set_usr_guestmode_visibility(pkgmgrinfo_appinfo_h handle, uid_t uid, bool status)
{
	const char *val;
	int ret;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *errmsg;
	sqlite3 *pkgmgr_parser_db;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");

	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	val = info->app_info->guestmode_visibility;
	if (val) {
		ret = db_util_open_with_options(getUserPkgParserDBPathUID(uid), &pkgmgr_parser_db,
				SQLITE_OPEN_READWRITE, NULL);
		if (ret != SQLITE_OK) {
			_LOGE("DB Open Failed\n");
			return PMINFO_R_ERROR;
		}

		/*TODO: Write to DB here*/
		if (status == true)
			snprintf(query, MAX_QUERY_LEN, "update package_app_info set app_guestmodevisibility = 'true' where app_id = '%s'", (char *)info->app_info->appid);
		else
			snprintf(query, MAX_QUERY_LEN, "update package_app_info set app_guestmodevisibility = 'false' where app_id = '%s'", (char *)info->app_info->appid);

		ret = sqlite3_exec(pkgmgr_parser_db, query, NULL, NULL, &errmsg);
		sqlite3_close(pkgmgr_parser_db);
		if (ret != SQLITE_OK) {
			_LOGE("DB update [%s] failed, error message = %s\n", query, errmsg);
			free(errmsg);
			return PMINFO_R_ERROR;
		}
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_set_guestmode_visibility(pkgmgrinfo_appinfo_h handle, bool status)
{
	return pkgmgrinfo_appinfo_set_usr_guestmode_visibility(handle, GLOBAL_USER, status);
}

API int pkgmgrinfo_pkginfo_set_usr_installed_storage(const char *pkgid, INSTALL_LOCATION location, uid_t uid)
{
	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "pkgid is NULL\n");
	int ret = -1;
	int exist = 0;
	sqlite3 *pkgmgr_parser_db = NULL;
	char *query = NULL;

	ret = db_util_open_with_options(getUserPkgParserDBPathUID(uid), &pkgmgr_parser_db,
			SQLITE_OPEN_READWRITE, NULL);
	retvm_if(ret != SQLITE_OK, PMINFO_R_ERROR, "connect db failed!");

	/*Begin transaction*/
	// Setting Manifest DB
	ret = sqlite3_exec(pkgmgr_parser_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Failed to begin transaction\n");
	_LOGD("Transaction Begin\n");

	// pkgcakge_info table
	query = sqlite3_mprintf("update package_info set installed_storage=%Q where package=%Q", location?"installed_external":"installed_internal", pkgid);

	ret = sqlite3_exec(pkgmgr_parser_db, query, NULL, NULL, NULL);
	tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Don't execute query = %s\n", query);
	sqlite3_free(query);

	// package_app_info table
	query = sqlite3_mprintf("update package_app_info set app_installed_storage=%Q where package=%Q", location?"installed_external":"installed_internal", pkgid);

	ret = sqlite3_exec(pkgmgr_parser_db, query, NULL, NULL, NULL);
	tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Don't execute query = %s\n", query);

	/*Commit transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to commit transaction. Rollback now\n");
		ret = sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		tryvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "Don't execute query = %s\n", query);
	}
	_LOGD("Transaction Commit and End\n");

	ret = PMINFO_R_OK;
catch:
	sqlite3_close(pkgmgr_parser_db);
	sqlite3_free(query);
	return ret;
}

API int pkgmgrinfo_pkginfo_set_installed_storage(const char *pkgid, INSTALL_LOCATION location)
{
	return pkgmgrinfo_pkginfo_set_usr_installed_storage(pkgid, location, GLOBAL_USER);
}
