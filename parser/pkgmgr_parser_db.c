/*
 * pkgmgr-info
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>,
 * Jaeho Lee <jaeho81.lee@samsung.com>, Shobhit Srivastava <shobhit.s@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/smack.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>

#include <db-util.h>
#include <glib.h>
#include <system_info.h>

/* For multi-user support */
#include <tzplatform_config.h>

#include "pkgmgr-info.h"
#include "pkgmgrinfo_basic.h"
#include "pkgmgrinfo_debug.h"
#include "pkgmgr_parser_internal.h"
#include "pkgmgr_parser_db.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "PKGMGR_PARSER"

#define PKGMGR_PARSER_DB_FILE tzplatform_mkpath(TZ_SYS_DB, ".pkgmgr_parser.db")
#define PKGMGR_CERT_DB_FILE tzplatform_mkpath(TZ_SYS_DB, ".pkgmgr_cert.db")
#define MAX_QUERY_LEN		4096
#define BUFSIZE 4096
#define OWNER_ROOT 0

#define LDPI "ldpi"
#define MDPI "mdpi"
#define HDPI "hdpi"
#define XHDPI "xhdpi"
#define XXHDPI "xxhdpi"

#define LDPI_MIN 0
#define LDPI_MAX 240
#define MDPI_MIN 241
#define MDPI_MAX 300
#define HDPI_MIN 301
#define HDPI_MAX 380
#define XHDPI_MIN 381
#define XHDPI_MAX 480
#define XXHDPI_MIN 481
#define XXHDPI_MAX 600

#define DB_LABEL "User::Home"
#define SET_SMACK_LABEL(x) \
do { \
	if (smack_setlabel((x), DB_LABEL, SMACK_LABEL_ACCESS)) \
		_LOGE("failed chsmack -a %s %s", DB_LABEL, x); \
	else \
		_LOGD("chsmack -a %s %s", DB_LABEL, x); \
} while (0)

sqlite3 *pkgmgr_parser_db;
sqlite3 *pkgmgr_cert_db;


#define QUERY_CREATE_TABLE_PACKAGE_INFO "CREATE TABLE IF NOT EXISTS package_info " \
						"(package TEXT PRIMARY KEY NOT NULL, " \
						"package_type TEXT DEFAULT 'tpk', " \
						"package_version TEXT, " \
						"package_api_version TEXT, " \
						"package_tep_name TEXT, " \
						"package_zip_mount_file TEXT, " \
						"install_location TEXT NOT NULL , " \
						"package_size TEXT, " \
						"package_removable TEXT NOT NULL DEFAULT 'true', " \
						"package_preload TEXT NOT NULL DEFAULT 'false', " \
						"package_readonly TEXT NOT NULL DEFAULT 'false', " \
						"package_update TEXT NOT NULL DEFAULT 'false', " \
						"package_appsetting TEXT NOT NULL DEFAULT 'false', " \
						"package_nodisplay TEXT NOT NULL DEFAULT 'false', " \
						"package_system TEXT NOT NULL DEFAULT 'false', " \
						"author_name TEXT, " \
						"author_email TEXT, " \
						"author_href TEXT," \
						"installed_time TEXT, " \
						"installed_storage TEXT, " \
						"storeclient_id TEXT, " \
						"mainapp_id TEXT, " \
						"package_url TEXT, " \
						"root_path TEXT, " \
						"csc_path TEXT, " \
						"package_support_disable TEXT NOT NULL DEFAULT 'false', " \
						"package_disable TEXT NOT NULL DEFAULT 'false')"

#define QUERY_CREATE_TABLE_PACKAGE_LOCALIZED_INFO "CREATE TABLE IF NOT EXISTS package_localized_info " \
						"(package TEXT NOT NULL, " \
						"package_locale TEXT NOT NULL DEFAULT 'No Locale', " \
						"package_label TEXT, " \
						"package_icon TEXT, " \
						"package_description TEXT, " \
						"package_license TEXT, " \
						"package_author TEXT, " \
						"PRIMARY KEY(package, package_locale), " \
						"FOREIGN KEY(package) " \
						"REFERENCES package_info(package) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_PRIVILEGE_INFO "CREATE TABLE IF NOT EXISTS package_privilege_info " \
						"(package TEXT NOT NULL, " \
						"privilege TEXT NOT NULL, " \
						"PRIMARY KEY(package, privilege) " \
						"FOREIGN KEY(package) " \
						"REFERENCES package_info(package) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_INFO "CREATE TABLE IF NOT EXISTS package_app_info " \
						"(app_id TEXT PRIMARY KEY NOT NULL, " \
						"app_component TEXT, " \
						"app_exec TEXT, " \
						"app_nodisplay TEXT NOT NULL DEFAULT 'false', " \
						"app_type TEXT, " \
						"app_onboot TEXT NOT NULL DEFAULT 'false', " \
						"app_multiple TEXT NOT NULL DEFAULT 'false', " \
						"app_autorestart TEXT NOT NULL DEFAULT 'false', " \
						"app_taskmanage TEXT NOT NULL DEFAULT 'false', " \
						"app_enabled TEXT NOT NULL DEFAULT 'true', " \
						"app_hwacceleration TEXT NOT NULL DEFAULT 'use-system-setting', " \
						"app_screenreader TEXT NOT NULL DEFAULT 'use-system-setting', " \
						"app_mainapp TEXT, " \
						"app_recentimage TEXT, " \
						"app_launchcondition TEXT, " \
						"app_indicatordisplay TEXT NOT NULL DEFAULT 'true', " \
						"app_portraitimg TEXT, " \
						"app_landscapeimg TEXT, " \
						"app_guestmodevisibility TEXT NOT NULL DEFAULT 'true', " \
						"app_permissiontype TEXT DEFAULT 'normal', " \
						"app_preload TEXT NOT NULL DEFAULT 'false', " \
						"app_submode TEXT NOT NULL DEFAULT 'false', " \
						"app_submode_mainid TEXT, " \
						"app_installed_storage TEXT, " \
						"app_process_pool TEXT NOT NULL DEFAULT 'false', " \
						"app_launch_mode TEXT NOT NULL DEFAULT 'caller', " \
						"app_ui_gadget TEXT NOT NULL DEFAULT 'false', " \
						"app_support_disable TEXT NOT NULL DEFAULT 'false', " \
						"app_disable TEXT NOT NULL DEFAULT 'false', " \
						"app_package_type TEXT DEFAULT 'tpk', " \
						"component_type TEXT, " \
						"package TEXT NOT NULL, " \
						"app_tep_name TEXT, " \
						"app_zip_mount_file TEXT, " \
						"app_background_category INTEGER DEFAULT 0, " \
						"app_root_path TEXT, " \
						"app_api_version TEXT, " \
						"app_effective_appid TEXT, " \
						"app_splash_screen_display TEXT NOT NULL DEFAULT 'true', " \
						"FOREIGN KEY(package) " \
						"REFERENCES package_info(package) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_LOCALIZED_INFO "CREATE TABLE IF NOT EXISTS package_app_localized_info " \
						"(app_id TEXT NOT NULL, " \
						"app_locale TEXT NOT NULL DEFAULT 'No Locale', " \
						"app_label TEXT, " \
						"app_icon TEXT, " \
						"PRIMARY KEY(app_id,app_locale) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_ICON_SECTION_INFO "CREATE TABLE IF NOT EXISTS package_app_icon_section_info " \
						"(app_id TEXT NOT NULL, " \
						"app_icon TEXT, " \
						"app_icon_section TEXT NOT NULL, " \
						"app_icon_resolution TEXT NOT NULL, " \
						"PRIMARY KEY(app_id,app_icon_section,app_icon_resolution) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_IMAGE_INFO "CREATE TABLE IF NOT EXISTS package_app_image_info " \
						"(app_id TEXT NOT NULL, " \
						"app_locale TEXT DEFAULT 'No Locale', " \
						"app_image_section TEXT NOT NULL, " \
						"app_image TEXT, " \
						"PRIMARY KEY(app_id,app_image_section) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_APP_CONTROL "CREATE TABLE IF NOT EXISTS package_app_app_control " \
						"(app_id TEXT NOT NULL, " \
						"app_control TEXT NOT NULL, " \
						"PRIMARY KEY(app_id,app_control) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_APP_CATEGORY "CREATE TABLE IF NOT EXISTS package_app_app_category " \
						"(app_id TEXT NOT NULL, " \
						"category TEXT NOT NULL, " \
						"PRIMARY KEY(app_id,category) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_APP_METADATA "CREATE TABLE IF NOT EXISTS package_app_app_metadata " \
						"(app_id TEXT NOT NULL, " \
						"md_key TEXT NOT NULL, " \
						"md_value TEXT, " \
						"PRIMARY KEY(app_id, md_key) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_APP_PERMISSION "CREATE TABLE IF NOT EXISTS package_app_app_permission " \
						"(app_id TEXT NOT NULL, " \
						"pm_type TEXT NOT NULL, " \
						"pm_value TEXT NOT NULL, " \
						"PRIMARY KEY(app_id, pm_type, pm_value) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_SHARE_ALLOWED "CREATE TABLE IF NOT EXISTS package_app_share_allowed " \
						"(app_id TEXT NOT NULL, " \
						"data_share_path TEXT NOT NULL, " \
						"data_share_allowed TEXT NOT NULL, " \
						"PRIMARY KEY(app_id,data_share_path,data_share_allowed) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_SHARE_REQUEST "CREATE TABLE IF NOT EXISTS package_app_share_request " \
						"(app_id TEXT NOT NULL, " \
						"data_share_request TEXT NOT NULL, " \
						"PRIMARY KEY(app_id,data_share_request) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_DATA_CONTROL "CREATE TABLE IF NOT EXISTS package_app_data_control " \
						"(app_id TEXT NOT NULL, " \
						"providerid TEXT NOT NULL, " \
						"access TEXT NOT NULL, " \
						"type TEXT NOT NULL, " \
						"PRIMARY KEY(app_id, providerid, access, type) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_INFO_FOR_UID "CREATE TABLE IF NOT EXISTS package_app_info_for_uid " \
						"(app_id TEXT NOT NULL, " \
						"uid INTEGER NOT NULL, " \
						"is_disabled TEXT NOT NULL DEFAULT 'false', " \
						"is_splash_screen_enabled TEXT NOT NULL, " \
						"PRIMARY KEY(app_id, uid))"

#define QUERY_CREATE_TRIGGER_UPDATE_PACKAGE_APP_INFO_FOR_UID \
						"CREATE TRIGGER IF NOT EXISTS update_package_appinfo_for_uid "\
						"AFTER UPDATE ON package_app_info_for_uid " \
						"BEGIN" \
						" DELETE FROM package_app_info_for_uid WHERE " \
						"	is_splash_screen_enabled=" \
						"	(SELECT package_app_info.app_splash_screen_display FROM " \
						"	package_app_info, package_app_info_for_uid WHERE " \
						"	package_app_info.app_id=OLD.app_id) AND is_disabled='false';" \
						"END;"

#define QUERY_CREATE_TABLE_PACKAGE_APP_SPLASH_SCREEN \
						"CREATE TABLE IF NOT EXISTS package_app_splash_screen " \
						"(app_id TEXT NOT NULL, " \
						"src TEXT NOT NULL, " \
						"type TEXT NOT NULL, " \
						"orientation TEXT NOT NULL, " \
						"indicatordisplay TEXT, " \
						"operation TEXT, " \
						"color_depth TEXT NOT NULL DEFAULT '24', " \
						"PRIMARY KEY(app_id, orientation) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"


/* FIXME: duplicated at pkgmgrinfo_db.c */
#define QUERY_CREATE_TABLE_PACKAGE_CERT_INDEX_INFO \
						"CREATE TABLE IF NOT EXISTS package_cert_index_info( " \
						" cert_info TEXT UNIQUE, " \
						" cert_id INTEGER PRIMARY KEY, " \
						" cert_ref_count INTEGER NOT NULL)"

#define QUERY_CREATE_TABLE_PACKAGE_CERT_INFO \
						"CREATE TABLE IF NOT EXISTS package_cert_info( " \
						" package TEXT PRIMARY KEY, " \
						" author_root_cert INTEGER, " \
						" author_im_cert INTEGER, " \
						" author_signer_cert INTEGER, " \
						" dist_root_cert INTEGER, " \
						" dist_im_cert INTEGER, " \
						" dist_signer_cert INTEGER, " \
						" dist2_root_cert INTEGER, " \
						" dist2_im_cert INTEGER, " \
						" dist2_signer_cert INTEGER)"

#define QUERY_CREATE_TRIGGER_DELETE_CERT_INFO \
						"CREATE TRIGGER IF NOT EXISTS delete_cert_info " \
						"AFTER DELETE ON package_cert_info " \
						"BEGIN" \
						" UPDATE package_cert_index_info SET" \
						"  cert_ref_count = cert_ref_count - 1" \
						" WHERE cert_id = OLD.author_root_cert" \
						"  OR cert_id = OLD.author_im_cert" \
						"  OR cert_id = OLD.author_signer_cert" \
						"  OR cert_id = OLD.dist_root_cert" \
						"  OR cert_id = OLD.dist_im_cert" \
						"  OR cert_id = OLD.dist_signer_cert" \
						"  OR cert_id = OLD.dist2_root_cert" \
						"  OR cert_id = OLD.dist2_im_cert" \
						"  OR cert_id = OLD.dist2_signer_cert;" \
						"END;"

#define QUERY_CREATE_TRIGGER_UPDATE_CERT_INDEX_INFO \
						"CREATE TRIGGER IF NOT EXISTS update_cert_index_info " \
						"AFTER UPDATE ON package_cert_index_info " \
						"WHEN ((SELECT cert_ref_count FROM package_cert_index_info " \
						"       WHERE cert_id = OLD.cert_id) = 0) "\
						"BEGIN" \
						" DELETE FROM package_cert_index_info WHERE cert_id = OLD.cert_id;" \
						"END;"

#define QUERY_CREATE_TRIGGER_UPDATE_CERT_INFO_FORMAT \
						"CREATE TRIGGER IF NOT EXISTS update_%s_info " \
						"AFTER UPDATE ON package_cert_info " \
						"WHEN (OLD.%s IS NOT NULL) " \
						"BEGIN" \
						" UPDATE package_cert_index_info SET" \
						"  cert_ref_count = cert_ref_count - 1" \
						" WHERE cert_id = OLD.%s;" \
						"END;"

static int __insert_application_info(manifest_x *mfx);
static int __insert_application_appcategory_info(manifest_x *mfx);
static int __insert_application_appcontrol_info(manifest_x *mfx);
static int __insert_application_appmetadata_info(manifest_x *mfx);
static int __insert_application_share_allowed_info(manifest_x *mfx);
static int __insert_application_share_request_info(manifest_x *mfx);
static int __insert_application_datacontrol_info(manifest_x *mfx);
static void __insert_application_locale_info(gpointer data, gpointer userdata);
static void __insert_pkglocale_info(gpointer data, gpointer userdata);
static int __insert_manifest_info_in_db(manifest_x *mfx, uid_t uid);
static int __delete_manifest_info_from_db(manifest_x *mfx, uid_t uid);
static int __delete_subpkg_info_from_db(char *appid);
static int __delete_appinfo_from_db(char *db_table, const char *appid);
static int __initialize_db(sqlite3 *db_handle, const char *db_query);
static int __exec_query(char *query);
static void __extract_data(gpointer data, GList *lbl, GList *lcn, GList *icn, GList *dcn, GList *ath,
		char **label, char **license, char **icon, char **description, char **author);
static gint __comparefunc(gconstpointer a, gconstpointer b, gpointer userdata);
static GList *__create_locale_list(GList *locale, GList *lbl, GList *lcn, GList *icn, GList *dcn, GList *ath);
static void __preserve_guestmode_visibility_value(manifest_x *mfx);
static int __guestmode_visibility_cb(void *data, int ncols, char **coltxt, char **colname);
static int __pkgmgr_parser_create_db(sqlite3 **db_handle, const char *db_path);
static int __parserdb_change_perm(const char *db_file, uid_t uid);

#define REGULAR_USER 5000
static inline uid_t _getuid(void)
{
	uid_t uid = getuid();

	if (uid < REGULAR_USER)
		return tzplatform_getuid(TZ_SYS_GLOBALAPP_USER);
	else
		return uid;
}

static int __delete_subpkg_list_cb(void *data, int ncols, char **coltxt, char **colname)
{
	if (coltxt[0])
		__delete_subpkg_info_from_db(coltxt[0]);

	return 0;
}

static int __pkgmgr_parser_create_db(sqlite3 **db_handle, const char *db_path)
{
	int ret = -1;
	sqlite3 *handle;
	char *query = NULL;
	char *error_message = NULL;

	ret = db_util_open(db_path, &handle,  DB_UTIL_REGISTER_HOOK_METHOD);
	if (ret != SQLITE_OK) {
		_LOGD("connect db [%s] failed!\n", db_path);
		return -1;
	}
	*db_handle = handle;

	/* add user_version for db upgrade*/
	query = sqlite3_mprintf("PRAGMA user_version=%d", (atoi(TIZEN_MAJOR_VER) * 10000 + atoi(TIZEN_MINOR_VER) * 100 + atoi(TIZEN_PATCH_VER)));
	if (SQLITE_OK !=
	    sqlite3_exec(handle, query, NULL, NULL, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
	}
	sqlite3_free(error_message);
	sqlite3_free(query);

	return 0;
}

static int __guestmode_visibility_cb(void *data, int ncols, char **coltxt, char **colname)
{
	manifest_x *mfx = (manifest_x *)data;
	int i = 0;
	char *appid = NULL;
	char *status = NULL;
	application_x *app;
	GList *tmp;
	if (mfx->application == NULL)
		return -1;
	app = (application_x *)mfx->application->data;
	for(i = 0; i < ncols; i++)
	{
		if (strcmp(colname[i], "app_id") == 0) {
			if (coltxt[i])
				appid = strdup(coltxt[i]);
		} else if (strcmp(colname[i], "app_guestmodevisibility") == 0) {
			if (coltxt[i])
				status = strdup(coltxt[i]);
		}
	}
	if (appid == NULL) {
		if(status != NULL)
			free(status);
		_LOGD("app id is NULL\n");
		return -1;
	}
	/*update guest mode visibility*/
	for (tmp = mfx->application; tmp; tmp = tmp->next) {
		app = (application_x *)tmp->data;
		if (app == NULL)
			continue;
		if (strcmp(app->appid, appid) == 0) {
			free((void *)app->guestmode_visibility);
			app->guestmode_visibility = strdup(status);
			break;
		}
	}
	if (appid) {
		free(appid);
		appid = NULL;
	}
	if (status) {
		free(status);
		status = NULL;
	}

	return 0;
}

static void __preserve_guestmode_visibility_value(manifest_x *mfx)
{
	char *error_message = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};
	sqlite3_snprintf(MAX_QUERY_LEN, query,
			"SELECT app_id, app_guestmodevisibility FROM package_app_info " \
			"WHERE package=%Q", mfx->package);
	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_parser_db, query,
			 __guestmode_visibility_cb, (void *)mfx, &error_message)) {
		_LOGD("Don't execute query = %s error message = %s\n",
		       query, error_message);
		sqlite3_free(error_message);
	}
	return;
}

static int __initialize_db(sqlite3 *db_handle, const char *db_query)
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(db_handle, db_query,
			 NULL, NULL, &error_message)) {
		_LOGD("Don't execute query = %s error message = %s\n",
		       db_query, error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __exec_query(char *query)
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_parser_db, query, NULL, NULL, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __exec_query_no_msg(char *query)
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_parser_db, query, NULL, NULL, &error_message)) {
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static GList *__create_locale_list(GList *locale, GList *lbls, GList *lcns, GList *icns, GList *dcns, GList *aths)
{
	GList *tmp;
	label_x *lbl;
	license_x *lcn;
	icon_x *icn;
	description_x *dcn;
	author_x *ath;
	for (tmp = lbls; tmp; tmp = tmp->next) {
		lbl = (label_x *)tmp->data;
		if (lbl == NULL)
			continue;
		if (lbl->lang)
			locale = g_list_insert_sorted_with_data(locale, (gpointer)lbl->lang, __comparefunc, NULL);
	}
	for (tmp = lcns; tmp; tmp = tmp->next) {
		lcn = (license_x *)tmp->data;
		if (lcn == NULL)
			continue;
		if (lcn->lang)
			locale = g_list_insert_sorted_with_data(locale, (gpointer)lcn->lang, __comparefunc, NULL);
	}
	for (tmp = icns; tmp; tmp = tmp->next) {
		icn = (icon_x *)tmp->data;
		if (icn == NULL)
			continue;
		if (icn->lang)
			locale = g_list_insert_sorted_with_data(locale, (gpointer)icn->lang, __comparefunc, NULL);
	}
	for (tmp = dcns; tmp; tmp = tmp->next) {
		dcn = (description_x *)tmp->data;
		if (dcn == NULL)
			continue;
		if (dcn->lang)
			locale = g_list_insert_sorted_with_data(locale, (gpointer)dcn->lang, __comparefunc, NULL);
	}
	for (tmp = aths; tmp; tmp = tmp->next) {
		ath = (author_x *)tmp->data;
		if (ath == NULL)
			continue;
		if (ath->lang)
			locale = g_list_insert_sorted_with_data(locale, (gpointer)ath->lang, __comparefunc, NULL);
	}
	return locale;

}

static GList *__create_icon_list(GList *appicon, GList *icns)
{
	GList *tmp;
	icon_x *icn;

	for (tmp = icns; tmp; tmp = tmp->next) {
		icn = (icon_x *)tmp->data;
		if (icn == NULL)
			continue;
		if (icn->section)
			appicon = g_list_insert_sorted_with_data(appicon, (gpointer)icn->section, __comparefunc, NULL);
	}
	return appicon;
}

static GList *__create_image_list(GList *appimage, GList *imgs)
{
	GList *tmp;
	image_x *img;

	for (tmp = imgs; tmp; tmp = tmp->next) {
		img = (image_x *)tmp->data;
		if (img == NULL)
			continue;
		if (img->section)
			appimage = g_list_insert_sorted_with_data(appimage, (gpointer)img->section, __comparefunc, NULL);
	}
	return appimage;
}

static void __trimfunc(GList* trim_list)
{
	char *trim_data = NULL;
	char *prev = NULL;

	GList *list = NULL;
	list = g_list_first(trim_list);

	while (list) {
		trim_data = (char *)list->data;
		if (trim_data) {
			if (prev) {
				if (strcmp(trim_data, prev) == 0) {
					trim_list = g_list_remove(trim_list, trim_data);
					list = g_list_first(trim_list);
					prev = NULL;
					continue;
				} else
					prev = trim_data;
			}
			else
				prev = trim_data;
		}
		list = g_list_next(list);
	}
}

static gint __comparefunc(gconstpointer a, gconstpointer b, gpointer userdata)
{
	if (a == NULL || b == NULL)
		return 0;
	if (strcmp((char*)a, (char*)b) == 0)
		return 0;
	if (strcmp((char*)a, (char*)b) < 0)
		return -1;
	if (strcmp((char*)a, (char*)b) > 0)
		return 1;
	return 0;
}

static int __check_dpi(const char *dpi_char, int dpi_int)
{
	if (dpi_char == NULL)
		return -1;

	if (strcasecmp(dpi_char, LDPI) == 0) {
		if (dpi_int >= LDPI_MIN && dpi_int <= LDPI_MAX)
			return 0;
		else
			return -1;
	} else if (strcasecmp(dpi_char, MDPI) == 0) {
		if (dpi_int >= MDPI_MIN && dpi_int <= MDPI_MAX)
			return 0;
		else
			return -1;
	} else if (strcasecmp(dpi_char, HDPI) == 0) {
		if (dpi_int >= HDPI_MIN && dpi_int <= HDPI_MAX)
			return 0;
		else
			return -1;
	} else if (strcasecmp(dpi_char, XHDPI) == 0) {
		if (dpi_int >= XHDPI_MIN && dpi_int <= XHDPI_MAX)
			return 0;
		else
			return -1;
	} else if (strcasecmp(dpi_char, XXHDPI) == 0) {
		if (dpi_int >= XXHDPI_MIN && dpi_int <= XXHDPI_MAX)
			return 0;
		else
			return -1;
	} else
		return -1;
}

static gint __check_icon_folder(const char *orig_icon_path, char **new_icon_path)
{
	char *dpi_path[2];
	char *icon_filename = NULL;
	char modified_iconpath[BUFSIZE] = { '\0' };
	char icon_path[BUFSIZE] = { '\0' };
	int i;
	int dpi = -1;

	if (orig_icon_path == NULL)
		return -1;

	system_info_get_platform_int("http://tizen.org/feature/screen.dpi", &dpi);
	if (!dpi)
		return -1;

	if (dpi >= LDPI_MIN && dpi <= LDPI_MAX) {
		dpi_path[0] = "LDPI";
		dpi_path[1] = "ldpi";
	} else if (dpi >= MDPI_MIN && dpi <= MDPI_MAX) {
		dpi_path[0] = "MDPI";
		dpi_path[1] = "mdpi";
	} else if (dpi >= HDPI_MIN && dpi <= HDPI_MAX) {
		dpi_path[0] = "HDPI";
		dpi_path[1] = "hdpi";
	} else if (dpi >= XHDPI_MIN && dpi <= XHDPI_MAX) {
		dpi_path[0] = "XHDPI";
		dpi_path[1] = "xhdpi";
	} else if (dpi >= XXHDPI_MIN && dpi <= XXHDPI_MAX) {
		dpi_path[0] = "XXHDPI";
		dpi_path[1] = "xxhdpi";
	} else {
		_LOGE("Unidentified dpi[%d]", dpi);
		return -1;
	}

	icon_filename = strrchr(orig_icon_path, '/');
	if (icon_filename == NULL)
		return -1;

	snprintf(icon_path, strlen(orig_icon_path) - (strlen(icon_filename) - 1), "%s", orig_icon_path);
	for (i = 0; i < 2; i++) {
		snprintf(modified_iconpath, BUFSIZE - 1, "%s/%s%s", icon_path, dpi_path[i], icon_filename);
		if (access(modified_iconpath, F_OK) != -1) {
			// if exists, return modified icon path
			*new_icon_path = strdup(modified_iconpath);
			return 0;
		}
	}

	return -1;
}

static gint __compare_icon(gconstpointer a, gconstpointer b)
{
	icon_x *icon = (icon_x *)a;

	char *icon_folder_path = NULL;

	if (icon->lang != NULL && strcasecmp(icon->lang, DEFAULT_LOCALE) != 0)
		return -1;

	if (icon->dpi != NULL)
		return -1;

	if (__check_icon_folder(icon->text, &icon_folder_path) == 0) {
		free(icon->text);
		icon->text = icon_folder_path;
	}

	return 0;
}

static gint __compare_icon_with_dpi(gconstpointer a, gconstpointer b)
{
	icon_x *icon = (icon_x *)a;
	int dpi = GPOINTER_TO_INT(b);

	if (icon->lang != NULL && strcasecmp(icon->lang, DEFAULT_LOCALE) != 0)
		return -1;

	if (icon->dpi == NULL)
		return -1;

	if (__check_dpi(icon->dpi, dpi) == 0)
		return 0;

	return -1;
}

static gint __compare_icon_with_lang(gconstpointer a, gconstpointer b)
{
	icon_x *icon = (icon_x *)a;
	char *lang = (char *)b;
	char *icon_folder_path = NULL;

	if (icon->dpi != NULL)
		return -1;

	if (strcasecmp(icon->lang, lang) == 0) {
		if (strcasecmp(icon->lang, DEFAULT_LOCALE) == 0) {
			//icon for no locale. check existance of folder-hierachied default icons
			if (__check_icon_folder(icon->text, &icon_folder_path) == 0) {
				free(icon->text);
				icon->text = icon_folder_path;
			}
		}
		return 0;
	}

	return -1;
}

static gint __compare_icon_with_lang_dpi(gconstpointer a, gconstpointer b)
{
	icon_x *icon = (icon_x *)a;
	char *lang = (char *)b;
	int dpi = -1;

	system_info_get_platform_int("http://tizen.org/feature/screen.dpi", &dpi);
	if (!dpi)
		return -1;

	if (strcasecmp(icon->lang, lang) == 0 && __check_dpi(icon->dpi, dpi) == 0)
		return 0;

	return -1;
}

static char *__find_icon(GList *icons, const char *lang)
{
	GList *tmp;
	icon_x *icon = NULL;
	int dpi = 0;

	// first, find icon whose locale and dpi with given lang and system's dpi has matched
	tmp = g_list_find_custom(icons, lang, (GCompareFunc)__compare_icon_with_lang_dpi);
	if (tmp != NULL) {
		icon = (icon_x *)tmp->data;
		return (char *)icon->text;
	}

	// if first has failed, find icon whose locale has matched
	tmp = g_list_find_custom(icons, lang, (GCompareFunc)__compare_icon_with_lang);
	if (tmp != NULL) {
		icon = (icon_x *)tmp->data;
		return (char *)icon->text;
	}

	// if second has failed, find icon whose dpi has matched with system's dpi
	system_info_get_platform_int("http://tizen.org/feature/screen.dpi", &dpi);
	if (!dpi)
		return NULL;
	tmp = g_list_find_custom(icons, GINT_TO_POINTER(dpi), (GCompareFunc)__compare_icon_with_dpi);
	if (tmp != NULL) {
		icon = (icon_x *)tmp->data;
		return (char *)icon->text;
	}

	// last, find default icon marked as "No Locale"
	tmp = g_list_find_custom(icons, NULL, (GCompareFunc)__compare_icon);
	if (tmp != NULL) {
		icon = (icon_x *)tmp->data;
		return (char *)icon->text;
	}

	return NULL;
}

static void __extract_data(gpointer data, GList *lbls, GList *lcns, GList *icns, GList *dcns, GList *aths,
		char **label, char **license, char **icon, char **description, char **author)
{
	GList *tmp;
	label_x *lbl;
	license_x *lcn;
	description_x *dcn;
	author_x *ath;
	for (tmp = lbls; tmp; tmp = tmp->next) {
		lbl = (label_x *)tmp->data;
		if (lbl == NULL)
			continue;
		if (lbl->lang) {
			if (strcmp(lbl->lang, (char *)data) == 0) {
				*label = (char*)lbl->text;
				break;
			}
		}
	}
	for (tmp = lcns; tmp; tmp = tmp->next) {
		lcn = (license_x *)tmp->data;
		if (lcn == NULL)
			continue;
		if (lcn->lang) {
			if (strcmp(lcn->lang, (char *)data) == 0) {
				*license = (char*)lcn->text;
				break;
			}
		}
	}

	*icon = __find_icon(icns, (char *)data);

	for (tmp = dcns; tmp; tmp = tmp->next) {
		dcn = (description_x *)tmp->data;
		if (dcn == NULL)
			continue;
		if (dcn->lang) {
			if (strcmp(dcn->lang, (char *)data) == 0) {
				*description = (char*)dcn->text;
				break;
			}
		}
	}
	for (tmp = aths; tmp; tmp = tmp->next) {
		ath = (author_x *)tmp->data;
		if (ath == NULL)
			continue;
		if (ath->lang) {
			if (strcmp(ath->lang, (char *)data) == 0) {
				*author = (char*)ath->text;
				break;
			}
		}
	}

}

static void __extract_icon_data(gpointer data, GList *icns, char **icon, char **resolution)
{
	GList *tmp;
	icon_x *icn;
	for (tmp = icns; tmp; tmp = tmp->next) {
		icn = (icon_x *)tmp->data;
		if (icn == NULL)
			continue;
		if (icn->section) {
			if (strcmp(icn->section, (char *)data) == 0) {
				*icon = (char*)icn->text;
				*resolution = (char*)icn->resolution;
				break;
			}
		}
	}
}

static void __extract_image_data(gpointer data, GList *imgs, char **lang, char **image)
{
	GList *tmp;
	image_x *img;
	for (tmp = imgs; tmp; tmp = tmp->next) {
		img = (image_x *)tmp->data;
		if (img == NULL)
			continue;
		if (img->section) {
			if (strcmp(img->section, (char *)data) == 0) {
				*lang = (char*)img->lang;
				*image = (char*)img->text;
				break;
			}
		}
	}
}

static void __insert_pkglocale_info(gpointer data, gpointer userdata)
{
	int ret = -1;
	char *label = NULL;
	char *icon = NULL;
	char *description = NULL;
	char *license = NULL;
	char *author = NULL;
	char *query = NULL;

	manifest_x *mfx = (manifest_x *)userdata;
	GList *lbl = mfx->label;
	GList *lcn = mfx->license;
	GList *icn = mfx->icon;
	GList *dcn = mfx->description;
	GList *ath = mfx->author;

	__extract_data(data, lbl, lcn, icn, dcn, ath, &label, &license, &icon, &description, &author);
	if (!label && !description && !icon && !license && !author)
		return;

	query = sqlite3_mprintf("INSERT INTO package_localized_info(package, package_locale, " \
		"package_label, package_icon, package_description, package_license, package_author) VALUES" \
		"(%Q, %Q, %Q, %Q, %Q, %Q, %Q)",
		mfx->package,
		(char*)data,
		label,
		icon,
		description,
		license,
		author);

	ret = __exec_query(query);
	if (ret == -1)
		_LOGD("Package Localized Info DB Insert failed\n");

	sqlite3_free(query);
}

static void __insert_application_locale_info(gpointer data, gpointer userdata)
{
	int ret = -1;
	char *label = NULL;
	char *icon = NULL;
	char *query = NULL;

	application_x *app = (application_x*)userdata;
	GList *lbl = app->label;
	GList *icn = app->icon;

	__extract_data(data, lbl, NULL, icn, NULL, NULL, &label, NULL, &icon, NULL, NULL);
	if (!label && !icon)
		return;

	query = sqlite3_mprintf("INSERT INTO package_app_localized_info(app_id, app_locale, " \
		"app_label, app_icon) VALUES" \
		"(%Q, %Q, %Q, %Q)", app->appid, (char*)data,
		label, icon);
	ret = __exec_query(query);
	if (ret == -1)
		_LOGD("Package UiApp Localized Info DB Insert failed\n");

	sqlite3_free(query);

	/*insert ui app locale info to pkg locale to get mainapp data */
	if (strcasecmp(app->mainapp, "true")==0) {
		query = sqlite3_mprintf("INSERT INTO package_localized_info(package, package_locale, " \
			"package_label, package_icon, package_description, package_license, package_author) VALUES" \
			"(%Q, %Q, %Q, %Q, %Q, %Q, %Q)",
			app->package,
			(char*)data,
			label,
			icon,
			NULL,
			NULL,
			NULL);

		ret = __exec_query_no_msg(query);
		sqlite3_free(query);

		if (icon != NULL) {
			query = sqlite3_mprintf("UPDATE package_localized_info SET package_icon=%Q "\
				"WHERE package=%Q AND package_locale=%Q", icon, app->package, (char*)data);
			ret = __exec_query_no_msg(query);
			sqlite3_free(query);
		}
	}
}

static void __insert_application_icon_section_info(gpointer data, gpointer userdata)
{
	int ret = -1;
	char *icon = NULL;
	char *resolution = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};

	application_x *app = (application_x*)userdata;
	GList *icn = app->icon;

	__extract_icon_data(data, icn, &icon, &resolution);
	if (!icon && !resolution)
		return;
	sqlite3_snprintf(MAX_QUERY_LEN, query, "INSERT INTO package_app_icon_section_info(app_id, " \
		"app_icon, app_icon_section, app_icon_resolution) VALUES " \
		"(%Q, %Q, %Q, %Q)", app->appid,
		icon, (char*)data, resolution);

	ret = __exec_query(query);
	if (ret == -1)
		_LOGD("Package UiApp Localized Info DB Insert failed\n");

}

static void __insert_application_image_info(gpointer data, gpointer userdata)
{
	int ret = -1;
	char *lang = NULL;
	char *img = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};

	application_x *app = (application_x*)userdata;
	GList *image = app->image;

	__extract_image_data(data, image, &lang, &img);
	if (!lang && !img)
		return;
	sqlite3_snprintf(MAX_QUERY_LEN, query,
		"INSERT INTO package_app_image_info(app_id, app_locale, " \
		"app_image_section, app_image) VALUES" \
		"(%Q, %Q, %Q, %Q)", app->appid, lang, (char*)data, img);

	ret = __exec_query(query);
	if (ret == -1)
		_LOGD("Package UiApp image Info DB Insert failed\n");

}


static int __insert_mainapp_info(manifest_x *mfx)
{
	GList *tmp;
	application_x *app;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	for (tmp = mfx->application; tmp; tmp = tmp->next) {
		app = (application_x *)tmp->data;
		if (app == NULL)
			continue;

		sqlite3_snprintf(MAX_QUERY_LEN, query,
				"UPDATE package_app_info SET app_mainapp=%Q WHERE app_id=%Q",
				app->mainapp, app->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			_LOGD("Package App Info DB Insert Failed\n");
			return -1;
		}
		if (strcasecmp(app->mainapp, "True")==0)
			mfx->mainapp_id = strdup(app->appid);
	}

	if (mfx->mainapp_id == NULL) {
		if (mfx->application == NULL)
			return -1;
		app = (application_x *)mfx->application->data;
		if (app == NULL)
			return -1;
		if (app->appid) {
			sqlite3_snprintf(MAX_QUERY_LEN, query,
					"UPDATE package_app_info SET app_mainapp='true' WHERE app_id=%Q",
					app->appid);
		} else {
			_LOGD("Not valid appid\n");
			return -1;
		}

		ret = __exec_query(query);
		if (ret == -1) {
			_LOGD("Package UiApp Info DB Insert Failed\n");
			return -1;
		}

		free((void *)app->mainapp);
		app->mainapp= strdup("true");
		mfx->mainapp_id = strdup(app->appid);
	}

	memset(query, '\0', MAX_QUERY_LEN);
	sqlite3_snprintf(MAX_QUERY_LEN, query,
			"UPDATE package_info SET mainapp_id=%Q WHERE package=%Q", mfx->mainapp_id, mfx->package);
	ret = __exec_query(query);
	if (ret == -1) {
		_LOGD("Package Info DB update Failed\n");
		return -1;
	}

	return 0;
}

static int __convert_background_category(GList *category_list)
{
	int ret = 0;
	GList *tmp_list = category_list;
	char *category_data = NULL;

	if (category_list == NULL)
		return 0;

	while (tmp_list != NULL) {
		category_data = (char *)tmp_list->data;
		if (strcmp(category_data, APP_BG_CATEGORY_MEDIA_STR) == 0) {
			ret = ret | APP_BG_CATEGORY_MEDIA_VAL;
		} else if (strcmp(category_data, APP_BG_CATEGORY_DOWNLOAD_STR) == 0) {
			ret = ret | APP_BG_CATEGORY_DOWNLOAD_VAL;
		} else if (strcmp(category_data, APP_BG_CATEGORY_BGNETWORK_STR) == 0) {
			ret = ret | APP_BG_CATEGORY_BGNETWORK_VAL;
		} else if (strcmp(category_data, APP_BG_CATEGORY_LOCATION_STR) == 0) {
			ret = ret | APP_BG_CATEGORY_LOCATION_VAL;
		} else if (strcmp(category_data, APP_BG_CATEGORY_SENSOR_STR) == 0) {
			ret = ret | APP_BG_CATEGORY_SENSOR_VAL;
		} else if (strcmp(category_data, APP_BG_CATEGORY_IOTCOMM_STR) == 0) {
			ret = ret | APP_BG_CATEGORY_IOTCOMM_VAL;
		} else if (strcmp(category_data, APP_BG_CATEGORY_SYSTEM) == 0) {
			ret = ret | APP_BG_CATEGORY_SYSTEM_VAL;
		} else {
			_LOGE("Unidentified category [%s]", category_data);
		}
		tmp_list = g_list_next(tmp_list);
	}

	return ret;
}

static const char *__find_effective_appid(GList *metadata_list)
{
	GList *tmp_list;
	metadata_x *md;

	for (tmp_list = metadata_list; tmp_list; tmp_list = tmp_list->next) {
		md = (metadata_x *)tmp_list->data;
		if (md == NULL || md->key == NULL)
			continue;

		if (strcmp(md->key, "http://tizen.org/metadata/effective-appid") == 0) {
			if (md->value)
				return md->value;
		}
	}

	return NULL;
}

static char *__get_bool(char *value, bool is_true)
{
	if (value != NULL)
		return value;

	return (is_true) ? "true" : "false";
}

/* _PRODUCT_LAUNCHING_ENHANCED_
*  app->indicatordisplay, app->portraitimg, app->landscapeimg, app->guestmode_appstatus
*/
static int __insert_application_info(manifest_x *mfx)
{
	GList *tmp;
	application_x *app;
	int ret = -1;
	int background_value = 0;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *type = NULL;
	const char *effective_appid;

	if (mfx->type)
		type = strdup(mfx->type);
	else
		type = strdup("tpk");

	for (tmp = mfx->application; tmp; tmp = tmp->next) {
		app = (application_x *)tmp->data;
		if (app == NULL)
			continue;

		background_value = __convert_background_category(app->background_category);
		if (background_value < 0) {
			_LOGE("Failed to retrieve background value[%d]", background_value);
			background_value = 0;
		}

		effective_appid = __find_effective_appid(app->metadata);

		sqlite3_snprintf(MAX_QUERY_LEN, query,
			"INSERT INTO package_app_info(" \
			"app_id, app_component, app_exec, app_nodisplay, app_type, " \
			"app_onboot, app_multiple, app_autorestart, app_taskmanage, app_enabled, " \
			"app_hwacceleration, app_screenreader, app_mainapp, app_recentimage, app_launchcondition, " \
			"app_indicatordisplay, app_portraitimg, app_landscapeimg, app_guestmodevisibility, app_permissiontype, " \
			"app_preload, app_submode, app_submode_mainid, app_installed_storage, app_process_pool, " \
			"app_launch_mode, app_ui_gadget, app_support_disable, component_type, package, " \
			"app_tep_name, app_zip_mount_file, app_background_category, app_package_type, app_root_path, " \
			"app_api_version, app_effective_appid, app_splash_screen_display) " \
			"VALUES(" \
			"%Q, %Q, %Q, LOWER(%Q), %Q, " \
			"LOWER(%Q), LOWER(%Q), LOWER(%Q), LOWER(%Q), LOWER(%Q), " \
			"%Q, %Q, %Q, %Q, %Q, " \
			"LOWER(%Q), %Q, %Q, LOWER(%Q), %Q, " \
			"LOWER(%Q), LOWER(%Q), %Q, %Q, LOWER(%Q), " \
			"COALESCE(%Q, 'caller'), LOWER(%Q), LOWER(%Q), %Q, %Q, " \
			"%Q, %Q, %d, %Q, %Q, " \
			"%Q, %Q, LOWER(%Q))", \
			app->appid, app->component_type, app->exec, __get_bool(app->nodisplay, false), app->type,
			__get_bool(app->onboot, false), __get_bool(app->multiple, false), __get_bool(app->autorestart, false), __get_bool(app->taskmanage, false), __get_bool(app->enabled, true),
			app->hwacceleration, app->screenreader, app->mainapp, app->recentimage, app->launchcondition,
			__get_bool(app->indicatordisplay, true), app->portraitimg, app->landscapeimg,
			__get_bool(app->guestmode_visibility, true), app->permission_type,
			__get_bool(mfx->preload, false), __get_bool(app->submode, false), app->submode_mainid, mfx->installed_storage, __get_bool(app->process_pool, false),
			app->launch_mode, __get_bool(app->ui_gadget, false), __get_bool(mfx->support_disable, false), app->component_type, mfx->package,
			mfx->tep_name, mfx->zip_mount_file, background_value, type, mfx->root_path, mfx->api_version,
			effective_appid, __get_bool(app->splash_screen_display, false));

		ret = __exec_query(query);
		if (ret == -1) {
			_LOGD("Package UiApp Info DB Insert Failed\n");
			if (type)
				free(type);
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
	}

	if (type)
		free(type);

	return 0;
}

static int __insert_application_appcategory_info(manifest_x *mfx)
{
	GList *app_tmp;
	application_x *app;
	GList *ct_tmp;
	const char *ct;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	for (app_tmp = mfx->application; app_tmp; app_tmp = app_tmp->next) {
		app = (application_x *)app_tmp->data;
		if (app == NULL)
			continue;
		for (ct_tmp = app->category; ct_tmp; ct_tmp = ct_tmp->next) {
			ct = (const char *)ct_tmp->data;
			if (ct == NULL)
				continue;
			sqlite3_snprintf(MAX_QUERY_LEN, query,
				"INSERT INTO package_app_app_category(app_id, category) " \
				"VALUES(%Q, %Q)",\
				 app->appid, ct);
			ret = __exec_query(query);
			if (ret == -1) {
				_LOGD("Package UiApp Category Info DB Insert Failed\n");
				return -1;
			}
			memset(query, '\0', MAX_QUERY_LEN);
		}
	}
	return 0;
}

static int __insert_application_appmetadata_info(manifest_x *mfx)
{
	GList *app_tmp;
	application_x *app;
	GList *md_tmp;
	metadata_x *md;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	for (app_tmp = mfx->application; app_tmp; app_tmp = app_tmp->next) {
		app = (application_x *)app_tmp->data;
		if (app == NULL)
			continue;
		for (md_tmp = app->metadata; md_tmp; md_tmp = md_tmp->next) {
			md = (metadata_x *)md_tmp->data;
			if (md == NULL)
				continue;
			if (md->key) {
				sqlite3_snprintf(MAX_QUERY_LEN, query,
					"INSERT INTO package_app_app_metadata(app_id, md_key, md_value) " \
					"VALUES(%Q, %Q, %Q)",\
					 app->appid, md->key, md->value ? md->value : NULL);
				ret = __exec_query(query);
				if (ret == -1) {
					_LOGD("Package UiApp Metadata Info DB Insert Failed\n");
					return -1;
				}
			}
			memset(query, '\0', MAX_QUERY_LEN);
		}
	}
	return 0;
}

static int __insert_application_apppermission_info(manifest_x *mfx)
{
	GList *app_tmp;
	application_x *app;
	GList *pm_tmp;
	permission_x *pm;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	for (app_tmp = mfx->application; app_tmp; app_tmp = app_tmp->next) {
		app = (application_x *)app_tmp->data;
		if (app == NULL)
			continue;
		for (pm_tmp = app->permission; pm_tmp; pm_tmp = pm_tmp->next) {
			pm = (permission_x *)pm_tmp->data;
			if (pm == NULL)
				continue;
			sqlite3_snprintf(MAX_QUERY_LEN, query,
				"INSERT INTO package_app_app_permission(app_id, pm_type, pm_value) " \
				"VALUES(%Q, %Q, %Q)",\
				 app->appid, pm->type, pm->value);
			ret = __exec_query(query);
			if (ret == -1) {
				_LOGD("Package UiApp permission Info DB Insert Failed\n");
				return -1;
			}
			memset(query, '\0', MAX_QUERY_LEN);
		}
	}
	return 0;
}

static int __insert_application_appcontrol_info(manifest_x *mfx)
{
	GList *app_tmp;
	application_x *app;
	GList *acontrol_tmp;
	appcontrol_x *acontrol;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	char buf[BUFSIZE] = {'\0'};
	for (app_tmp = mfx->application; app_tmp; app_tmp = app_tmp->next) {
		app = (application_x *)app_tmp->data;
		if (app == NULL)
			continue;
		for (acontrol_tmp = app->appcontrol; acontrol_tmp; acontrol_tmp = acontrol_tmp->next) {
			acontrol = (appcontrol_x *)acontrol_tmp->data;
			if (acontrol == NULL)
				continue;
			snprintf(buf, BUFSIZE, "%s|%s|%s",\
					acontrol->operation ? (strlen(acontrol->operation) > 0 ? acontrol->operation : "NULL") : "NULL",
					acontrol->uri ? (strlen(acontrol->uri) > 0 ? acontrol->uri : "NULL") : "NULL",
					acontrol->mime ? (strlen(acontrol->mime) > 0 ? acontrol->mime : "NULL") : "NULL");
			sqlite3_snprintf(MAX_QUERY_LEN, query,
					"INSERT INTO package_app_app_control(app_id, app_control) " \
					"VALUES(%Q, %Q)",\
					app->appid, buf);
			ret = __exec_query(query);
			if (ret == -1) {
				_LOGD("Package UiApp AppSvc DB Insert Failed\n");
				return -1;
			}
			memset(query, '\0', MAX_QUERY_LEN);
		}
	}
	return 0;
}

static int __insert_application_datacontrol_info(manifest_x *mfx)
{
	GList *app_tmp;
	application_x *app;
	GList *dc_tmp;
	datacontrol_x *dc;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};

	for (app_tmp = mfx->application; app_tmp; app_tmp = app_tmp->next) {
		app = (application_x *)app_tmp->data;
		if (app == NULL)
			continue;
		for (dc_tmp = app->datacontrol; dc_tmp; dc_tmp = dc_tmp->next) {
			dc = (datacontrol_x *)dc_tmp->data;
			if (dc == NULL)
				continue;
			sqlite3_snprintf(MAX_QUERY_LEN, query,
					"INSERT INTO package_app_data_control(app_id, providerid, access, type) " \
					"VALUES(%Q, %Q, %Q, %Q)",\
					app->appid,
					dc->providerid,
					dc->access,
					dc->type);

			ret = __exec_query(query);
			if (ret == -1) {
				_LOGD("Package UiApp Data Control DB Insert Failed\n");
				return -1;
			}
			memset(query, '\0', MAX_QUERY_LEN);
		}
	}
	return 0;
}

static int __insert_application_share_request_info(manifest_x *mfx)
{
	GList *app_tmp;
	application_x *app;
	GList *ds_tmp;
	datashare_x *ds;
	GList *rq_tmp;
	const char *rq;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	for (app_tmp = mfx->application; app_tmp; app_tmp = app_tmp->next) {
		app = (application_x *)app_tmp->data;
		if (app == NULL)
			continue;
		for (ds_tmp = app->datashare; ds_tmp; ds_tmp = ds_tmp->next) {
			ds = (datashare_x *)ds_tmp->data;
			if (ds == NULL)
				continue;
			for (rq_tmp = ds->request; rq_tmp; rq_tmp = rq_tmp->next) {
				rq = (const char *)rq_tmp->data;
				if (rq == NULL)
					continue;
				sqlite3_snprintf(MAX_QUERY_LEN, query,
						"INSERT INTO package_app_share_request(app_id, data_share_request) " \
						"VALUEES(%Q, %Q)",\
					 app->appid, rq);
				ret = __exec_query(query);
				if (ret == -1) {
					_LOGD("Package UiApp Share Request DB Insert Failed\n");
					return -1;
				}
				memset(query, '\0', MAX_QUERY_LEN);
			}
		}
	}
	return 0;
}

static int __insert_application_share_allowed_info(manifest_x *mfx)
{
	GList *app_tmp;
	application_x *app;
	GList *ds_tmp;
	datashare_x *ds;
	GList *df_tmp;
	define_x *df;
	GList *al_tmp;
	const char *al;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	for (app_tmp = mfx->application; app_tmp; app_tmp = app_tmp->next) {
		app = (application_x *)app_tmp->data;
		if (app == NULL)
			continue;
		for (ds_tmp = app->datashare; ds_tmp; ds_tmp = ds_tmp->next) {
			ds = (datashare_x *)ds_tmp->data;
			if (ds == NULL)
				continue;
			for (df_tmp = ds->define; df_tmp; df_tmp = df_tmp->next) {
				df = (define_x *)df_tmp->data;
				if (df == NULL)
					continue;
				for (al_tmp = df->allowed; al_tmp; al_tmp = al_tmp->next) {
					al = (const char *)al_tmp->data;
					if (al == NULL)
						continue;
					sqlite3_snprintf(MAX_QUERY_LEN, query,
							"INSERT INTO package_app_share_allowed(app_id, data_share_path, data_share_allowed) " \
							"VALUES(%Q, %Q, %Q)",\
						 app->appid, df->path, al);
					ret = __exec_query(query);
					if (ret == -1) {
						_LOGD("Package UiApp Share Allowed DB Insert Failed\n");
						return -1;
					}
					memset(query, '\0', MAX_QUERY_LEN);
				}
			}
		}
	}
	return 0;
}

static gint __compare_splashscreen_with_orientation_dpi(gconstpointer a, gconstpointer b)
{
	splashscreen_x *ss = (splashscreen_x *)a;
	const char *orientation = (const char *)b;
	int dpi = -1;

	if (ss->operation || ss->dpi == NULL)
		return -1;

	system_info_get_platform_int("http://tizen.org/feature/screen.dpi", &dpi);
	if (!dpi)
		return -1;

	if (strcasecmp(ss->orientation, orientation) == 0 && __check_dpi(ss->dpi, dpi) == 0)
		return 0;

	return -1;
}

static gint __compare_splashscreen_with_orientation(gconstpointer a, gconstpointer b)
{
	splashscreen_x *ss = (splashscreen_x *)a;
	const char *orientation = (const char *)b;

	if (ss->operation || ss->dpi)
		return -1;

	if (strcasecmp(ss->orientation, orientation) == 0)
		return 0;

	return -1;
}

static splashscreen_x *__find_default_splashscreen(GList *splashscreens,
					const char *orientation)
{
	GList *tmp;

	tmp = g_list_find_custom(splashscreens, orientation,
			(GCompareFunc)__compare_splashscreen_with_orientation_dpi);
	if (tmp)
		return (splashscreen_x *)tmp->data;

	tmp = g_list_find_custom(splashscreens, orientation,
			(GCompareFunc)__compare_splashscreen_with_orientation);
	if (tmp)
		return (splashscreen_x *)tmp->data;

	return NULL;
}

static void __find_appcontrol_splashscreen_with_dpi(gpointer data, gpointer user_data)
{
	splashscreen_x *ss = (splashscreen_x *)data;
	GList **list = (GList **)user_data;
	int dpi = -1;

	if (ss->operation == NULL || ss->dpi == NULL)
		return;

	system_info_get_platform_int("http://tizen.org/feature/screen.dpi", &dpi);
	if (!dpi)
		return;

	if (__check_dpi(ss->dpi, dpi) != 0)
		return;

	*list = g_list_append(*list, ss);
}

static void __find_appcontrol_splashscreen(gpointer data, gpointer user_data)
{
	splashscreen_x *ss = (splashscreen_x *)data;
	GList **list = (GList **)user_data;
	splashscreen_x *ss_tmp;
	GList *tmp;

	if (ss->operation == NULL || ss->dpi)
		return;

	for (tmp = *list; tmp; tmp = tmp->next) {
		ss_tmp = (splashscreen_x *)tmp->data;
		if (ss_tmp->operation
			&& strcmp(ss_tmp->operation, ss->operation) == 0
			&& strcmp(ss_tmp->orientation, ss->orientation) == 0)
			return;
	}

	*list = g_list_append(*list, ss);
}

static GList *__find_splashscreens(GList *splashscreens)
{
	GList *list = NULL;
	splashscreen_x *ss;

	g_list_foreach(splashscreens,
			__find_appcontrol_splashscreen_with_dpi, &list);
	g_list_foreach(splashscreens,
			__find_appcontrol_splashscreen, &list);

	ss = __find_default_splashscreen(splashscreens, "portrait");
	if (ss)
		list = g_list_append(list, ss);
	ss = __find_default_splashscreen(splashscreens, "landscape");
	if (ss)
		list = g_list_append(list, ss);

	return list;
}

static int __insert_application_splashscreen_info(manifest_x *mfx)
{
	GList *app_tmp;
	application_x *app;
	GList *ss_tmp;
	splashscreen_x *ss;
	GList *tmp;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};

	for (app_tmp = mfx->application; app_tmp; app_tmp = app_tmp->next) {
		app = (application_x *)app_tmp->data;
		if (app == NULL || app->splashscreens == NULL)
			continue;

		ss_tmp = __find_splashscreens(app->splashscreens);
		if (ss_tmp == NULL)
			continue;

		for (tmp = ss_tmp; tmp; tmp = tmp->next) {
			ss = (splashscreen_x *)tmp->data;
			sqlite3_snprintf(MAX_QUERY_LEN, query,
					"INSERT INTO package_app_splash_screen" \
					"(app_id, src, type, orientation, indicatordisplay, operation, color_depth) " \
					"VALUES(%Q, %Q, %Q, %Q, %Q, %Q, %Q)",
					app->appid, ss->src, ss->type, ss->orientation,
					ss->indicatordisplay, ss->operation,
					ss->color_depth);
			ret = __exec_query(query);
			if (ret == -1) {
				_LOGD("Package UiApp Splash Screen DB Insert Failed");
				return -1;
			}
			memset(query, '\0', MAX_QUERY_LEN);
		}
		g_list_free(ss_tmp);
	}
	return 0;
}

static int __insert_application_legacy_splashscreen_info(manifest_x *mfx)
{
	GList *app_tmp;
	application_x *app;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *tmp;
	const char *image_type;
	const char *indicatordisplay;
	const char *orientation;
	const char *operation = NULL;
	const char *color_depth = "24"; /* default */

	for (app_tmp = mfx->application; app_tmp; app_tmp = app_tmp->next) {
		app = (application_x *)app_tmp->data;
		if (app == NULL ||
			(app->portraitimg == NULL && app->landscapeimg == NULL))
			continue;
		image_type = "img"; /* default */
		if (app->effectimage_type) {
			tmp = strstr(app->effectimage_type, "edj");
			if (tmp)
				image_type = "edj";
		}
		indicatordisplay = "true"; /* default */
		if (app->indicatordisplay)
			indicatordisplay = app->indicatordisplay;
		if (app->portraitimg) {
			orientation = "portrait";
			sqlite3_snprintf(MAX_QUERY_LEN, query,
					"INSERT INTO package_app_splash_screen" \
					"(app_id, src, type, orientation, indicatordisplay, operation, color_depth) " \
					"VALUES(%Q, %Q, %Q, %Q, %Q, %Q, %Q)",
					app->appid, app->portraitimg, image_type,
					orientation, indicatordisplay, operation,
					color_depth);
			ret = __exec_query(query);
			if (ret == -1) {
				_LOGD("Package UiApp Splash Screen DB Insert Failed");
				return -1;
			}
			memset(query, '\0', MAX_QUERY_LEN);
		}
		if (app->landscapeimg) {
			orientation = "landscape";
			sqlite3_snprintf(MAX_QUERY_LEN, query,
					"INSERT INTO package_app_splash_screen" \
					"(app_id, src, type, orientation, indicatordisplay, operation, color_depth) " \
					"VALUES(%Q, %Q, %Q, %Q, %Q, %Q, %Q)",
					app->appid, app->landscapeimg, image_type,
					orientation, indicatordisplay, operation,
					color_depth);
			ret = __exec_query(query);
			if (ret == -1) {
				_LOGD("Package UiApp Splash Screen DB Insert Failed");
				return -1;
			}
			memset(query, '\0', MAX_QUERY_LEN);
		}
	}
	return 0;
}

static int __insert_application_metadata_splashscreen_info(manifest_x *mfx)
{
	GList *app_tmp;
	application_x *app;
	GList *md_tmp;
	metadata_x *md;
	int ret;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *token;
	char *tmpptr = NULL;
	const char *operation;
	const char *portraitimg;
	const char *landscapeimg;
	const char *indicatordisplay;
	const char *orientation;
	const char *image_type;
	const char *color_depth = "24"; /* default */

	for (app_tmp = mfx->application; app_tmp; app_tmp = app_tmp->next) {
		app = (application_x *)app_tmp->data;
		if (app == NULL)
			continue;

		for (md_tmp = app->metadata; md_tmp; md_tmp = md_tmp->next) {
			md = (metadata_x *)md_tmp->data;
			if (md == NULL || md->key == NULL || md->value == NULL)
				continue;

			if (strcasestr(md->key, "operation_effect=")) {
				operation = index(md->key, '=');
				if (operation[1] != '\0')
					operation++;
				else
					operation = NULL;
			} else if (strcasestr(md->key, "launch_effect")) {
				operation = NULL;
			} else {
				continue;
			}

			portraitimg = NULL;
			landscapeimg = NULL;
			indicatordisplay = "true"; /* default */
			token = strtok_r(md->value, "|", &tmpptr);
			while (token != NULL) {
				if (strcasestr(token, "portrait-effectimage=")) {
					portraitimg = index(token, '=');
					if (portraitimg[1] != '\0')
						portraitimg++;
					else
						portraitimg = NULL;
				} else if (strcasestr(token, "landscape-effectimage=")) {
					landscapeimg = index(token, '=');
					if (landscapeimg[1] != '\0')
						landscapeimg++;
					else
						landscapeimg = NULL;
				} else if (strcasestr(token, "indicatordisplay=")) {
					indicatordisplay = index(token, '=');
					if (indicatordisplay[1] != '\0')
						indicatordisplay++;
					else
						indicatordisplay = "true";
				}

				token = strtok_r(NULL, "|", &tmpptr);
			}

			if (portraitimg) {
				orientation = "portrait";
				image_type = "img";
				if (strcasestr(portraitimg, "edj"))
					image_type = "edj";
				sqlite3_snprintf(MAX_QUERY_LEN, query,
					"INSERT INTO package_app_splash_screen" \
					"(app_id, src, type, orientation, indicatordisplay, operation, color_depth) " \
					"VALUES(%Q, %Q, %Q, %Q, %Q, %Q, %Q)",
					app->appid, portraitimg, image_type,
					orientation, indicatordisplay, operation,
					color_depth);
				ret = __exec_query(query);
				if (ret == -1) {
					_LOGD("Package UiApp Splash Screen DB Insert Failed");
					return -1;
				}
				memset(query, '\0', MAX_QUERY_LEN);
			}
			if (landscapeimg) {
				orientation = "landscape";
				image_type = "img";
				if (strcasestr(landscapeimg, "edj"))
					image_type = "edj";
				sqlite3_snprintf(MAX_QUERY_LEN, query,
					"INSERT INTO package_app_splash_screen" \
					"(app_id, src, type, orientation, indicatordisplay, operation, color_depth) " \
					"VALUES(%Q, %Q, %Q, %Q, %Q, %Q, %Q)",
					app->appid, landscapeimg, image_type,
					orientation, indicatordisplay, operation,
					color_depth);
				ret = __exec_query(query);
				if (ret == -1) {
					_LOGD("Package UiApp Splash Screen DB Insert Failed");
					return -1;
				}
				memset(query, '\0', MAX_QUERY_LEN);
			}
		}
	}

	return 0;
}

static int __insert_manifest_info_in_db(manifest_x *mfx, uid_t uid)
{
	GList *tmp;
	application_x *app;
	const char *pv = NULL;
	char query[MAX_QUERY_LEN] = { '\0' };
	int ret = -1;
	author_x *author;
	const char *auth_name = NULL;
	const char *auth_email = NULL;
	const char *auth_href = NULL;

	GList *pkglocale = NULL;
	GList *applocale = NULL;
	GList *appicon = NULL;
	GList *appimage = NULL;

	if (mfx->author && mfx->author->data) {
		author = (author_x *)mfx->author->data;
		if (author->text)
			auth_name = author->text;
		if (author->email)
			auth_email = author->email;
		if (author->href)
			auth_href = author->href;
	}

	/*Insert in the package_cert_info CERT_DB*/
	pkgmgrinfo_instcertinfo_h cert_handle = NULL;
	ret = pkgmgrinfo_set_cert_value(&cert_handle, PMINFO_SET_AUTHOR_ROOT_CERT, "author root certificate");
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_destroy_certinfo_set_handle(cert_handle);
		_LOGE("Cert Info DB create handle failed\n");
		return -1;
	}
	ret = pkgmgrinfo_save_certinfo(mfx->package, &cert_handle, uid);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_destroy_certinfo_set_handle(cert_handle);
		_LOGE("Cert Info DB Insert Failed\n");
		return -1;
	}

	if (ret != PMINFO_R_OK) {
		_LOGE("Failed to set default values");
		return -1;
	}

	/*Insert in the package_info DB*/
	sqlite3_snprintf(MAX_QUERY_LEN, query,
		"INSERT INTO package_info(" \
		"package, package_type, package_version, package_api_version, package_tep_name, package_zip_mount_file, " \
		"install_location, package_size, package_removable, package_preload, package_readonly, " \
		"package_update, package_appsetting, package_nodisplay, package_system, author_name, " \
		"author_email, author_href, installed_time, installed_storage, storeclient_id, " \
		"mainapp_id, package_url, root_path, csc_path, package_support_disable) " \
		"VALUES(" \
		"%Q, %Q, %Q, %Q, %Q, %Q, " \
		"%Q, %Q, LOWER(%Q), LOWER(%Q), LOWER(%Q), " \
		"LOWER(%Q), LOWER(%Q), LOWER(%Q), LOWER(%Q), %Q, " \
		"%Q, %Q, %Q, %Q, %Q, " \
		"%Q, %Q, %Q, %Q, LOWER(%Q))",
		mfx->package, mfx->type, mfx->version, mfx->api_version, mfx->tep_name, mfx->zip_mount_file,
		mfx->installlocation, mfx->package_size, __get_bool(mfx->removable, true), __get_bool(mfx->preload, false), __get_bool(mfx->readonly, false),
		__get_bool(mfx->update, false), __get_bool(mfx->appsetting, false), __get_bool(mfx->nodisplay_setting, false), __get_bool(mfx->system, false), auth_name,
		auth_email, auth_href, mfx->installed_time, mfx->installed_storage,
		mfx->storeclient_id,
		mfx->mainapp_id, mfx->package_url, mfx->root_path, mfx->csc_path, __get_bool(mfx->support_disable, false));

	ret = __exec_query(query);
	if (ret == -1) {
		_LOGD("Package Info DB Insert Failed\n");
		return -1;
	}

	/*Insert in the package_privilege_info DB*/
	for (tmp = mfx->privileges; tmp; tmp = tmp->next) {
		pv = (const char *)tmp->data;
		if (pv == NULL)
			continue;
		memset(query, '\0', MAX_QUERY_LEN);
		sqlite3_snprintf(MAX_QUERY_LEN, query,
			"INSERT INTO package_privilege_info(package, privilege) " \
			"VALUES(%Q, %Q)",\
			 mfx->package, pv);
		ret = __exec_query(query);
		if (ret == -1) {
			_LOGD("Package Privilege Info DB Insert Failed\n");
			return -1;
		}
	}

	if (mfx->application != NULL) {
		ret = __insert_mainapp_info(mfx);
		if (ret == -1)
			return -1;
	}

	/*Insert the package locale*/
	pkglocale = __create_locale_list(pkglocale, mfx->label, mfx->license, mfx->icon, mfx->description, mfx->author);
	/*remove duplicated data in pkglocale*/
	__trimfunc(pkglocale);

	/*Insert the app locale, icon, image info */
	for (tmp = mfx->application; tmp; tmp = tmp->next) {
		app = (application_x *)tmp->data;
		if (app == NULL)
			continue;
		applocale = __create_locale_list(applocale, app->label, NULL, app->icon, NULL, NULL);
		appicon = __create_icon_list(appicon, app->icon);
		appimage = __create_image_list(appimage, app->image);
	}
	/*remove duplicated data in applocale*/
	__trimfunc(applocale);
	__trimfunc(appicon);
	__trimfunc(appimage);

	g_list_foreach(pkglocale, __insert_pkglocale_info, (gpointer)mfx);

	/*native app locale info*/
	for (tmp = mfx->application; tmp; tmp = tmp->next) {
		app = (application_x *)tmp->data;
		if (app == NULL)
			continue;
		g_list_foreach(applocale, __insert_application_locale_info, (gpointer)app);
		g_list_foreach(appicon, __insert_application_icon_section_info, (gpointer)app);
		g_list_foreach(appimage, __insert_application_image_info, (gpointer)app);
	}

	g_list_free(pkglocale);
	pkglocale = NULL;
	g_list_free(applocale);
	applocale = NULL;
	g_list_free(appicon);
	appicon = NULL;
	g_list_free(appimage);
	appimage = NULL;

	/*Insert in the package_app_info DB*/
	ret = __insert_application_info(mfx);
	if (ret == -1)
		return -1;
	/*Insert in the package_app_app_control DB*/
	ret = __insert_application_appcontrol_info(mfx);
	if (ret == -1)
		return -1;

	/*Insert in the package_app_app_category DB*/
	ret = __insert_application_appcategory_info(mfx);
	if (ret == -1)
		return -1;

	/*Insert in the package_app_app_metadata DB*/
	ret = __insert_application_appmetadata_info(mfx);
	if (ret == -1)
		return -1;

	/*Insert in the package_app_app_permission DB*/
	ret = __insert_application_apppermission_info(mfx);
	if (ret == -1)
		return -1;

	/*Insert in the package_app_share_allowed DB*/
	ret = __insert_application_share_allowed_info(mfx);
	if (ret == -1)
		return -1;

	/*Insert in the package_app_share_request DB*/
	ret = __insert_application_share_request_info(mfx);
	if (ret == -1)
		return -1;

	/*Insert in the package_app_data_control DB*/
	ret = __insert_application_datacontrol_info(mfx);
	if (ret == -1)
		return -1;

	/*Insert in the package_app_splash_screen DB (backward compatibility)*/
	ret = __insert_application_legacy_splashscreen_info(mfx);
	if (ret == -1)
		return -1;

	/*Insert in the package_app_splash_screen DB (backward compatibility)*/
	ret = __insert_application_metadata_splashscreen_info(mfx);
	if (ret == -1)
		return -1;

	/*Insert in the package_app_splash_screen DB*/
	ret = __insert_application_splashscreen_info(mfx);
	if (ret == -1)
		return -1;

	return 0;

}

static int __delete_appinfo_from_db(char *db_table, const char *appid)
{
	char query[MAX_QUERY_LEN] = { '\0' };
	int ret = -1;

	sqlite3_snprintf(MAX_QUERY_LEN, query,
		 "DELETE FROM %q where app_id=%Q", db_table, appid);
	ret = __exec_query(query);
	if (ret == -1) {
		_LOGD("DB Deletion from table (%s) Failed\n", db_table);
		return -1;
	}
	return 0;
}

static int __delete_subpkg_info_from_db(char *appid)
{
	int ret = -1;

	ret = __delete_appinfo_from_db("package_app_info", appid);
	if (ret < 0)
		return ret;
	ret = __delete_appinfo_from_db("package_app_localized_info", appid);
	if (ret < 0)
		return ret;
	ret = __delete_appinfo_from_db("package_app_icon_section_info", appid);
	if (ret < 0)
		return ret;
	ret = __delete_appinfo_from_db("package_app_image_info", appid);
	if (ret < 0)
		return ret;
	ret = __delete_appinfo_from_db("package_app_app_control", appid);
	if (ret < 0)
		return ret;
	ret = __delete_appinfo_from_db("package_app_app_category", appid);
	if (ret < 0)
		return ret;
	ret = __delete_appinfo_from_db("package_app_app_metadata", appid);
	if (ret < 0)
		return ret;
	ret = __delete_appinfo_from_db("package_app_app_permission", appid);
	if (ret < 0)
		return ret;
	ret = __delete_appinfo_from_db("package_app_share_allowed", appid);
	if (ret < 0)
		return ret;
	ret = __delete_appinfo_from_db("package_app_share_request", appid);
	if (ret < 0)
		return ret;
	ret = __delete_appinfo_from_db("package_app_data_control", appid);
	if (ret < 0)
		return ret;
	ret = __delete_appinfo_from_db("package_app_splash_screen", appid);
	if (ret < 0)
		return ret;

	return 0;
}

static int __delete_subpkg_from_db(manifest_x *mfx)
{
	char query[MAX_QUERY_LEN] = { '\0' };
	char *error_message = NULL;

	sqlite3_snprintf(MAX_QUERY_LEN, query, "SELECT app_id FROM package_app_info WHERE package=%Q", mfx->package);
	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_parser_db, query, __delete_subpkg_list_cb, NULL, &error_message)) {
		_LOGE("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);

	return 0;
}

static int __delete_manifest_info_from_db(manifest_x *mfx, uid_t uid)
{
	char query[MAX_QUERY_LEN] = { '\0' };
	int ret = -1;
	GList *tmp;
	application_x *app;
	/*Delete from cert table*/
	ret = pkgmgrinfo_delete_certinfo(mfx->package);
	if (ret) {
		_LOGD("Cert Info  DB Delete Failed\n");
		return -1;
	}

	/*Delete from Package Info DB*/
	sqlite3_snprintf(MAX_QUERY_LEN, query,
		 "DELETE FROM package_info WHERE package=%Q", mfx->package);
	ret = __exec_query(query);
	if (ret == -1) {
		_LOGD("Package Info DB Delete Failed\n");
		return -1;
	}
	memset(query, '\0', MAX_QUERY_LEN);

	/*Delete from Package Localized Info*/
	sqlite3_snprintf(MAX_QUERY_LEN, query,
		 "DELETE FROM package_localized_info WHERE package=%Q", mfx->package);
	ret = __exec_query(query);
	if (ret == -1) {
		_LOGD("Package Localized Info DB Delete Failed\n");
		return -1;
	}

	/*Delete from Package Privilege Info*/
	sqlite3_snprintf(MAX_QUERY_LEN, query,
		 "DELETE FROM package_privilege_info WHERE package=%Q", mfx->package);
	ret = __exec_query(query);
	if (ret == -1) {
		_LOGD("Package Privilege Info DB Delete Failed\n");
		return -1;
	}

	for (tmp = mfx->application; tmp; tmp = tmp->next) {
		app = (application_x *)tmp->data;
		if (app == NULL)
			continue;
		ret = __delete_appinfo_from_db("package_app_info", app->appid);
		if (ret < 0)
			return ret;
		ret = __delete_appinfo_from_db("package_app_localized_info", app->appid);
		if (ret < 0)
			return ret;
		ret = __delete_appinfo_from_db("package_app_icon_section_info", app->appid);
		if (ret < 0)
			return ret;
		ret = __delete_appinfo_from_db("package_app_image_info", app->appid);
		if (ret < 0)
			return ret;
		ret = __delete_appinfo_from_db("package_app_app_control", app->appid);
		if (ret < 0)
			return ret;
		ret = __delete_appinfo_from_db("package_app_app_category", app->appid);
		if (ret < 0)
			return ret;
		ret = __delete_appinfo_from_db("package_app_app_metadata", app->appid);
		if (ret < 0)
			return ret;
		ret = __delete_appinfo_from_db("package_app_app_permission", app->appid);
		if (ret < 0)
			return ret;
		ret = __delete_appinfo_from_db("package_app_share_allowed", app->appid);
		if (ret < 0)
			return ret;
		ret = __delete_appinfo_from_db("package_app_share_request", app->appid);
		if (ret < 0)
			return ret;
		ret = __delete_appinfo_from_db("package_app_data_control", app->appid);
		if (ret < 0)
			return ret;
		ret = __delete_appinfo_from_db("package_app_splash_screen", app->appid);
		if (ret < 0)
			return ret;
	}

	/* if main package has sub pkg, delete sub pkg data*/
	__delete_subpkg_from_db(mfx);

	return 0;
}

static int __disable_app(const char *appid)
{
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	sqlite3_snprintf(MAX_QUERY_LEN, query,
			"UPDATE package_app_info SET app_disable='true' WHERE app_id=%Q",
			appid);
	ret = __exec_query(query);
	if (ret == -1)
		_LOGD("Insert global app disable failed\n");

	return ret;
}

static int __enable_app(const char *appid)
{
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	sqlite3_snprintf(MAX_QUERY_LEN, query,
			"UPDATE package_app_info SET app_disable='false' WHERE app_id=%Q",
			appid);
	ret = __exec_query(query);
	if (ret == -1)
		_LOGD("Insert global app disable failed\n");

	return ret;
}

static int __check_appinfo_for_uid_table(const char *appid, uid_t uid)
{
	int ret = -1;
	char query[MAX_QUERY_LEN] = { '\0', };
	sqlite3_stmt *stmt;
	const char *val = NULL;

	if (appid == NULL)
		return -1;

	sqlite3_snprintf(MAX_QUERY_LEN, query,
			"SELECT COUNT(*) FROM "
			"package_app_info_for_uid WHERE app_id=%Q "
			"AND uid=%d", appid, (int)uid);

	ret = sqlite3_prepare_v2(pkgmgr_parser_db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(pkgmgr_parser_db));
		return PMINFO_R_ERROR;
	}

	if (sqlite3_step(stmt) != SQLITE_ROW) {
		LOGE("failed to step");
		sqlite3_finalize(stmt);
		return PMINFO_R_ERROR;
	}

	val = (const char *)sqlite3_column_text(stmt, 0);
	ret = atoi(val);
	sqlite3_finalize(stmt);

	return ret;
}

static int __disable_global_app_for_user(const char *appid, uid_t uid)
{
	int ret = -1;
	char query[MAX_QUERY_LEN] = { '\0', };

	ret = __check_appinfo_for_uid_table(appid, uid);
	if (ret < 0) {
		_LOGE("Failed to check package_app_info_for_uid with appid[%s], uid[%d]",
				appid, (int)uid);
		return -1;
	} else if (ret == 0) {
		sqlite3_snprintf(MAX_QUERY_LEN, query, "INSERT INTO "
				"package_app_info_for_uid(app_id, uid, is_disabled, is_splash_screen_enabled) "
				"VALUES(%Q, %d, 'true', "
				"(SELECT app_splash_screen_display FROM package_app_info WHERE appid='%Q'))",
				appid, (int)uid, appid);
	} else {
		sqlite3_snprintf(MAX_QUERY_LEN, query, "UPDATE "
				"package_app_info_for_uid SET is_disabled='true' "
				"WHERE app_id=%Q AND uid=%d", appid, (int)uid);
	}

	ret = __exec_query(query);
	if (ret == -1)
		_LOGD("Add global app disable info failed\n");

	return ret;
}

static int __enable_global_app_for_user(const char *appid, uid_t uid)
{
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};

	ret = __check_appinfo_for_uid_table(appid, uid);
	if (ret < 0) {
		_LOGE("Failed to check package_app_info_for_uid with appid[%s], uid[%d]",
				appid, (int)uid);
		return -1;
	} else if (ret > 0) {
		sqlite3_snprintf(MAX_QUERY_LEN, query,
				"UPDATE package_app_info_for_uid SET "
				"is_disabled='false' WHERE app_id=%Q AND "
				"uid=%d", appid, (int)uid);
	}

	ret = __exec_query(query);
	if (ret == -1)
		_LOGD("Remove global app disable info failed\n");

	return ret;
}

static int __update_global_app_splash_screen_for_user(const char *appid,
		uid_t uid, int flag)
{
	int ret = -1;
	char query[MAX_QUERY_LEN] = { '\0', };

	ret = __check_appinfo_for_uid_table(appid, uid);
	if (ret < 0) {
		_LOGE("Failed to check package_app_info_for_uid with appid[%s], uid[%d]",
				appid, (int)uid);
		return -1;
	} else if (ret == 0) {
		sqlite3_snprintf(MAX_QUERY_LEN, query, "INSERT INTO "
				"package_app_info_for_uid(app_id, uid, is_splash_screen_enabled) "
				"VALUES(%Q, %d, %Q)", appid, (int)uid,
				flag ? "true" : "false");
	} else {
		sqlite3_snprintf(MAX_QUERY_LEN, query,
				"UPDATE package_app_info_for_uid SET "
				"is_splash_screen_enabled=%Q WHERE app_id=%Q AND "
				"uid=%d", flag ? "true" : "false", appid, (int)uid);
	}

	ret = __exec_query(query);
	if (ret == -1)
		_LOGD("update global app splash screen info failed\n");

	return ret;
}

static int __disable_app_splash_screen(const char *appid)
{
	int ret;
	char query[MAX_QUERY_LEN] = {'\0'};

	sqlite3_snprintf(MAX_QUERY_LEN, query,
			"UPDATE package_app_info SET app_splash_screen_display='false' WHERE app_id=%Q",
			appid);
	ret = __exec_query(query);
	if (ret == -1)
		_LOGD("Failed to update app_palsh_screen_display");

	return ret;
}

static int __enable_app_splash_screen(const char *appid)
{
	int ret;
	char query[MAX_QUERY_LEN] = {'\0'};

	sqlite3_snprintf(MAX_QUERY_LEN, query,
			"UPDATE package_app_info SET app_splash_screen_display='true' WHERE app_id=%Q",
			appid);
	ret = __exec_query(query);
	if (ret == -1)
		_LOGD("Failed to update app_splash_screen_display");

	return ret;
}

API int pkgmgr_parser_initialize_db(uid_t uid)
{
	int ret = -1;
	int i;
	char query[MAX_QUERY_LEN];
	static const char *columns[] = {
		"author_root_cert", "author_im_cert", "author_signer_cert",
		"dist_root_cert", "dist_im_cert", "dist_signer_cert",
		"dist2_root_cert", "dist2_im_cert", "dist2_signer_cert",
		NULL};

	/*Manifest DB*/
	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_INFO);
	if (ret == -1) {
		_LOGD("package info DB initialization failed\n");
		return ret;
	}
	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_LOCALIZED_INFO);
	if (ret == -1) {
		_LOGD("package localized info DB initialization failed\n");
		return ret;
	}
	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_PRIVILEGE_INFO);
	if (ret == -1) {
		_LOGD("package app app privilege DB initialization failed\n");
		return ret;
	}
	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_APP_INFO);
	if (ret == -1) {
		_LOGD("package app info DB initialization failed\n");
		return ret;
	}
	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_APP_LOCALIZED_INFO);
	if (ret == -1) {
		_LOGD("package app localized info DB initialization failed\n");
		return ret;
	}
	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_APP_ICON_SECTION_INFO);
	if (ret == -1) {
		_LOGD("package app icon localized info DB initialization failed\n");
		return ret;
	}
	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_APP_IMAGE_INFO);
	if (ret == -1) {
		_LOGD("package app image info DB initialization failed\n");
		return ret;
	}
	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_APP_APP_CONTROL);
	if (ret == -1) {
		_LOGD("package app app control DB initialization failed\n");
		return ret;
	}
	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_APP_APP_CATEGORY);
	if (ret == -1) {
		_LOGD("package app app category DB initialization failed\n");
		return ret;
	}
	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_APP_APP_METADATA);
	if (ret == -1) {
		_LOGD("package app app category DB initialization failed\n");
		return ret;
	}
	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_APP_APP_PERMISSION);
	if (ret == -1) {
		_LOGD("package app app permission DB initialization failed\n");
		return ret;
	}
	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_APP_SHARE_ALLOWED);
	if (ret == -1) {
		_LOGD("package app share allowed DB initialization failed\n");
		return ret;
	}
	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_APP_SHARE_REQUEST);
	if (ret == -1) {
		_LOGD("package app share request DB initialization failed\n");
		return ret;
	}
	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_APP_DATA_CONTROL);
	if (ret == -1) {
		_LOGD("package app data control DB initialization failed\n");
		return ret;
	}

	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_APP_INFO_FOR_UID);
	if (ret == -1) {
		_LOGD("package_app_info_for_uid for user DB initialization failed\n");
		return ret;
	}

	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_APP_SPLASH_SCREEN);
	if (ret == -1) {
		_LOGD("package app splash screen DB initialization failed\n");
		return ret;
	}

	/* Trigger package_app_info_for_uid */
	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TRIGGER_UPDATE_PACKAGE_APP_INFO_FOR_UID);
	if (ret == -1) {
		_LOGD("package app info for uid DB initialization failed\n");
		return ret;
	}

	/*Cert DB*/
	/* TODO: refactor this code */
	ret = __initialize_db(pkgmgr_cert_db, QUERY_CREATE_TABLE_PACKAGE_CERT_INFO);
	if (ret == -1) {
		_LOGD("package cert info DB initialization failed\n");
		return ret;
	}
	ret = __initialize_db(pkgmgr_cert_db, QUERY_CREATE_TABLE_PACKAGE_CERT_INDEX_INFO);
	if (ret == -1) {
		_LOGD("package cert index info DB initialization failed\n");
		return ret;
	}
	ret = __initialize_db(pkgmgr_cert_db, QUERY_CREATE_TRIGGER_DELETE_CERT_INFO);
	if (ret == -1) {
		_LOGD("package cert info DB initialization failed\n");
		return ret;
	}
	ret = __initialize_db(pkgmgr_cert_db, QUERY_CREATE_TRIGGER_UPDATE_CERT_INDEX_INFO);
	if (ret == -1) {
		_LOGD("package cert index info DB initialization failed\n");
		return ret;
	}
	for (i = 0; columns[i] != NULL; i++) {
		snprintf(query, sizeof(query),
				QUERY_CREATE_TRIGGER_UPDATE_CERT_INFO_FORMAT,
				columns[i], columns[i], columns[i]);
		ret = __initialize_db(pkgmgr_cert_db, query);
		if (ret == -1) {
			_LOGD("package cert index info DB initialization failed\n");
			return ret;
		}
	}

	if( 0 != __parserdb_change_perm(getUserPkgCertDBPathUID(GLOBAL_USER), GLOBAL_USER)) {
		_LOGD("Failed to change cert db permission\n");
	}
	if( 0 != __parserdb_change_perm(getUserPkgParserDBPathUID(uid), uid)) {
		_LOGD("Failed to change parser db permission\n");
	}

	return 0;
}

static int __parserdb_change_perm(const char *db_file, uid_t uid)
{
	char buf[BUFSIZE];
	char pwuid_buf[1024];
	char journal_file[BUFSIZE];
	int fd;
	struct stat sb;
	char *files[3];
	int ret, i;
	struct passwd userinfo, *result = NULL;
	files[0] = (char *)db_file;
	files[1] = journal_file;
	files[2] = NULL;
	mode_t mode;

	if (db_file == NULL)
		return -1;

	if (getuid() != OWNER_ROOT) //At this time we should be root to apply this
		return 0;
	snprintf(journal_file, sizeof(journal_file), "%s%s", db_file, "-journal");
	if (uid == OWNER_ROOT)
		uid = GLOBAL_USER;
	ret = getpwuid_r(uid, &userinfo, pwuid_buf, sizeof(pwuid_buf), &result);
	if (ret != 0 || result == NULL) {
		_LOGE("FAIL: user %d doesn't exist", uid);
		return -1;
	}
	snprintf(journal_file, sizeof(journal_file), "%s%s", db_file, "-journal");

	for (i = 0; files[i]; i++) {
		fd = open(files[i], O_RDONLY);
		if (fd == -1) {
			if (strerror_r(errno, buf, sizeof(buf)))
				strncpy(buf, "", BUFSIZE - 1);
			_LOGD("FAIL : open %s : %s", files[i], buf);
			return -1;
		}
		ret = fstat(fd, &sb);
		if (ret == -1) {
			if (strerror_r(errno, buf, sizeof(buf)))
				strncpy(buf, "", BUFSIZE - 1);
			_LOGD("FAIL : fstat %s : %s", files[i], buf);
			close(fd);
			return -1;
		}
		if (S_ISLNK(sb.st_mode)) {
			_LOGE("FAIL : %s is symlink!", files[i]);
			close(fd);
			return -1;
		}
		ret = fchown(fd, uid, userinfo.pw_gid);
		if (ret == -1) {
			if (strerror_r(errno, buf, sizeof(buf)))
				strncpy(buf, "", BUFSIZE - 1);
			_LOGD("FAIL : fchown %s %d.%d : %s", files[i], uid,
					userinfo.pw_gid, buf);
			close(fd);
			return -1;
		}

		mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;
		if (!strcmp(db_file, getUserPkgCertDBPathUID(GLOBAL_USER)))
			mode |= S_IWOTH;
		ret = fchmod(fd, mode);
		if (ret == -1) {
			if (strerror_r(errno, buf, sizeof(buf)))
				strncpy(buf, "", BUFSIZE - 1);
			_LOGD("FAIL : fchmod %s 0664 : %s", files[i], buf);
			close(fd);
			return -1;
		}
		close(fd);
		SET_SMACK_LABEL(files[i]);
	}
	return 0;
}

API int pkgmgr_parser_create_and_initialize_db(uid_t uid)
{
	int ret;

	if (getuid() != OWNER_ROOT) {
		_LOGE("Only root user is allowed");
		return -1;
	}

	if (access(getUserPkgParserDBPathUID(uid), F_OK) != -1) {
		_LOGE("Manifest db for user %d is already exists", uid);
		return -1;
	}

	if (access(getUserPkgCertDBPathUID(uid), F_OK) != -1) {
		_LOGE("Cert db for user %d is already exists", uid);
		return -1;
	}

	ret = pkgmgr_parser_check_and_create_db(uid);
	if (ret < 0)
		return -1;
	ret = pkgmgr_parser_initialize_db(uid);
	if (ret < 0) {
		pkgmgr_parser_close_db();
		return -1;
	}
	pkgmgr_parser_close_db();

	return 0;
}

API int pkgmgr_parser_check_and_create_db(uid_t uid)
{
	int ret = -1;
	/*Manifest DB*/
	ret = __pkgmgr_parser_create_db(&pkgmgr_parser_db, getUserPkgParserDBPathUID(uid));
	if (ret) {
		_LOGD("Manifest DB creation Failed\n");
		return -1;
	}

	/*Cert DB*/
	ret = __pkgmgr_parser_create_db(&pkgmgr_cert_db, getUserPkgCertDBPathUID(GLOBAL_USER));
	if (ret) {
		_LOGD("Cert DB creation Failed\n");
		return -1;
	}
	return 0;
}

void pkgmgr_parser_close_db(void)
{
	sqlite3_close(pkgmgr_parser_db);
	sqlite3_close(pkgmgr_cert_db);
}


API int pkgmgr_parser_insert_manifest_info_in_db(manifest_x *mfx)
{
	_LOGD("pkgmgr_parser_insert_manifest_info_in_db\n");
	if (mfx == NULL) {
		_LOGD("manifest pointer is NULL\n");
		return -1;
	}
	int ret = 0;
	ret = pkgmgr_parser_check_and_create_db(GLOBAL_USER);
	if (ret == -1) {
		_LOGD("Failed to open DB\n");
		return ret;
	}
	ret = pkgmgr_parser_initialize_db(GLOBAL_USER);
	if (ret == -1)
		goto err;
	/*Begin transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGD("Failed to begin transaction\n");
		ret = -1;
		goto err;
	}
	_LOGD("Transaction Begin\n");
	ret = __insert_manifest_info_in_db(mfx, GLOBAL_USER);
	if (ret == -1) {
		_LOGD("Insert into DB failed. Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		goto err;
	}
	/*Commit transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGD("Failed to commit transaction. Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		ret = -1;
		goto err;
	}
	_LOGD("Transaction Commit and End\n");
err:
	pkgmgr_parser_close_db();
	return ret;
}

API int pkgmgr_parser_insert_manifest_info_in_usr_db(manifest_x *mfx, uid_t uid)
{
	_LOGD("pkgmgr_parser_insert_manifest_info_in_usr_db\n");
	if (mfx == NULL) {
		_LOGD("manifest pointer is NULL\n");
		return -1;
	}
	int ret = 0;
	ret = pkgmgr_parser_check_and_create_db(uid);
	if (ret == -1) {
		_LOGD("Failed to open DB\n");
		return ret;
	}
	ret = pkgmgr_parser_initialize_db(uid);
	if (ret == -1)
		goto err;
	/*Begin transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGD("Failed to begin transaction\n");
		ret = -1;
		goto err;
	}
	_LOGD("Transaction Begin\n");
	ret = __insert_manifest_info_in_db(mfx, uid);
	if (ret == -1) {
		_LOGD("Insert into DB failed. Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		goto err;
	}
	/*Commit transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGD("Failed to commit transaction. Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		ret = -1;
		goto err;
	}
	_LOGD("Transaction Commit and End\n");
err:
	pkgmgr_parser_close_db();
	return ret;
}

API int pkgmgr_parser_update_manifest_info_in_usr_db(manifest_x *mfx, uid_t uid)
{
	if (mfx == NULL) {
		_LOGD("manifest pointer is NULL\n");
		return -1;
	}
	int ret = 0;
	ret = pkgmgr_parser_check_and_create_db(uid);
	if (ret == -1) {
		_LOGD("Failed to open DB\n");
		return ret;
	}
	ret = pkgmgr_parser_initialize_db(uid);
	if (ret == -1)
		goto err;
	/*Preserve guest mode visibility*/
	__preserve_guestmode_visibility_value( mfx);
	/*Begin transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGD("Failed to begin transaction\n");
		ret = -1;
		goto err;
	}
	_LOGD("Transaction Begin\n");
	ret = __delete_manifest_info_from_db(mfx, uid);
	if (ret == -1) {
		_LOGD("Delete from DB failed. Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		goto err;
	}
	ret = __insert_manifest_info_in_db(mfx, uid);
	if (ret == -1) {
		_LOGD("Insert into DB failed. Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		goto err;
	}

	/*Commit transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGD("Failed to commit transaction. Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		ret = -1;
		goto err;
	}
	_LOGD("Transaction Commit and End\n");
err:
	pkgmgr_parser_close_db();
	return ret;
}

API int pkgmgr_parser_update_manifest_info_in_db(manifest_x *mfx)
{
	return pkgmgr_parser_update_manifest_info_in_usr_db(mfx, _getuid());
}

API int pkgmgr_parser_delete_manifest_info_from_usr_db(manifest_x *mfx, uid_t uid)
{
	if (mfx == NULL) {
		_LOGD("manifest pointer is NULL\n");
		return -1;
	}
	int ret = 0;
	ret = pkgmgr_parser_check_and_create_db(uid);
	if (ret == -1) {
		_LOGD("Failed to open DB\n");
		return ret;
	}
	/*Begin transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGD("Failed to begin transaction\n");
		ret = -1;
		goto err;
	}
	_LOGD("Transaction Begin\n");
	ret = __delete_manifest_info_from_db(mfx, uid);
	if (ret == -1) {
		_LOGD("Delete from DB failed. Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		goto err;
	}
	/*Commit transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGD("Failed to commit transaction, Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		ret = -1;
		goto err;
	}
	_LOGD("Transaction Commit and End\n");
err:
	pkgmgr_parser_close_db();
	return ret;
}

API int pkgmgr_parser_delete_manifest_info_from_db(manifest_x *mfx)
{
	return pkgmgr_parser_delete_manifest_info_from_usr_db(mfx, _getuid());
}

API int pkgmgr_parser_update_global_app_disable_for_uid_info_in_db(const char *appid, uid_t uid, int is_disable)
{
	int ret = -1;

	ret = pkgmgr_parser_check_and_create_db(GLOBAL_USER);
	if (ret == -1) {
		_LOGD("Failed to open DB\n");
		return ret;
	}

	/*Begin transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGD("Failed to begin transaction\n");
		ret = -1;
		goto err;
	}
	_LOGD("Transaction Begin\n");
	if (is_disable)
		ret = __disable_global_app_for_user(appid, uid);
	else
		ret = __enable_global_app_for_user(appid, uid);
	if (ret == -1) {
		_LOGD("__update_global_app_disable_condition_in_db failed. Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		goto err;
	}
	/*Commit transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGD("Failed to commit transaction, Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		ret = -1;
		goto err;
	}
	_LOGD("Transaction Commit and End\n");
err:
	pkgmgr_parser_close_db();
	return ret;

}

API int pkgmgr_parser_update_app_disable_info_in_db(const char *appid, int is_disable)
{
	return pkgmgr_parser_update_app_disable_info_in_usr_db(appid, _getuid(), is_disable);
}

API int pkgmgr_parser_update_app_disable_info_in_usr_db(const char *appid, uid_t uid, int is_disable)
{
	int ret = -1;

	ret = pkgmgr_parser_check_and_create_db(uid);
	if (ret == -1) {
		_LOGD("Failed to open DB\n");
		return ret;
	}

	/*Begin transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGD("Failed to begin transaction\n");
		ret = -1;
		goto err;
	}
	_LOGD("Transaction Begin\n");
	if (is_disable)
		ret = __disable_app(appid);
	else
		ret = __enable_app(appid);
	if (ret == -1) {
		_LOGD("__update_app_disable_condition_in_db failed. Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		goto err;
	}
	/*Commit transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGD("Failed to commit transaction, Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		ret = -1;
		goto err;
	}
	_LOGD("Transaction Commit and End\n");
err:
	pkgmgr_parser_close_db();
	return ret;

}

API int pkgmgr_parser_update_global_app_splash_screen_display_info_in_usr_db(const char *appid, uid_t uid, int flag)
{
	int ret = -1;

	if (appid == NULL) {
		_LOGD("Invalid parameter");
		return -1;
	}

	ret = pkgmgr_parser_check_and_create_db(GLOBAL_USER);
	if (ret == -1) {
		_LOGD("Failed to open DB\n");
		return ret;
	}

	/* Begin transaction */
	ret = sqlite3_exec(pkgmgr_parser_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGD("Failed to begin transaction\n");
		ret = -1;
		goto err;
	}
	_LOGD("Transaction Begin\n");

	ret = __update_global_app_splash_screen_for_user(appid, uid, flag);
	if (ret == -1) {
		_LOGD("__update_splash_screen_disable_condition_in_db failed. Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		goto err;
	}
	/* Commit transaction */
	ret = sqlite3_exec(pkgmgr_parser_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGD("Failed to commit transaction, Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		ret = -1;
		goto err;
	}
	_LOGD("Transaction Commit and End\n");
err:
	pkgmgr_parser_close_db();
	return ret;
}

API int pkgmgr_parser_update_app_splash_screen_display_info_in_db(const char *appid, int flag)
{
	return pkgmgr_parser_update_app_splash_screen_display_info_in_usr_db(appid, _getuid(), flag);
}

API int pkgmgr_parser_update_app_splash_screen_display_info_in_usr_db(const char *appid, uid_t uid, int flag)
{
	int ret;

	if (appid == NULL) {
		_LOGD("Invalid parameter");
		return -1;
	}

	ret = pkgmgr_parser_check_and_create_db(uid);
	if (ret == -1) {
		_LOGD("Failed to open DB");
		return -1;
	}

	/* Begin transaction */
	ret = sqlite3_exec(pkgmgr_parser_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGD("Failed to begin transaction");
		ret = -1;
		goto err;
	}
	_LOGD("Transaction Begin");

	if (flag)
		ret = __enable_app_splash_screen(appid);
	else
		ret = __disable_app_splash_screen(appid);
	if (ret == -1) {
		_LOGD("__update_app_splash_screen_condition_in_db. Rollback now");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		goto err;
	}
	/* Commit transaction */
	ret = sqlite3_exec(pkgmgr_parser_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGD("Failed to commit transaction, Rollback now");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		ret = -1;
		goto err;
	}
	_LOGD("Transaction Commit and End");

err:
	pkgmgr_parser_close_db();
	return ret;
}

