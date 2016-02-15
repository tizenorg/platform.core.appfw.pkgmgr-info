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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/smack.h>
#include <sys/stat.h>
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


#define QUERY_CREATE_TABLE_PACKAGE_INFO "create table if not exists package_info " \
						"(package text primary key not null, " \
						"package_type text DEFAULT 'rpm', " \
						"package_version text, " \
						"package_api_version text, " \
						"package_tep_name text, " \
						"install_location text, " \
						"package_size text, " \
						"package_removable text DEFAULT 'true', " \
						"package_preload text DEFAULT 'false', " \
						"package_readonly text DEFAULT 'false', " \
						"package_update text DEFAULT 'false', " \
						"package_appsetting text DEFAULT 'false', " \
						"package_nodisplay text DEFAULT 'false', " \
						"package_system text DEFAULT 'false', " \
						"author_name text, " \
						"author_email text, " \
						"author_href text," \
						"installed_time text," \
						"installed_storage text," \
						"storeclient_id text," \
						"mainapp_id text," \
						"package_url text," \
						"root_path text," \
						"csc_path text," \
						"package_support_disable text DEFAULT 'false', " \
						"package_disable text DEFAULT 'false')"

#define QUERY_CREATE_TABLE_PACKAGE_LOCALIZED_INFO "create table if not exists package_localized_info " \
						"(package text not null, " \
						"package_locale text DEFAULT 'No Locale', " \
						"package_label text, " \
						"package_icon text, " \
						"package_description text, " \
						"package_license text, " \
						"package_author, " \
						"PRIMARY KEY(package, package_locale), " \
						"FOREIGN KEY(package) " \
						"REFERENCES package_info(package) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_PRIVILEGE_INFO "create table if not exists package_privilege_info " \
						"(package text not null, " \
						"privilege text not null, " \
						"PRIMARY KEY(package, privilege) " \
						"FOREIGN KEY(package) " \
						"REFERENCES package_info(package) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_INFO "create table if not exists package_app_info " \
						"(app_id text primary key not null, " \
						"app_component text, " \
						"app_exec text, " \
						"app_nodisplay text DEFAULT 'false', " \
						"app_type text, " \
						"app_onboot text DEFAULT 'false', " \
						"app_multiple text DEFAULT 'false', " \
						"app_autorestart text DEFAULT 'false', " \
						"app_taskmanage text DEFAULT 'false', " \
						"app_enabled text DEFAULT 'true', " \
						"app_hwacceleration text DEFAULT 'use-system-setting', " \
						"app_screenreader text DEFAULT 'use-system-setting', " \
						"app_mainapp text, " \
						"app_recentimage text, " \
						"app_launchcondition text, " \
						"app_indicatordisplay text DEFAULT 'true', " \
						"app_portraitimg text, " \
						"app_landscapeimg text, " \
						"app_guestmodevisibility text DEFAULT 'true', " \
						"app_permissiontype text DEFAULT 'normal', " \
						"app_preload text DEFAULT 'false', " \
						"app_submode text DEFAULT 'false', " \
						"app_submode_mainid text, " \
						"app_installed_storage text, " \
						"app_process_pool text DEFAULT 'false', " \
						"app_launch_mode text NOT NULL DEFAULT 'caller', " \
						"app_ui_gadget text DEFAULT 'false', " \
						"app_support_disable text DEFAULT 'false', " \
						"app_disable text DEFAULT 'false', " \
						"app_package_type text DEFAULT 'tpk', " \
						"component_type text, " \
						"package text not null, " \
						"app_tep_name text, " \
						"app_background_category INTEGER DEFAULT 0, " \
						"FOREIGN KEY(package) " \
						"REFERENCES package_info(package) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_LOCALIZED_INFO "create table if not exists package_app_localized_info " \
						"(app_id text not null, " \
						"app_locale text DEFAULT 'No Locale', " \
						"app_label text, " \
						"app_icon text, " \
						"PRIMARY KEY(app_id,app_locale) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_ICON_SECTION_INFO "create table if not exists package_app_icon_section_info " \
						"(app_id text not null, " \
						"app_icon text, " \
						"app_icon_section text, " \
						"app_icon_resolution text, " \
						"PRIMARY KEY(app_id,app_icon_section,app_icon_resolution) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_IMAGE_INFO "create table if not exists package_app_image_info " \
						"(app_id text not null, " \
						"app_locale text DEFAULT 'No Locale', " \
						"app_image_section text, " \
						"app_image text, " \
						"PRIMARY KEY(app_id,app_image_section) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_APP_CONTROL "create table if not exists package_app_app_control " \
						"(app_id text not null, " \
						"app_control text not null, " \
						"PRIMARY KEY(app_id,app_control) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_APP_CATEGORY "create table if not exists package_app_app_category " \
						"(app_id text not null, " \
						"category text not null, " \
						"PRIMARY KEY(app_id,category) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_APP_METADATA "create table if not exists package_app_app_metadata " \
						"(app_id text not null, " \
						"md_key text not null, " \
						"md_value text not null, " \
						"PRIMARY KEY(app_id, md_key, md_value) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_APP_PERMISSION "create table if not exists package_app_app_permission " \
						"(app_id text not null, " \
						"pm_type text not null, " \
						"pm_value text not null, " \
						"PRIMARY KEY(app_id, pm_type, pm_value) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_SHARE_ALLOWED "create table if not exists package_app_share_allowed " \
						"(app_id text not null, " \
						"data_share_path text not null, " \
						"data_share_allowed text not null, " \
						"PRIMARY KEY(app_id,data_share_path,data_share_allowed) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_SHARE_REQUEST "create table if not exists package_app_share_request " \
						"(app_id text not null, " \
						"data_share_request text not null, " \
						"PRIMARY KEY(app_id,data_share_request) " \
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

#define QUERY_CREATE_TABLE_PACKAGE_APP_DATA_CONTROL "create table if not exists package_app_data_control " \
						"(app_id text not null, " \
						"providerid text not null, " \
						"access text not null, " \
						"type text not null, " \
						"PRIMARY KEY(app_id, providerid, access, type) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_DISABLE_FOR_USER "CREATE TABLE IF NOT EXISTS package_app_disable_for_user " \
						"(app_id text not null, " \
						"uid text not null, " \
						"PRIMARY KEY(app_id, uid))"

#define QUERY_CREATE_TABLE_PACKAGE_APP_SPLASH_SCREEN \
	"create table if not exists package_app_splash_screen " \
	"(app_id text not null, " \
	"src text not null, " \
	"type text not null, " \
	"orientation text not null, " \
	"indicatordisplay text, " \
	"PRIMARY KEY(app_id, orientation) " \
	"FOREIGN KEY(app_id) " \
	"REFERENCES package_app_info(app_id) " \
	"ON DELETE CASCADE)"

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

static int __delete_subpkg_list_cb(void *data, int ncols, char **coltxt, char **colname)
{
	if (coltxt[0])
		__delete_subpkg_info_from_db(coltxt[0]);

	return 0;
}

static const char *__get_str(const char *str)
{
	if (str == NULL)
	{
		return PKGMGR_PARSER_EMPTY_STR;
	}

	return str;
}

static int __pkgmgr_parser_create_db(sqlite3 **db_handle, const char *db_path)
{
	int ret = -1;
	sqlite3 *handle;

	ret = db_util_open(db_path, &handle,  DB_UTIL_REGISTER_HOOK_METHOD);
	if (ret != SQLITE_OK) {
		_LOGD("connect db [%s] failed!\n", db_path);
		return -1;
	}
	*db_handle = handle;

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
	snprintf(query, MAX_QUERY_LEN - 1, "select app_id, app_guestmodevisibility from package_app_info where package='%s'", mfx->package);
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

static gint __compare_icon(gconstpointer a, gconstpointer b)
{
	icon_x *icon = (icon_x *)a;

	if (icon->lang != NULL && strcasecmp(icon->lang, DEFAULT_LOCALE) != 0)
		return -1;

	if (icon->dpi != NULL)
		return -1;

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

	if (icon->dpi != NULL)
		return -1;

	if (strcasecmp(icon->lang, lang) == 0)
		return 0;

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

	query = sqlite3_mprintf("insert into package_localized_info(package, package_locale, " \
		"package_label, package_icon, package_description, package_license, package_author) values " \
		"(%Q, %Q, %Q, %Q, %Q, %Q, %Q)",
		mfx->package,
		(char*)data,
		__get_str(label),
		__get_str(icon),
		__get_str(description),
		__get_str(license),
		__get_str(author));

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

	query = sqlite3_mprintf("insert into package_app_localized_info(app_id, app_locale, " \
		"app_label, app_icon) values " \
		"(%Q, %Q, %Q, %Q)", app->appid, (char*)data,
		__get_str(label), __get_str(icon));
	ret = __exec_query(query);
	if (ret == -1)
		_LOGD("Package UiApp Localized Info DB Insert failed\n");

	sqlite3_free(query);

	/*insert ui app locale info to pkg locale to get mainapp data */
	if (strcasecmp(app->mainapp, "true")==0) {
		query = sqlite3_mprintf("insert into package_localized_info(package, package_locale, " \
			"package_label, package_icon, package_description, package_license, package_author) values " \
			"(%Q, %Q, %Q, %Q, %Q, %Q, %Q)",
			app->package,
			(char*)data,
			__get_str(label),
			__get_str(icon),
			PKGMGR_PARSER_EMPTY_STR,
			PKGMGR_PARSER_EMPTY_STR,
			PKGMGR_PARSER_EMPTY_STR);

		ret = __exec_query_no_msg(query);
		sqlite3_free(query);

		if (icon != NULL) {
			query = sqlite3_mprintf("update package_localized_info set package_icon=%Q "\
				"where package=%Q and package_locale=%Q", icon, app->package, (char*)data);
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
	sqlite3_snprintf(MAX_QUERY_LEN, query, "insert into package_app_icon_section_info(app_id, " \
		"app_icon, app_icon_section, app_icon_resolution) values " \
		"('%q', '%q', '%q', '%q')", app->appid,
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
	sqlite3_snprintf(MAX_QUERY_LEN, query, "insert into package_app_image_info(app_id, app_locale, " \
		"app_image_section, app_image) values " \
		"('%q', '%q', '%q', '%q')", app->appid, lang, (char*)data, img);

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
		snprintf(query, MAX_QUERY_LEN,
			"update package_app_info set app_mainapp='%s' where app_id='%s'", app->mainapp, app->appid);

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
			snprintf(query, MAX_QUERY_LEN, "update package_app_info set app_mainapp='true' where app_id='%s'", app->appid);
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
	snprintf(query, MAX_QUERY_LEN,
		"update package_info set mainapp_id='%s' where package='%s'", mfx->mainapp_id, mfx->package);
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

		snprintf(query, MAX_QUERY_LEN,
			"insert into package_app_info(" \
			"app_id, app_component, app_exec, app_nodisplay, app_type, " \
			"app_onboot, app_multiple, app_autorestart, app_taskmanage, app_enabled, " \
			"app_hwacceleration, app_screenreader, app_mainapp, app_recentimage, app_launchcondition, " \
			"app_indicatordisplay, app_portraitimg, app_landscapeimg, app_guestmodevisibility, app_permissiontype, " \
			"app_preload, app_submode, app_submode_mainid, app_installed_storage, app_process_pool, " \
			"app_launch_mode, app_ui_gadget, app_support_disable, component_type, package, " \
			"app_tep_name, app_background_category, app_package_type) " \
			"values(" \
			"'%s', '%s', '%s', '%s', '%s', " \
			"'%s', '%s', '%s', '%s', '%s', " \
			"'%s', '%s', '%s', '%s', '%s', " \
			"'%s', '%s', '%s', '%s', '%s', " \
			"'%s', '%s', '%s', '%s', '%s', " \
			"'%s', '%s', '%s', '%s', '%s', " \
			"'%s', '%d', '%s')", \
			app->appid, app->component_type, app->exec, app->nodisplay, app->type,
			app->onboot, app->multiple, app->autorestart, app->taskmanage, app->enabled,
			app->hwacceleration, app->screenreader, app->mainapp, __get_str(app->recentimage), app->launchcondition,
			app->indicatordisplay, __get_str(app->portraitimg), __get_str(app->landscapeimg),
			app->guestmode_visibility, app->permission_type,
			mfx->preload, app->submode, __get_str(app->submode_mainid), mfx->installed_storage, app->process_pool,
			app->launch_mode, app->ui_gadget, mfx->support_disable, app->component_type, mfx->package,
			__get_str(mfx->tep_name), background_value, type);

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
			snprintf(query, MAX_QUERY_LEN,
				"insert into package_app_app_category(app_id, category) " \
				"values('%s','%s')",\
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
				snprintf(query, MAX_QUERY_LEN,
					"insert into package_app_app_metadata(app_id, md_key, md_value) " \
					"values('%s','%s', '%s')",\
					 app->appid, md->key, md->value ? md->value : "");
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
			snprintf(query, MAX_QUERY_LEN,
				"insert into package_app_app_permission(app_id, pm_type, pm_value) " \
				"values('%s','%s', '%s')",\
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
			snprintf(query, MAX_QUERY_LEN,
					"insert into package_app_app_control(app_id, app_control) " \
					"values('%s', '%s')",\
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
			snprintf(query, MAX_QUERY_LEN,
					"insert into package_app_data_control(app_id, providerid, access, type) " \
					"values('%s', '%s', '%s', '%s')",\
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
				snprintf(query, MAX_QUERY_LEN,
					 "insert into package_app_share_request(app_id, data_share_request) " \
					"values('%s', '%s')",\
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
					snprintf(query, MAX_QUERY_LEN,
						 "insert into package_app_share_allowed(app_id, data_share_path, data_share_allowed) " \
						"values('%s', '%s', '%s')",\
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

static int __insert_application_splashscreen_info(manifest_x *mfx)
{
	GList *app_tmp;
	application_x *app;
	GList *ss_tmp;
	splashscreen_x *ss;
	int ret = -1;
	char query[MAX_QUERY_LEN];
	int dpi = -1;

	system_info_get_platform_int("http://tizen.org/feature/screen.dpi", &dpi);
	if (!dpi)
		return -1;

	for (app_tmp = mfx->application; app_tmp; app_tmp = app_tmp->next) {
		app = (application_x *)app_tmp->data;
		if (app == NULL)
			continue;
		for (ss_tmp = app->splashscreens; ss_tmp; ss_tmp = ss_tmp->next) {
			ss = (splashscreen_x *)ss_tmp->data;
			if (ss == NULL)
				continue;

			if (ss->dpi && __check_dpi(ss->dpi, dpi) != 0)
				continue;

			snprintf(query, sizeof(query),
					"insert into package_app_splash_screen" \
					"(app_id, src, type, orientation, indicatordisplay) " \
					"values('%s', '%s', '%s', '%s', '%s')",
					app->appid, ss->src, ss->type, ss->orientation,
					ss->indicatordisplay);
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

static int __insert_application_legacy_splashscreen_info(manifest_x *mfx)
{
	GList *app_tmp;
	application_x *app;
	int ret = -1;
	char query[MAX_QUERY_LEN];
	char *tmp;
	const char *image_type;
	const char *indicatordisplay;
	const char *orientation;

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
			snprintf(query, sizeof(query),
					"insert into package_app_splash_screen" \
					"(app_id, src, type, orientation, indicatordisplay) " \
					"values('%s', '%s', '%s', '%s', '%s')",
					app->appid, app->portraitimg, image_type,
					orientation, indicatordisplay);
			ret = __exec_query(query);
			if (ret == -1) {
				_LOGD("Package UiApp Splash Screen DB Insert Failed");
				return -1;
			}
			memset(query, '\0', MAX_QUERY_LEN);
		} else if (app->landscapeimg) {
			orientation = "landscape";
			snprintf(query, sizeof(query),
					"insert into package_app_splash_screen" \
					"(app_id, src, type, orientation, indicatordisplay) " \
					"values('%s', '%s', '%s', '%s', '%s')",
					app->appid, app->landscapeimg, image_type,
					orientation, indicatordisplay);
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

	/*Insert in the package_info DB*/
	snprintf(query, MAX_QUERY_LEN,
		"insert into package_info(" \
		"package, package_type, package_version, package_api_version, package_tep_name, " \
		"install_location, package_size, package_removable, package_preload, package_readonly, " \
		"package_update, package_appsetting, package_nodisplay, package_system, author_name, " \
		"author_email, author_href, installed_time, installed_storage, storeclient_id, " \
		"mainapp_id, package_url, root_path, csc_path, package_support_disable) " \
		"values(" \
		"'%s', '%s', '%s', '%s', '%s', " \
		"'%s', '%s', '%s', '%s', '%s', " \
		"'%s', '%s', '%s', '%s', '%s', " \
		"'%s', '%s', '%s', '%s', '%s', " \
		"'%s', '%s', '%s', '%s', '%s')", \
		mfx->package, mfx->type, mfx->version, __get_str(mfx->api_version), __get_str(mfx->tep_name),
		__get_str(mfx->installlocation), __get_str(mfx->package_size), mfx->removable, mfx->preload, mfx->readonly,
		mfx->update, mfx->appsetting, mfx->nodisplay_setting, mfx->system, __get_str(auth_name),
		__get_str(auth_email), __get_str(auth_href), mfx->installed_time, mfx->installed_storage,
		__get_str(mfx->storeclient_id),
		mfx->mainapp_id, __get_str(mfx->package_url), mfx->root_path, __get_str(mfx->csc_path), mfx->support_disable);

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
		snprintf(query, MAX_QUERY_LEN,
			"insert into package_privilege_info(package, privilege) " \
			"values('%s','%s')",\
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

	/*Insert in the package_app_splash_screen DB*/
	ret = __insert_application_legacy_splashscreen_info(mfx);
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
	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN,
		 "delete from %s where app_id='%s'", db_table, appid);
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

	snprintf(query, MAX_QUERY_LEN, "select app_id from package_app_info where package='%s'", mfx->package);
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
	snprintf(query, MAX_QUERY_LEN,
		 "delete from package_info where package='%s'", mfx->package);
	ret = __exec_query(query);
	if (ret == -1) {
		_LOGD("Package Info DB Delete Failed\n");
		return -1;
	}
	memset(query, '\0', MAX_QUERY_LEN);

	/*Delete from Package Localized Info*/
	snprintf(query, MAX_QUERY_LEN,
		 "delete from package_localized_info where package='%s'", mfx->package);
	ret = __exec_query(query);
	if (ret == -1) {
		_LOGD("Package Localized Info DB Delete Failed\n");
		return -1;
	}

	/*Delete from Package Privilege Info*/
	snprintf(query, MAX_QUERY_LEN,
		 "delete from package_privilege_info where package='%s'", mfx->package);
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
			"UPDATE package_app_info set app_disable='true' where app_id=%Q",
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
			"UPDATE package_app_info set app_disable='false' where app_id=%Q",
			appid);
	ret = __exec_query(query);
	if (ret == -1)
		_LOGD("Insert global app disable failed\n");

	return ret;
}

static int __disable_global_app_for_user(const char *appid, uid_t uid)
{
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};

	sqlite3_snprintf(MAX_QUERY_LEN, query, "INSERT INTO " \
			"package_app_disable_for_user(app_id, uid) VALUES(%Q, '%d')",
			appid, (int)uid);
	ret = __exec_query(query);
	if (ret == -1)
		_LOGD("Insert global app disable failed\n");

	return ret;
}

static int __enable_global_app_for_user(const char *appid, uid_t uid)
{
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};

	sqlite3_snprintf(MAX_QUERY_LEN, query, "DELETE FROM " \
			"package_app_disable_for_user WHERE app_id=%Q AND uid='%d'",
			appid, (int)uid);
	ret = __exec_query(query);
	if (ret == -1)
		_LOGD("Delete global app disable failed\n");

	return ret;
}

static int __update_preload_condition_in_db()
{
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};

	snprintf(query, MAX_QUERY_LEN, "update package_info set package_preload='true'");

	ret = __exec_query(query);
	if (ret == -1)
		_LOGD("Package preload_condition update failed\n");

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

	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_APP_DISABLE_FOR_USER);
	if (ret == -1) {
		_LOGD("package app disable for user DB initialization failed\n");
		return ret;
	}

	ret = __initialize_db(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_APP_SPLASH_SCREEN);
	if (ret == -1) {
		_LOGD("package app splash screen DB initialization failed\n");
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
	char journal_file[BUFSIZE];
	char *files[3];
	int ret, i;
	struct passwd *userinfo = NULL;
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
	userinfo = getpwuid(uid);
	if (!userinfo) {
		_LOGE("FAIL: user %d doesn't exist", uid);
		return -1;
	}
	snprintf(journal_file, sizeof(journal_file), "%s%s", db_file, "-journal");

	for (i = 0; files[i]; i++) {
		ret = chown(files[i], uid, userinfo->pw_gid);
		if (ret == -1) {
			if (strerror_r(errno, buf, sizeof(buf)))
				strcpy(buf, "");
			_LOGD("FAIL : chown %s %d.%d : %s", files[i], uid,
					userinfo->pw_gid, buf);
			return -1;
		}

		mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;
		if (!strcmp(db_file, getUserPkgCertDBPathUID(GLOBAL_USER)))
			mode |= S_IWOTH;
		ret = chmod(files[i], mode);
		if (ret == -1) {
			if (strerror_r(errno, buf, sizeof(buf)))
				strcpy(buf, "");
			_LOGD("FAIL : chmod %s 0664 : %s", files[i], buf);
			return -1;
		}
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

API int pkgmgr_parser_update_tep_info_in_db(const char *pkgid, const char *tep_path)
{
	return pkgmgr_parser_update_tep_info_in_usr_db(pkgid, tep_path, GLOBAL_USER);
}

API int pkgmgr_parser_update_tep_info_in_usr_db(const char *pkgid, const char *tep_path, uid_t uid)
{
	if (pkgid == NULL || tep_path == NULL) {
		_LOGE("invalid parameter");
		return -1;
	}

	int ret = -1;
	char *query = NULL;

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


	/* Updating TEP info in "package_info" table */
	query = sqlite3_mprintf("UPDATE package_info "\
						"SET package_tep_name = %Q "\
						"WHERE package = %Q", tep_path, pkgid);

	ret = __exec_query(query);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		ret = PM_PARSER_R_ERROR;
		_LOGE("sqlite exec failed to insert entries into package_info!!");
		goto err;
	}

	/* Updating TEP info in "package_app_info" table */
	query = sqlite3_mprintf("UPDATE package_app_info "\
						"SET app_tep_name = %Q "\
						"WHERE package = %Q", tep_path, pkgid);

	ret = __exec_query(query);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		ret = PM_PARSER_R_ERROR;
		_LOGE("sqlite exec failed to insert entries into package_app_info!!");
		goto err;
	}

	/*Commit transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("Failed to commit transaction, Rollback now\n");
		ret = sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		if (ret != SQLITE_OK)
			_LOGE("Failed to Rollback\n");

		ret = PM_PARSER_R_ERROR;
		goto err;
	}
	_LOGD("Transaction Commit and End\n");
	ret =  PM_PARSER_R_OK;

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
	return pkgmgr_parser_update_manifest_info_in_usr_db(mfx, GLOBAL_USER);
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
	return pkgmgr_parser_delete_manifest_info_from_usr_db(mfx, GLOBAL_USER);
}

API int pkgmgr_parser_update_preload_info_in_db()
{
	int ret = 0;
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
	ret = __update_preload_condition_in_db();
	if (ret == -1) {
		_LOGD("__update_preload_condition_in_db failed. Rollback now\n");
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

API int pkgmgr_parser_update_preload_info_in_usr_db(uid_t uid)
{
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
	ret = __update_preload_condition_in_db();
	if (ret == -1) {
		_LOGD("__update_preload_condition_in_db failed. Rollback now\n");
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
	return pkgmgr_parser_update_app_disable_info_in_usr_db(appid, GLOBAL_USER, is_disable);
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
