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
#include <sys/stat.h>
#include <unistd.h>
#include <db-util.h>
#include <glib.h>
#include "pkgmgr_parser_internal.h"
#include "pkgmgr_parser_db.h"

#define PKGMGR_PARSER_DB_FILE "/opt/dbspace/.pkgmgr_parser.db"
#define PKGMGR_CERT_DB_FILE "/opt/dbspace/.pkgmgr_cert.db"
#define MAX_QUERY_LEN		4096
sqlite3 *pkgmgr_parser_db;
sqlite3 *pkgmgr_cert_db;
GList *pkglocale = NULL;
GList *applocale = NULL;
GList *appicon = NULL;
GList *appimage = NULL;
char *prev = NULL;

#define QUERY_CREATE_TABLE_PACKAGE_INFO "create table if not exists package_info " \
						"(package text primary key not null, " \
						"package_type text DEFAULT 'rpm', " \
						"package_version text, " \
						"install_location text, " \
						"package_size text, " \
						"package_removable text DEFAULT 'true', " \
						"package_preload text DEFAULT 'false', " \
						"package_readonly text DEFAULT 'false', " \
						"package_update text DEFAULT 'false', " \
						"package_appsetting text DEFAULT 'false', " \
						"author_name text, " \
						"author_email text, " \
						"author_href text," \
						"installed_time text," \
						"installed_storage text," \
						"storeclient_id text," \
						"mainapp_id text," \
						"package_url text," \
						"root_path text)"

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
						"app_mainapp text, " \
						"app_recentimage text, " \
						"app_indicatordisplay text DEFAULT 'true', " \
						"app_portraitimg text, " \
						"app_landscapeimg text, " \
						"app_guestmodevisibility text DEFAULT 'true', " \
						"package text not null, " \
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
						"operation text not null, " \
						"uri_scheme text, " \
						"mime_type text, " \
						"subapp_name text, " \
						"PRIMARY KEY(app_id,operation,uri_scheme,mime_type,subapp_name) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_APP_SVC "create table if not exists package_app_app_svc " \
						"(app_id text not null, " \
						"operation text not null, " \
						"uri_scheme text, " \
						"mime_type text, " \
						"subapp_name text, " \
						"PRIMARY KEY(app_id,operation,uri_scheme,mime_type,subapp_name) " \
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
						"md_name text not null, " \
						"md_value text not null, " \
						"PRIMARY KEY(app_id, md_name) " \
						"FOREIGN KEY(app_id) " \
						"REFERENCES package_app_info(app_id) " \
						"ON DELETE CASCADE)"

#define QUERY_CREATE_TABLE_PACKAGE_APP_APP_PERMISSION "create table if not exists package_app_app_permission " \
						"(app_id text not null, " \
						"pm_type text not null, " \
						"pm_value text not null, " \
						"PRIMARY KEY(app_id) " \
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

#define QUERY_CREATE_TABLE_PACKAGE_CERT_INFO "create table if not exists package_cert_info " \
						"(package text not null, " \
						"author_root_cert text, " \
						"author_im_cert text, " \
						"author_signer_cert text, " \
						"dist_root_cert text, " \
						"dist_im_cert text, " \
						"dist_signer_cert text, " \
						"dist2_root_cert text, " \
						"dist2_im_cert text, " \
						"dist2_signer_cert text, " \
						"PRIMARY KEY(package), " \
						"FOREIGN KEY(package) " \
						"REFERENCES package_info(package) " \
						"ON DELETE CASCADE)"

static int __insert_uiapplication_info(manifest_x *mfx);
static int __insert_serviceapplication_info(manifest_x *mfx);
static int __insert_uiapplication_appsvc_info(manifest_x *mfx);
static int __insert_serviceapplication_appsvc_info(manifest_x *mfx);
static int __insert_uiapplication_appcategory_info(manifest_x *mfx);
static int __insert_serviceapplication_appcategory_info(manifest_x *mfx);
static int __insert_uiapplication_appcontrol_info(manifest_x *mfx);
static int __insert_serviceapplication_appmetadata_info(manifest_x *mfx);
static int __insert_uiapplication_appmetadata_info(manifest_x *mfx);
static int __insert_serviceapplication_appcontrol_info(manifest_x *mfx);
static int __insert_uiapplication_share_allowed_info(manifest_x *mfx);
static int __insert_serviceapplication_share_allowed_info(manifest_x *mfx);
static int __insert_uiapplication_share_request_info(manifest_x *mfx);
static int __insert_serviceapplication_share_request_info(manifest_x *mfx);
static void __insert_serviceapplication_locale_info(gpointer data, gpointer userdata);
static void __insert_uiapplication_locale_info(gpointer data, gpointer userdata);
static void __insert_pkglocale_info(gpointer data, gpointer userdata);
static int __insert_manifest_info_in_db(manifest_x *mfx);
static int __update_manifest_info_in_db(manifest_x *mfx);
static int __delete_cert_info_from_db(manifest_x *mfx);
static int __delete_manifest_info_from_db(manifest_x *mfx);
static int __initialize_package_info_db();
static int __initialize_package_localized_info_db();
static int __initialize_package_app_info_db();
static int __initialize_package_cert_info_db();
static int __initialize_package_app_localized_info_db();
static int __initialize_package_app_icon_section_info_db();
static int __initialize_package_app_image_info_db();
static int __initialize_package_app_app_svc_db();
static int __initialize_package_app_app_category_db();
static int __initialize_package_app_app_control_db();
static int __initialize_package_app_app_metadata_db();
static int __initialize_package_app_share_allowed_db();
static int __initialize_package_app_share_request_db();
static int __exec_query(char *query);
static void __extract_data(gpointer data, label_x *lbl, license_x *lcn, icon_x *icn, description_x *dcn, author_x *ath,
		char **label, char **license, char **icon, char **description, char **author);

static gint __comparefunc(gconstpointer a, gconstpointer b, gpointer userdata);
static void __trimfunc1(gpointer data, gpointer userdata);
static void __trimfunc2(gpointer data, gpointer userdata);
static GList *__create_locale_list(GList *locale, label_x *lbl, license_x *lcn, icon_x *icn, description_x *dcn, author_x *ath);
static void __preserve_guestmode_visibility_value(manifest_x *mfx);
static int __guestmode_visibility_cb(void *data, int ncols, char **coltxt, char **colname);

static int __guestmode_visibility_cb(void *data, int ncols, char **coltxt, char **colname)
{
	manifest_x *mfx = (manifest_x *)data;
	int i = 0;
	char *appid = NULL;
	char *status = NULL;
	uiapplication_x *uiapp = NULL;
	for(i = 0; i < ncols; i++)
	{
		uiapp = mfx->uiapplication;
		if (strcmp(colname[i], "app_id") == 0) {
			if (coltxt[i])
				appid = strdup(coltxt[i]);
		} else if (strcmp(colname[i], "app_guestmodevisibility") == 0) {
			if (coltxt[i])
				status = strdup(coltxt[i]);
		}
	}
	/*update guest mode visibility*/
	for (; uiapp != NULL; uiapp = uiapp->next) {
		if (strcmp(uiapp->appid, appid) == 0) {
			free((void *)uiapp->guestmode_visibility);
			uiapp->guestmode_visibility = strdup(status);
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
		DBG("Don't execute query = %s error message = %s\n",
		       query, error_message);
		sqlite3_free(error_message);
	}
	return;
}

static int __initialize_package_info_db()
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_INFO,
			 NULL, NULL, &error_message)) {
		DBG("Don't execute query = %s error message = %s\n",
		       QUERY_CREATE_TABLE_PACKAGE_INFO, error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __pkgmgr_parser_cert_create_db()
{
	int ret = -1;
	if (access(PKGMGR_CERT_DB_FILE, F_OK) == 0) {
		ret =
		    db_util_open(PKGMGR_CERT_DB_FILE, &pkgmgr_cert_db,
				 DB_UTIL_REGISTER_HOOK_METHOD);
		if (ret != SQLITE_OK) {
			DBG("connect db [%s] failed!\n",
			       PKGMGR_CERT_DB_FILE);
			return -1;
		}
		return 0;
	}
	DBG("Pkgmgr DB does not exists. Create one!!\n");

	ret =
	    db_util_open(PKGMGR_CERT_DB_FILE, &pkgmgr_cert_db,
			 DB_UTIL_REGISTER_HOOK_METHOD);

	if (ret != SQLITE_OK) {
		DBG("connect db [%s] failed!\n", PKGMGR_CERT_DB_FILE);
		return -1;
	}
	return 0;
}

static int __initialize_package_cert_info_db()
{
	char *error_message = NULL;
	int ret = -1;
	ret = __pkgmgr_parser_cert_create_db();
	if (ret == -1) {
		DBG("Failed to open DB\n");
		return ret;
	}

	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_cert_db, QUERY_CREATE_TABLE_PACKAGE_CERT_INFO,
			 NULL, NULL, &error_message)) {
		DBG("Don't execute query = %s error message = %s\n",
		       QUERY_CREATE_TABLE_PACKAGE_CERT_INFO, error_message);
		sqlite3_free(error_message);
		sqlite3_close(pkgmgr_cert_db);
		return -1;
	}
	sqlite3_free(error_message);
	sqlite3_close(pkgmgr_cert_db);
	return 0;
}

static int __initialize_package_localized_info_db()
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_parser_db,
			 QUERY_CREATE_TABLE_PACKAGE_LOCALIZED_INFO, NULL, NULL,
			 &error_message)) {
		DBG("Don't execute query = %s error message = %s\n",
		       QUERY_CREATE_TABLE_PACKAGE_LOCALIZED_INFO,
		       error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __initialize_package_app_info_db()
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_parser_db, QUERY_CREATE_TABLE_PACKAGE_APP_INFO,
			 NULL, NULL, &error_message)) {
		DBG("Don't execute query = %s error message = %s\n",
		       QUERY_CREATE_TABLE_PACKAGE_APP_INFO, error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __initialize_package_app_localized_info_db()
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_parser_db,
			 QUERY_CREATE_TABLE_PACKAGE_APP_LOCALIZED_INFO, NULL,
			 NULL, &error_message)) {
		DBG("Don't execute query = %s error message = %s\n",
		       QUERY_CREATE_TABLE_PACKAGE_APP_LOCALIZED_INFO,
		       error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __initialize_package_app_icon_section_info_db()
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_parser_db,
			 QUERY_CREATE_TABLE_PACKAGE_APP_ICON_SECTION_INFO, NULL,
			 NULL, &error_message)) {
		DBG("Don't execute query = %s error message = %s\n",
		       QUERY_CREATE_TABLE_PACKAGE_APP_ICON_SECTION_INFO,
		       error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __initialize_package_app_image_info_db()
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_parser_db,
			 QUERY_CREATE_TABLE_PACKAGE_APP_IMAGE_INFO, NULL,
			 NULL, &error_message)) {
		DBG("Don't execute query = %s error message = %s\n",
		       QUERY_CREATE_TABLE_PACKAGE_APP_IMAGE_INFO,
		       error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __initialize_package_app_app_control_db()
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_parser_db,
			 QUERY_CREATE_TABLE_PACKAGE_APP_APP_CONTROL, NULL, NULL,
			 &error_message)) {
		DBG("Don't execute query = %s error message = %s\n",
		       QUERY_CREATE_TABLE_PACKAGE_APP_APP_CONTROL, error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __initialize_package_app_app_category_db()
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_parser_db,
			 QUERY_CREATE_TABLE_PACKAGE_APP_APP_CATEGORY, NULL, NULL,
			 &error_message)) {
		DBG("Don't execute query = %s error message = %s\n",
		       QUERY_CREATE_TABLE_PACKAGE_APP_APP_CATEGORY, error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __initialize_package_app_app_metadata_db()
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_parser_db,
			 QUERY_CREATE_TABLE_PACKAGE_APP_APP_METADATA, NULL, NULL,
			 &error_message)) {
		DBG("Don't execute query = %s error message = %s\n",
		       QUERY_CREATE_TABLE_PACKAGE_APP_APP_METADATA, error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __initialize_package_app_app_permission_db()
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_parser_db,
			 QUERY_CREATE_TABLE_PACKAGE_APP_APP_PERMISSION, NULL, NULL,
			 &error_message)) {
		DBG("Don't execute query = %s error message = %s\n",
		       QUERY_CREATE_TABLE_PACKAGE_APP_APP_PERMISSION, error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __initialize_package_app_app_svc_db()
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_parser_db,
			 QUERY_CREATE_TABLE_PACKAGE_APP_APP_SVC, NULL, NULL,
			 &error_message)) {
		DBG("Don't execute query = %s error message = %s\n",
		       QUERY_CREATE_TABLE_PACKAGE_APP_APP_SVC, error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __initialize_package_app_share_allowed_db()
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_parser_db,
			 QUERY_CREATE_TABLE_PACKAGE_APP_SHARE_ALLOWED, NULL,
			 NULL, &error_message)) {
		DBG("Don't execute query = %s error message = %s\n",
		       QUERY_CREATE_TABLE_PACKAGE_APP_SHARE_ALLOWED,
		       error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}

static int __initialize_package_app_share_request_db()
{
	char *error_message = NULL;
	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_parser_db,
			 QUERY_CREATE_TABLE_PACKAGE_APP_SHARE_REQUEST, NULL,
			 NULL, &error_message)) {
		DBG("Don't execute query = %s error message = %s\n",
		       QUERY_CREATE_TABLE_PACKAGE_APP_SHARE_REQUEST,
		       error_message);
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
		DBG("Don't execute query = %s error message = %s\n", query,
		       error_message);
		sqlite3_free(error_message);
		return -1;
	}
	sqlite3_free(error_message);
	return 0;
}
static GList *__create_locale_list(GList *locale, label_x *lbl, license_x *lcn, icon_x *icn, description_x *dcn, author_x *ath)
{

	while(lbl != NULL)
	{
		if (lbl->lang)
			locale = g_list_insert_sorted_with_data(locale, (gpointer)lbl->lang, __comparefunc, NULL);
		lbl = lbl->next;
	}
	while(lcn != NULL)
	{
		if (lcn->lang)
			locale = g_list_insert_sorted_with_data(locale, (gpointer)lcn->lang, __comparefunc, NULL);
		lcn = lcn->next;
	}
	while(icn != NULL)
	{
		if (icn->lang)
			locale = g_list_insert_sorted_with_data(locale, (gpointer)icn->lang, __comparefunc, NULL);
		icn = icn->next;
	}
	while(dcn != NULL)
	{
		if (dcn->lang)
			locale = g_list_insert_sorted_with_data(locale, (gpointer)dcn->lang, __comparefunc, NULL);
		dcn = dcn->next;
	}
	while(ath != NULL)
	{
		if (ath->lang)
			locale = g_list_insert_sorted_with_data(locale, (gpointer)ath->lang, __comparefunc, NULL);
		ath = ath->next;
	}
	return locale;

}

static GList *__create_icon_list(GList *locale, icon_x *icn)
{
	while(icn != NULL)
	{
		if (icn->section)
			locale = g_list_insert_sorted_with_data(locale, (gpointer)icn->section, __comparefunc, NULL);
		icn = icn->next;
	}
	return locale;
}

static GList *__create_image_list(GList *locale, image_x *image)
{
	while(image != NULL)
	{
		if (image->section)
			locale = g_list_insert_sorted_with_data(locale, (gpointer)image->section, __comparefunc, NULL);
		image = image->next;
	}
	return locale;
}

static void __printfunc(gpointer data, gpointer userdata)
{
	DBG("%s  ", (char*)data);
}

static void __trimfunc1(gpointer data, gpointer userdata)
{
	if (prev) {
		if (strcmp((char *)data, prev) == 0) {
			pkglocale = g_list_remove(pkglocale, data);
		} else
			prev = (char *)data;
	}
	else
		prev = (char *)data;
}

static void __trimfunc2(gpointer data, gpointer userdata)
{
	if (prev) {
		if (strcmp((char *)data, prev) == 0) {
			applocale = g_list_remove(applocale, data);
		} else
			prev = (char *)data;
	}
	else
		prev = (char *)data;
}

static void __trimfunc3(gpointer data, gpointer userdata)
{
	if (prev) {
		if (strcmp((char *)data, prev) == 0) {
			appicon = g_list_remove(appicon, data);
		} else
			prev = (char *)data;
	}
	else
		prev = (char *)data;
}

static void __trimfunc4(gpointer data, gpointer userdata)
{
	if (prev) {
		if (strcmp((char *)data, prev) == 0) {
			appimage = g_list_remove(appimage, data);
		} else
			prev = (char *)data;
	}
	else
		prev = (char *)data;
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
}

static void __extract_data(gpointer data, label_x *lbl, license_x *lcn, icon_x *icn, description_x *dcn, author_x *ath,
		char **label, char **license, char **icon, char **description, char **author)
{
	while(lbl != NULL)
	{
		if (lbl->lang) {
			if (strcmp(lbl->lang, (char *)data) == 0) {
				*label = (char*)lbl->text;
				break;
			}
		}
		lbl = lbl->next;
	}
	while(lcn != NULL)
	{
		if (lcn->lang) {
			if (strcmp(lcn->lang, (char *)data) == 0) {
				*license = (char*)lcn->text;
				break;
			}
		}
		lcn = lcn->next;
	}
	while(icn != NULL)
	{
		if (icn->lang) {
			if (strcmp(icn->lang, (char *)data) == 0) {
				*icon = (char*)icn->text;
				break;
			}
		}
		icn = icn->next;
	}
	while(dcn != NULL)
	{
		if (dcn->lang) {
			if (strcmp(dcn->lang, (char *)data) == 0) {
				*description = (char*)dcn->text;
				break;
			}
		}
		dcn = dcn->next;
	}
	while(ath != NULL)
	{
		if (ath->lang) {
			if (strcmp(ath->lang, (char *)data) == 0) {
				*author = (char*)ath->text;
				break;
			}
		}
		ath = ath->next;
	}

}

static void __extract_icon_data(gpointer data, icon_x *icn, char **icon, char **resolution)
{
	while(icn != NULL)
	{
		if (icn->section) {
			if (strcmp(icn->section, (char *)data) == 0) {
				*icon = (char*)icn->text;
				*resolution = (char*)icn->resolution;
				break;
			}
		}
		icn = icn->next;
	}
}

static void __extract_image_data(gpointer data, icon_x *image, char **lang, char **img)
{
	while(image != NULL)
	{
		if (image->section) {
			if (strcmp(image->section, (char *)data) == 0) {
				*lang = (char*)image->lang;
				*img = (char*)image->text;
				break;
			}
		}
		image = image->next;
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
	char query[MAX_QUERY_LEN] = {'\0'};

	manifest_x *mfx = (manifest_x *)userdata;
	label_x *lbl = mfx->label;
	license_x *lcn = mfx->license;
	icon_x *icn = mfx->icon;
	description_x *dcn = mfx->description;
	author_x *ath = mfx->author;

	__extract_data(data, lbl, lcn, icn, dcn, ath, &label, &license, &icon, &description, &author);
	if (!label && !description && !icon && !license && !author)
		return;
	snprintf(query, MAX_QUERY_LEN, "insert into package_localized_info(package, package_locale, " \
		"package_label, package_icon, package_description, package_license, package_author) values " \
		"('%s', '%s', '%s', '%s', '%s', '%s', '%s')", mfx->package, (char*)data,
		label, icon, description, license, author);
	ret = __exec_query(query);
	if (ret == -1)
		DBG("Package Localized Info DB Insert failed\n");
}

static void __insert_uiapplication_locale_info(gpointer data, gpointer userdata)
{
	int ret = -1;
	char *label = NULL;
	char *icon = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};

	uiapplication_x *up = (uiapplication_x*)userdata;
	label_x *lbl = up->label;
	icon_x *icn = up->icon;

	__extract_data(data, lbl, NULL, icn, NULL, NULL, &label, NULL, &icon, NULL, NULL);
	if (!label && !icon)
		return;
	sqlite3_snprintf(MAX_QUERY_LEN, query, "insert into package_app_localized_info(app_id, app_locale, " \
		"app_label, app_icon) values " \
		"('%q', '%q', '%q', '%q')", up->appid, (char*)data,
		label, icon);
	ret = __exec_query(query);
	if (ret == -1)
		DBG("Package UiApp Localized Info DB Insert failed\n");

}

static void __insert_uiapplication_icon_section_info(gpointer data, gpointer userdata)
{
	int ret = -1;
	char *icon = NULL;
	char *resolution = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};

	uiapplication_x *up = (uiapplication_x*)userdata;
	icon_x *icn = up->icon;

	__extract_icon_data(data, icn, &icon, &resolution);
	if (!icon && !resolution)
		return;
	sqlite3_snprintf(MAX_QUERY_LEN, query, "insert into package_app_icon_section_info(app_id, " \
		"app_icon, app_icon_section, app_icon_resolution) values " \
		"('%q', '%q', '%q', '%q')", up->appid,
		icon, (char*)data, resolution);

	ret = __exec_query(query);
	if (ret == -1)
		DBG("Package UiApp Localized Info DB Insert failed\n");

}

static void __insert_uiapplication_image_info(gpointer data, gpointer userdata)
{
	int ret = -1;
	char *lang = NULL;
	char *img = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};

	uiapplication_x *up = (uiapplication_x*)userdata;
	image_x *image = up->image;

	__extract_image_data(data, image, &lang, &img);
	if (!lang && !img)
		return;
	sqlite3_snprintf(MAX_QUERY_LEN, query, "insert into package_app_image_info(app_id, app_locale, " \
		"app_image_section, app_image) values " \
		"('%q', '%q', '%q', '%q')", up->appid, lang, (char*)data, img);

	ret = __exec_query(query);
	if (ret == -1)
		DBG("Package UiApp image Info DB Insert failed\n");

}


static void __insert_serviceapplication_locale_info(gpointer data, gpointer userdata)
{
	int ret = -1;
	char *icon = NULL;
	char *label = NULL;
	char query[MAX_QUERY_LEN] = {'\0'};

	serviceapplication_x *sp = (serviceapplication_x*)userdata;
	label_x *lbl = sp->label;
	icon_x *icn = sp->icon;

	__extract_data(data, lbl, NULL, icn, NULL, NULL, &label, NULL, &icon, NULL, NULL);
	if (!icon && !label)
		return;
	sqlite3_snprintf(MAX_QUERY_LEN, query, "insert into package_app_localized_info(app_id, app_locale, " \
		"app_label, app_icon) values " \
		"('%q', '%q', '%q', '%q')", sp->appid, (char*)data,
		label, icon);
	ret = __exec_query(query);
	if (ret == -1)
		DBG("Package ServiceApp Localized Info DB Insert failed\n");
}

static int __insert_ui_mainapp_info(manifest_x *mfx)
{
	uiapplication_x *up = mfx->uiapplication;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	while(up != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			"update package_app_info set app_mainapp='%s' where app_id='%s'", up->mainapp, up->appid);

		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package UiApp Info DB Insert Failed\n");
			return -1;
		}
		if (strcasecmp(up->mainapp, "True")==0)
			mfx->mainapp_id = strdup(up->appid);

		up = up->next;
		memset(query, '\0', MAX_QUERY_LEN);
	}

	if (mfx->mainapp_id == NULL){
		if (mfx->uiapplication
		&& mfx->uiapplication->appid) {
			snprintf(query, MAX_QUERY_LEN,
			"update package_app_info set app_mainapp='true' where app_id='%s'", mfx->uiapplication->appid);
		} else if (mfx->serviceapplication
			&& mfx->serviceapplication->appid) {
	                snprintf(query, MAX_QUERY_LEN,
                        "update package_app_info set app_mainapp='true' where app_id='%s'", mfx->serviceapplication->appid);
                } else {
			DBG("Not valid appid\n");
                        return -1;
		}

		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package UiApp Info DB Insert Failed\n");
			return -1;
		}
                if (mfx->uiapplication && mfx->uiapplication->appid)
                        mfx->mainapp_id = strdup(mfx->uiapplication->appid);
                else if (mfx->serviceapplication && mfx->serviceapplication->appid)
                        mfx->mainapp_id = strdup(mfx->serviceapplication->appid);

}

	memset(query, '\0', MAX_QUERY_LEN);
	snprintf(query, MAX_QUERY_LEN,
		"update package_info set mainapp_id='%s' where package='%s'", mfx->mainapp_id, mfx->package);
	ret = __exec_query(query);
	if (ret == -1) {
		DBG("Package Info DB update Failed\n");
		return -1;
	}

	return 0;
}
/* _PRODUCT_LAUNCHING_ENHANCED_
*  up->indicatordisplay, up->portraitimg, up->landscapeimg, up->guestmode_appstatus
*/
static int __insert_uiapplication_info(manifest_x *mfx)
{
	uiapplication_x *up = mfx->uiapplication;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	while(up != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "insert into package_app_info(app_id, app_component, app_exec, app_nodisplay, app_type, app_onboot, " \
			"app_multiple, app_autorestart, app_taskmanage, app_enabled, app_hwacceleration, app_mainapp , app_recentimage, app_indicatordisplay, app_portraitimg, app_landscapeimg, app_guestmodevisibility, package) " \
			"values('%s', '%s', '%s', '%s', '%s', '%s','%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')",\
			 up->appid, "uiapp", up->exec, up->nodisplay, up->type, "\0", up->multiple,
			 "\0", up->taskmanage, up->enabled, up->hwacceleration,up->mainapp, up->recentimage, up->indicatordisplay, up->portraitimg, up->landscapeimg, up->guestmode_visibility, mfx->package);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package UiApp Info DB Insert Failed\n");
			return -1;
		}
		up = up->next;
		memset(query, '\0', MAX_QUERY_LEN);
	}
	return 0;
}

static int __insert_uiapplication_appcategory_info(manifest_x *mfx)
{
	uiapplication_x *up = mfx->uiapplication;
	category_x *ct = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	while(up != NULL)
	{
		ct = up->category;
		while (ct != NULL)
		{
			snprintf(query, MAX_QUERY_LEN,
				"insert into package_app_app_category(app_id, category) " \
				"values('%s','%s')",\
				 up->appid, ct->name);
			ret = __exec_query(query);
			if (ret == -1) {
				DBG("Package UiApp Category Info DB Insert Failed\n");
				return -1;
			}
			ct = ct->next;
			memset(query, '\0', MAX_QUERY_LEN);
		}
		up = up->next;
	}
	return 0;
}

static int __insert_uiapplication_appmetadata_info(manifest_x *mfx)
{
	uiapplication_x *up = mfx->uiapplication;
	metadata_x *md = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	while(up != NULL)
	{
		md = up->metadata;
		while (md != NULL)
		{
			if (md->name && md->value) {
				snprintf(query, MAX_QUERY_LEN,
					"insert into package_app_app_metadata(app_id, md_name, md_value) " \
					"values('%s','%s', '%s')",\
					 up->appid, md->name, md->value);
				ret = __exec_query(query);
				if (ret == -1) {
					DBG("Package UiApp Metadata Info DB Insert Failed\n");
					return -1;
				}
			}
			md = md->next;
			memset(query, '\0', MAX_QUERY_LEN);
		}
		up = up->next;
	}
	return 0;
}

static int __insert_uiapplication_apppermission_info(manifest_x *mfx)
{
	uiapplication_x *up = mfx->uiapplication;
	permission_x *pm = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	while(up != NULL)
	{
		pm = up->permission;
		while (pm != NULL)
		{
			snprintf(query, MAX_QUERY_LEN,
				"insert into package_app_app_permission(app_id, pm_type, pm_value) " \
				"values('%s','%s', '%s')",\
				 up->appid, pm->type, pm->value);
			ret = __exec_query(query);
			if (ret == -1) {
				DBG("Package UiApp permission Info DB Insert Failed\n");
				return -1;
			}
			pm = pm->next;
			memset(query, '\0', MAX_QUERY_LEN);
		}
		up = up->next;
	}
	return 0;
}

static int __insert_uiapplication_appcontrol_info(manifest_x *mfx)
{
	uiapplication_x *up = mfx->uiapplication;
	appcontrol_x *acontrol = NULL;
	operation_x *op = NULL;
	mime_x *mi = NULL;
	uri_x *ui = NULL;
	subapp_x *sub = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *operation = NULL;
	char *mime = NULL;
	char *uri = NULL;
	char *subapp = NULL;
	while(up != NULL)
	{
		acontrol = up->appcontrol;
		while(acontrol != NULL)
		{
			op = acontrol->operation;
			while(op != NULL)
			{
				if (op)
					operation = op->name;
				mi = acontrol->mime;

				do
				{
					if (mi)
						mime = mi->name;
					sub = acontrol->subapp;
					do
					{
						if (sub)
							subapp = sub->name;
						ui = acontrol->uri;
						do
						{
							if (ui)
								uri = ui->name;
							snprintf(query, MAX_QUERY_LEN,
								 "insert into package_app_app_control(app_id, operation, uri_scheme, mime_type, subapp_name) " \
								"values('%s', '%s', '%s', '%s', '%s')",\
								 up->appid, operation, uri, mime, subapp);

							ret = __exec_query(query);
							if (ret == -1) {
								DBG("Package UiApp AppSvc DB Insert Failed\n");
								return -1;
							}
							memset(query, '\0', MAX_QUERY_LEN);
							if (ui)
								ui = ui->next;
							uri = NULL;
						} while(ui != NULL);
						if (sub)
							sub = sub->next;
						subapp = NULL;
					}while(sub != NULL);
					if (mi)
						mi = mi->next;
					mime = NULL;
				}while(mi != NULL);
				if (op)
					op = op->next;
				operation = NULL;
			}
			acontrol = acontrol->next;
		}
		up = up->next;
	}
	return 0;
}

static int __insert_uiapplication_appsvc_info(manifest_x *mfx)
{
	uiapplication_x *up = mfx->uiapplication;
	appsvc_x *asvc = NULL;
	operation_x *op = NULL;
	mime_x *mi = NULL;
	uri_x *ui = NULL;
	subapp_x *sub = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	char *operation = NULL;
	char *mime = NULL;
	char *uri = NULL;
	char *subapp = NULL;
	while(up != NULL)
	{
		asvc = up->appsvc;
		while(asvc != NULL)
		{
			op = asvc->operation;
			while(op != NULL)
			{
				if (op)
					operation = op->name;
				mi = asvc->mime;

				do
				{
					if (mi)
						mime = mi->name;
					sub = asvc->subapp;
					do
					{
						if (sub)
							subapp = sub->name;
						ui = asvc->uri;
						do
						{
							if (ui)
								uri = ui->name;
							snprintf(query, MAX_QUERY_LEN,
								 "insert into package_app_app_svc(app_id, operation, uri_scheme, mime_type, subapp_name) " \
								"values('%s', '%s', '%s', '%s', '%s')",\
								 up->appid, operation, uri, mime, subapp);

							ret = __exec_query(query);
							if (ret == -1) {
								DBG("Package UiApp AppSvc DB Insert Failed\n");
								return -1;
							}
							memset(query, '\0', MAX_QUERY_LEN);
							if (ui)
								ui = ui->next;
							uri = NULL;
						} while(ui != NULL);
						if (sub)
							sub = sub->next;
						subapp = NULL;
					}while(sub != NULL);
					if (mi)
						mi = mi->next;
					mime = NULL;
				}while(mi != NULL);
				if (op)
					op = op->next;
				operation = NULL;
			}
			asvc = asvc->next;
		}
		up = up->next;
	}
	return 0;
}

static int __insert_uiapplication_share_request_info(manifest_x *mfx)
{
	uiapplication_x *up = mfx->uiapplication;
	datashare_x *ds = NULL;
	request_x *rq = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	while(up != NULL)
	{
		ds = up->datashare;
		while(ds != NULL)
		{
			rq = ds->request;
			while(rq != NULL)
			{
				snprintf(query, MAX_QUERY_LEN,
					 "insert into package_app_share_request(app_id, data_share_request) " \
					"values('%s', '%s')",\
					 up->appid, rq->text);
				ret = __exec_query(query);
				if (ret == -1) {
					DBG("Package UiApp Share Request DB Insert Failed\n");
					return -1;
				}
				memset(query, '\0', MAX_QUERY_LEN);
				rq = rq->next;
			}
			ds = ds->next;
		}
		up = up->next;
	}
	return 0;
}

static int __insert_uiapplication_share_allowed_info(manifest_x *mfx)
{
	uiapplication_x *up = mfx->uiapplication;
	datashare_x *ds = NULL;
	define_x *df = NULL;
	allowed_x *al = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	while(up != NULL)
	{
		ds = up->datashare;
		while(ds != NULL)
		{
			df = ds->define;
			while(df != NULL)
			{
				al = df->allowed;
				while(al != NULL)
				{
					snprintf(query, MAX_QUERY_LEN,
						 "insert into package_app_share_allowed(app_id, data_share_path, data_share_allowed) " \
						"values('%s', '%s', '%s')",\
						 up->appid, df->path, al->text);
					ret = __exec_query(query);
					if (ret == -1) {
						DBG("Package UiApp Share Allowed DB Insert Failed\n");
						return -1;
					}
					memset(query, '\0', MAX_QUERY_LEN);
					al = al->next;
				}
				df = df->next;
			}
			ds = ds->next;
		}
		up = up->next;
	}
	return 0;
}

static int __insert_serviceapplication_info(manifest_x *mfx)
{
	serviceapplication_x *sp = mfx->serviceapplication;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	while(sp != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "insert into package_app_info(app_id, app_component, app_exec, app_type, app_onboot, " \
			"app_multiple, app_autorestart, app_enabled, package) " \
			"values('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')",\
			 sp->appid, "svcapp", sp->exec, sp->type, sp->onboot, "\0",
			 sp->autorestart, sp->enabled, mfx->package);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package ServiceApp Info DB Insert Failed\n");
			return -1;
		}
		sp = sp->next;
		memset(query, '\0', MAX_QUERY_LEN);
	}
	return 0;
}

static int __insert_serviceapplication_appcategory_info(manifest_x *mfx)
{
	serviceapplication_x *sp = mfx->serviceapplication;
	category_x *ct = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	while(sp != NULL)
	{
		ct = sp->category;
		while (ct != NULL)
		{
			snprintf(query, MAX_QUERY_LEN,
				"insert into package_app_app_category(app_id, category) " \
				"values('%s','%s')",\
				 sp->appid, ct->name);
			ret = __exec_query(query);
			if (ret == -1) {
				DBG("Package ServiceApp Category Info DB Insert Failed\n");
				return -1;
			}
			ct = ct->next;
			memset(query, '\0', MAX_QUERY_LEN);
		}
		sp = sp->next;
	}
	return 0;
}

static int __insert_serviceapplication_appmetadata_info(manifest_x *mfx)
{
	serviceapplication_x *sp = mfx->serviceapplication;
	metadata_x *md = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	while(sp != NULL)
	{
		md = sp->metadata;
		while (md != NULL)
		{
			if (md->name && md->value) {
				snprintf(query, MAX_QUERY_LEN,
					"insert into package_app_app_metadata(app_id, md_name, md_value) " \
					"values('%s','%s', '%s')",\
					 sp->appid, md->name, md->value);
				ret = __exec_query(query);
				if (ret == -1) {
					DBG("Package ServiceApp Metadata Info DB Insert Failed\n");
					return -1;
				}
			}
			md = md->next;
			memset(query, '\0', MAX_QUERY_LEN);
		}
		sp = sp->next;
	}
	return 0;
}

static int __insert_serviceapplication_apppermission_info(manifest_x *mfx)
{
	serviceapplication_x *sp = mfx->serviceapplication;
	permission_x *pm = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	while(sp != NULL)
	{
		pm = sp->permission;
		while (pm != NULL)
		{
			snprintf(query, MAX_QUERY_LEN,
				"insert into package_app_app_permission(app_id, pm_type, pm_value) " \
				"values('%s','%s', '%s')",\
				 sp->appid, pm->type, pm->value);
			ret = __exec_query(query);
			if (ret == -1) {
				DBG("Package ServiceApp permission Info DB Insert Failed\n");
				return -1;
			}
			pm = pm->next;
			memset(query, '\0', MAX_QUERY_LEN);
		}
		sp = sp->next;
	}
	return 0;
}

static int __insert_serviceapplication_appcontrol_info(manifest_x *mfx)
{
	serviceapplication_x *sp = mfx->serviceapplication;
	appcontrol_x *acontrol = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	operation_x *op = NULL;
	mime_x *mi = NULL;
	uri_x *ui = NULL;
	subapp_x *sub = NULL;
	char *operation = NULL;
	char *mime = NULL;
	char *uri = NULL;
	char *subapp = NULL;
	while(sp != NULL)
	{
		acontrol = sp->appcontrol;
		while(acontrol != NULL)
		{
			op = acontrol->operation;
			while(op != NULL)
			{
			if (op)
				operation = op->name;
			mi = acontrol->mime;
				do
				{
				if (mi)
					mime = mi->name;
				sub = acontrol->subapp;
					do
					{
					if (sub)
						subapp = sub->name;
					ui = acontrol->uri;
						do
						{
							if (ui)
								uri = ui->name;
							snprintf(query, MAX_QUERY_LEN,
								 "insert into package_app_app_control(app_id, operation, uri_scheme, mime_type,subapp_name) " \
								"values('%s', '%s', '%s', '%s', '%s')",\
								 sp->appid, operation, uri, mime, subapp);
							ret = __exec_query(query);
							if (ret == -1) {
								DBG("Package UiApp AppSvc DB Insert Failed\n");
								return -1;
							}
							memset(query, '\0', MAX_QUERY_LEN);
							if (ui)
								ui = ui->next;
							uri = NULL;
						} while(ui != NULL);
						if (sub)
							sub = sub->next;
						subapp = NULL;
						}while(sub != NULL);
					if (mi)
						mi = mi->next;
					mime = NULL;
				}while(mi != NULL);
				if (op)
					op = op->next;
				operation = NULL;
			}
			acontrol = acontrol->next;
		}
		sp = sp->next;
	}
	return 0;
}

static int __insert_serviceapplication_appsvc_info(manifest_x *mfx)
{
	serviceapplication_x *sp = mfx->serviceapplication;
	appsvc_x *asvc = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	operation_x *op = NULL;
	mime_x *mi = NULL;
	uri_x *ui = NULL;
	subapp_x *sub = NULL;
	char *operation = NULL;
	char *mime = NULL;
	char *uri = NULL;
	char *subapp = NULL;
	while(sp != NULL)
	{
		asvc = sp->appsvc;
		while(asvc != NULL)
		{
			op = asvc->operation;
			while(op != NULL)
			{
			if (op)
				operation = op->name;
			mi = asvc->mime;
				do
				{
				if (mi)
					mime = mi->name;
				sub = asvc->subapp;
					do
					{
					if (sub)
						subapp = sub->name;
					ui = asvc->uri;
							do
							{
								if (ui)
									uri = ui->name;
								snprintf(query, MAX_QUERY_LEN,
									 "insert into package_app_app_svc(app_id, operation, uri_scheme, mime_type, subapp_name) " \
									"values('%s', '%s', '%s', '%s', '%s')",\
									 sp->appid, operation, uri, mime, subapp);
								ret = __exec_query(query);
								if (ret == -1) {
									DBG("Package UiApp AppSvc DB Insert Failed\n");
									return -1;
								}
								memset(query, '\0', MAX_QUERY_LEN);
								if (ui)
									ui = ui->next;
								uri = NULL;
							} while(ui != NULL);
						if (sub)
							sub	= sub->next;
						subapp = NULL;
					}while(sub != NULL);
					if (mi)
						mi = mi->next;
					mime = NULL;
				}while(mi != NULL);
				if (op)
					op = op->next;
				operation = NULL;
			}
			asvc = asvc->next;
		}
		sp = sp->next;
	}
	return 0;
}



static int __insert_serviceapplication_share_request_info(manifest_x *mfx)
{
	serviceapplication_x *sp = mfx->serviceapplication;
	datashare_x *ds = NULL;
	request_x *rq = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	while(sp != NULL)
	{
		ds = sp->datashare;
		while(ds != NULL)
		{
			rq = ds->request;
			while(rq != NULL)
			{
				snprintf(query, MAX_QUERY_LEN,
					 "insert into package_app_share_request(app_id, data_share_request) " \
					"values('%s', '%s')",\
					 sp->appid, rq->text);
				ret = __exec_query(query);
				if (ret == -1) {
					DBG("Package ServiceApp Share Request DB Insert Failed\n");
					return -1;
				}
				memset(query, '\0', MAX_QUERY_LEN);
				rq = rq->next;
			}
			ds = ds->next;
		}
		sp = sp->next;
	}
	return 0;
}



static int __insert_serviceapplication_share_allowed_info(manifest_x *mfx)
{
	serviceapplication_x *sp = mfx->serviceapplication;
	datashare_x *ds = NULL;
	define_x *df = NULL;
	allowed_x *al = NULL;
	int ret = -1;
	char query[MAX_QUERY_LEN] = {'\0'};
	while(sp != NULL)
	{
		ds = sp->datashare;
		while(ds != NULL)
		{
			df = ds->define;
			while(df != NULL)
			{
				al = df->allowed;
				while(al != NULL)
				{
					snprintf(query, MAX_QUERY_LEN,
						 "insert into package_app_share_allowed(app_id, data_share_path, data_share_allowed) " \
						"values('%s', '%s', '%s')",\
						 sp->appid, df->path, al->text);
					ret = __exec_query(query);
					if (ret == -1) {
						DBG("Package App Share Allowed DB Insert Failed\n");
						return -1;
					}
					memset(query, '\0', MAX_QUERY_LEN);
					al = al->next;
				}
				df = df->next;
			}
			ds = ds->next;
		}
		sp = sp->next;
	}
	return 0;
}

static int __insert_manifest_info_in_db(manifest_x *mfx)
{
	label_x *lbl = mfx->label;
	license_x *lcn = mfx->license;
	icon_x *icn = mfx->icon;
	description_x *dcn = mfx->description;
	author_x *ath = mfx->author;
	uiapplication_x *up = mfx->uiapplication;
	uiapplication_x *up_icn = mfx->uiapplication;
	uiapplication_x *up_image = mfx->uiapplication;
	serviceapplication_x *sp = mfx->serviceapplication;
	char query[MAX_QUERY_LEN] = { '\0' };
	int ret = -1;
	char *type = NULL;
	char *path = NULL;
	char *auth_name = NULL;
	char *auth_email = NULL;
	char *auth_href = NULL;
	if (ath) {
		if (ath->text)
			auth_name = ath->text;
		if (ath->email)
			auth_email = ath->email;
		if (ath->href)
			auth_href = ath->href;
	}

	/*Insert in the package_info DB*/
	if (mfx->type)
		type = strdup(mfx->type);
	else
		type = strdup("rpm");
	/*Insert in the package_info DB*/
	if (mfx->root_path)
		path = strdup(mfx->root_path);
	else{
		if (strcmp(type,"rpm")==0)
			path = strdup("/usr/apps");
		else
			path = strdup("/opt/usr/apps");
	}
	snprintf(query, MAX_QUERY_LEN,
		 "insert into package_info(package, package_type, package_version, install_location, package_size, " \
		"package_removable, package_preload, package_readonly, package_update, package_appsetting, author_name, author_email, author_href, installed_time, installed_storage, storeclient_id, mainapp_id, package_url, root_path) " \
		"values('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')",\
		 mfx->package, type, mfx->version, mfx->installlocation, mfx->package_size, mfx->removable, mfx->preload,
		 mfx->readonly, mfx->update, mfx->appsetting, auth_name, auth_email, auth_href, mfx->installed_time, mfx->installed_storage, mfx->storeclient_id, mfx->mainapp_id, mfx->package_url, path);
	ret = __exec_query(query);
	if (ret == -1) {
		DBG("Package Info DB Insert Failed\n");
		if (type) {
			free(type);
			type = NULL;
		}
		if (path) {
			free(path);
			path = NULL;
		}
		return -1;
	}
	if (type) {
		free(type);
		type = NULL;
	}
	if (path) {
		free(path);
		path = NULL;
	}
	/*Insert the package locale and app locale info */
	pkglocale = __create_locale_list(pkglocale, lbl, lcn, icn, dcn, ath);
	g_list_foreach(pkglocale, __trimfunc1, NULL);
	prev = NULL;

	while(up != NULL)
	{
		applocale = __create_locale_list(applocale, up->label, NULL, up->icon, NULL, NULL);
		up = up->next;
	}
	while(sp != NULL)
	{
		applocale = __create_locale_list(applocale, sp->label, NULL, sp->icon, NULL, NULL);
		sp = sp->next;
	}
	g_list_foreach(applocale, __trimfunc2, NULL);
	prev = NULL;

	/*Insert the app icon info */
	while(up_icn != NULL)
	{
		appicon = __create_icon_list(appicon, up_icn->icon);
		up_icn = up_icn->next;
	}
	g_list_foreach(appicon, __trimfunc3, NULL);
	prev = NULL;

	/*Insert the image info */
	while(up_image != NULL)
	{
		appimage = __create_image_list(appimage, up_image->image);
		up_image = up_image->next;
	}
	g_list_foreach(appimage, __trimfunc4, NULL);
	prev = NULL;

	/*g_list_foreach(pkglocale, __printfunc, NULL);*/
	/*DBG("\n");*/
	/*g_list_foreach(applocale, __printfunc, NULL);*/

	/*package locale info*/
	g_list_foreach(pkglocale, __insert_pkglocale_info, (gpointer)mfx);
	/*native app locale info*/
	up = mfx->uiapplication;
	while(up != NULL)
	{
		g_list_foreach(applocale, __insert_uiapplication_locale_info, (gpointer)up);
		up = up->next;
	}
	/*agent app locale info*/
	sp = mfx->serviceapplication;
	while(sp != NULL)
	{
		g_list_foreach(applocale, __insert_serviceapplication_locale_info, (gpointer)sp);
		sp = sp->next;
	}

	/*app icon locale info*/
	up_icn = mfx->uiapplication;
	while(up_icn != NULL)
	{
		g_list_foreach(appicon, __insert_uiapplication_icon_section_info, (gpointer)up_icn);
		up_icn = up_icn->next;
	}

	/*app image info*/
	up_image = mfx->uiapplication;
	while(up_image != NULL)
	{
		g_list_foreach(appimage, __insert_uiapplication_image_info, (gpointer)up_image);
		up_image = up_image->next;
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
	ret = __insert_uiapplication_info(mfx);
	if (ret == -1)
		return -1;
	ret = __insert_ui_mainapp_info(mfx);
	if (ret == -1)
		return -1;
	ret = __insert_serviceapplication_info(mfx);
	if (ret == -1)
		return -1;

	/*Insert in the package_app_app_control DB*/
	ret = __insert_uiapplication_appcontrol_info(mfx);
	if (ret == -1)
		return -1;
	ret = __insert_serviceapplication_appcontrol_info(mfx);
	if (ret == -1)
		return -1;

	/*Insert in the package_app_app_category DB*/
	ret = __insert_uiapplication_appcategory_info(mfx);
	if (ret == -1)
		return -1;
	ret = __insert_serviceapplication_appcategory_info(mfx);
	if (ret == -1)
		return -1;

	/*Insert in the package_app_app_metadata DB*/
	ret = __insert_uiapplication_appmetadata_info(mfx);
	if (ret == -1)
		return -1;
	ret = __insert_serviceapplication_appmetadata_info(mfx);
	if (ret == -1)
		return -1;

	/*Insert in the package_app_app_permission DB*/
	ret = __insert_uiapplication_apppermission_info(mfx);
	if (ret == -1)
		return -1;
	ret = __insert_serviceapplication_apppermission_info(mfx);
	if (ret == -1)
		return -1;

	/*Insert in the package_app_app_svc DB*/
	ret = __insert_uiapplication_appsvc_info(mfx);
	if (ret == -1)
		return -1;
	ret = __insert_serviceapplication_appsvc_info(mfx);
	if (ret == -1)
		return -1;

	/*Insert in the package_app_share_allowed DB*/
	ret = __insert_uiapplication_share_allowed_info(mfx);
	if (ret == -1)
		return -1;
	ret = __insert_serviceapplication_share_allowed_info(mfx);
	if (ret == -1)
		return -1;

	/*Insert in the package_app_share_request DB*/
	ret = __insert_uiapplication_share_request_info(mfx);
	if (ret == -1)
		return -1;
	ret = __insert_serviceapplication_share_request_info(mfx);
	if (ret == -1)
		return -1;

	return 0;

}

static int __delete_cert_info_from_db(manifest_x *mfx)
{
	char query[MAX_QUERY_LEN] = { '\0' };
	int ret = -1;
	char *error_message = NULL;

	ret = __pkgmgr_parser_cert_create_db();
	if (ret == -1) {
		DBG("Failed to open DB\n");
		return ret;
	}

	/*Begin transaction*/
	ret = sqlite3_exec(pkgmgr_cert_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		DBG("Failed to begin transaction\n");
		sqlite3_close(pkgmgr_cert_db);
		return -1;
	}
	DBG("Transaction Begin\n");
	snprintf(query, MAX_QUERY_LEN,
		 "delete from package_cert_info where package='%s'", mfx->package);

	if (SQLITE_OK !=
	    sqlite3_exec(pkgmgr_cert_db, query, NULL, NULL, &error_message)) {
		DBG("Don't execute query = %s error message = %s\n", query,
		       error_message);
		ret = -1;
	}
	sqlite3_free(error_message);

	if (ret == -1) {
		DBG("Delete from DB failed. Rollback now\n");
		sqlite3_exec(pkgmgr_cert_db, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(pkgmgr_cert_db);
		return -1;
	}
	/*Commit transaction*/
	ret = sqlite3_exec(pkgmgr_cert_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		DBG("Failed to commit transaction, Rollback now\n");
		sqlite3_exec(pkgmgr_cert_db, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(pkgmgr_cert_db);
		return -1;
	}
	DBG("Transaction Commit and End\n");
	sqlite3_free(error_message);
	sqlite3_close(pkgmgr_cert_db);
	return 0;

}

static int __delete_manifest_info_from_db(manifest_x *mfx)
{
	char query[MAX_QUERY_LEN] = { '\0' };
	int ret = -1;
	uiapplication_x *up = mfx->uiapplication;
	serviceapplication_x *sp = mfx->serviceapplication;

	ret = __delete_cert_info_from_db(mfx);
	if (ret == -1) {
		DBG("Package cert DB Delete Failed\n");
		return -1;
	}

	/*Delete from Package Info DB*/
	snprintf(query, MAX_QUERY_LEN,
		 "delete from package_info where package='%s'", mfx->package);
	ret = __exec_query(query);
	if (ret == -1) {
		DBG("Package Info DB Delete Failed\n");
		return -1;
	}
	memset(query, '\0', MAX_QUERY_LEN);

	/*Delete from Package Localized Info*/
	snprintf(query, MAX_QUERY_LEN,
		 "delete from package_localized_info where package='%s'", mfx->package);
	ret = __exec_query(query);
	if (ret == -1) {
		DBG("Package Localized Info DB Delete Failed\n");
		return -1;
	}
	memset(query, '\0', MAX_QUERY_LEN);

	/*Delete from Package App Info*/
	while(up != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_info where app_id='%s'", up->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App Info DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		up = up->next;
	}
	while(sp != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_info where app_id='%s'", sp->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App Info DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		sp = sp->next;
	}

	/*Delete from Package App Localized Info*/
	up = mfx->uiapplication;
	sp = mfx->serviceapplication;
	while(up != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_localized_info where app_id='%s'", up->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App Localized Info DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		up = up->next;
	}
	while(sp != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_localized_info where app_id='%s'", sp->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App Localized Info DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		sp = sp->next;
	}

	/*Delete from  App icon localized Info*/
	up = mfx->uiapplication;
	while(up != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_icon_section_info where app_id='%s'", up->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App image Info DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		up = up->next;
	}

	/*Delete from  App image Info*/
	up = mfx->uiapplication;
	while(up != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_image_info where app_id='%s'", up->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App image Info DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		up = up->next;
	}

	/*Delete from Package App App-Svc*/
	up = mfx->uiapplication;
	sp = mfx->serviceapplication;
	while(up != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_app_svc where app_id='%s'", up->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App App-Svc DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		up = up->next;
	}
	while(sp != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_app_svc where app_id='%s'", sp->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App App-Svc DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		sp = sp->next;
	}

	/*Delete from Package App App-Control*/
	up = mfx->uiapplication;
	sp = mfx->serviceapplication;
	while(up != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_app_control where app_id='%s'", up->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App App-Control DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		up = up->next;
	}
	while(sp != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_app_control where app_id='%s'", sp->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App App-Control DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		sp = sp->next;
	}

	/*Delete from Package App App-Category*/
	up = mfx->uiapplication;
	sp = mfx->serviceapplication;
	while(up != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_app_category where app_id='%s'", up->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App App-Category DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		up = up->next;
	}
	while(sp != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_app_category where app_id='%s'", sp->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App App-Category DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		sp = sp->next;
	}

	/*Delete from Package App App-Metadata*/
	up = mfx->uiapplication;
	sp = mfx->serviceapplication;
	while(up != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_app_metadata where app_id='%s'", up->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App App-Metadata DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		up = up->next;
	}
	while(sp != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_app_metadata where app_id='%s'", sp->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App App-Metadata DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		sp = sp->next;
	}

	/*Delete from Package App App-permission*/
	up = mfx->uiapplication;
	sp = mfx->serviceapplication;
	while(up != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_app_permission where app_id='%s'", up->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App App-permission DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		up = up->next;
	}
	while(sp != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_app_permission where app_id='%s'", sp->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App App-permission DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		sp = sp->next;
	}

	/*Delete from Package App Share Allowed*/
	up = mfx->uiapplication;
	sp = mfx->serviceapplication;
	while(up != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_share_allowed where app_id='%s'", up->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App Share Allowed DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		up = up->next;
	}
	while(sp != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_share_allowed where app_id='%s'", sp->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App Share Allowed DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		sp = sp->next;
	}

	/*Delete from Package App Share Request*/
	up = mfx->uiapplication;
	sp = mfx->serviceapplication;
	while(up != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_share_request where app_id='%s'", up->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App Share Request DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		up = up->next;
	}
	while(sp != NULL)
	{
		snprintf(query, MAX_QUERY_LEN,
			 "delete from package_app_share_request where app_id='%s'", sp->appid);
		ret = __exec_query(query);
		if (ret == -1) {
			DBG("Package App Share Request DB Delete Failed\n");
			return -1;
		}
		memset(query, '\0', MAX_QUERY_LEN);
		sp = sp->next;
	}
	return 0;
}


int pkgmgr_parser_initialize_db()
{
	int ret = -1;
	ret = __initialize_package_info_db();
	if (ret == -1) {
		DBG("package info DB initialization failed\n");
		return ret;
	}
	ret = __initialize_package_localized_info_db();
	if (ret == -1) {
		DBG("package localized info DB initialization failed\n");
		return ret;
	}
	ret = __initialize_package_cert_info_db();
	if (ret == -1) {
		DBG("package cert info DB initialization failed\n");
		return ret;
	}
	ret = __initialize_package_app_info_db();
	if (ret == -1) {
		DBG("package app info DB initialization failed\n");
		return ret;
	}
	ret = __initialize_package_app_localized_info_db();
	if (ret == -1) {
		DBG("package app localized info DB initialization failed\n");
		return ret;
	}
	ret = __initialize_package_app_icon_section_info_db();
	if (ret == -1) {
		DBG("package app icon localized info DB initialization failed\n");
		return ret;
	}
	ret = __initialize_package_app_image_info_db();
	if (ret == -1) {
		DBG("package app image info DB initialization failed\n");
		return ret;
	}
	ret = __initialize_package_app_app_control_db();
	if (ret == -1) {
		DBG("package app app control DB initialization failed\n");
		return ret;
	}
	ret = __initialize_package_app_app_category_db();
	if (ret == -1) {
		DBG("package app app category DB initialization failed\n");
		return ret;
	}
	ret = __initialize_package_app_app_metadata_db();
	if (ret == -1) {
		DBG("package app app category DB initialization failed\n");
		return ret;
	}
	ret = __initialize_package_app_app_permission_db();
	if (ret == -1) {
		DBG("package app app permission DB initialization failed\n");
		return ret;
	}
	ret = __initialize_package_app_app_svc_db();
	if (ret == -1) {
		DBG("package app app svc DB initialization failed\n");
		return ret;
	}
	ret = __initialize_package_app_share_allowed_db();
	if (ret == -1) {
		DBG("package app share allowed DB initialization failed\n");
		return ret;
	}
	ret = __initialize_package_app_share_request_db();
	if (ret == -1) {
		DBG("package app share request DB initialization failed\n");
		return ret;
	}
	return 0;
}

int pkgmgr_parser_check_and_create_db()
{
	int ret = -1;
	if (access(PKGMGR_PARSER_DB_FILE, F_OK) == 0) {
		ret =
		    db_util_open(PKGMGR_PARSER_DB_FILE, &pkgmgr_parser_db,
				 DB_UTIL_REGISTER_HOOK_METHOD);
		if (ret != SQLITE_OK) {
			DBG("connect db [%s] failed!\n",
			       PKGMGR_PARSER_DB_FILE);
			return -1;
		}
		ret = chmod(PKGMGR_PARSER_DB_FILE, 0664);
		if (ret)
			DBG("Failed to change mode of manifest DB\n");
		return 0;
	}
	DBG("Pkgmgr DB does not exists. Create one!!\n");

	ret =
	    db_util_open(PKGMGR_PARSER_DB_FILE, &pkgmgr_parser_db,
			 DB_UTIL_REGISTER_HOOK_METHOD);

	if (ret != SQLITE_OK) {
		DBG("connect db [%s] failed!\n", PKGMGR_PARSER_DB_FILE);
		return -1;
	}
	ret = chmod(PKGMGR_PARSER_DB_FILE, 0664);
	if (ret)
		DBG("Failed to change mode of manifest DB\n");
	return 0;
}

API int pkgmgr_parser_insert_manifest_info_in_db(manifest_x *mfx)
{
	if (mfx == NULL) {
		DBG("manifest pointer is NULL\n");
		return -1;
	}
	int ret = -1;
	ret = pkgmgr_parser_check_and_create_db();
	if (ret == -1) {
		DBG("Failed to open DB\n");
		return ret;
	}
	ret = pkgmgr_parser_initialize_db();
	if (ret == -1)
		return ret;
	/*Begin transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		DBG("Failed to begin transaction\n");
		sqlite3_close(pkgmgr_parser_db);
		return -1;
	}
	DBG("Transaction Begin\n");
	ret = __insert_manifest_info_in_db(mfx);
	if (ret == -1) {
		DBG("Insert into DB failed. Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(pkgmgr_parser_db);
		return -1;
	}
	/*Commit transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		DBG("Failed to commit transaction. Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(pkgmgr_parser_db);
		return -1;
	}
	DBG("Transaction Commit and End\n");
	sqlite3_close(pkgmgr_parser_db);
	return 0;
}

API int pkgmgr_parser_update_manifest_info_in_db(manifest_x *mfx)
{
	if (mfx == NULL) {
		DBG("manifest pointer is NULL\n");
		return -1;
	}
	int ret = -1;
	ret = pkgmgr_parser_check_and_create_db();
	if (ret == -1) {
		DBG("Failed to open DB\n");
		return ret;
	}
	ret = pkgmgr_parser_initialize_db();
	if (ret == -1)
		return ret;
	/*Preserve guest mode visibility*/
	__preserve_guestmode_visibility_value( mfx);
	/*Begin transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		DBG("Failed to begin transaction\n");
		sqlite3_close(pkgmgr_parser_db);
		return -1;
	}
	DBG("Transaction Begin\n");
	ret = __delete_manifest_info_from_db(mfx);
	if (ret == -1) {
		DBG("Delete from DB failed. Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(pkgmgr_parser_db);
		return -1;
	}
	ret = __insert_manifest_info_in_db(mfx);
	if (ret == -1) {
		DBG("Insert into DB failed. Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(pkgmgr_parser_db);
		return -1;
	}

	/*Commit transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		DBG("Failed to commit transaction. Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(pkgmgr_parser_db);
		return -1;
	}
	DBG("Transaction Commit and End\n");
	sqlite3_close(pkgmgr_parser_db);
	return 0;
}

API int pkgmgr_parser_delete_manifest_info_from_db(manifest_x *mfx)
{
	if (mfx == NULL) {
		DBG("manifest pointer is NULL\n");
		return -1;
	}
	int ret = -1;
	ret = pkgmgr_parser_check_and_create_db();
	if (ret == -1) {
		DBG("Failed to open DB\n");
		return ret;
	}
	/*Begin transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		DBG("Failed to begin transaction\n");
		sqlite3_close(pkgmgr_parser_db);
		return -1;
	}
	DBG("Transaction Begin\n");
	ret = __delete_manifest_info_from_db(mfx);
	if (ret == -1) {
		DBG("Delete from DB failed. Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(pkgmgr_parser_db);
		return -1;
	}
	/*Commit transaction*/
	ret = sqlite3_exec(pkgmgr_parser_db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		DBG("Failed to commit transaction, Rollback now\n");
		sqlite3_exec(pkgmgr_parser_db, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(pkgmgr_parser_db);
		return -1;
	}
	DBG("Transaction Commit and End\n");
	sqlite3_close(pkgmgr_parser_db);
	return 0;
}
