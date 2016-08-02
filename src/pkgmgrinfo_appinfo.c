#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>

#include <sqlite3.h>
#include <glib.h>

#include "pkgmgr-info.h"
#include "pkgmgrinfo_debug.h"
#include "pkgmgrinfo_private.h"
#include "pkgmgr_parser.h"

static bool _get_bool_value(const char *str)
{
	if (str && !strcmp(str, "true"))
		return true;
	else
		return false;
}

static void __cleanup_appinfo(pkgmgr_appinfo_x *data)
{
	pkgmgr_appinfo_x *info = data;

	if (info != NULL) {
		if (info->package)
			free((void *)info->package);
		if (info->locale)
			free((void *)info->locale);

		pkgmgrinfo_basic_free_application(info->app_info);
		free((void *)info);
	}
	return;
}

static const char join_localized_info[] =
	" LEFT OUTER JOIN package_app_localized_info"
	"  ON ai.app_id=package_app_localized_info.app_id"
	"  AND package_app_localized_info.app_locale=?";
static const char join_category[] =
	" LEFT OUTER JOIN package_app_app_category"
	" ON ai.app_id=package_app_app_category.app_id";
static const char join_app_control[] =
	" LEFT OUTER JOIN package_app_app_control"
	"  ON ai.app_id=package_app_app_control.app_id";
static const char join_metadata[] =
	" LEFT OUTER JOIN package_app_app_metadata"
	"  ON ai.app_id=package_app_app_metadata.app_id ";

static int _get_filtered_query(pkgmgrinfo_filter_x *filter,
	const char *locale, char **query, GList **bind_params)
{
	int joined = 0;
	size_t len = 0;
	char *condition = NULL;
	char buf[MAX_QUERY_LEN] = { '\0' };
	char tmp_query[MAX_QUERY_LEN] = { '\0' };
	GSList *list;

	if (filter == NULL)
		return PMINFO_R_OK;

	len += strlen(" WHERE 1=1");
	strncat(buf, " WHERE 1=1", MAX_QUERY_LEN - len - 1);
	for (list = filter->list; list; list = list->next) {
		joined |= __get_filter_condition(list->data, &condition, bind_params);
		if (condition == NULL)
			continue;

		len += strlen(" AND ");
		strncat(buf, " AND ", MAX_QUERY_LEN - len - 1);

		len += strlen(condition);
		strncat(buf, condition, sizeof(buf) - len - 1);
		free(condition);
		condition = NULL;
	}

	if (joined & E_PMINFO_APPINFO_JOIN_LOCALIZED_INFO) {
		strncat(tmp_query, join_localized_info, MAX_QUERY_LEN - len - 1);
		len += strlen(join_localized_info);
		*bind_params = g_list_append(*bind_params, strdup(locale));
	}
	if (joined & E_PMINFO_APPINFO_JOIN_CATEGORY) {
		strncat(tmp_query, join_category, MAX_QUERY_LEN - len - 1);
		len += strlen(join_category);
	}
	if (joined & E_PMINFO_APPINFO_JOIN_APP_CONTROL) {
		strncat(tmp_query, join_app_control, MAX_QUERY_LEN - len - 1);
		len += strlen(join_app_control);
	}
	if (joined & E_PMINFO_APPINFO_JOIN_METADATA) {
		strncat(tmp_query, join_metadata, MAX_QUERY_LEN - len - 1);
		len += strlen(join_metadata);
	}
	strncat(tmp_query, buf, MAX_QUERY_LEN - len - 1);

	*query = strdup(tmp_query);
	if (*query == NULL)
		return PMINFO_R_ERROR;

	return PMINFO_R_OK;
}

static int _appinfo_get_label(const char *locale, char *value, GList **label)
{
	label_x *info;

	info = calloc(1, sizeof(label_x));
	if (info == NULL) {
		LOGE("out of memory");
		return PMINFO_R_ERROR;
	}
	info->text = value;
	info->lang = strdup(locale);
	*label = g_list_append(*label, info);

	return PMINFO_R_OK;
}

static int _appinfo_get_icon(const char *locale, char *value, GList **icon)
{
	icon_x *info;

	info = calloc(1, sizeof(icon_x));
	if (info == NULL) {
		LOGE("out of memory");
		return PMINFO_R_ERROR;
	}
	info->text = value;
	info->lang = strdup(locale);
	*icon = g_list_append(*icon, info);

	return PMINFO_R_OK;
}

static int _appinfo_get_category(sqlite3 *db, const char *appid,
		GList **category)
{
	static const char query_raw[] =
		"SELECT category FROM package_app_app_category WHERE app_id=%Q";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	char *val;

	query = sqlite3_mprintf(query_raw, appid);
	if (query == NULL) {
		LOGE("out of memory");
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		val = NULL;
		_save_column_str(stmt, 0, &val);
		if (val)
			*category = g_list_append(*category, (gpointer)val);
	}

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

static void __parse_appcontrol(GList **appcontrol, char *appcontrol_str)
{
	char *dup;
	char *token;
	char *ptr = NULL;
	appcontrol_x *ac;

	if (appcontrol_str == NULL)
		return;

	dup = strdup(appcontrol_str);
	do {
		ac = calloc(1, sizeof(appcontrol_x));
		if (ac == NULL) {
			_LOGE("out of memory");
			break;
		}
		token = strtok_r(dup, "|", &ptr);
		if (token && strcmp(token, "NULL"))
			ac->operation = strdup(token);
		token = strtok_r(NULL, "|", &ptr);
		if (token && strcmp(token, "NULL"))
			ac->uri = strdup(token);
		token = strtok_r(NULL, "|", &ptr);
		if (token && strcmp(token, "NULL"))
			ac->mime = strdup(token);
		*appcontrol = g_list_append(*appcontrol, ac);
	} while ((token = strtok_r(NULL, ";", &ptr)));

	free(dup);
}

static int _appinfo_get_app_control(sqlite3 *db, const char *appid,
		GList **appcontrol)
{
	static const char query_raw[] =
		"SELECT app_control FROM package_app_app_control "
		"WHERE app_id=%Q";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	char *str;

	query = sqlite3_mprintf(query_raw, appid);
	if (query == NULL) {
		LOGE("out of memory");
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		str = NULL;
		_save_column_str(stmt, 0, &str);
		/* TODO: revise */
		__parse_appcontrol(appcontrol, str);
		free(str);
	}

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

static int _appinfo_get_data_control(sqlite3 *db, const char *appid,
		GList **datacontrol)
{
	static const char query_raw[] =
		"SELECT providerid, access, type "
		"FROM package_app_data_control WHERE app_id=%Q";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	int idx;
	datacontrol_x *info;

	query = sqlite3_mprintf(query_raw, appid);
	if (query == NULL) {
		LOGE("out of memory");
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		info = calloc(1, sizeof(datacontrol_x));
		if (info == NULL) {
			LOGE("out of memory");
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}
		idx = 0;
		_save_column_str(stmt, idx++, &info->providerid);
		_save_column_str(stmt, idx++, &info->access);
		_save_column_str(stmt, idx++, &info->type);
		*datacontrol = g_list_append(*datacontrol, info);
	}

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

static int _appinfo_get_metadata(sqlite3 *db, const char *appid,
		GList **metadata)
{
	static const char query_raw[] =
		"SELECT md_key, md_value "
		"FROM package_app_app_metadata WHERE app_id=%Q";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	int idx;
	metadata_x *info;

	query = sqlite3_mprintf(query_raw, appid);
	if (query == NULL) {
		LOGE("out of memory");
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		info = calloc(1, sizeof(metadata_x));
		if (info == NULL) {
			LOGE("out of memory");
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}
		idx = 0;
		_save_column_str(stmt, idx++, &info->key);
		_save_column_str(stmt, idx++, &info->value);
		*metadata = g_list_append(*metadata, info);
	}

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;

}

static int _appinfo_get_splashscreens(sqlite3 *db, const char *appid,
		GList **splashscreens)
{
	static const char query_raw[] =
		"SELECT src, type, orientation, indicatordisplay, operation, color_depth "
		"FROM package_app_splash_screen WHERE app_id=%Q";
	int ret;
	char *query;
	sqlite3_stmt *stmt;
	int idx;
	splashscreen_x *info;

	query = sqlite3_mprintf(query_raw, appid);
	if (query == NULL) {
		LOGE("out of memory");
		return PMINFO_R_ERROR;
	}

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(db));
		return PMINFO_R_ERROR;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		info = calloc(1, sizeof(splashscreen_x));
		if (info == NULL) {
			LOGE("out of memory");
			sqlite3_finalize(stmt);
			return PMINFO_R_ERROR;
		}
		idx = 0;
		_save_column_str(stmt, idx++, &info->src);
		_save_column_str(stmt, idx++, &info->type);
		_save_column_str(stmt, idx++, &info->orientation);
		_save_column_str(stmt, idx++, &info->indicatordisplay);
		_save_column_str(stmt, idx++, &info->operation);
		_save_column_str(stmt, idx++, &info->color_depth);
		*splashscreens = g_list_append(*splashscreens, info);
	}

	sqlite3_finalize(stmt);

	return PMINFO_R_OK;
}

static GList *__get_background_category(const char *value)
{
	GList *category_list = NULL;
	int convert_value = 0;
	if (!value || strlen(value) == 0)
		return NULL;

	convert_value = atoi(value);
	if (convert_value < 0)
		return NULL;

	if (convert_value & APP_BG_CATEGORY_USER_DISABLE_TRUE_VAL)
		category_list = g_list_append(category_list, strdup(APP_BG_CATEGORY_USER_DISABLE_TRUE_STR));
	else
		category_list = g_list_append(category_list, strdup(APP_BG_CATEGORY_USER_DISABLE_FALSE_STR));

	if (convert_value & APP_BG_CATEGORY_MEDIA_VAL)
		category_list = g_list_append(category_list, strdup(APP_BG_CATEGORY_MEDIA_STR));

	if (convert_value & APP_BG_CATEGORY_DOWNLOAD_VAL)
		category_list = g_list_append(category_list, strdup(APP_BG_CATEGORY_DOWNLOAD_STR));

	if (convert_value & APP_BG_CATEGORY_BGNETWORK_VAL)
		category_list = g_list_append(category_list, strdup(APP_BG_CATEGORY_BGNETWORK_STR));

	if (convert_value & APP_BG_CATEGORY_LOCATION_VAL)
		category_list = g_list_append(category_list, strdup(APP_BG_CATEGORY_LOCATION_STR));

	if (convert_value & APP_BG_CATEGORY_SENSOR_VAL)
		category_list = g_list_append(category_list, strdup(APP_BG_CATEGORY_SENSOR_STR));

	if (convert_value & APP_BG_CATEGORY_IOTCOMM_VAL)
		category_list = g_list_append(category_list, strdup(APP_BG_CATEGORY_IOTCOMM_STR));

	if (convert_value & APP_BG_CATEGORY_SYSTEM_VAL)
		category_list = g_list_append(category_list, strdup(APP_BG_CATEGORY_SYSTEM));

	return category_list;

}

static void __get_splash_screen_display(sqlite3 *db, const char *appid, uid_t uid, char **value)
{
	static const char query_raw[] =
		"SELECT is_splash_screen_enabled FROM package_app_info_for_uid "
		"WHERE app_id='%s' AND uid='%d'";
	int ret;
	char *query;
	sqlite3_stmt *stmt;

	query = sqlite3_mprintf(query_raw, appid, uid);
	if (query == NULL) {
		LOGE("out of memory");
		return;
	}

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	sqlite3_free(query);
	if (ret != SQLITE_OK) {
		LOGE("sqlite3_prepare_v2() failed: %s", sqlite3_errmsg(db));
		return;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		if (*value)
			free(*value);
		_save_column_str(stmt, 0, value);
	}

	sqlite3_finalize(stmt);
}

static void __free_applications(gpointer data)
{
	pkgmgrinfo_basic_free_application((application_x *)data);
}

static int __bind_params(sqlite3_stmt *stmt, GList *params)
{
	GList *tmp_list = NULL;
	int idx = 0;
	int ret;

	if (stmt == NULL || params == NULL)
		return PMINFO_R_EINVAL;

	tmp_list = params;
	while (tmp_list) {
		ret = sqlite3_bind_text(stmt, ++idx, (char *)tmp_list->data, -1, SQLITE_STATIC);
		if (ret != SQLITE_OK)
			return PMINFO_R_ERROR;
		tmp_list = tmp_list->next;
	}

	return PMINFO_R_OK;
}

static int _appinfo_get_applications(uid_t db_uid, uid_t uid,
		const char *locale, pkgmgrinfo_filter_x *filter, int flag,
		GHashTable *applications)
{
	static const char query_raw[] =
		"SELECT DISTINCT ai.app_id, ai.app_component, ai.app_exec, "
		"ai.app_nodisplay, ai.app_type, ai.app_onboot, "
		"ai.app_multiple, ai.app_autorestart, ai.app_taskmanage, "
		"ai.app_enabled, ai.app_hwacceleration, ai.app_screenreader, "
		"ai.app_mainapp, ai.app_recentimage, ai.app_launchcondition, "
		"ai.app_indicatordisplay, ai.app_portraitimg, "
		"ai.app_landscapeimg, ai.app_guestmodevisibility, "
		"ai.app_permissiontype, ai.app_preload, ai.app_submode, "
		"ai.app_submode_mainid, ai.app_launch_mode, ai.app_ui_gadget, "
		"ai.app_support_disable, ai.app_process_pool, "
		"ai.app_installed_storage, ai.app_background_category, "
		"ai.app_package_type, ai.app_root_path, ai.app_api_version, "
		"ai.app_effective_appid, ai.app_disable, "
		"ai.app_splash_screen_display, ai.app_tep_name, "
		"ai.app_zip_mount_file, ai.component_type, ai.package";
	static const char query_label[] =
		", COALESCE("
		"(SELECT app_label FROM package_app_localized_info WHERE ai.app_id=app_id AND app_locale=?), "
		"(SELECT app_label FROM package_app_localized_info WHERE ai.app_id=app_id AND app_locale='No Locale')"
		") AS app_label";
	static const char query_icon[] =
		", COALESCE("
		"(SELECT app_icon FROM package_app_localized_info WHERE ai.app_id=app_id AND app_locale=?), "
		"(SELECT app_icon FROM package_app_localized_info WHERE ai.app_id=app_id AND app_locale='No Locale')"
		") AS app_icon";
	static const char query_from_clause[] = " FROM package_app_info as ai";
	int ret = PMINFO_R_ERROR;
	int idx;
	int len = 0;
	const char *dbpath;
	char *bg_category_str = NULL;
	char *constraint = NULL;
	char *tmp_record = NULL;
	char query[MAX_QUERY_LEN] = { '\0' };
	application_x *info = NULL;
	GList *bind_params = NULL;
	sqlite3 *db = NULL;
	sqlite3_stmt *stmt = NULL;

	dbpath = getUserPkgParserDBPathUID(db_uid);
	if (dbpath == NULL)
		return PMINFO_R_ERROR;

	ret = sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READONLY, NULL);
	if (ret != SQLITE_OK) {
		_LOGE("failed to open db: %d", ret);
		return PMINFO_R_ERROR;
	}

	len = strlen(query_raw);
	snprintf(query, MAX_QUERY_LEN - 1, "%s", query_raw);
	if (flag & PMINFO_APPINFO_GET_LABEL) {
		strncat(query, query_label, MAX_QUERY_LEN - len - 1);
		len += strlen(query_label);
		bind_params = g_list_append(bind_params, strdup(locale));
	}
	if (flag & PMINFO_APPINFO_GET_ICON) {
		strncat(query, query_icon, MAX_QUERY_LEN - len - 1);
		len += strlen(query_icon);
		bind_params = g_list_append(bind_params, strdup(locale));
	}

	ret = _get_filtered_query(filter, locale, &constraint, &bind_params);
	if (ret != PMINFO_R_OK) {
		LOGE("Failed to get WHERE clause");
		goto catch;
	}
	strncat(query, query_from_clause, MAX_QUERY_LEN - len - 1);
	len += strlen(query_from_clause);

	if (constraint)
		strncat(query, constraint, MAX_QUERY_LEN - len - 1);

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		LOGE("prepare failed: %s", sqlite3_errmsg(db));
		ret = PMINFO_R_ERROR;
		goto catch;
	}

	if (g_list_length(bind_params) != 0) {
		ret = __bind_params(stmt, bind_params);
		if (ret != SQLITE_OK) {
			LOGE("Failed to bind parameters");
			goto catch;
		}
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		info = calloc(1, sizeof(application_x));
		if (info == NULL) {
			LOGE("out of memory");
			ret = PMINFO_R_ERROR;
			goto catch;
		}
		idx = 0;
		_save_column_str(stmt, idx++, &info->appid);
		if (g_hash_table_contains(applications,
					(gconstpointer)info->appid)) {
			free(info->appid);
			free(info);
			continue;
		}
		_save_column_str(stmt, idx++, &info->component);
		_save_column_str(stmt, idx++, &info->exec);
		_save_column_str(stmt, idx++, &info->nodisplay);
		_save_column_str(stmt, idx++, &info->type);
		_save_column_str(stmt, idx++, &info->onboot);
		_save_column_str(stmt, idx++, &info->multiple);
		_save_column_str(stmt, idx++, &info->autorestart);
		_save_column_str(stmt, idx++, &info->taskmanage);
		_save_column_str(stmt, idx++, &info->enabled);
		_save_column_str(stmt, idx++, &info->hwacceleration);
		_save_column_str(stmt, idx++, &info->screenreader);
		_save_column_str(stmt, idx++, &info->mainapp);
		_save_column_str(stmt, idx++, &info->recentimage);
		_save_column_str(stmt, idx++, &info->launchcondition);
		_save_column_str(stmt, idx++, &info->indicatordisplay);
		_save_column_str(stmt, idx++, &info->portraitimg);
		_save_column_str(stmt, idx++, &info->landscapeimg);
		_save_column_str(stmt, idx++, &info->guestmode_visibility);
		_save_column_str(stmt, idx++, &info->permission_type);
		_save_column_str(stmt, idx++, &info->preload);
		_save_column_str(stmt, idx++, &info->submode);
		_save_column_str(stmt, idx++, &info->submode_mainid);
		_save_column_str(stmt, idx++, &info->launch_mode);
		_save_column_str(stmt, idx++, &info->ui_gadget);
		_save_column_str(stmt, idx++, &info->support_disable);
		_save_column_str(stmt, idx++, &info->process_pool);
		_save_column_str(stmt, idx++, &info->installed_storage);
		_save_column_str(stmt, idx++, &bg_category_str);
		_save_column_str(stmt, idx++, &info->package_type);
		_save_column_str(stmt, idx++, &info->root_path);
		_save_column_str(stmt, idx++, &info->api_version);
		_save_column_str(stmt, idx++, &info->effective_appid);
		_save_column_str(stmt, idx++, &info->is_disabled);
		_save_column_str(stmt, idx++, &info->splash_screen_display);
		_save_column_str(stmt, idx++, &info->tep_name);
		_save_column_str(stmt, idx++, &info->zip_mount_file);
		_save_column_str(stmt, idx++, &info->component_type);
		_save_column_str(stmt, idx++, &info->package);
		info->for_all_users =
			strdup((uid != GLOBAL_USER) ? "false" : "true");

		if (db_uid == GLOBAL_USER)
			__get_splash_screen_display(db, info->appid, db_uid,
					&info->splash_screen_display);

		info->background_category = __get_background_category(
				bg_category_str);
		free(bg_category_str);

		if (flag & PMINFO_APPINFO_GET_LABEL) {
			tmp_record = NULL;
			_save_column_str(stmt, idx++, &tmp_record);
			if (_appinfo_get_label(locale, tmp_record, &info->label)) {
				ret = PMINFO_R_ERROR;
				goto catch;
			}
		}

		if (flag & PMINFO_APPINFO_GET_ICON) {
			tmp_record = NULL;
			_save_column_str(stmt, idx++, &tmp_record);
			if (_appinfo_get_icon(locale, tmp_record, &info->icon)) {
				ret = PMINFO_R_ERROR;
				goto catch;
			}
		}

		if (flag & PMINFO_APPINFO_GET_CATEGORY) {
			if (_appinfo_get_category(db, info->appid,
						&info->category)) {
				ret = PMINFO_R_ERROR;
				goto catch;
			}
		}

		if (flag & PMINFO_APPINFO_GET_APP_CONTROL) {
			if (_appinfo_get_app_control(db, info->appid,
						&info->appcontrol)) {
				ret = PMINFO_R_ERROR;
				goto catch;
			}
		}

		if (flag & PMINFO_APPINFO_GET_DATA_CONTROL) {
			if (_appinfo_get_data_control(db, info->appid,
						&info->datacontrol)) {
				ret = PMINFO_R_ERROR;
				goto catch;
			}
		}

		if (flag & PMINFO_APPINFO_GET_METADATA) {
			if (_appinfo_get_metadata(db, info->appid,
						&info->metadata)) {
				ret = PMINFO_R_ERROR;
				goto catch;
			}
		}

		if (flag & PMINFO_APPINFO_GET_SPLASH_SCREEN) {
			if (_appinfo_get_splashscreens(db, info->appid,
						&info->splashscreens)) {
				ret = PMINFO_R_ERROR;
				goto catch;
			}
		}

		g_hash_table_insert(applications, (gpointer)info->appid,
				(gpointer)info);
	}

	ret = PMINFO_R_OK;

catch:
	if (constraint)
		free(constraint);

	if (ret != PMINFO_R_OK && info != NULL)
		pkgmgrinfo_basic_free_application(info);

	g_list_free_full(bind_params, free);
	sqlite3_close_v2(db);
	sqlite3_finalize(stmt);

	return ret;
}

API int pkgmgrinfo_appinfo_get_usr_disabled_appinfo(const char *appid, uid_t uid,
		pkgmgrinfo_appinfo_h *handle)
{
	int ret;
	char *locale;
	GHashTable *list;
	pkgmgrinfo_appinfo_filter_h filter;
	pkgmgr_appinfo_x *info;

	if (appid == NULL || handle == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	locale = _get_system_locale();
	if (locale == NULL)
		return PMINFO_R_ERROR;

	ret = pkgmgrinfo_appinfo_filter_create(&filter);
	if (ret != PMINFO_R_OK) {
		free(locale);
		return ret;
	}

	ret = pkgmgrinfo_appinfo_filter_add_string(filter,
			PMINFO_APPINFO_PROP_APP_ID, appid);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_appinfo_filter_destroy(filter);
		free(locale);
		return PMINFO_R_ERROR;
	}

	ret = pkgmgrinfo_appinfo_filter_add_bool(filter,
			PMINFO_APPINFO_PROP_APP_DISABLE, true);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_appinfo_filter_destroy(filter);
		free(locale);
		return PMINFO_R_ERROR;
	}

	list = g_hash_table_new(g_str_hash, g_str_equal);
	if (list == NULL) {
		pkgmgrinfo_appinfo_filter_destroy(filter);
		free(locale);
		return PMINFO_R_ERROR;
	}

	ret = _appinfo_get_applications(uid, uid, locale, filter,
			PMINFO_APPINFO_GET_ALL, list);
	if (!g_hash_table_size(list) && uid != GLOBAL_USER)
		ret = _appinfo_get_applications(GLOBAL_USER, uid, locale,
				filter, PMINFO_APPINFO_GET_ALL, list);

	pkgmgrinfo_appinfo_filter_destroy(filter);
	if (ret != PMINFO_R_OK) {
		g_hash_table_destroy(list);
		free(locale);
		return ret;
	}

	if (!g_hash_table_size(list)) {
		_LOGI("Appinfo for [%s] is not existed for user [%d]",
				appid, uid);
		g_hash_table_destroy(list);
		free(locale);
		return PMINFO_R_ENOENT;
	}

	info = calloc(1, sizeof(pkgmgr_appinfo_x));
	if (info == NULL) {
		_LOGE("out of memory");
		free(locale);
		return PMINFO_R_ERROR;
	}

	info->app_info = (application_x *)g_hash_table_lookup(list, appid);
	info->locale = locale;
	info->package = strdup(info->app_info->package);

	/* just free list only */
	g_hash_table_destroy(list);

	*handle = info;

	return ret;
}

API int pkgmgrinfo_appinfo_get_disabled_appinfo(const char *appid, pkgmgrinfo_appinfo_h *handle)
{
	return pkgmgrinfo_appinfo_get_usr_disabled_appinfo(appid, _getuid(), handle);
}

API int pkgmgrinfo_appinfo_get_usr_appinfo(const char *appid, uid_t uid,
		pkgmgrinfo_appinfo_h *handle)
{
	int ret;
	char *locale;
	GHashTable *list;
	pkgmgrinfo_appinfo_filter_h filter;
	pkgmgr_appinfo_x *info;

	if (appid == NULL || handle == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	locale = _get_system_locale();
	if (locale == NULL)
		return PMINFO_R_ERROR;

	ret = pkgmgrinfo_appinfo_filter_create(&filter);
	if (ret != PMINFO_R_OK) {
		free(locale);
		return ret;
	}

	ret = pkgmgrinfo_appinfo_filter_add_string(filter,
			PMINFO_APPINFO_PROP_APP_ID, appid);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_appinfo_filter_destroy(filter);
		free(locale);
		return PMINFO_R_ERROR;
	}

	ret = pkgmgrinfo_appinfo_filter_add_bool(filter,
			PMINFO_APPINFO_PROP_APP_DISABLE, false);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_appinfo_filter_destroy(filter);
		free(locale);
		return PMINFO_R_ERROR;
	}

	list = g_hash_table_new(g_str_hash, g_str_equal);
	if (list == NULL) {
		pkgmgrinfo_appinfo_filter_destroy(filter);
		free(locale);
		return PMINFO_R_ERROR;
	}

	ret = _appinfo_get_applications(uid, uid, locale, filter,
			PMINFO_APPINFO_GET_ALL, list);
	if (!g_hash_table_size(list) && uid != GLOBAL_USER)
		ret = _appinfo_get_applications(GLOBAL_USER, uid, locale,
				filter, PMINFO_APPINFO_GET_ALL, list);

	pkgmgrinfo_appinfo_filter_destroy(filter);
	if (ret != PMINFO_R_OK) {
		g_hash_table_destroy(list);
		free(locale);
		return ret;
	}

	if (!g_hash_table_size(list)) {
		_LOGI("Appinfo for [%s] is not existed for user [%d]", appid, uid);
		g_hash_table_destroy(list);
		free(locale);
		return PMINFO_R_ENOENT;
	}

	info = calloc(1, sizeof(pkgmgr_appinfo_x));
	if (info == NULL) {
		_LOGE("out of memory");
		free(locale);
		return PMINFO_R_ERROR;
	}

	info->app_info = (application_x *)g_hash_table_lookup(list, appid);
	info->locale = locale;
	info->package = strdup(info->app_info->package);

	/* just free list only */
	g_hash_table_destroy(list);

	*handle = info;

	return ret;
}

API int pkgmgrinfo_appinfo_get_appinfo(const char *appid, pkgmgrinfo_appinfo_h *handle)
{
	return pkgmgrinfo_appinfo_get_usr_appinfo(appid, _getuid(), handle);
}

static gpointer __copy_str(gconstpointer src, gpointer data)
{
	const char *tmp = (const char *)src;
	char *buffer;

	buffer = strdup(tmp);
	if (buffer == NULL) {
		LOGE("memory alloc failed");
		*(int *)data = -1;
		return NULL;
	}

	return buffer;
}

static gpointer __copy_label(gconstpointer src, gpointer data)
{
	label_x *tmp = (label_x *)src;
	label_x *label;

	label = calloc(1, sizeof(label_x));
	if (label == NULL) {
		LOGE("memory alloc failed");
		*(int *)data = -1;
		return NULL;
	}

	if (tmp->name)
		label->name = strdup(tmp->name);
	if (tmp->text)
		label->text = strdup(tmp->text);
	if (tmp->lang)
		label->lang = strdup(tmp->lang);

	return label;
}

static gpointer __copy_icon(gconstpointer src, gpointer data)
{
	icon_x *tmp = (icon_x *)src;
	icon_x *icon;

	icon = calloc(1, sizeof(icon_x));
	if (icon== NULL) {
		LOGE("memory alloc failed");
		*(int *)data = -1;
		return NULL;
	}

	if (tmp->text)
		icon->text = strdup(tmp->text);
	if (tmp->lang)
		icon->lang = strdup(tmp->lang);
	if (tmp->section)
		icon->section = strdup(tmp->section);
	if (tmp->size)
		icon->size = strdup(tmp->size);
	if (tmp->resolution)
		icon->resolution = strdup(tmp->resolution);

	return icon;
}

static gpointer __copy_metadata(gconstpointer src, gpointer data)
{
	metadata_x *tmp = (metadata_x *)src;
	metadata_x *metadata;

	metadata = calloc(1, sizeof(metadata_x));
	if (metadata == NULL) {
		LOGE("memory alloc failed");
		*(int *)data = -1;
		return NULL;
	}

	if (tmp->key)
		metadata->key = strdup(tmp->key);
	if (tmp->value)
		metadata->value = strdup(tmp->value);

	return metadata;
}

static gpointer __copy_datacontrol(gconstpointer src, gpointer data)
{
	datacontrol_x *tmp = (datacontrol_x *)src;
	datacontrol_x *datacontrol;

	datacontrol = calloc(1, sizeof(datacontrol_x));
	if (datacontrol == NULL) {
		LOGE("memory alloc failed");
		*(int *)data = -1;
		return NULL;
	}

	if (tmp->providerid)
		datacontrol->providerid = strdup(tmp->providerid);
	if (tmp->access)
		datacontrol->access = strdup(tmp->access);
	if (tmp->type)
		datacontrol->type = strdup(tmp->type);

	return datacontrol;
}

static gpointer __copy_appcontrol(gconstpointer src, gpointer data)
{
	appcontrol_x *tmp = (appcontrol_x *)src;
	appcontrol_x *appcontrol;

	appcontrol = calloc(1, sizeof(appcontrol_x));
	if (appcontrol ==NULL) {
		LOGE("memory alloc failed");
		*(int *)data = -1;
		return NULL;
	}

	if (tmp->operation)
		appcontrol->operation = strdup(tmp->operation);
	if (tmp->uri)
		appcontrol->uri = strdup(tmp->uri);
	if (tmp->mime)
		appcontrol->mime = strdup(tmp->mime);

	return appcontrol;
}

static gpointer __copy_splashscreens(gconstpointer src, gpointer data)
{
	splashscreen_x *tmp = (splashscreen_x *)src;
	splashscreen_x *splashscreen;

	splashscreen = (splashscreen_x *)calloc(1, sizeof(splashscreen_x));
	if (splashscreen == NULL) {
		LOGE("memory alloc failed");
		*(int *)data = -1;
		return NULL;
	}

	if (tmp->src)
		splashscreen->src = strdup(tmp->src);
	if (tmp->type)
		splashscreen->type = strdup(tmp->type);
	if (tmp->orientation)
		splashscreen->orientation = strdup(tmp->orientation);
	if (tmp->indicatordisplay)
		splashscreen->indicatordisplay = strdup(tmp->indicatordisplay);
	if (tmp->operation)
		splashscreen->operation = strdup(tmp->operation);
	if (tmp->color_depth)
		splashscreen->color_depth = strdup(tmp->color_depth);

	return splashscreen;
}

static int _appinfo_copy_appinfo(application_x **application, application_x *data)
{
	application_x *app_info;
	int ret;

	app_info = calloc(1, sizeof(application_x));
	if (app_info == NULL) {
		LOGE("memory alloc failed");
		return PMINFO_R_ERROR;
	}

	if (data->appid != NULL)
		app_info->appid = strdup(data->appid);
	if (data->exec != NULL)
		app_info->exec = strdup(data->exec);
	if (data->nodisplay != NULL)
		app_info->nodisplay = strdup(data->nodisplay);
	if (data->multiple != NULL)
		app_info->multiple = strdup(data->multiple);
	if (data->taskmanage != NULL)
		app_info->taskmanage = strdup(data->taskmanage);
	if (data->enabled != NULL)
		app_info->enabled = strdup(data->enabled);
	if (data->type != NULL)
		app_info->type = strdup(data->type);
	if (data->categories != NULL)
		app_info->categories = strdup(data->categories);
	if (data->hwacceleration != NULL)
		app_info->hwacceleration = strdup(data->hwacceleration);
	if (data->screenreader != NULL)
		app_info->screenreader = strdup(data->screenreader);
	if (data->mainapp != NULL)
		app_info->mainapp = strdup(data->mainapp);
	if (data->package != NULL)
		app_info->package = strdup(data->package);
	if (data->recentimage != NULL)
		app_info->recentimage = strdup(data->recentimage);
	if (data->launchcondition != NULL)
		app_info->launchcondition = strdup(data->launchcondition);
	if (data->indicatordisplay != NULL)
		app_info->indicatordisplay = strdup(data->indicatordisplay);
	if (data->portraitimg != NULL)
		app_info->portraitimg = strdup(data->portraitimg);
	if (data->landscapeimg != NULL)
		app_info->landscapeimg = strdup(data->landscapeimg);
	if (data->guestmode_visibility != NULL)
		app_info->guestmode_visibility = strdup(data->guestmode_visibility);
	if (data->component != NULL)
		app_info->component = strdup(data->component);
	if (data->permission_type != NULL)
		app_info->permission_type = strdup(data->permission_type);
	if (data->component_type != NULL)
		app_info->component_type = strdup(data->component_type);
	if (data->preload != NULL)
		app_info->preload = strdup(data->preload);
	if (data->submode != NULL)
		app_info->submode = strdup(data->submode);
	if (data->submode_mainid != NULL)
		app_info->submode_mainid = strdup(data->submode_mainid);
	if (data->process_pool != NULL)
		app_info->process_pool = strdup(data->process_pool);
	if (data->installed_storage != NULL)
		app_info->installed_storage = strdup(data->installed_storage);
	if (data->autorestart != NULL)
		app_info->autorestart = strdup(data->autorestart);
	if (data->onboot != NULL)
		app_info->onboot = strdup(data->onboot);
	if (data->support_disable != NULL)
		app_info->support_disable = strdup(data->support_disable);
	if (data->ui_gadget != NULL)
		app_info->ui_gadget = strdup(data->ui_gadget);
	if (data->launch_mode != NULL)
		app_info->launch_mode = strdup(data->launch_mode);
	if (data->package_type != NULL)
		app_info->package_type = strdup(data->package_type);
	if (data->effective_appid != NULL)
		app_info->effective_appid = strdup(data->effective_appid);
	if (data->splash_screen_display != NULL)
		app_info->splash_screen_display = strdup(data->splash_screen_display);

	/* GList */
	ret = 0;
	app_info->label = g_list_copy_deep(data->label, __copy_label, &ret);
	if (ret < 0) {
		LOGE("memory alloc failed");
		pkgmgrinfo_basic_free_application(app_info);
		return PMINFO_R_ERROR;
	}

	ret = 0;
	app_info->icon = g_list_copy_deep(data->icon, __copy_icon, &ret);
	if (ret < 0) {
		LOGE("memory alloc failed");
		pkgmgrinfo_basic_free_application(app_info);
		return PMINFO_R_ERROR;
	}

	ret = 0;
	app_info->category = g_list_copy_deep(data->category, __copy_str, &ret);
	if (ret < 0) {
		LOGE("memory alloc failed");
		pkgmgrinfo_basic_free_application(app_info);
		return PMINFO_R_ERROR;
	}

	ret = 0;
	app_info->metadata = g_list_copy_deep(data->metadata, __copy_metadata, &ret);
	if (ret < 0) {
		LOGE("memory alloc failed");
		pkgmgrinfo_basic_free_application(app_info);
		return PMINFO_R_ERROR;
	}

	ret = 0;
	app_info->datacontrol = g_list_copy_deep(data->datacontrol, __copy_datacontrol, &ret);
	if (ret < 0) {
		LOGE("memory alloc failed");
		pkgmgrinfo_basic_free_application(app_info);
		return PMINFO_R_ERROR;
	}

	ret = 0;
	app_info->appcontrol = g_list_copy_deep(data->appcontrol, __copy_appcontrol, &ret);
	if (ret < 0) {
		LOGE("memory alloc failed");
		pkgmgrinfo_basic_free_application(app_info);
		return PMINFO_R_ERROR;
	}

	ret = 0;
	app_info->background_category = g_list_copy_deep(data->background_category, __copy_str, &ret);
	if (ret < 0) {
		LOGE("memory alloc failed");
		pkgmgrinfo_basic_free_application(app_info);
		return PMINFO_R_ERROR;
	}

	ret = 0;
	app_info->splashscreens = g_list_copy_deep(data->splashscreens, __copy_splashscreens, &ret);
	if (ret < 0) {
		LOGE("memory alloc failed");
		pkgmgrinfo_basic_free_application(app_info);
		return PMINFO_R_ERROR;
	}

	*application = app_info;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_clone_appinfo(pkgmgrinfo_appinfo_h handle,
		pkgmgrinfo_appinfo_h *clone)
{
	pkgmgr_appinfo_x *info;
	pkgmgr_appinfo_x *temp = (pkgmgr_appinfo_x *)handle;

	if (handle == NULL)
		return PMINFO_R_EINVAL;

	info = calloc(1, sizeof(pkgmgr_appinfo_x));
	if (info == NULL) {
		LOGE("memory alloc failed");
		return PMINFO_R_ERROR;
	}

	if (temp->package != NULL)
		info->package = strdup(temp->package);
	if (temp->locale != NULL)
		info->locale = strdup(temp->locale);

	info->app_component = temp->app_component;

	if (_appinfo_copy_appinfo(&info->app_info, temp->app_info) < 0) {
		LOGE("appinfo copy failed");
		if (info->package)
			free((void *)info->package);
		if (info->locale)
			free(info->locale);
		free(info);
		return PMINFO_R_ERROR;
	}

	*clone = info;

	return PMINFO_R_OK;
}

static int _appinfo_get_filtered_foreach_appinfo(uid_t uid,
		pkgmgrinfo_filter_x *filter, int flag, pkgmgrinfo_app_list_cb app_list_cb,
		void *user_data)
{
	int ret;
	char *locale;
	application_x *app;
	pkgmgr_appinfo_x info;
	GHashTable *list;
	GHashTableIter iter;
	gpointer value;

	locale = _get_system_locale();
	if (locale == NULL)
		return PMINFO_R_ERROR;

	list = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			__free_applications);
	if (list == NULL) {
		free(locale);
		return PMINFO_R_ERROR;
	}

	ret = _appinfo_get_applications(uid, uid, locale, filter, flag, list);
	if (ret == PMINFO_R_OK && uid != GLOBAL_USER)
		ret = _appinfo_get_applications(GLOBAL_USER, uid, locale,
				filter, flag, list);

	if (ret != PMINFO_R_OK) {
		g_hash_table_destroy(list);
		free(locale);
		return ret;
	}

	g_hash_table_iter_init(&iter, list);
	while (g_hash_table_iter_next(&iter, NULL, &value)) {
		app = (application_x *)value;
		info.app_info = app;
		info.locale = locale;
		info.package = app->package;
		if (app_list_cb(&info, user_data) < 0)
			break;
	}
	g_hash_table_destroy(list);
	free(locale);

	return PMINFO_R_OK;
}

static const char *__appcomponent_str(pkgmgrinfo_app_component comp);

API int pkgmgrinfo_appinfo_get_usr_list(pkgmgrinfo_pkginfo_h handle,
		pkgmgrinfo_app_component component,
		pkgmgrinfo_app_list_cb app_func, void *user_data, uid_t uid)
{
	int ret;
	pkgmgrinfo_appinfo_filter_h filter;
	char *pkgid;
	const char *comp_str = NULL;

	if (handle == NULL || app_func == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	if (pkgmgrinfo_pkginfo_get_pkgid(handle, &pkgid)) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	if (pkgmgrinfo_appinfo_filter_create(&filter))
		return PMINFO_R_ERROR;

	if (pkgmgrinfo_appinfo_filter_add_string(filter,
				PMINFO_APPINFO_PROP_APP_PACKAGE, pkgid)) {
		pkgmgrinfo_appinfo_filter_destroy(filter);
		return PMINFO_R_ERROR;
	}

	if (uid == GLOBAL_USER) {
		if (pkgmgrinfo_appinfo_filter_add_int(filter,
					PMINFO_APPINFO_PROP_APP_DISABLE_FOR_USER,
					(int)getuid())) {
			pkgmgrinfo_appinfo_filter_destroy(filter);
			return PMINFO_R_ERROR;
		}
	}

	comp_str = __appcomponent_str(component);

	if (comp_str) {
		if (pkgmgrinfo_appinfo_filter_add_string(filter,
					PMINFO_APPINFO_PROP_APP_COMPONENT,
					comp_str)) {
			pkgmgrinfo_appinfo_filter_destroy(filter);
			return PMINFO_R_ERROR;
		}
	}

	ret = _appinfo_get_filtered_foreach_appinfo(uid, filter,
			PMINFO_APPINFO_GET_ALL, app_func, user_data);

	pkgmgrinfo_appinfo_filter_destroy(filter);

	return ret;
}

API int pkgmgrinfo_appinfo_get_list(pkgmgrinfo_pkginfo_h handle,
		pkgmgrinfo_app_component component,
		pkgmgrinfo_app_list_cb app_func, void *user_data)
{
	return pkgmgrinfo_appinfo_get_usr_list(handle, component, app_func, user_data, _getuid());
}

API int pkgmgrinfo_appinfo_get_usr_installed_list_full(
		pkgmgrinfo_app_list_cb app_func, uid_t uid, int flag,
		void *user_data)
{
	int ret;
	pkgmgrinfo_appinfo_filter_h filter;

	if (app_func == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	if (pkgmgrinfo_appinfo_filter_create(&filter)) {
		return PMINFO_R_ERROR;
	}

	if (pkgmgrinfo_appinfo_filter_add_bool(filter,
				PMINFO_APPINFO_PROP_APP_DISABLE, false)) {
		pkgmgrinfo_appinfo_filter_destroy(filter);
		return PMINFO_R_ERROR;
	}

	if (uid == GLOBAL_USER) {
		if (pkgmgrinfo_appinfo_filter_add_int(filter,
					PMINFO_APPINFO_PROP_APP_DISABLE_FOR_USER,
					(int)getuid())) {
			pkgmgrinfo_appinfo_filter_destroy(filter);
			return PMINFO_R_ERROR;
		}
	}

	ret = _appinfo_get_filtered_foreach_appinfo(uid, filter, flag, app_func,
			user_data);

	pkgmgrinfo_appinfo_filter_destroy(filter);

	return ret;
}

API int pkgmgrinfo_appinfo_get_installed_list_full(
		pkgmgrinfo_app_list_cb app_func, int flag, void *user_data)
{
	return pkgmgrinfo_appinfo_get_usr_installed_list_full(app_func,
			_getuid(), flag, user_data);
}

API int pkgmgrinfo_appinfo_get_usr_install_list(pkgmgrinfo_app_list_cb app_func,
		uid_t uid, void *user_data)
{
	return pkgmgrinfo_appinfo_get_usr_installed_list_full(app_func,
			uid, PMINFO_APPINFO_GET_ALL, user_data);
}

API int pkgmgrinfo_appinfo_get_install_list(pkgmgrinfo_app_list_cb app_func,
		void *user_data)
{
	return pkgmgrinfo_appinfo_get_usr_installed_list_full(app_func,
			_getuid(), PMINFO_APPINFO_GET_ALL, user_data);
}

API int pkgmgrinfo_appinfo_get_usr_installed_list(
		pkgmgrinfo_app_list_cb app_func, uid_t uid, void *user_data)
{
	if (app_func == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	return _appinfo_get_filtered_foreach_appinfo(uid, NULL,
			PMINFO_APPINFO_GET_ALL, app_func, user_data);
}

API int pkgmgrinfo_appinfo_get_installed_list(pkgmgrinfo_app_list_cb app_func,
		void *user_data)
{
	return pkgmgrinfo_appinfo_get_usr_installed_list(app_func, _getuid(),
			user_data);
}

API int pkgmgrinfo_appinfo_get_appid(pkgmgrinfo_appinfo_h handle, char **appid)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(appid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL || info->app_info->appid == NULL)
		return PMINFO_R_ERROR;
	*appid = (char *)info->app_info->appid;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_pkgname(pkgmgrinfo_appinfo_h handle, char **pkg_name)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(pkg_name == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->package == NULL)
		return PMINFO_R_ERROR;

	*pkg_name = (char *)info->package;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_pkgid(pkgmgrinfo_appinfo_h handle, char **pkgid)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->package == NULL)
		return PMINFO_R_ERROR;

	*pkgid = (char *)info->package;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_pkgtype(pkgmgrinfo_appinfo_h  handle, char **pkgtype)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(pkgtype == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	*pkgtype = (char *)info->app_info->package_type;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_exec(pkgmgrinfo_appinfo_h handle, char **exec)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(exec == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL || info->app_info->exec == NULL)
		return PMINFO_R_ERROR;
	*exec = (char *)info->app_info->exec;

	return PMINFO_R_OK;
}


API int pkgmgrinfo_appinfo_get_icon(pkgmgrinfo_appinfo_h handle, char **icon)
{
	icon_x *ptr;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(icon == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	if (info->app_info->icon == NULL) {
		*icon = "";
		return PMINFO_R_OK;
	}

	ptr = (icon_x *)info->app_info->icon->data;
	if (ptr == NULL)
		return PMINFO_R_ERROR;

	if (ptr->text == NULL)
		return PMINFO_R_ERROR;
		else
			*icon = ptr->text;

	return PMINFO_R_OK;
}


API int pkgmgrinfo_appinfo_get_label(pkgmgrinfo_appinfo_h handle, char **label)
{
	label_x *ptr;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(label == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL || info->app_info->label == NULL)
		return PMINFO_R_ERROR;

	ptr = (label_x *)info->app_info->label->data;
	if (ptr == NULL)
		return PMINFO_R_ERROR;

	if (ptr->text == NULL)
		return PMINFO_R_ERROR;
	else
		*label = ptr->text;

	return PMINFO_R_OK;
}

static char *_get_localed_label(const char *appid, const char *locale, uid_t uid)
{
	char *result = NULL;
	char *query = NULL;
	sqlite3_stmt *stmt = NULL;
	sqlite3 *db = NULL;
	char *val;
	const char *manifest_db;

	manifest_db = getUserPkgParserDBPathUID(uid);
	if (manifest_db == NULL) {
		_LOGE("Failed to get manifest db path");
		goto err;
	}

	if (sqlite3_open_v2(manifest_db, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
		_LOGE("DB open fail\n");
		goto err;
	}

	query = sqlite3_mprintf("select app_label from package_app_localized_info where app_id=%Q and app_locale=%Q", appid, locale);
	if (query == NULL) {
		_LOGE("Out of memory");
		goto err;
	}

	if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
		_LOGE("prepare_v2 fail\n");
		goto err;
	}

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		val = (char *)sqlite3_column_text(stmt, 0);
		if (val != NULL)
			result = strdup(val);
	}

err:
	sqlite3_finalize(stmt);
	sqlite3_free(query);
	sqlite3_close(db);

	return result;
}

API int pkgmgrinfo_appinfo_usr_get_localed_label(const char *appid, const char *locale, uid_t uid, char **label)
{
	char *val;

	retvm_if(appid == NULL || locale == NULL || label == NULL, PMINFO_R_EINVAL, "Argument is NULL");

	val = _get_localed_label(appid, locale, uid);
	if (val == NULL)
		val = _get_localed_label(appid, DEFAULT_LOCALE, uid);

	if (val == NULL)
		return PMINFO_R_ERROR;

	*label = val;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_localed_label(const char *appid, const char *locale, char **label)
{
	return pkgmgrinfo_appinfo_usr_get_localed_label(appid, locale, _getuid(), label);
}

API int pkgmgrinfo_appinfo_get_metadata_value(pkgmgrinfo_appinfo_h handle, const char *metadata_key, char **metadata_value)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(metadata_key == NULL, PMINFO_R_EINVAL, "metadata_key is NULL");
	retvm_if(metadata_value == NULL, PMINFO_R_EINVAL, "metadata_value is NULL");

	GList *list_md = NULL;
	metadata_x *metadata = NULL;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	list_md = info->app_info->metadata;

	for (; list_md; list_md = list_md->next) {
		metadata = (metadata_x *)list_md->data;
		if (metadata && metadata->key) {
			if (strcasecmp(metadata->key, metadata_key) == 0) {
				if (metadata->value == NULL)
					metadata->value = strdup("");
				*metadata_value = (char*)metadata->value;
				return PMINFO_R_OK;
			}
		}
	}

	return PMINFO_R_EINVAL;
}

static pkgmgrinfo_app_component __appcomponent_convert(const char *comp)
{
	if (strcasecmp(comp, "uiapp") == 0)
		return PMINFO_UI_APP;
	else if (strcasecmp(comp, "svcapp") == 0)
		return PMINFO_SVC_APP;
	else if (strcasecmp(comp, "widgetapp") == 0)
		return PMINFO_WIDGET_APP;
	else if (strcasecmp(comp, "watchapp") == 0)
		return PMINFO_WATCH_APP;
	else
		return -1;
}

static const char *__appcomponent_str(pkgmgrinfo_app_component comp)
{
	switch (comp) {
	case PMINFO_UI_APP:
		return "uiapp";
	case PMINFO_SVC_APP:
		return "svcapp";
	case PMINFO_WIDGET_APP:
		return "widgetapp";
	case PMINFO_WATCH_APP:
		return "watchapp";
	default:
		return NULL;
	}
}

API int pkgmgrinfo_appinfo_get_component(pkgmgrinfo_appinfo_h handle, pkgmgrinfo_app_component *component)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	int comp;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(component == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	comp = __appcomponent_convert(info->app_info->component);
	if (comp < 0)
		return PMINFO_R_ERROR;

	*component = comp;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_apptype(pkgmgrinfo_appinfo_h handle, char **app_type)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(app_type == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL || info->app_info->type == NULL)
		return PMINFO_R_ERROR;
	*app_type = (char *)info->app_info->type;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_operation(pkgmgrinfo_appcontrol_h  handle,
					int *operation_count, char ***operation)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(operation == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	retvm_if(operation_count == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgrinfo_appcontrol_x *data = (pkgmgrinfo_appcontrol_x *)handle;
	*operation_count = data->operation_count;
	*operation = data->operation;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_uri(pkgmgrinfo_appcontrol_h  handle,
					int *uri_count, char ***uri)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(uri == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	retvm_if(uri_count == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgrinfo_appcontrol_x *data = (pkgmgrinfo_appcontrol_x *)handle;
	*uri_count = data->uri_count;
	*uri = data->uri;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_mime(pkgmgrinfo_appcontrol_h  handle,
					int *mime_count, char ***mime)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(mime == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	retvm_if(mime_count == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgrinfo_appcontrol_x *data = (pkgmgrinfo_appcontrol_x *)handle;
	*mime_count = data->mime_count;
	*mime = data->mime;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_subapp(pkgmgrinfo_appcontrol_h  handle,
					int *subapp_count, char ***subapp)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(subapp == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	retvm_if(subapp_count == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgrinfo_appcontrol_x *data = (pkgmgrinfo_appcontrol_x *)handle;
	*subapp_count = data->subapp_count;
	*subapp = data->subapp;
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_setting_icon(pkgmgrinfo_appinfo_h handle, char **icon)
{
	char *val;
	icon_x *ptr;
	GList *tmp;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(icon == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	for (tmp = info->app_info->icon; tmp; tmp = tmp->next) {
		ptr = (icon_x *)tmp->data;
		if (ptr == NULL || ptr->section == NULL)
			continue;

		val = (char *)ptr->section;
		if (val && strcmp(val, "setting") == 0) {
			*icon = (char *)ptr->text;
			return PMINFO_R_OK;
		}
	}

	return PMINFO_R_ERROR;
}


API int pkgmgrinfo_appinfo_get_notification_icon(pkgmgrinfo_appinfo_h handle, char **icon)
{
	char *val;
	icon_x *ptr;
	GList *tmp;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(icon == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	for (tmp = info->app_info->icon; tmp; tmp = tmp->next) {
		ptr = (icon_x *)tmp->data;
		if (ptr == NULL || ptr->section == NULL)
			continue;

		val = (char *)ptr->section;
		if (val && strcmp(val, "notification") == 0){
			*icon = (char *)ptr->text;
			return PMINFO_R_OK;
		}
	}

	return PMINFO_R_ERROR;
}

API int pkgmgrinfo_appinfo_get_recent_image_type(pkgmgrinfo_appinfo_h handle, pkgmgrinfo_app_recentimage *type)
{
	char *val;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(type == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL || info->app_info->recentimage == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->app_info->recentimage;
	if (strcasecmp(val, "capture") == 0)
		*type = PMINFO_RECENTIMAGE_USE_CAPTURE;
	else if (strcasecmp(val, "icon") == 0)
		*type = PMINFO_RECENTIMAGE_USE_ICON;
	else
		*type = PMINFO_RECENTIMAGE_USE_NOTHING;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_preview_image(pkgmgrinfo_appinfo_h handle, char **preview_img)
{
	char *val;
	image_x *ptr;
	GList *tmp;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(preview_img == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	for (tmp = info->app_info->image; tmp; tmp = tmp->next) {
		ptr = (image_x *)tmp->data;
		if (ptr == NULL || ptr->section == NULL)
			continue;

		val = (char *)ptr->section;
		if (val && strcmp(val, "preview") == 0) {
			*preview_img = (char *)ptr->text;
			return PMINFO_R_OK;
		}
	}

	return PMINFO_R_ERROR;
}

API int pkgmgrinfo_appinfo_get_permission_type(pkgmgrinfo_appinfo_h handle, pkgmgrinfo_permission_type *permission)
{
	const char *val;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(permission == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	val = info->app_info->permission_type;
	if (val == NULL)
		return PMINFO_R_ERROR;

	if (strcmp(val, "signature") == 0)
		*permission = PMINFO_PERMISSION_SIGNATURE;
	else if (strcmp(val, "privilege") == 0)
		*permission = PMINFO_PERMISSION_PRIVILEGE;
	else
		*permission = PMINFO_PERMISSION_NORMAL;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_component_type(pkgmgrinfo_appinfo_h handle, char **component_type)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(component_type == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL || info->app_info->component_type == NULL)
		return PMINFO_R_ERROR;

	*component_type = (char *)info->app_info->component_type;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_hwacceleration(pkgmgrinfo_appinfo_h handle, pkgmgrinfo_app_hwacceleration *hwacceleration)
{
	char *val;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(hwacceleration == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL || info->app_info->hwacceleration == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->app_info->hwacceleration;
	if (strcasecmp(val, "off") == 0)
		*hwacceleration = PMINFO_HWACCELERATION_OFF;
	else if (strcasecmp(val, "on") == 0)
		*hwacceleration = PMINFO_HWACCELERATION_ON;
	else
		*hwacceleration = PMINFO_HWACCELERATION_DEFAULT;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_screenreader(pkgmgrinfo_appinfo_h handle, pkgmgrinfo_app_screenreader *screenreader)
{
	char *val;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(screenreader == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL || info->app_info->screenreader == NULL)
		return PMINFO_R_ERROR;

	val = (char *)info->app_info->screenreader;
	if (strcasecmp(val, "screenreader-off") == 0)
		*screenreader = PMINFO_SCREENREADER_OFF;
	else if (strcasecmp(val, "screenreader-on") == 0)
		*screenreader = PMINFO_SCREENREADER_ON;
	else
		*screenreader = PMINFO_SCREENREADER_USE_SYSTEM_SETTING;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_effectimage(pkgmgrinfo_appinfo_h handle, char **portrait_img, char **landscape_img)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(portrait_img == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	retvm_if(landscape_img == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;
	if (info->app_info->portraitimg == NULL)
		info->app_info->portraitimg = strdup("");
	if (info->app_info->landscapeimg== NULL)
		info->app_info->landscapeimg = strdup("");

	*portrait_img = (char *)info->app_info->portraitimg;
	*landscape_img = (char *)info->app_info->landscapeimg;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_effectimage_type(pkgmgrinfo_appinfo_h handle, char **effectimage_type)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (handle == NULL || effectimage_type == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	if (info->app_info == NULL || info->app_info->effectimage_type == NULL)
		return PMINFO_R_ERROR;

	*effectimage_type = (char *)info->app_info->effectimage_type;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_submode_mainid(pkgmgrinfo_appinfo_h  handle, char **submode_mainid)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(submode_mainid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;
	if (info->app_info->submode_mainid == NULL)
		info->app_info->submode_mainid = strdup("");

	*submode_mainid = (char *)info->app_info->submode_mainid;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_installed_storage_location(pkgmgrinfo_appinfo_h handle, pkgmgrinfo_installed_storage *storage)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info && info->app_info->installed_storage){
		 if (strcmp(info->app_info->installed_storage,"installed_internal") == 0)
			*storage = PMINFO_INTERNAL_STORAGE;
		 else if (strcmp(info->app_info->installed_storage,"installed_external") == 0)
			 *storage = PMINFO_EXTERNAL_STORAGE;
		 else
			 return PMINFO_R_ERROR;
	}else
		return PMINFO_R_ERROR;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_launch_mode(pkgmgrinfo_appinfo_h handle, char **mode)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(mode == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->app_info->launch_mode == NULL)
		return PMINFO_R_ERROR;

	*mode = (char *)(info->app_info->launch_mode);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_alias_appid(pkgmgrinfo_appinfo_h handle, char **alias_appid)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (handle == NULL || alias_appid == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	if (info->app_info == NULL || info->app_info->alias_appid == NULL)
		return PMINFO_R_ERROR;

	*alias_appid = (char *)info->app_info->alias_appid;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_effective_appid(pkgmgrinfo_appinfo_h handle, char **effective_appid)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (handle == NULL || effective_appid == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;
	if (info->app_info->effective_appid == NULL)
		info->app_info->effective_appid = strdup("");

	*effective_appid = (char *)info->app_info->effective_appid;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_tep_name(pkgmgrinfo_appinfo_h handle, char **tep_name)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (handle == NULL || tep_name == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;
	if (info->app_info->tep_name == NULL)
		info->app_info->tep_name = strdup("");

	*tep_name = (char *)info->app_info->tep_name;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_zip_mount_file(pkgmgrinfo_appinfo_h handle, char **zip_mount_file)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (handle == NULL || zip_mount_file == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;
	if (info->app_info->zip_mount_file == NULL)
		info->app_info->zip_mount_file = strdup("");

	*zip_mount_file = (char *)info->app_info->zip_mount_file;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_root_path(pkgmgrinfo_appinfo_h handle, char **root_path)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (handle == NULL || root_path == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	if (info->app_info == NULL || info->app_info->root_path == NULL)
		return PMINFO_R_ERROR;

	*root_path = (char *)info->app_info->root_path;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_api_version(pkgmgrinfo_appinfo_h handle, char **api_version)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (handle == NULL || api_version == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	if (info->app_info == NULL || info->app_info->api_version == NULL)
		return PMINFO_R_ERROR;

	*api_version = (char *)info->app_info->api_version;

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_usr_get_datacontrol_info(const char *providerid, const char *type, uid_t uid, char **appid, char **access)
{
	retvm_if(providerid == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(type == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(appid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	retvm_if(access == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	int ret = PMINFO_R_OK;
	char *query = NULL;
	sqlite3_stmt *stmt = NULL;

	/*open db*/
	ret = __open_manifest_db(uid, true);
	retvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	/*Start constructing query*/
	query = sqlite3_mprintf("select * from package_app_data_control where providerid=%Q and type=%Q", providerid, type);
	tryvm_if(query == NULL, ret = PMINFO_R_ERROR, "Out of memory");

	/*prepare query*/
	ret = sqlite3_prepare_v2(GET_DB(manifest_db), query, strlen(query), &stmt, NULL);
	tryvm_if(ret != PMINFO_R_OK, ret = PMINFO_R_ERROR, "sqlite3_prepare_v2 failed[%s]\n", query);

	/*step query*/
	ret = sqlite3_step(stmt);
	tryvm_if((ret != SQLITE_ROW) || (ret == SQLITE_DONE), ret = PMINFO_R_ERROR, "No records found");

	*appid = strdup((char *)sqlite3_column_text(stmt, 0));
	*access = strdup((char *)sqlite3_column_text(stmt, 2));

	ret = PMINFO_R_OK;

catch:
	sqlite3_free(query);
	sqlite3_finalize(stmt);
	__close_manifest_db();
	return ret;
}

API int pkgmgrinfo_appinfo_get_datacontrol_info(const char *providerid, const char *type, char **appid, char **access)
{
	return pkgmgrinfo_appinfo_usr_get_datacontrol_info(providerid, type, _getuid(), appid, access);
}

API int pkgmgrinfo_appinfo_usr_get_datacontrol_appid(const char *providerid, uid_t uid, char **appid)
{
	retvm_if(providerid == NULL, PMINFO_R_EINVAL, "Argument supplied is NULL\n");
	retvm_if(appid == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	int ret = PMINFO_R_OK;
	char *query = NULL;
	sqlite3_stmt *stmt = NULL;

	/*open db*/
	ret = __open_manifest_db(uid, true);
	retvm_if(ret != SQLITE_OK, ret = PMINFO_R_ERROR, "connect db [%s] failed!", MANIFEST_DB);

	/*Start constructing query*/
	query = sqlite3_mprintf("select * from package_app_data_control where providerid=%Q", providerid);
	tryvm_if(query == NULL, ret = PMINFO_R_ERROR, "Out of memory");

	/*prepare query*/
	ret = sqlite3_prepare_v2(GET_DB(manifest_db), query, strlen(query), &stmt, NULL);
	tryvm_if(ret != PMINFO_R_OK, ret = PMINFO_R_ERROR, "sqlite3_prepare_v2 failed[%s]\n", query);

	/*step query*/
	ret = sqlite3_step(stmt);
	tryvm_if((ret != SQLITE_ROW) || (ret == SQLITE_DONE), ret = PMINFO_R_ERROR, "No records found");

	*appid = strdup((char *)sqlite3_column_text(stmt, 0));

	ret = PMINFO_R_OK;

catch:
	sqlite3_free(query);
	sqlite3_finalize(stmt);
	__close_manifest_db();
	return ret;
}

API int pkgmgrinfo_appinfo_get_datacontrol_appid(const char *providerid, char **appid)
{
	return pkgmgrinfo_appinfo_usr_get_datacontrol_appid(providerid, _getuid(), appid);
}

API int pkgmgrinfo_appinfo_foreach_permission(pkgmgrinfo_appinfo_h handle,
			pkgmgrinfo_app_permission_list_cb permission_func, void *user_data)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(permission_func == NULL, PMINFO_R_EINVAL, "Callback function is NULL");
	int ret = -1;
	permission_x *ptr;
	GList *tmp;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	for (tmp = info->app_info->permission; tmp; tmp = tmp->next) {
		ptr = (permission_x *)tmp->data;
		if (ptr == NULL)
			continue;
		if (ptr->value) {
			ret = permission_func(ptr->value, user_data);
			if (ret < 0)
				break;
		}
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_foreach_category(pkgmgrinfo_appinfo_h handle,
			pkgmgrinfo_app_category_list_cb category_func, void *user_data)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(category_func == NULL, PMINFO_R_EINVAL, "Callback function is NULL");
	int ret = -1;
	const char *category;
	GList *tmp;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	for (tmp = info->app_info->category; tmp; tmp = tmp->next) {
		category = (const char *)tmp->data;
		if (category) {
			ret = category_func(category, user_data);
			if (ret < 0)
				break;
		}
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_foreach_metadata(pkgmgrinfo_appinfo_h handle,
			pkgmgrinfo_app_metadata_list_cb metadata_func, void *user_data)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(metadata_func == NULL, PMINFO_R_EINVAL, "Callback function is NULL");
	int ret = -1;
	metadata_x *ptr;
	GList *tmp;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	for (tmp = info->app_info->metadata; tmp; tmp = tmp->next) {
		ptr = (metadata_x *)tmp->data;
		if (ptr == NULL)
			continue;
		if (ptr->key) {
			if (ptr->value == NULL)
				ptr->value = strdup("");
			ret = metadata_func(ptr->key, ptr->value, user_data);
			if (ret < 0)
				break;
		}
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_foreach_appcontrol(pkgmgrinfo_appinfo_h handle,
			pkgmgrinfo_app_control_list_cb appcontrol_func, void *user_data)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(appcontrol_func == NULL, PMINFO_R_EINVAL, "Callback function is NULL");
	int ret;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	appcontrol_x *appcontrol;
	GList *tmp;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	for (tmp = info->app_info->appcontrol; tmp; tmp = tmp->next) {
		appcontrol = (appcontrol_x *)tmp->data;
		if (appcontrol == NULL)
			continue;
		ret = appcontrol_func(appcontrol->operation, appcontrol->uri, appcontrol->mime, user_data);
		if (ret < 0)
			break;
	}

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_foreach_background_category(
		pkgmgrinfo_appinfo_h handle,
		pkgmgrinfo_app_background_category_list_cb category_func,
		void *user_data)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	GList *tmp;
	char *category;

	if (handle == NULL || category_func == NULL || info->app_info == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	for (tmp = info->app_info->background_category; tmp; tmp = tmp->next) {
		category = (char *)tmp->data;
		if (category == NULL)
			continue;

		if (category_func(category, user_data) < 0)
			break;
	}

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_foreach_splash_screen(pkgmgrinfo_appinfo_h handle,
		pkgmgrinfo_app_splash_screen_list_cb splash_screen_func,
		void *user_data)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	splashscreen_x *splashscreen;
	GList *tmp;
	int ret;

	if (info == NULL || info->app_info == NULL
			|| splash_screen_func == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	for (tmp = info->app_info->splashscreens; tmp; tmp = tmp->next) {
		splashscreen = (splashscreen_x *)tmp->data;
		if (splashscreen == NULL)
			continue;
		ret = splash_screen_func(splashscreen->src,
				splashscreen->type,
				splashscreen->orientation,
				splashscreen->indicatordisplay,
				splashscreen->operation,
				splashscreen->color_depth,
				user_data);
		if (ret < 0)
			break;
	}

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_nodisplay(pkgmgrinfo_appinfo_h handle, bool *nodisplay)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(nodisplay == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL || info->app_info->nodisplay == NULL)
		return PMINFO_R_ERROR;

	*nodisplay = _get_bool_value(info->app_info->nodisplay);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_multiple(pkgmgrinfo_appinfo_h handle, bool *multiple)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(multiple == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL || info->app_info->multiple == NULL)
		return PMINFO_R_ERROR;

	*multiple = _get_bool_value(info->app_info->multiple);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_indicator_display_allowed(pkgmgrinfo_appinfo_h handle, bool *indicator_disp)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(indicator_disp == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL || info->app_info->indicatordisplay == NULL)
		return PMINFO_R_ERROR;

	*indicator_disp = _get_bool_value(info->app_info->indicatordisplay);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_taskmanage(pkgmgrinfo_appinfo_h  handle, bool *taskmanage)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(taskmanage == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL || info->app_info->taskmanage == NULL)
		return PMINFO_R_ERROR;

	*taskmanage = _get_bool_value(info->app_info->taskmanage);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_enabled(pkgmgrinfo_appinfo_h  handle, bool *enabled)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(enabled == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL || info->app_info->enabled == NULL)
		return PMINFO_R_ERROR;

	*enabled = _get_bool_value(info->app_info->enabled);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_onboot(pkgmgrinfo_appinfo_h  handle, bool *onboot)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(onboot == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL || info->app_info->onboot == NULL)
		return PMINFO_R_ERROR;

	*onboot = _get_bool_value(info->app_info->onboot);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_autorestart(pkgmgrinfo_appinfo_h  handle, bool *autorestart)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(autorestart == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL || info->app_info->autorestart == NULL)
		return PMINFO_R_ERROR;

	*autorestart = _get_bool_value(info->app_info->autorestart);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_mainapp(pkgmgrinfo_appinfo_h  handle, bool *mainapp)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(mainapp == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL || info->app_info->mainapp == NULL)
		return PMINFO_R_ERROR;

	*mainapp = _get_bool_value(info->app_info->mainapp);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_preload(pkgmgrinfo_appinfo_h handle, bool *preload)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(preload == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL || info->app_info->preload == NULL)
		return PMINFO_R_ERROR;

	*preload = _get_bool_value(info->app_info->preload);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_submode(pkgmgrinfo_appinfo_h handle, bool *submode)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(submode == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL || info->app_info->submode == NULL)
		return PMINFO_R_ERROR;

	*submode = _get_bool_value(info->app_info->submode);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_process_pool(pkgmgrinfo_appinfo_h handle, bool *process_pool)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (handle == NULL || process_pool == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	*process_pool = _get_bool_value(info->app_info->process_pool);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_category_exist(pkgmgrinfo_appinfo_h handle, const char *category, bool *exist)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(category == NULL, PMINFO_R_EINVAL, "category is NULL");
	retvm_if(exist == NULL, PMINFO_R_EINVAL, "exist is NULL");

	const char *val;
	GList *tmp;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL)
		return PMINFO_R_ERROR;

	*exist = 0;
	for (tmp = info->app_info->category; tmp; tmp = tmp->next) {
		val = (const char *)tmp->data;
		if (val == NULL)
			continue;
		if (strcasecmp(val, category) == 0) {
			*exist = 1;
			break;
		}
	}

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_ui_gadget(pkgmgrinfo_appinfo_h handle,
		bool *ui_gadget)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info == NULL || info->app_info == NULL || ui_gadget == NULL) {
		_LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}
	if (info->app_info->ui_gadget == NULL)
		info->app_info->ui_gadget = strdup("false");

	*ui_gadget = _get_bool_value(info->app_info->ui_gadget);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_support_disable(pkgmgrinfo_appinfo_h handle,
		bool *support_disable)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info == NULL || info->app_info == NULL || support_disable == NULL) {
		_LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	*support_disable = _get_bool_value(info->app_info->support_disable);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_disabled(pkgmgrinfo_appinfo_h handle, bool *disabled)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	retvm_if(disabled == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info->app_info == NULL || info->app_info->is_disabled == NULL)
		return PMINFO_R_ERROR;

	*disabled = _get_bool_value(info->app_info->is_disabled);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_is_global(pkgmgrinfo_appinfo_h handle, bool *global)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(global == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	if (info->app_info == NULL || info->app_info->for_all_users == NULL)
		return PMINFO_R_ERROR;

	*global = _get_bool_value(info->app_info->for_all_users);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_get_splash_screen_display(pkgmgrinfo_appinfo_h handle, bool *splash_screen_display)
{
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	if (info == NULL || splash_screen_display == NULL) {
		_LOGE("Invalid parameter");
		return PMINFO_R_EINVAL;
	}

	if (info->app_info == NULL || info->app_info->splash_screen_display == NULL)
		return PMINFO_R_ERROR;

	*splash_screen_display = _get_bool_value(info->app_info->splash_screen_display);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_destroy_appinfo(pkgmgrinfo_appinfo_h handle)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL");
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;
	__cleanup_appinfo(info);
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_filter_create(pkgmgrinfo_appinfo_filter_h *handle)
{
	return (pkgmgrinfo_pkginfo_filter_create(handle));
}

API int pkgmgrinfo_appinfo_filter_destroy(pkgmgrinfo_appinfo_filter_h handle)
{
	return (pkgmgrinfo_pkginfo_filter_destroy(handle));
}

static gint __compare_func(gconstpointer data1, gconstpointer data2)
{
	pkgmgrinfo_node_x *node1 = (pkgmgrinfo_node_x*)data1;
	pkgmgrinfo_node_x *node2 = (pkgmgrinfo_node_x*)data2;
	if (node1->prop == node2->prop)
		return 0;
	else if (node1->prop > node2->prop)
		return 1;
	else
		return -1;
}

API int pkgmgrinfo_appinfo_filter_add_int(pkgmgrinfo_appinfo_filter_h handle,
				const char *property, const int value)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(property == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	char buf[PKG_VALUE_STRING_LEN_MAX] = {'\0'};
	char *val = NULL;
	GSList *link = NULL;
	int prop = -1;
	prop = _pminfo_appinfo_convert_to_prop_int(property);
	if (prop < E_PMINFO_APPINFO_PROP_APP_MIN_INT ||
		prop > E_PMINFO_APPINFO_PROP_APP_MAX_INT) {
		_LOGE("Invalid Integer Property\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)handle;
	pkgmgrinfo_node_x *node = (pkgmgrinfo_node_x*)calloc(1, sizeof(pkgmgrinfo_node_x));
	if (node == NULL) {
		_LOGE("Out of Memory!!!\n");
		return PMINFO_R_ERROR;
	}
	snprintf(buf, PKG_VALUE_STRING_LEN_MAX - 1, "%d", value);
	val = strndup(buf, PKG_VALUE_STRING_LEN_MAX - 1);
	if (val == NULL) {
		_LOGE("Out of Memory\n");
		free(node);
		node = NULL;
		return PMINFO_R_ERROR;
	}
	node->prop = prop;
	node->value = val;
	/*If API is called multiple times for same property, we should override the previous values.
	Last value set will be used for filtering.*/
	link = g_slist_find_custom(filter->list, (gconstpointer)node, __compare_func);
	if (link)
		filter->list = g_slist_delete_link(filter->list, link);
	filter->list = g_slist_append(filter->list, (gpointer)node);
	return PMINFO_R_OK;

}

API int pkgmgrinfo_appinfo_filter_add_bool(pkgmgrinfo_appinfo_filter_h handle,
				const char *property, const bool value)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(property == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	char *val = NULL;
	GSList *link = NULL;
	int prop = -1;
	prop = _pminfo_appinfo_convert_to_prop_bool(property);
	if (prop < E_PMINFO_APPINFO_PROP_APP_MIN_BOOL ||
		prop > E_PMINFO_APPINFO_PROP_APP_MAX_BOOL) {
		_LOGE("Invalid Boolean Property\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)handle;
	pkgmgrinfo_node_x *node = (pkgmgrinfo_node_x*)calloc(1, sizeof(pkgmgrinfo_node_x));
	if (node == NULL) {
		_LOGE("Out of Memory!!!\n");
		return PMINFO_R_ERROR;
	}
	if (value)
		val = strndup("true", 4);
	else
		val = strndup("false", 5);
	if (val == NULL) {
		_LOGE("Out of Memory\n");
		free(node);
		node = NULL;
		return PMINFO_R_ERROR;
	}
	node->prop = prop;
	node->value = val;
	/*If API is called multiple times for same property, we should override the previous values.
	Last value set will be used for filtering.*/
	link = g_slist_find_custom(filter->list, (gconstpointer)node, __compare_func);
	if (link)
		filter->list = g_slist_delete_link(filter->list, link);
	filter->list = g_slist_append(filter->list, (gpointer)node);
	return PMINFO_R_OK;

}

API int pkgmgrinfo_appinfo_filter_add_string(pkgmgrinfo_appinfo_filter_h handle,
				const char *property, const char *value)
{
	retvm_if(handle == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(property == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	retvm_if(value == NULL, PMINFO_R_EINVAL, "Filter handle input parameter is NULL\n");
	char *val = NULL;
	pkgmgrinfo_node_x *ptr = NULL;
	char prev[PKG_STRING_LEN_MAX] = {'\0'};
	char temp[PKG_STRING_LEN_MAX] = {'\0'};
	GSList *link = NULL;
	int prop = -1;
	prop = _pminfo_appinfo_convert_to_prop_str(property);
	if (prop < E_PMINFO_APPINFO_PROP_APP_MIN_STR ||
		prop > E_PMINFO_APPINFO_PROP_APP_MAX_STR) {
		_LOGE("Invalid String Property\n");
		return PMINFO_R_EINVAL;
	}
	pkgmgrinfo_filter_x *filter = (pkgmgrinfo_filter_x*)handle;
	pkgmgrinfo_node_x *node = (pkgmgrinfo_node_x*)calloc(1, sizeof(pkgmgrinfo_node_x));
	if (node == NULL) {
		_LOGE("Out of Memory!!!\n");
		return PMINFO_R_ERROR;
	}
	node->prop = prop;
	switch (prop) {
	case E_PMINFO_APPINFO_PROP_APP_COMPONENT:
		node->value = strdup(value);
		link = g_slist_find_custom(filter->list, (gconstpointer)node, __compare_func);
		if (link)
			filter->list = g_slist_delete_link(filter->list, link);
		filter->list = g_slist_append(filter->list, (gpointer)node);
		break;
	case E_PMINFO_APPINFO_PROP_APP_CATEGORY:
		val = (char *)calloc(1, PKG_STRING_LEN_MAX);
		if (val == NULL) {
			_LOGE("Out of Memory\n");
			free(node);
			node = NULL;
			return PMINFO_R_ERROR;
		}
		link = g_slist_find_custom(filter->list, (gconstpointer)node, __compare_func);
		if (link) {
			ptr = (pkgmgrinfo_node_x *)link->data;
			strncpy(prev, ptr->value, PKG_STRING_LEN_MAX - 1);
			_LOGI("Previous value is %s\n", prev);
			filter->list = g_slist_delete_link(filter->list, link);
			snprintf(temp, PKG_STRING_LEN_MAX - 1, "%s,%s", prev, value);
			strncpy(val, temp, PKG_STRING_LEN_MAX - 1);
			_LOGI("New value is %s\n", val);
			node->value = val;
			filter->list = g_slist_append(filter->list, (gpointer)node);
			memset(temp, '\0', PKG_STRING_LEN_MAX);
		} else {
			snprintf(temp, PKG_STRING_LEN_MAX - 1, "%s", value);
			strncpy(val, temp, PKG_STRING_LEN_MAX - 1);
			_LOGI("First value is %s\n", val);
			node->value = val;
			filter->list = g_slist_append(filter->list, (gpointer)node);
			memset(temp, '\0', PKG_STRING_LEN_MAX);
		}
		break;
	default:
		node->value = strndup(value, PKG_STRING_LEN_MAX - 1);
		link = g_slist_find_custom(filter->list, (gconstpointer)node, __compare_func);
		if (link)
			filter->list = g_slist_delete_link(filter->list, link);
		filter->list = g_slist_append(filter->list, (gpointer)node);
		break;
	}
	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_usr_filter_count(pkgmgrinfo_appinfo_filter_h handle, int *count, uid_t uid)
{
	int ret;
	char *locale;
	GHashTable *list;

	if (handle == NULL || count == NULL) {
		_LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	locale = _get_system_locale();
	if (locale == NULL)
		return PMINFO_R_ERROR;

	list = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			__free_applications);
	if (list == NULL) {
		free(locale);
		return PMINFO_R_ERROR;
	}

	ret = _appinfo_get_applications(uid, uid, locale, handle, 0, list);
	if (ret == PMINFO_R_OK && uid != GLOBAL_USER)
		ret = _appinfo_get_applications(GLOBAL_USER, uid, locale,
				handle, 0, list);

	if (ret != PMINFO_R_OK) {
		g_hash_table_destroy(list);
		free(locale);
		return PMINFO_R_ERROR;
	}

	*count = g_hash_table_size(list);
	g_hash_table_destroy(list);
	free(locale);

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_filter_count(pkgmgrinfo_appinfo_filter_h handle, int *count)
{
	return pkgmgrinfo_appinfo_usr_filter_count(handle, count, _getuid());
}

API int pkgmgrinfo_appinfo_usr_filter_foreach_appinfo(
		pkgmgrinfo_appinfo_filter_h handle,
		pkgmgrinfo_app_list_cb app_cb, void *user_data, uid_t uid)
{
	if (handle == NULL || app_cb == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	return _appinfo_get_filtered_foreach_appinfo(uid, handle, PMINFO_APPINFO_GET_ALL, app_cb,
			user_data);
}

API int pkgmgrinfo_appinfo_filter_foreach_appinfo(pkgmgrinfo_appinfo_filter_h handle,
				pkgmgrinfo_app_list_cb app_cb, void * user_data)
{
	return pkgmgrinfo_appinfo_usr_filter_foreach_appinfo(handle, app_cb, user_data, _getuid());
}

API int pkgmgrinfo_appinfo_metadata_filter_create(pkgmgrinfo_appinfo_metadata_filter_h *handle)
{
	return (pkgmgrinfo_pkginfo_filter_create(handle));
}

API int pkgmgrinfo_appinfo_metadata_filter_destroy(pkgmgrinfo_appinfo_metadata_filter_h handle)
{
	return (pkgmgrinfo_pkginfo_filter_destroy(handle));
}

API int pkgmgrinfo_appinfo_metadata_filter_add(
		pkgmgrinfo_appinfo_metadata_filter_h handle,
		const char *key, const char *value)
{
	int ret;

	ret = pkgmgrinfo_appinfo_filter_add_string(handle,
			PMINFO_APPINFO_PROP_APP_METADATA_KEY, key);
	if (ret != PMINFO_R_OK)
		return ret;

	/* value can be NULL.
	 * In that case all apps with specified key should be displayed
	 */
	if (value) {
		ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_METADATA_VALUE, value);
		if (ret != PMINFO_R_OK)
			return ret;
	}

	return PMINFO_R_OK;
}

API int pkgmgrinfo_appinfo_usr_metadata_filter_foreach(
		pkgmgrinfo_appinfo_metadata_filter_h handle,
		pkgmgrinfo_app_list_cb app_cb, void *user_data, uid_t uid)
{
	if (handle == NULL || app_cb == NULL) {
		LOGE("invalid parameter");
		return PMINFO_R_EINVAL;
	}

	return _appinfo_get_filtered_foreach_appinfo(uid, handle, PMINFO_APPINFO_GET_ALL, app_cb,
			user_data);
}

API int pkgmgrinfo_appinfo_metadata_filter_foreach(
		pkgmgrinfo_appinfo_metadata_filter_h handle,
		pkgmgrinfo_app_list_cb app_cb, void *user_data)
{
	return pkgmgrinfo_appinfo_usr_metadata_filter_foreach(handle, app_cb,
			user_data, _getuid());
}

API int pkgmgrinfo_appinfo_is_guestmode_visibility(pkgmgrinfo_appinfo_h handle, bool *status)
{
	const char *val;
	pkgmgr_appinfo_x *info = (pkgmgr_appinfo_x *)handle;

	retvm_if(handle == NULL, PMINFO_R_EINVAL, "appinfo handle is NULL\n");
	retvm_if(status == NULL, PMINFO_R_EINVAL, "Argument supplied to hold return value is NULL\n");

	val = info->app_info->guestmode_visibility;
	*status = _get_bool_value(val);
	return PMINFO_R_OK;
}
