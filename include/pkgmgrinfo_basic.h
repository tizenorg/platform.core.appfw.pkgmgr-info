#ifndef __PKGMGR_INFO_BASIC_H__
#define __PKGMGR_INFO_BASIC_H__

#include <glib.h>

typedef struct metadata_x {
	const char *key;
	const char *value;
} metadata_x;

typedef struct permission_x {
	const char *type;
	const char *value;
} permission_x;

typedef struct icon_x {
	const char *name;
	const char *text;
	const char *lang;
	const char *section;
	const char *size;
	const char *resolution;
} icon_x;

typedef struct image_x {
	const char *name;
	const char *text;
	const char *lang;
	const char *section;
} image_x;

typedef struct define_x {
	const char *path;
	GList *allowed;
	GList *request;
} define_x;

typedef struct datashare_x {
	GList *define;
	GList *request;
} datashare_x;

typedef struct description_x {
	const char *name;
	const char *text;
	const char *lang;
} description_x;

typedef struct label_x {
	const char *name;
	const char *text;
	const char *lang;
} label_x;

typedef struct author_x {
	const char *email;
	const char *href;
	const char *text;
	const char *lang;
} author_x;

typedef struct license_x {
	const char *text;
	const char *lang;
} license_x;

typedef struct condition_x {
	const char *name;
	const char *text;
} condition_x;

typedef struct notification_x {
	const char *name;
	const char *text;
} notification_x;

typedef struct appsvc_x {
	const char *text;
	const char *operation;
	const char *uri;
	const char *mime;
	const char *subapp;
} appsvc_x;

typedef struct appcontrol_x {
	const char *operation;
	const char *uri;
	const char *mime;
} appcontrol_x;

typedef struct compatibility_x {
	const char *name;
	const char *text;
} compatibility_x;

typedef struct datacontrol_x {
	const char *providerid;
	const char *access;
	const char *type;
} datacontrol_x;

typedef struct application_x {
	const char *appid;
	const char *component;
	const char *exec;
	const char *nodisplay;
	const char *type;
	const char *onboot;
	const char *multiple;
	const char *autorestart;
	const char *taskmanage;
	const char *enabled;
	const char *categories;
	const char *extraid;
	const char *hwacceleration;
	const char *screenreader;
	const char *mainapp;
	const char *recentimage;
	const char *launchcondition;
	const char *indicatordisplay;
	const char *portraitimg;
	const char *landscapeimg;
	const char *guestmode_visibility;
	const char *permission_type;
	const char *preload;
	const char *submode;
	const char *submode_mainid;
	const char *launch_mode;
	const char *ui_gadget;
	const char *support_disable;
	const char *component_type;
	const char *package;
	GList *label;
	GList *icon;
	GList *image;
	GList *appsvc;
	GList *appcontrol;
	GList *category;
	GList *metadata;
	GList *permission;
	GList *launchconditions;
	GList *notification;
	GList *datashare;
	GList *datacontrol;
} application_x;

typedef struct package_x {
	const char *for_all_users;		/**< Flag that indicates if the package is available for everyone or for current user only*/
	const char *package;		/**< package name*/
	const char *version;		/**< package version*/
	const char *installlocation;		/**< package install location*/
	const char *ns;		/**<name space*/
	const char *removable;		/**< package removable flag*/
	const char *preload;		/**< package preload flag*/
	const char *readonly;		/**< package readonly flag*/
	const char *update;			/**< package update flag*/
	const char *appsetting;		/**< package app setting flag*/
	const char *system;		/**< package system flag*/
	const char *type;		/**< package type*/
	const char *package_size;		/**< package size for external installation*/
	const char *installed_time;		/**< installed time after finishing of installation*/
	const char *installed_storage;		/**< package currently installed storage*/
	const char *storeclient_id;		/**< id of store client for installed package*/
	const char *mainapp_id;		/**< app id of main application*/
	const char *package_url;		/**< app id of main application*/
	const char *root_path;		/**< package root path*/
	const char *csc_path;		/**< package csc path*/
	const char *nodisplay_setting;		/**< package no display setting menu*/
	const char *api_version;		/**< minimum version of API package using*/
	const char *support_disable;		/**< package support disable flag*/
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
		const char *tep_path;		/**< package tep path if exists*/
#endif
	GList *icon;		/**< package icon*/
	GList *label;		/**< package label*/
	GList *author;		/**< package author*/
	GList *description;		/**< package description*/
	GList *license;		/**< package license*/
	GList *privileges;	/**< package privileges*/
	GList *application;		/**< package's application*/
	GList *compatibility;		/**< package compatibility*/
} package_x;

typedef struct package_x manifest_x;

void pkgmgrinfo_basic_free_application(application_x *application);
void pkgmgrinfo_basic_free_package(package_x *package);

#endif
