#ifndef __PKGMGR_INFO_BASIC_H__
#define __PKGMGR_INFO_BASIC_H__

#include <glib.h>

typedef struct metadata_x {
	char *key;
	char *value;
} metadata_x;

typedef struct permission_x {
	char *type;
	char *value;
} permission_x;

typedef struct icon_x {
	char *text;
	char *lang;
	char *section;
	char *size;
	char *resolution;
	char *dpi;
} icon_x;

typedef struct image_x {
	char *text;
	char *lang;
	char *section;
} image_x;

typedef struct define_x {
	char *path;
	GList *allowed;
	GList *request;
} define_x;

typedef struct datashare_x {
	GList *define;
	GList *request;
} datashare_x;

typedef struct description_x {
	char *name;
	char *text;
	char *lang;
} description_x;

typedef struct label_x {
	char *name;
	char *text;
	char *lang;
} label_x;

typedef struct author_x {
	char *email;
	char *href;
	char *text;
	char *lang;
} author_x;

typedef struct license_x {
	char *text;
	char *lang;
} license_x;

typedef struct condition_x {
	char *name;
	char *text;
} condition_x;

typedef struct notification_x {
	char *name;
	char *text;
} notification_x;

typedef struct appcontrol_x {
	char *operation;
	char *uri;
	char *mime;
} appcontrol_x;

typedef struct compatibility_x {
	char *name;
	char *text;
} compatibility_x;

typedef struct datacontrol_x {
	char *providerid;
	char *access;
	char *type;
} datacontrol_x;

typedef struct splashscreen_x {
	char *src;
	char *type;
	char *dpi;
	char *orientation;
	char *indicatordisplay;
	char *operation;
} splashscreen_x;

typedef struct application_x {
	char *appid;	/*attr*/
	char *exec;	/*attr*/
	char *nodisplay;	/*attr, default: "false"*/
	char *multiple;	/*attr, default: "false"*/
	char *taskmanage;	/*attr, default: "true"*/
	char *enabled;	/*attr, default: "true"*/
	char *type;	/*attr*/
	char *categories;	/*attr*/
	char *extraid;	/*attr*/
	char *hwacceleration;	/*attr, default: "default"*/
	char *screenreader;	/*attr, default: "use-system-setting"*/
	char *mainapp;	/*attr, default: "false"*/
	char *package;	/*set from package_x*/
	char *recentimage;	/*attr, default: "false"*/
	char *launchcondition;	/*attr, default: "false"*/
	char *indicatordisplay;	/*attr, default: "true"*/
	char *portraitimg;	/*attr*/
	char *landscapeimg;	/*attr*/
	char *effectimage_type;	/*attr, default: "image"*/
	char *guestmode_visibility;	/*attr, default: "true"*/
	char *component;	/*no xml part*/
	char *permission_type;	/*attr, default: "normal"*/
	char *component_type;	/*attr, default: "uiapp"*/
	char *preload;	/*no xml part*/
	char *submode;	/*attr, default: "false"*/
	char *submode_mainid;	/*attr, default: "false"*/
	char *process_pool;	/*attr, default: "false"*/
	char *installed_storage;
	char *autorestart;	/*attr, default: "false"*/
	char *onboot;	/*attr, default: "false"*/
	char *support_disable;	/*set from package_x*/
	char *ui_gadget;	/*attr, default: "false"*/
	char *launch_mode;	/*attr, default: "single"*/
	char *ambient_support;	/*attr, default: "false"*/
	char *alias_appid;	/*attr*/
	char *effective_appid;	/*attr*/
	char *package_type;	/*set from package_x*/
	char *tep_name;	/*set from package_x*/
	char *root_path;	/*set from package_x*/
	char *api_version;	/*set from package_x*/
	char *for_all_users; /**< Flag that indicates if the package is available for everyone or for current user only, no xml part*/
	char *is_disabled; /**< Flag that indicates if the application is disabled, no xml part*/
	GList *label;	/*element*/
	GList *icon;	/*element*/
	GList *image;	/*element*/
	GList *category; /*element*/
	GList *metadata;	/*element*/
	GList *permission;	/*element*/
	GList *launchconditions;	/*element*/
	GList *notification;	/*element*/
	GList *datashare;	/*element*/
	GList *datacontrol; /*element*/
	GList *background_category; /*element*/
	GList *appcontrol; /*element*/
	GList *splashscreens; /*element*/
} application_x;

typedef struct package_x {
	char *for_all_users;		/**< Flag that indicates if the package is available for everyone or for current user only, no xml part*/
	char *package;		/**< package name, attr*/
	char *version;		/**< package version, attr*/
	char *installlocation;		/**< package install location, attr, default: "internal-only"*/
	char *ns;		/**<name space, attr*/
	char *removable;		/**< package removable flag, no xml part*/
	char *preload;		/**< package preload flag, no xml part*/
	char *readonly;		/**< package readonly flag, no xml part*/
	char *update;			/**< package update flag, no xml part*/
	char *appsetting;		/**< package app setting flag, attr, default: "false"*/
	char *system;		/**< package system flag, no xml part*/
	char *type;		/**< package type, attr*/
	char *package_size;		/**< package size for external installation, attr*/
	char *installed_time;		/**< installed time after finishing of installation, no xml part*/
	char *installed_storage;		/**< package currently installed storage, no xml part*/
	char *storeclient_id;		/**< id of store client for installed package, attr*/
	char *mainapp_id;		/**< app id of main application, no xml part*/
	char *package_url;		/**< app id of main application, attr*/
	char *root_path;		/**< package root path, attr*/
	char *csc_path;		/**< package csc path, attr*/
	char *nodisplay_setting;		/**< package no display setting menu, attr, default: "false"*/
	char *support_disable;		/**< package support disable flag, attr, default: "false"*/
	char *api_version;		/**< minimum version of API package using, attr, default: patch_version trimmed version from tizen_full_version*/
	char *tep_name;	/*no xml part*/
	char *backend_installer;		/**< package backend installer, attr*/
	GList *icon;		/**< package icon, element*/
	GList *label;		/**< package label, element*/
	GList *author;		/**< package author, element*/
	GList *description;		/**< package description, element*/
	GList *license;		/**< package license, no xml part*/
	GList *privileges;	/**< package privileges, element*/
	GList *application;		/**< package's application, element*/
	GList *compatibility;		/**< package compatibility, element*/
	GList *deviceprofile;		/**< package device profile, element*/
} package_x;

typedef struct package_x manifest_x;

void pkgmgrinfo_basic_free_application(application_x *application);
void pkgmgrinfo_basic_free_package(package_x *package);

#endif
