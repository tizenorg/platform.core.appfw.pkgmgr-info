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
	const char *text;
	const char *lang;
	const char *section;
	const char *size;
	const char *resolution;
	const char *dpi;
} icon_x;

typedef struct image_x {
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
	const char *appid;	/*attr*/
	const char *exec;	/*attr*/
	const char *nodisplay;	/*attr, default: "false"*/
	const char *multiple;	/*attr, default: "false"*/
	const char *taskmanage;	/*attr, default: "true"*/
	const char *enabled;	/*attr, default: "true"*/
	const char *type;	/*attr*/
	const char *categories;	/*attr*/
	const char *extraid;	/*attr*/
	const char *hwacceleration;	/*attr, default: "default"*/
	const char *screenreader;	/*attr, default: "use-system-setting"*/
	const char *mainapp;	/*attr, default: "false"*/
	const char *package;	/*set from package_x*/
	const char *recentimage;	/*attr, default: "false"*/
	const char *launchcondition;	/*attr, default: "false"*/
	const char *indicatordisplay;	/*attr, default: "true"*/
	const char *portraitimg;	/*attr*/
	const char *landscapeimg;	/*attr*/
	const char *effectimage_type;	/*attr, default: "image"*/
	const char *guestmode_visibility;	/*attr, default: "true"*/
	const char *component;	/*no xml part*/
	const char *permission_type;	/*attr, default: "normal"*/
	const char *component_type;	/*attr, default: "uiapp"*/
	const char *preload;	/*no xml part*/
	const char *submode;	/*attr, default: "false"*/
	const char *submode_mainid;	/*attr, default: "false"*/
	const char *process_pool;	/*attr, default: "false"*/
	const char *installed_storage;
	const char *autorestart;	/*attr, default: "false"*/
	const char *onboot;	/*attr, default: "false"*/
	const char *support_disable;	/*set from package_x*/
	const char *ui_gadget;	/*attr, default: "false"*/
	const char *launch_mode;	/*attr, default: "single"*/
	const char *ambient_support;	/*attr, default: "false"*/
	const char *alias_appid;	/*attr*/
	const char *effective_appid;	/*attr*/
	const char *package_type;	/*set from package_x*/
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
} application_x;

typedef struct package_x {
	const char *for_all_users;		/**< Flag that indicates if the package is available for everyone or for current user only, no xml part*/
	const char *package;		/**< package name, attr*/
	const char *version;		/**< package version, attr*/
	const char *installlocation;		/**< package install location, attr, default: "internal-only"*/
	const char *ns;		/**<name space, attr*/
	const char *removable;		/**< package removable flag, no xml part*/
	const char *preload;		/**< package preload flag, no xml part*/
	const char *readonly;		/**< package readonly flag, no xml part*/
	const char *update;			/**< package update flag, no xml part*/
	const char *appsetting;		/**< package app setting flag, attr, default: "false"*/
	const char *system;		/**< package system flag, no xml part*/
	const char *type;		/**< package type, attr, default: "rpm"*/
	const char *package_size;		/**< package size for external installation, attr*/
	const char *installed_time;		/**< installed time after finishing of installation, no xml part*/
	const char *installed_storage;		/**< package currently installed storage, no xml part*/
	const char *storeclient_id;		/**< id of store client for installed package, attr*/
	const char *mainapp_id;		/**< app id of main application, no xml part*/
	const char *package_url;		/**< app id of main application, attr*/
	const char *root_path;		/**< package root path, attr*/
	const char *csc_path;		/**< package csc path, attr*/
	const char *nodisplay_setting;		/**< package no display setting menu, attr, default: "false"*/
	const char *support_disable;		/**< package support disable flag, attr, default: "false"*/
	const char *api_version;		/**< minimum version of API package using, attr, default: patch_version trimmed version from tizen_full_version*/
	const char *tep_name;	/*no xml part*/
	const char *backend_installer;		/**< package backend installer, attr*/
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
