#include <stdlib.h>

#include "pkgmgrinfo_basic.h"
#include "pkgmgrinfo_private.h"

static void __ps_free_metadata(gpointer data)
{
	metadata_x *metadata = (metadata_x *)data;
	if (metadata == NULL)
		return;
	if (metadata->key)
		free((void *)metadata->key);
	if (metadata->value)
		free((void *)metadata->value);
	free((void*)metadata);
}

static void __ps_free_permission(gpointer data)
{
	permission_x *permission = (permission_x *)data;
	if (permission == NULL)
		return;
	if (permission->type)
		free((void *)permission->type);
	if (permission->value)
		free((void *)permission->value);
	free((void*)permission);
}

static void __ps_free_icon(gpointer data)
{
	icon_x *icon = (icon_x *)data;
	if (icon == NULL)
		return;
	if (icon->text)
		free((void *)icon->text);
	if (icon->lang)
		free((void *)icon->lang);
	if (icon->section)
		free((void *)icon->section);
	if (icon->size)
		free((void *)icon->size);
	if (icon->resolution)
		free((void *)icon->resolution);
	if (icon->dpi)
		free((void *)icon->dpi);
	free((void*)icon);
}

static void __ps_free_image(gpointer data)
{
	image_x *image = (image_x *)data;
	if (image == NULL)
		return;
	if (image->text)
		free((void *)image->text);
	if (image->lang)
		free((void *)image->lang);
	if (image->section)
		free((void *)image->section);
	free((void*)image);
}

static void __ps_free_notification(gpointer data)
{
	notification_x *notification = (notification_x *)data;
	if (notification == NULL)
		return;
	if (notification->text)
		free((void *)notification->text);
	if (notification->name)
		free((void *)notification->name);
	free((void*)notification);
}

static void __ps_free_compatibility(gpointer data)
{
	compatibility_x *compatibility = (compatibility_x *)data;
	if (compatibility == NULL)
		return;
	if (compatibility->text)
		free((void *)compatibility->text);
	if (compatibility->name)
		free((void *)compatibility->name);
	free((void*)compatibility);
}

static void __ps_free_datacontrol(gpointer data)
{
	datacontrol_x *datacontrol = (datacontrol_x *)data;
	if (datacontrol == NULL)
		return;
	if (datacontrol->providerid)
		free((void *)datacontrol->providerid);
	if (datacontrol->access)
		free((void *)datacontrol->access);
	if (datacontrol->type)
		free((void *)datacontrol->type);
	free((void*)datacontrol);
}

static void __ps_free_appcontrol(gpointer data)
{
	appcontrol_x *appcontrol = (appcontrol_x *)data;
	if (appcontrol == NULL)
		return;
	/*Free Operation*/
	if (appcontrol->operation)
		free((void *)appcontrol->operation);
	/*Free Uri*/
	if (appcontrol->uri)
		free((void *)appcontrol->uri);
	/*Free Mime*/
	if (appcontrol->mime)
		free((void *)appcontrol->mime);
	free((void*)appcontrol);
}

static void __ps_free_define(gpointer data)
{
	define_x *define = (define_x *)data;

	if (define == NULL)
		return;
	if (define->path)
		free((void *)define->path);
	/*Free Request*/
	g_list_free_full(define->request, free);
	/*Free Allowed*/
	g_list_free_full(define->allowed, free);
	free((void*)define);
}

static void __ps_free_datashare(gpointer data)
{
	datashare_x *datashare = (datashare_x *)data;
	if (datashare == NULL)
		return;
	/*Free Define*/
	g_list_free_full(datashare->define, __ps_free_define);
	/*Free Request*/
	g_list_free_full(datashare->request, free);
	free((void*)datashare);
}

static void __ps_free_label(gpointer data)
{
	label_x *label = (label_x *)data;
	if (label == NULL)
		return;
	if (label->name)
		free((void *)label->name);
	if (label->text)
		free((void *)label->text);
	if (label->lang)
		free((void *)label->lang);
	free((void*)label);
}

static void __ps_free_author(gpointer data)
{
	author_x *author = (author_x *)data;
	if (author == NULL)
		return;
	if (author->email)
		free((void *)author->email);
	if (author->text)
		free((void *)author->text);
	if (author->href)
		free((void *)author->href);
	if (author->lang)
		free((void *)author->lang);
	free((void*)author);
}

static void __ps_free_description(gpointer data)
{
	description_x *description = (description_x *)data;
	if (description == NULL)
		return;
	if (description->name)
		free((void *)description->name);
	if (description->text)
		free((void *)description->text);
	if (description->lang)
		free((void *)description->lang);
	free((void*)description);
}

static void __ps_free_license(gpointer data)
{
	license_x *license = (license_x *)data;
	if (license == NULL)
		return;
	if (license->text)
		free((void *)license->text);
	if (license->lang)
		free((void *)license->lang);
	free((void*)license);
}

static void __ps_free_splashscreen(gpointer data)
{
	splashscreen_x *splashscreen = (splashscreen_x *)data;
	if (splashscreen == NULL)
		return;
	if (splashscreen->src)
		free((void *)splashscreen->src);
	if (splashscreen->type)
		free((void *)splashscreen->type);
	if (splashscreen->dpi)
		free((void *)splashscreen->dpi);
	if (splashscreen->orientation)
		free((void *)splashscreen->orientation);
	if (splashscreen->indicatordisplay)
		free((void *)splashscreen->indicatordisplay);
	free((void *)splashscreen);
}

static void __ps_free_application(gpointer data)
{
	application_x *application = (application_x *)data;
	if (application == NULL)
		return;

	if (application->appid)
		free((void *)application->appid);
	if (application->component)
		free((void *)application->component);
	if (application->exec)
		free((void *)application->exec);
	if (application->nodisplay)
		free((void *)application->nodisplay);
	if (application->type)
		free((void *)application->type);
	if (application->onboot)
		free((void *)application->onboot);
	if (application->multiple)
		free((void *)application->multiple);
	if (application->autorestart)
		free((void *)application->autorestart);
	if (application->taskmanage)
		free((void *)application->taskmanage);
	if (application->enabled)
		free((void *)application->enabled);
	if (application->categories)
		free((void *)application->categories);
	if (application->extraid)
		free((void *)application->extraid);
	if (application->hwacceleration)
		free((void *)application->hwacceleration);
	if (application->screenreader)
		free((void *)application->screenreader);
	if (application->mainapp)
		free((void *)application->mainapp);
	if (application->recentimage)
		free((void *)application->recentimage);
	if (application->launchcondition)
		free((void *)application->launchcondition);
	if (application->indicatordisplay)
		free((void *)application->indicatordisplay);
	if (application->portraitimg)
		free((void *)application->portraitimg);
	if (application->landscapeimg)
		free((void *)application->landscapeimg);
	if (application->guestmode_visibility)
		free((void *)application->guestmode_visibility);
	if (application->permission_type)
		free((void *)application->permission_type);
	if (application->preload)
		free((void *)application->preload);
	if (application->submode)
		free((void *)application->submode);
	if (application->submode_mainid)
		free((void *)application->submode_mainid);
	if (application->process_pool)
		free((void *)application->process_pool);
	if (application->installed_storage)
		free((void *)application->installed_storage);
	if (application->launch_mode)
		free((void *)application->launch_mode);
	if (application->ui_gadget)
		free((void *)application->ui_gadget);
	if (application->component_type)
		free((void *)application->component_type);
	if (application->package)
		free((void *)application->package);
	if (application->support_disable)
		free((void *)application->support_disable);

	/*Free Label*/
	g_list_free_full(application->label, __ps_free_label);
	/*Free Icon*/
	g_list_free_full(application->icon, __ps_free_icon);
	/*Free image*/
	g_list_free_full(application->image, __ps_free_image);
	/*Free AppControl*/
	g_list_free_full(application->appcontrol, __ps_free_appcontrol);
	/*Free Category*/
	g_list_free_full(application->category, free);
	/*Free Metadata*/
	g_list_free_full(application->metadata, __ps_free_metadata);
	/*Free permission*/
	g_list_free_full(application->permission, __ps_free_permission);
	/*Free LaunchConditions*/
	g_list_free_full(application->launchconditions, free);
	/*Free Notification*/
	g_list_free_full(application->notification, __ps_free_notification);
	/*Free DataShare*/
	g_list_free_full(application->datashare, __ps_free_datashare);
	/*Free DataControl*/
	g_list_free_full(application->datacontrol, __ps_free_datacontrol);
	/*Free BackgroundCategory*/
	g_list_free_full(application->background_category, free);
	/*Free SplashScreen*/
	g_list_free_full(application->splashscreens, __ps_free_splashscreen);

	free((void *)application);
}

API void pkgmgrinfo_basic_free_application(application_x *application)
{
	__ps_free_application(application);
}

API void pkgmgrinfo_basic_free_package(package_x *package)
{
	if (package == NULL)
		return;
	if (package->for_all_users)
		free((void *)package->for_all_users);
	if (package->ns)
		free((void *)package->ns);
	if (package->package)
		free((void *)package->package);
	if (package->version)
		free((void *)package->version);
	if (package->installlocation)
		free((void *)package->installlocation);
	if (package->preload)
		free((void *)package->preload);
	if (package->readonly)
		free((void *)package->readonly);
	if (package->removable)
		free((void *)package->removable);
	if (package->update)
		free((void *)package->update);
	if (package->system)
		free((void *)package->system);
	if (package->type)
		free((void *)package->type);
	if (package->package_size)
		free((void *)package->package_size);
	if (package->installed_time)
		free((void *)package->installed_time);
	if (package->installed_storage)
		free((void *)package->installed_storage);
	if (package->storeclient_id)
		free((void *)package->storeclient_id);
	if (package->mainapp_id)
		free((void *)package->mainapp_id);
	if (package->package_url)
		free((void *)package->package_url);
	if (package->root_path)
		free((void *)package->root_path);
	if (package->csc_path)
		free((void *)package->csc_path);
	if (package->appsetting)
		free((void *)package->appsetting);
	if (package->nodisplay_setting)
		free((void *)package->nodisplay_setting);
	if (package->api_version)
		free((void *)package->api_version);
	if (package->support_disable)
		free((void *)package->support_disable);
	if (package->tep_name)
		free((void *)package->tep_name);

	/*Free Icon*/
	g_list_free_full(package->icon, __ps_free_icon);
	/*Free Label*/
	g_list_free_full(package->label, __ps_free_label);
	/*Free Author*/
	g_list_free_full(package->author, __ps_free_author);
	/*Free Description*/
	g_list_free_full(package->description, __ps_free_description);
	/*Free License*/
	g_list_free_full(package->license, __ps_free_license);
	/*Free Privileges*/
	g_list_free_full(package->privileges, free);
	/*Free Application*/
	g_list_free_full(package->application, __ps_free_application);
	/*Free Compatibility*/
	g_list_free_full(package->compatibility, __ps_free_compatibility);
	/*Free Device profiles*/
	g_list_free_full(package->deviceprofile, free);
	free((void*)package);
	return;
}

