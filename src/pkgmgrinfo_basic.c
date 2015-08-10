
#include <stdlib.h>

#include "pkgmgrinfo_basic.h"
#include "pkgmgrinfo_private.h"

static void __ps_free_category(category_x *category)
{
	if (category == NULL)
		return;
	if (category->name) {
		free((void *)category->name);
		category->name = NULL;
	}
	free((void*)category);
	category = NULL;
}

static void __ps_free_privilege(privilege_x *privilege)
{
	if (privilege == NULL)
		return;
	if (privilege->text) {
		free((void *)privilege->text);
		privilege->text = NULL;
	}
	free((void*)privilege);
	privilege = NULL;
}

static void __ps_free_privileges(privileges_x *privileges)
{
	if (privileges == NULL)
		return;
	/*Free Privilege*/
	if (privileges->privilege) {
		privilege_x *privilege = privileges->privilege;
		privilege_x *tmp = NULL;
		while(privilege != NULL) {
			tmp = privilege->next;
			__ps_free_privilege(privilege);
			privilege = tmp;
		}
	}
	free((void*)privileges);
	privileges = NULL;
}

static void __ps_free_metadata(metadata_x *metadata)
{
	if (metadata == NULL)
		return;
	if (metadata->key) {
		free((void *)metadata->key);
		metadata->key = NULL;
	}
	if (metadata->value) {
		free((void *)metadata->value);
		metadata->value = NULL;
	}
	free((void*)metadata);
	metadata = NULL;
}

static void __ps_free_permission(permission_x *permission)
{
	if (permission == NULL)
		return;
	if (permission->type) {
		free((void *)permission->type);
		permission->type = NULL;
	}
	if (permission->value) {
		free((void *)permission->value);
		permission->value = NULL;
	}
	free((void*)permission);
	permission = NULL;
}

static void __ps_free_icon(icon_x *icon)
{
	if (icon == NULL)
		return;
	if (icon->text) {
		free((void *)icon->text);
		icon->text = NULL;
	}
	if (icon->lang) {
		free((void *)icon->lang);
		icon->lang = NULL;
	}
	if (icon->name) {
		free((void *)icon->name);
		icon->name= NULL;
	}
	if (icon->section) {
		free((void *)icon->section);
		icon->section = NULL;
	}
	if (icon->size) {
		free((void *)icon->size);
		icon->size = NULL;
	}
	if (icon->resolution) {
		free((void *)icon->resolution);
		icon->resolution = NULL;
	}
	free((void*)icon);
	icon = NULL;
}

static void __ps_free_image(image_x *image)
{
	if (image == NULL)
		return;
	if (image->text) {
		free((void *)image->text);
		image->text = NULL;
	}
	if (image->lang) {
		free((void *)image->lang);
		image->lang = NULL;
	}
	if (image->name) {
		free((void *)image->name);
		image->name= NULL;
	}
	if (image->section) {
		free((void *)image->section);
		image->section = NULL;
	}
	free((void*)image);
	image = NULL;
}

static void __ps_free_operation(operation_x *operation)
{
	if (operation == NULL)
		return;
	if (operation->text) {
		free((void *)operation->text);
		operation->text = NULL;
	}
	free((void*)operation);
	operation = NULL;
}

static void __ps_free_uri(uri_x *uri)
{
	if (uri == NULL)
		return;
	if (uri->text) {
		free((void *)uri->text);
		uri->text = NULL;
	}
	free((void*)uri);
	uri = NULL;
}

static void __ps_free_mime(mime_x *mime)
{
	if (mime == NULL)
		return;
	if (mime->text) {
		free((void *)mime->text);
		mime->text = NULL;
	}
	free((void*)mime);
	mime = NULL;
}

static void __ps_free_subapp(subapp_x *subapp)
{
	if (subapp == NULL)
		return;
	if (subapp->text) {
		free((void *)subapp->text);
		subapp->text = NULL;
	}
	free((void*)subapp);
	subapp = NULL;
}

static void __ps_free_condition(condition_x *condition)
{
	if (condition == NULL)
		return;
	if (condition->text) {
		free((void *)condition->text);
		condition->text = NULL;
	}
	if (condition->name) {
		free((void *)condition->name);
		condition->name = NULL;
	}
	free((void*)condition);
	condition = NULL;
}

static void __ps_free_notification(notification_x *notification)
{
	if (notification == NULL)
		return;
	if (notification->text) {
		free((void *)notification->text);
		notification->text = NULL;
	}
	if (notification->name) {
		free((void *)notification->name);
		notification->name = NULL;
	}
	free((void*)notification);
	notification = NULL;
}

static void __ps_free_compatibility(compatibility_x *compatibility)
{
	if (compatibility == NULL)
		return;
	if (compatibility->text) {
		free((void *)compatibility->text);
		compatibility->text = NULL;
	}
	if (compatibility->name) {
		free((void *)compatibility->name);
		compatibility->name = NULL;
	}
	free((void*)compatibility);
	compatibility = NULL;
}

static void __ps_free_allowed(allowed_x *allowed)
{
	if (allowed == NULL)
		return;
	if (allowed->name) {
		free((void *)allowed->name);
		allowed->name = NULL;
	}
	if (allowed->text) {
		free((void *)allowed->text);
		allowed->text = NULL;
	}
	free((void*)allowed);
	allowed = NULL;
}

static void __ps_free_request(request_x *request)
{
	if (request == NULL)
		return;
	if (request->text) {
		free((void *)request->text);
		request->text = NULL;
	}
	free((void*)request);
	request = NULL;
}

static void __ps_free_datacontrol(datacontrol_x *datacontrol)
{
	if (datacontrol == NULL)
		return;
	if (datacontrol->providerid) {
		free((void *)datacontrol->providerid);
		datacontrol->providerid = NULL;
	}
	if (datacontrol->access) {
		free((void *)datacontrol->access);
		datacontrol->access = NULL;
	}
	if (datacontrol->type) {
		free((void *)datacontrol->type);
		datacontrol->type = NULL;
	}
	free((void*)datacontrol);
	datacontrol = NULL;
}

static void __ps_free_launchconditions(launchconditions_x *launchconditions)
{
	if (launchconditions == NULL)
		return;
	if (launchconditions->text) {
		free((void *)launchconditions->text);
		launchconditions->text = NULL;
	}
	/*Free Condition*/
	if (launchconditions->condition) {
		condition_x *condition = launchconditions->condition;
		condition_x *tmp = NULL;
		while(condition != NULL) {
			tmp = condition->next;
			__ps_free_condition(condition);
			condition = tmp;
		}
	}
	free((void*)launchconditions);
	launchconditions = NULL;
}

static void __ps_free_appcontrol(appcontrol_x *appcontrol)
{
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
	appcontrol = NULL;
}

static void __ps_free_appsvc(appsvc_x *appsvc)
{
	if (appsvc == NULL)
		return;
	if (appsvc->text) {
		free((void *)appsvc->text);
		appsvc->text = NULL;
	}
	/*Free Operation*/
	if (appsvc->operation) {
		operation_x *operation = appsvc->operation;
		operation_x *tmp = NULL;
		while(operation != NULL) {
			tmp = operation->next;
			__ps_free_operation(operation);
			operation = tmp;
		}
	}
	/*Free Uri*/
	if (appsvc->uri) {
		uri_x *uri = appsvc->uri;
		uri_x *tmp = NULL;
		while(uri != NULL) {
			tmp = uri->next;
			__ps_free_uri(uri);
			uri = tmp;
		}
	}
	/*Free Mime*/
	if (appsvc->mime) {
		mime_x *mime = appsvc->mime;
		mime_x *tmp = NULL;
		while(mime != NULL) {
			tmp = mime->next;
			__ps_free_mime(mime);
			mime = tmp;
		}
	}
	/*Free subapp*/
	if (appsvc->subapp) {
		subapp_x *subapp = appsvc->subapp;
		subapp_x *tmp = NULL;
		while(subapp != NULL) {
			tmp = subapp->next;
			__ps_free_subapp(subapp);
			subapp = tmp;
		}
	}
	free((void*)appsvc);
	appsvc = NULL;
}

static void __ps_free_deviceprofile(deviceprofile_x *deviceprofile)
{
	return;
}

static void __ps_free_define(define_x *define)
{
	if (define == NULL)
		return;
	if (define->path) {
		free((void *)define->path);
		define->path = NULL;
	}
	/*Free Request*/
	if (define->request) {
		request_x *request = define->request;
		request_x *tmp = NULL;
		while(request != NULL) {
			tmp = request->next;
			__ps_free_request(request);
			request = tmp;
		}
	}
	/*Free Allowed*/
	if (define->allowed) {
		allowed_x *allowed = define->allowed;
		allowed_x *tmp = NULL;
		while(allowed != NULL) {
			tmp = allowed->next;
			__ps_free_allowed(allowed);
			allowed = tmp;
		}
	}
	free((void*)define);
	define = NULL;
}

static void __ps_free_datashare(datashare_x *datashare)
{
	if (datashare == NULL)
		return;
	/*Free Define*/
	if (datashare->define) {
		define_x *define =  datashare->define;
		define_x *tmp = NULL;
		while(define != NULL) {
			tmp = define->next;
			__ps_free_define(define);
			define = tmp;
		}
	}
	/*Free Request*/
	if (datashare->request) {
		request_x *request = datashare->request;
		request_x *tmp = NULL;
		while(request != NULL) {
			tmp = request->next;
			__ps_free_request(request);
			request = tmp;
		}
	}
	free((void*)datashare);
	datashare = NULL;
}

static void __ps_free_label(label_x *label)
{
	if (label == NULL)
		return;
	if (label->name) {
		free((void *)label->name);
		label->name = NULL;
	}
	if (label->text) {
		free((void *)label->text);
		label->text = NULL;
	}
	if (label->lang) {
		free((void *)label->lang);
		label->lang= NULL;
	}
	free((void*)label);
	label = NULL;
}

static void __ps_free_author(author_x *author)
{
	if (author == NULL)
		return;
	if (author->email) {
		free((void *)author->email);
		author->email = NULL;
	}
	if (author->text) {
		free((void *)author->text);
		author->text = NULL;
	}
	if (author->href) {
		free((void *)author->href);
		author->href = NULL;
	}
	if (author->lang) {
		free((void *)author->lang);
		author->lang = NULL;
	}
	free((void*)author);
	author = NULL;
}

static void __ps_free_description(description_x *description)
{
	if (description == NULL)
		return;
	if (description->name) {
		free((void *)description->name);
		description->name = NULL;
	}
	if (description->text) {
		free((void *)description->text);
		description->text = NULL;
	}
	if (description->lang) {
		free((void *)description->lang);
		description->lang = NULL;
	}
	free((void*)description);
	description = NULL;
}

static void __ps_free_license(license_x *license)
{
	if (license == NULL)
		return;
	if (license->text) {
		free((void *)license->text);
		license->text = NULL;
	}
	if (license->lang) {
		free((void *)license->lang);
		license->lang = NULL;
	}
	free((void*)license);
	license = NULL;
}

static void __ps_free_uiapplication(uiapplication_x *uiapplication)
{
	if (uiapplication == NULL)
		return;
	if (uiapplication->exec) {
		free((void *)uiapplication->exec);
		uiapplication->exec = NULL;
	}
	if (uiapplication->appid) {
		free((void *)uiapplication->appid);
		uiapplication->appid = NULL;
	}
	if (uiapplication->nodisplay) {
		free((void *)uiapplication->nodisplay);
		uiapplication->nodisplay = NULL;
	}
	if (uiapplication->multiple) {
		free((void *)uiapplication->multiple);
		uiapplication->multiple = NULL;
	}
	if (uiapplication->type) {
		free((void *)uiapplication->type);
		uiapplication->type = NULL;
	}
	if (uiapplication->categories) {
		free((void *)uiapplication->categories);
		uiapplication->categories = NULL;
	}
	if (uiapplication->extraid) {
		free((void *)uiapplication->extraid);
		uiapplication->extraid = NULL;
	}
	if (uiapplication->taskmanage) {
		free((void *)uiapplication->taskmanage);
		uiapplication->taskmanage = NULL;
	}
	if (uiapplication->enabled) {
		free((void *)uiapplication->enabled);
		uiapplication->enabled = NULL;
	}
	if (uiapplication->hwacceleration) {
		free((void *)uiapplication->hwacceleration);
		uiapplication->hwacceleration = NULL;
	}
	if (uiapplication->screenreader) {
		free((void *)uiapplication->screenreader);
		uiapplication->screenreader = NULL;
	}
	if (uiapplication->mainapp) {
		free((void *)uiapplication->mainapp);
		uiapplication->mainapp = NULL;
	}
	if (uiapplication->recentimage) {
		free((void *)uiapplication->recentimage);
		uiapplication->recentimage = NULL;
	}
	if (uiapplication->package) {
		free((void *)uiapplication->package);
		uiapplication->package = NULL;
	}
	if (uiapplication->launchcondition) {
		free((void *)uiapplication->launchcondition);
		uiapplication->launchcondition = NULL;
	}
	/*Free Label*/
	if (uiapplication->label) {
		label_x *label = uiapplication->label;
		label_x *tmp = NULL;
		while(label != NULL) {
			tmp = label->next;
			__ps_free_label(label);
			label = tmp;
		}
	}
	/*Free Icon*/
	if (uiapplication->icon) {
		icon_x *icon = uiapplication->icon;
		icon_x *tmp = NULL;
		while(icon != NULL) {
			tmp = icon->next;
			__ps_free_icon(icon);
			icon = tmp;
		}
	}
	/*Free image*/
	if (uiapplication->image) {
		image_x *image = uiapplication->image;
		image_x *tmp = NULL;
		while(image != NULL) {
			tmp = image->next;
			__ps_free_image(image);
			image = tmp;
		}
	}
	/*Free AppControl*/
	if (uiapplication->appcontrol) {
		appcontrol_x *appcontrol = uiapplication->appcontrol;
		appcontrol_x *tmp = NULL;
		while(appcontrol != NULL) {
			tmp = appcontrol->next;
			__ps_free_appcontrol(appcontrol);
			appcontrol = tmp;
		}
	}
	/*Free LaunchConditions*/
	if (uiapplication->launchconditions) {
		launchconditions_x *launchconditions = uiapplication->launchconditions;
		launchconditions_x *tmp = NULL;
		while(launchconditions != NULL) {
			tmp = launchconditions->next;
			__ps_free_launchconditions(launchconditions);
			launchconditions = tmp;
		}
	}
	/*Free Notification*/
	if (uiapplication->notification) {
		notification_x *notification = uiapplication->notification;
		notification_x *tmp = NULL;
		while(notification != NULL) {
			tmp = notification->next;
			__ps_free_notification(notification);
			notification = tmp;
		}
	}
	/*Free DataShare*/
	if (uiapplication->datashare) {
		datashare_x *datashare = uiapplication->datashare;
		datashare_x *tmp = NULL;
		while(datashare != NULL) {
			tmp = datashare->next;
			__ps_free_datashare(datashare);
			datashare = tmp;
		}
	}
	/*Free AppSvc*/
	if (uiapplication->appsvc) {
		appsvc_x *appsvc = uiapplication->appsvc;
		appsvc_x *tmp = NULL;
		while(appsvc != NULL) {
			tmp = appsvc->next;
			__ps_free_appsvc(appsvc);
			appsvc = tmp;
		}
	}
	/*Free Category*/
	if (uiapplication->category) {
		category_x *category = uiapplication->category;
		category_x *tmp = NULL;
		while(category != NULL) {
			tmp = category->next;
			__ps_free_category(category);
			category = tmp;
		}
	}
	/*Free Metadata*/
	if (uiapplication->metadata) {
		metadata_x *metadata = uiapplication->metadata;
		metadata_x *tmp = NULL;
		while(metadata != NULL) {
			tmp = metadata->next;
			__ps_free_metadata(metadata);
			metadata = tmp;
		}
	}
	/*Free permission*/
	if (uiapplication->permission) {
		permission_x *permission = uiapplication->permission;
		permission_x *tmp = NULL;
		while(permission != NULL) {
			tmp = permission->next;
			__ps_free_permission(permission);
			permission = tmp;
		}
	}
	/*Free DataControl*/
	if (uiapplication->datacontrol) {
		datacontrol_x *datacontrol = uiapplication->datacontrol;
		datacontrol_x *tmp = NULL;
		while(datacontrol != NULL) {
			tmp = datacontrol->next;
			__ps_free_datacontrol(datacontrol);
			datacontrol = tmp;
		}
	}
	/* _PRODUCT_LAUNCHING_ENHANCED_ START */
	if (uiapplication->indicatordisplay) {
		free((void *)uiapplication->indicatordisplay);
		uiapplication->indicatordisplay = NULL;
	}
	if (uiapplication->portraitimg) {
		free((void *)uiapplication->portraitimg);
		uiapplication->portraitimg = NULL;
	}
	if (uiapplication->landscapeimg) {
		free((void *)uiapplication->landscapeimg);
		uiapplication->landscapeimg = NULL;
	}
	/* _PRODUCT_LAUNCHING_ENHANCED_ END */
	if (uiapplication->guestmode_visibility) {
		free((void *)uiapplication->guestmode_visibility);
		uiapplication->guestmode_visibility = NULL;
	}
	if (uiapplication->app_component) {
		free((void *)uiapplication->app_component);
		uiapplication->app_component = NULL;
	}
	if (uiapplication->permission_type) {
		free((void *)uiapplication->permission_type);
		uiapplication->permission_type = NULL;
	}
	if (uiapplication->component_type) {
		free((void *)uiapplication->component_type);
		uiapplication->component_type = NULL;
	}
	if (uiapplication->preload) {
		free((void *)uiapplication->preload);
		uiapplication->preload = NULL;
	}
	if (uiapplication->submode) {
		free((void *)uiapplication->submode);
		uiapplication->submode = NULL;
	}
	if (uiapplication->submode_mainid) {
		free((void *)uiapplication->submode_mainid);
		uiapplication->submode_mainid = NULL;
	}

	free((void*)uiapplication);
	uiapplication = NULL;
}

static void __ps_free_serviceapplication(serviceapplication_x *serviceapplication)
{
	if (serviceapplication == NULL)
		return;
	if (serviceapplication->exec) {
		free((void *)serviceapplication->exec);
		serviceapplication->exec = NULL;
	}
	if (serviceapplication->appid) {
		free((void *)serviceapplication->appid);
		serviceapplication->appid = NULL;
	}
	if (serviceapplication->onboot) {
		free((void *)serviceapplication->onboot);
		serviceapplication->onboot = NULL;
	}
	if (serviceapplication->autorestart) {
		free((void *)serviceapplication->autorestart);
		serviceapplication->autorestart = NULL;
	}
	if (serviceapplication->type) {
		free((void *)serviceapplication->type);
		serviceapplication->type = NULL;
	}
	if (serviceapplication->enabled) {
		free((void *)serviceapplication->enabled);
		serviceapplication->enabled = NULL;
	}
	if (serviceapplication->package) {
		free((void *)serviceapplication->package);
		serviceapplication->package = NULL;
	}
	if (serviceapplication->permission_type) {
		free((void *)serviceapplication->permission_type);
		serviceapplication->permission_type = NULL;
	}
	/*Free Label*/
	if (serviceapplication->label) {
		label_x *label = serviceapplication->label;
		label_x *tmp = NULL;
		while(label != NULL) {
			tmp = label->next;
			__ps_free_label(label);
			label = tmp;
		}
	}
	/*Free Icon*/
	if (serviceapplication->icon) {
		icon_x *icon = serviceapplication->icon;
		icon_x *tmp = NULL;
		while(icon != NULL) {
			tmp = icon->next;
			__ps_free_icon(icon);
			icon = tmp;
		}
	}
	/*Free AppControl*/
	if (serviceapplication->appcontrol) {
		appcontrol_x *appcontrol = serviceapplication->appcontrol;
		appcontrol_x *tmp = NULL;
		while(appcontrol != NULL) {
			tmp = appcontrol->next;
			__ps_free_appcontrol(appcontrol);
			appcontrol = tmp;
		}
	}
	/*Free DataControl*/
	if (serviceapplication->datacontrol) {
		datacontrol_x *datacontrol = serviceapplication->datacontrol;
		datacontrol_x *tmp = NULL;
		while(datacontrol != NULL) {
			tmp = datacontrol->next;
			__ps_free_datacontrol(datacontrol);
			datacontrol = tmp;
		}
	}
	/*Free LaunchConditions*/
	if (serviceapplication->launchconditions) {
		launchconditions_x *launchconditions = serviceapplication->launchconditions;
		launchconditions_x *tmp = NULL;
		while(launchconditions != NULL) {
			tmp = launchconditions->next;
			__ps_free_launchconditions(launchconditions);
			launchconditions = tmp;
		}
	}
	/*Free Notification*/
	if (serviceapplication->notification) {
		notification_x *notification = serviceapplication->notification;
		notification_x *tmp = NULL;
		while(notification != NULL) {
			tmp = notification->next;
			__ps_free_notification(notification);
			notification = tmp;
		}
	}
	/*Free DataShare*/
	if (serviceapplication->datashare) {
		datashare_x *datashare = serviceapplication->datashare;
		datashare_x *tmp = NULL;
		while(datashare != NULL) {
			tmp = datashare->next;
			__ps_free_datashare(datashare);
			datashare = tmp;
		}
	}
	/*Free AppSvc*/
	if (serviceapplication->appsvc) {
		appsvc_x *appsvc = serviceapplication->appsvc;
		appsvc_x *tmp = NULL;
		while(appsvc != NULL) {
			tmp = appsvc->next;
			__ps_free_appsvc(appsvc);
			appsvc = tmp;
		}
	}
	/*Free Category*/
	if (serviceapplication->category) {
		category_x *category = serviceapplication->category;
		category_x *tmp = NULL;
		while(category != NULL) {
			tmp = category->next;
			__ps_free_category(category);
			category = tmp;
		}
	}
	/*Free Metadata*/
	if (serviceapplication->metadata) {
		metadata_x *metadata = serviceapplication->metadata;
		metadata_x *tmp = NULL;
		while(metadata != NULL) {
			tmp = metadata->next;
			__ps_free_metadata(metadata);
			metadata = tmp;
		}
	}
	/*Free permission*/
	if (serviceapplication->permission) {
		permission_x *permission = serviceapplication->permission;
		permission_x *tmp = NULL;
		while(permission != NULL) {
			tmp = permission->next;
			__ps_free_permission(permission);
			permission = tmp;
		}
	}
	free((void*)serviceapplication);
	serviceapplication = NULL;
}

static void __ps_free_font(font_x *font)
{
	if (font == NULL)
		return;
	if (font->name) {
		free((void *)font->name);
		font->name = NULL;
	}
	if (font->text) {
		free((void *)font->text);
		font->text = NULL;
	}
	free((void*)font);
	font = NULL;
}

static void __ps_free_theme(theme_x *theme)
{
	if (theme == NULL)
		return;
	if (theme->name) {
		free((void *)theme->name);
		theme->name = NULL;
	}
	if (theme->text) {
		free((void *)theme->text);
		theme->text = NULL;
	}
	free((void*)theme);
	theme = NULL;
}

static void __ps_free_daemon(daemon_x *daemon)
{
	if (daemon == NULL)
		return;
	if (daemon->name) {
		free((void *)daemon->name);
		daemon->name = NULL;
	}
	if (daemon->text) {
		free((void *)daemon->text);
		daemon->text = NULL;
	}
	free((void*)daemon);
	daemon = NULL;
}

static void __ps_free_ime(ime_x *ime)
{
	if (ime == NULL)
		return;
	if (ime->name) {
		free((void *)ime->name);
		ime->name = NULL;
	}
	if (ime->text) {
		free((void *)ime->text);
		ime->text = NULL;
	}
	free((void*)ime);
	ime = NULL;
}

API void pkgmgrinfo_basic_free_application(application_x *application)
{
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
	if (application->launch_mode)
		free((void *)application->launch_mode);
	if (application->component_type)
		free((void *)application->component_type);
	if (application->package)
		free((void *)application->package);

	/*Free Label*/
	if (application->label) {
		label_x *label = application->label;
		label_x *tmp = NULL;
		while(label != NULL) {
			tmp = label->next;
			__ps_free_label(label);
			label = tmp;
		}
	}
	/*Free Icon*/
	if (application->icon) {
		icon_x *icon = application->icon;
		icon_x *tmp = NULL;
		while(icon != NULL) {
			tmp = icon->next;
			__ps_free_icon(icon);
			icon = tmp;
		}
	}
	/*Free image*/
	if (application->image) {
		image_x *image = application->image;
		image_x *tmp = NULL;
		while(image != NULL) {
			tmp = image->next;
			__ps_free_image(image);
			image = tmp;
		}
	}
	/*Free AppSvc*/
	if (application->appsvc) {
		appsvc_x *appsvc = application->appsvc;
		appsvc_x *tmp = NULL;
		while(appsvc != NULL) {
			tmp = appsvc->next;
			__ps_free_appsvc(appsvc);
			appsvc = tmp;
		}
	}
	/*Free AppControl*/
	if (application->appcontrol) {
		appcontrol_x *appcontrol = application->appcontrol;
		appcontrol_x *tmp = NULL;
		while(appcontrol != NULL) {
			tmp = appcontrol->next;
			__ps_free_appcontrol(appcontrol);
			appcontrol = tmp;
		}
	}
	/*Free Category*/
	if (application->category) {
		category_x *category = application->category;
		category_x *tmp = NULL;
		while(category != NULL) {
			tmp = category->next;
			__ps_free_category(category);
			category = tmp;
		}
	}
	/*Free Metadata*/
	if (application->metadata) {
		metadata_x *metadata = application->metadata;
		metadata_x *tmp = NULL;
		while(metadata != NULL) {
			tmp = metadata->next;
			__ps_free_metadata(metadata);
			metadata = tmp;
		}
	}
	/*Free permission*/
	if (application->permission) {
		permission_x *permission = application->permission;
		permission_x *tmp = NULL;
		while(permission != NULL) {
			tmp = permission->next;
			__ps_free_permission(permission);
			permission = tmp;
		}
	}
	/*Free LaunchConditions*/
	if (application->launchconditions) {
		launchconditions_x *launchconditions = application->launchconditions;
		launchconditions_x *tmp = NULL;
		while(launchconditions != NULL) {
			tmp = launchconditions->next;
			__ps_free_launchconditions(launchconditions);
			launchconditions = tmp;
		}
	}
	/*Free Notification*/
	if (application->notification) {
		notification_x *notification = application->notification;
		notification_x *tmp = NULL;
		while(notification != NULL) {
			tmp = notification->next;
			__ps_free_notification(notification);
			notification = tmp;
		}
	}
	/*Free DataShare*/
	if (application->datashare) {
		datashare_x *datashare = application->datashare;
		datashare_x *tmp = NULL;
		while(datashare != NULL) {
			tmp = datashare->next;
			__ps_free_datashare(datashare);
			datashare = tmp;
		}
	}
	/*Free DataControl*/
	if (application->datacontrol) {
		datacontrol_x *datacontrol = application->datacontrol;
		datacontrol_x *tmp = NULL;
		while(datacontrol != NULL) {
			tmp = datacontrol->next;
			__ps_free_datacontrol(datacontrol);
			datacontrol = tmp;
		}
	}
	free((void *)application);
}

API void pkgmgrinfo_basic_free_package(package_x *package)
{
	if (package == NULL)
		return;
	if (package->for_all_users) {
		free((void *)package->for_all_users);
		package->for_all_users = NULL;
	}
	if (package->ns) {
		free((void *)package->ns);
		package->ns = NULL;
	}
	if (package->package) {
		free((void *)package->package);
		package->package = NULL;
	}
	if (package->version) {
		free((void *)package->version);
		package->version = NULL;
	}
	if (package->installlocation) {
		free((void *)package->installlocation);
		package->installlocation = NULL;
	}
	if (package->preload) {
		free((void *)package->preload);
		package->preload = NULL;
	}
	if (package->readonly) {
		free((void *)package->readonly);
		package->readonly = NULL;
	}
	if (package->removable) {
		free((void *)package->removable);
		package->removable = NULL;
	}
	if (package->update) {
		free((void *)package->update);
		package->update = NULL;
	}
	if (package->system) {
		free((void *)package->system);
		package->system = NULL;
	}
	if (package->type) {
		free((void *)package->type);
		package->type = NULL;
	}
	if (package->package_size) {
		free((void *)package->package_size);
		package->package_size = NULL;
	}
	if (package->installed_time) {
		free((void *)package->installed_time);
		package->installed_time = NULL;
	}
	if (package->installed_storage) {
		free((void *)package->installed_storage);
		package->installed_storage = NULL;
	}
	if (package->storeclient_id) {
		free((void *)package->storeclient_id);
		package->storeclient_id = NULL;
	}
	if (package->mainapp_id) {
		free((void *)package->mainapp_id);
		package->mainapp_id = NULL;
	}
	if (package->package_url) {
		free((void *)package->package_url);
		package->package_url = NULL;
	}
	if (package->root_path) {
		free((void *)package->root_path);
		package->root_path = NULL;
	}
	if (package->csc_path) {
		free((void *)package->csc_path);
		package->csc_path = NULL;
	}
	if (package->appsetting) {
		free((void *)package->appsetting);
		package->appsetting = NULL;
	}
	if (package->nodisplay_setting) {
		free((void *)package->nodisplay_setting);
		package->nodisplay_setting = NULL;
	}
	if (package->api_version) {
		free((void *)package->api_version);
		package->api_version = NULL;
	}

	/*Free Icon*/
	if (package->icon) {
		icon_x *icon = package->icon;
		icon_x *tmp = NULL;
		while(icon != NULL) {
			tmp = icon->next;
			__ps_free_icon(icon);
			icon = tmp;
		}
	}
	/*Free Label*/
	if (package->label) {
		label_x *label = package->label;
		label_x *tmp = NULL;
		while(label != NULL) {
			tmp = label->next;
			__ps_free_label(label);
			label = tmp;
		}
	}
	/*Free Author*/
	if (package->author) {
		author_x *author = package->author;
		author_x *tmp = NULL;
		while(author != NULL) {
			tmp = author->next;
			__ps_free_author(author);
			author = tmp;
		}
	}
	/*Free Description*/
	if (package->description) {
		description_x *description = package->description;
		description_x *tmp = NULL;
		while(description != NULL) {
			tmp = description->next;
			__ps_free_description(description);
			description = tmp;
		}
	}
	/*Free License*/
	if (package->license) {
		license_x *license = package->license;
		license_x *tmp = NULL;
		while(license != NULL) {
			tmp = license->next;
			__ps_free_license(license);
			license = tmp;
		}
	}
	/*Free Privileges*/
	if (package->privileges) {
		privileges_x *privileges = package->privileges;
		privileges_x *tmp = NULL;
		while(privileges != NULL) {
			tmp = privileges->next;
			__ps_free_privileges(privileges);
			privileges = tmp;
		}
	}
	/*Free UiApplication*/
	if (package->uiapplication) {
		uiapplication_x *uiapplication = package->uiapplication;
		uiapplication_x *tmp = NULL;
		while(uiapplication != NULL) {
			tmp = uiapplication->next;
			__ps_free_uiapplication(uiapplication);
			uiapplication = tmp;
		}
	}
	/*Free ServiceApplication*/
	if (package->serviceapplication) {
		serviceapplication_x *serviceapplication = package->serviceapplication;
		serviceapplication_x *tmp = NULL;
		while(serviceapplication != NULL) {
			tmp = serviceapplication->next;
			__ps_free_serviceapplication(serviceapplication);
			serviceapplication = tmp;
		}
	}
	/*Free Daemon*/
	if (package->daemon) {
		daemon_x *daemon = package->daemon;
		daemon_x *tmp = NULL;
		while(daemon != NULL) {
			tmp = daemon->next;
			__ps_free_daemon(daemon);
			daemon = tmp;
		}
	}
	/*Free Theme*/
	if (package->theme) {
		theme_x *theme = package->theme;
		theme_x *tmp = NULL;
		while(theme != NULL) {
			tmp = theme->next;
			__ps_free_theme(theme);
			theme = tmp;
		}
	}
	/*Free Font*/
	if (package->font) {
		font_x *font = package->font;
		font_x *tmp = NULL;
		while(font != NULL) {
			tmp = font->next;
			__ps_free_font(font);
			font = tmp;
		}
	}
	/*Free Ime*/
	if (package->ime) {
		ime_x *ime = package->ime;
		ime_x *tmp = NULL;
		while(ime != NULL) {
			tmp = ime->next;
			__ps_free_ime(ime);
			ime = tmp;
		}
	}
	/*Free Compatibility*/
	if (package->compatibility) {
		compatibility_x *compatibility = package->compatibility;
		compatibility_x *tmp = NULL;
		while(compatibility != NULL) {
			tmp = compatibility->next;
			__ps_free_compatibility(compatibility);
			compatibility = tmp;
		}
	}
	/*Free DeviceProfile*/
	if (package->deviceprofile) {
		deviceprofile_x *deviceprofile = package->deviceprofile;
		deviceprofile_x *tmp = NULL;
		while(deviceprofile != NULL) {
			tmp = deviceprofile->next;
			__ps_free_deviceprofile(deviceprofile);
			deviceprofile = tmp;
		}
	}
	free((void*)package);
	package = NULL;
	return;
}

