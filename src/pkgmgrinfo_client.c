#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "pkgmgrinfo_type.h"
#include "pkgmgrinfo_debug.h"
#include "pkgmgrinfo_private.h"

API pkgmgrinfo_client *pkgmgrinfo_client_new(pkgmgrinfo_client_type ctype)
{
	char *errmsg;
	void *pc = NULL;
	void *handle;
	pkgmgrinfo_client *(*__pkgmgr_client_new)(pkgmgrinfo_client_type ctype) = NULL;

	handle = dlopen("libpkgmgr-client.so.0", RTLD_LAZY | RTLD_GLOBAL);
	retvm_if(!handle, NULL, "dlopen() failed. [%s]", dlerror());

	__pkgmgr_client_new = dlsym(handle, "pkgmgr_client_new");
	errmsg = dlerror();
	trym_if((errmsg != NULL) || (__pkgmgr_client_new == NULL), "dlsym() failed. [%s]", errmsg);

	pc = __pkgmgr_client_new(ctype);
	trym_if(pc == NULL, "pkgmgr_client_new failed.");

catch:
	dlclose(handle);
	return (pkgmgrinfo_client *) pc;
}

API int pkgmgrinfo_client_set_status_type(pkgmgrinfo_client *pc, int status_type)
{
	int ret;
	char *errmsg;
	void *handle;
	int (*__pkgmgr_client_set_status_type)(pkgmgrinfo_client *pc, int status_type) = NULL;

	handle = dlopen("libpkgmgr-client.so.0", RTLD_LAZY | RTLD_GLOBAL);
	retvm_if(!handle, PMINFO_R_ERROR, "dlopen() failed. [%s]", dlerror());

	__pkgmgr_client_set_status_type = dlsym(handle, "pkgmgr_client_set_status_type");
	errmsg = dlerror();
	tryvm_if((errmsg != NULL) || (__pkgmgr_client_set_status_type == NULL), ret = PMINFO_R_ERROR, "dlsym() failed. [%s]", errmsg);

	ret = __pkgmgr_client_set_status_type(pc, status_type);
	tryvm_if(ret < 0, ret = PMINFO_R_ERROR, "pkgmgr_client_new failed.");

catch:
        /*
         * Do not close libpkgmgr-client.so.0 to avoid munmap registered callback
         *
         * The lib dependency chain like below
         * amd --> pkgmgr-info -- dlopen --> libpkgmgr-client --> libpkgmgr-installer-client
         *
         * And there is a function in libpkgmgr-installer-client named _on_signal_handle_filter()
         * which will registered to dbus callback in amd though in fact amd doesn't direct depends
         * on libpkgmgr-installer-client.
         *
         * So when the dlcose happen, then libpkgmgr-installer-client been closed too since no one
         * link to it then.
         *
         * However, when the libdbus call into the callback function, it suddenly fond that the
         * function address is gone (unmapped), then we receive a SIGSEGV.
         *
         * I'm not sure why we're using dlopen/dlclose in this case, I think it's much simple and
         * robust if we just link to the well-known lib.
         *
         * See https://bugs.tizen.org/jira/browse/PTREL-591
	dlclose(handle);
         */
	return ret;
}

API int pkgmgrinfo_client_listen_status(pkgmgrinfo_client *pc, pkgmgrinfo_handler event_cb, void *data)
{
	int ret = 0;
	char *errmsg = NULL;
	void *handle = NULL;
	int (*__pkgmgr_client_listen_status)(pkgmgrinfo_client *pc, pkgmgrinfo_handler event_cb, void *data) = NULL;

	handle = dlopen("libpkgmgr-client.so.0", RTLD_LAZY | RTLD_GLOBAL);
	retvm_if(!handle, PMINFO_R_ERROR, "dlopen() failed. [%s]", dlerror());

	__pkgmgr_client_listen_status = dlsym(handle, "pkgmgr_client_listen_status");
	errmsg = dlerror();
	tryvm_if((errmsg != NULL) || (__pkgmgr_client_listen_status == NULL), ret = PMINFO_R_ERROR, "dlsym() failed. [%s]", errmsg);

	ret = __pkgmgr_client_listen_status(pc, event_cb, data);
	tryvm_if(ret < 0, ret = PMINFO_R_ERROR, "pkgmgr_client_new failed.");

catch:
        /* same as pkgmgrinfo_client_new */
	return ret;
}

API int pkgmgrinfo_client_free(pkgmgrinfo_client *pc)
{
	int ret = 0;
	char *errmsg = NULL;
	void *handle = NULL;
	int (*__pkgmgr_client_free)(pkgmgrinfo_client *pc) = NULL;

	handle = dlopen("libpkgmgr-client.so.0", RTLD_LAZY | RTLD_GLOBAL);
	retvm_if(!handle, PMINFO_R_ERROR, "dlopen() failed. [%s]", dlerror());

	__pkgmgr_client_free = dlsym(handle, "pkgmgr_client_free");
	errmsg = dlerror();
	tryvm_if((errmsg != NULL) || (__pkgmgr_client_free == NULL), ret = PMINFO_R_ERROR, "dlsym() failed. [%s]", errmsg);

	ret = __pkgmgr_client_free(pc);
	tryvm_if(ret < 0, ret = PMINFO_R_ERROR, "pkgmgr_client_new failed.");

catch:
        /* same as pkgmgrinfo_client_new */
	return ret;
}

static int __get_pkg_location(const char *pkgid)
{
	retvm_if(pkgid == NULL, PMINFO_R_OK, "pkginfo handle is NULL");

	FILE *fp = NULL;
	char pkg_mmc_path[FILENAME_MAX] = { 0, };
	snprintf(pkg_mmc_path, FILENAME_MAX, "%s%s", PKG_SD_PATH, pkgid);

	/*check whether application is in external memory or not */
	fp = fopen(pkg_mmc_path, "r");
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;
		return PMINFO_EXTERNAL_STORAGE;
	}

	return PMINFO_INTERNAL_STORAGE;
}

API int pkgmgrinfo_client_request_enable_external_pkg(char *pkgid)
{
	DBusConnection *bus;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;

	retvm_if(pkgid == NULL, PMINFO_R_EINVAL, "pkgid is NULL\n");

	if(__get_pkg_location(pkgid) != PMINFO_EXTERNAL_STORAGE)
		return PMINFO_R_OK;

	bus = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	retvm_if(bus == NULL, PMINFO_R_EINVAL, "dbus_bus_get() failed.");

	message = dbus_message_new_method_call (SERVICE_NAME, PATH_NAME, INTERFACE_NAME, METHOD_NAME);
	trym_if(message == NULL, "dbus_message_new_method_call() failed.");

	dbus_message_append_args(message, DBUS_TYPE_STRING, &pkgid, DBUS_TYPE_INVALID);

	reply = dbus_connection_send_with_reply_and_block(bus, message, -1, NULL);
	trym_if(reply == NULL, "connection_send dbus fail");

catch:
	dbus_connection_flush(bus);
	if (message)
		dbus_message_unref(message);
	if (reply)
		dbus_message_unref(reply);

	return PMINFO_R_OK;
}
