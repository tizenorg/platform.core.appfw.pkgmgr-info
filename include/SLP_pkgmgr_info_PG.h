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


/**

 *
 * @ingroup   SLP_PG
 * @defgroup   PackageManagerInfoGuide


@par Package Manager Information Library Programming Guide

<h1 class="pg"> Introduction</h1>
<h2 class="pg"> Purpose of this document</h2>
The purpose of this document is to describe how applications can use Package Manager Information APIs.\n
This document gives only programming guidelines to application developers.

<h2 class="pg"> Scope</h2>
The scope of this document is limited to Samsung platform Package Manager Info API usage.

<h1 class="pg"> Architecture</h1>
<h2 class="pg"> Architecture overview</h2>
Package Manager Information Library is responsible for getting/setting manifest file information from/to manifest DB.\n

The library provides APIs to parse the package's manifest file\n
It also provides APIs to insert/update/delete this parsed data from manifest DB.


<h2 class="pg"> Features</h2>
Package Manager Info Library has the following features:\n

 - Get /Set Package Information in DB
	- It provides API to get package manifest data from DB.
	- It provides API to get package certificate data from DB.
	- It provides API to set package manifest data in DB.
	- It provides API to set package certificate data in DB.

@image html SLP_pkgmgr_info.png "High-Level Architure depicting get/set operation"

 - Filter Package/Application Information
	- It provides API to filter package information query result.
	- It provides API to filter application information query result.

 - Manifest Parser
	- It provides API to parse package manifest file.
	- It provides API to insert/update/delete manifest data in DB.

@image html SLP_pkgmgr_parser.png "High-Level Architure depicting manifest parsing"

<h1 class="pg"> Package Manager API descriptions</h1>
<b> SEE API manual </b>

<h1 class="pg"> Package Manager Features with sample code</h1>
<h2 class="pg"> Get /Set Package Information in DB</h2>

Client application
- Get package version from manifest DB

@code
#include <pkgmgr-info.h>

static int get_pkg_version(const char *pkgid)
{
	int ret = 0;
	char *version = NULL;
	pkgmgrinfo_pkginfo_h handle;
	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret != PMINFO_R_OK)
		return -1;
	ret = pkgmgrinfo_pkginfo_get_version(handle, &version);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return -1;
	}
	printf("pkg version: %s\n", version);
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	return 0;
}
@endcode

- Get package author root certificate from manifest DB

@code
static int get_cert_info(const char *pkgid)
{
	int ret = 0;
	pkgmgrinfo_certinfo_h handle;
	char *auth_cert = NULL;
	ret = pkgmgrinfo_pkginfo_create_certinfo(&handle);
	if (ret != PMINFO_R_OK)
		return -1;
	ret = pkgmgrinfo_pkginfo_load_certinfo(pkgid, handle);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_pkginfo_destroy_certinfo(handle);
		return -1;
	}
	ret = pkgmgrinfo_pkginfo_get_cert_value(handle, PMINFO_AUTHOR_ROOT_CERT, &auth_cert);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_pkginfo_destroy_certinfo(handle);
		return -1;
	}
	printf("Author root certificate: %s\n", auth_root);
	pkgmgrinfo_pkginfo_destroy_certinfo(handle);
	return 0;
}
@endcode

- Set package version in manifest DB

@code
#include <pkgmgr-info.h>

static int set_pkg_version_in_db(const char *pkgid)
{
	int ret = 0;
	pkgmgrinfo_pkgdbinfo_h handle;
	ret = pkgmgrinfo_create_pkgdbinfo(pkgid, &handle);
	if (ret != PMINFO_R_OK)
		return -1;
	ret = pkgmgrinfo_set_version_to_pkgdbinfo(handle, "0.0.1");
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_destroy_pkgdbinfo(handle);
		return -1;
	}
	ret = pkgmgrinfo_save_pkgdbinfo(handle);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_destroy_pkgdbinfo(handle);
		return -1;
	}
	pkgmgrinfo_destroy_pkgdbinfo(handle);
	return 0;
}
@endcode

- Set package author root certificate in manifest DB

@code
static int set_cert_in_db(const char *pkgid)
{
	int ret = 0;
	pkgmgrinfo_instcertinfo_h handle;
	ret = pkgmgrinfo_create_certinfo_set_handle(&handle);
	if (ret != PMINFO_R_OK)
		return -1;
	ret = pkgmgrinfo_set_cert_value(handle, PMINFO_SET_AUTHOR_ROOT_CERT, "author root certificate");
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_destroy_certinfo_set_handle(handle);
		return -1;
	}
	ret = pkgmgrinfo_save_pkgdbinfo(pkgid, handle);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_destroy_certinfo_set_handle(handle);
		return -1;
	}
	pkgmgrinfo_destroy_certinfo_set_handle(handle);
	return 0;
}
@endcode


<h2 class="pg"> Filter Package/Application Information </h2>

- Filter number of installed rpm packages out of total number of packages installed.

@code
#include <pkgmgr-info.h>
int pkg_list_cb(pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	char *pkgid = NULL;
	pkgmgrinfo_pkginfo_get_pkgname(handle, &pkgid);
	printf("pkg id : %s\n", pkgid);
	return 0;
}

static int get_rpm_pkg_list()
{
	int ret = 0;
	pkgmgrinfo_pkginfo_filter_h handle;
	ret = pkgmgrinfo_pkginfo_filter_create(&handle);
	if (ret != PMINFO_R_OK)
		return -1;
	ret = pkgmgrinfo_pkginfo_filter_add_string(handle, PMINFO_PKGINFO_PROP_PACKAGE_TYPE, "rpm");
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_pkginfo_filter_destroy(handle);
		return -1;
	}
	ret = pkgmgrinfo_pkginfo_filter_foreach_pkginfo(handle, pkg_list_cb, NULL);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_pkginfo_filter_destroy(handle);
		return -1;
	}
	pkgmgrinfo_pkginfo_filter_destroy(handle);
	return 0;
}
@endcode

- Filter number of installed applications which are of type "capp".

@code
#include <pkgmgr-info.h>

static int get_capp_count()
{
	int ret = 0;
	int count = 0;
	pkgmgrinfo_appinfo_filter_h handle;
	ret = pkgmgrinfo_appinfo_filter_create(&handle);
	if (ret != PMINFO_R_OK)
		return -1;
	ret = pkgmgrinfo_appinfo_filter_add_string(handle, PMINFO_APPINFO_PROP_APP_TYPE, "capp");
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_appinfo_filter_destroy(handle);
		return -1;
	}
	ret = pkgmgrinfo_appinfo_filter_count(handle, &count);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_appinfo_filter_destroy(handle);
		return -1;
	}
	printf("No of capp: %d\n", count);
	pkgmgrinfo_appinfo_filter_destroy(handle);
	return 0;
}
@endcode

<h2 class="pg"> Manifest Parser </h2>

- Parse the package manifest file and insert the parsed data in manifest DB.

@code
#include <pkgmgr-info.h>

static int parse_manifest_file_for_installation(const char *manifest)
{
	int ret = 0;
	ret = pkgmgr_parser_parse_manifest_for_installation(manifest, NULL);
	if (ret)
		return -1;
	return 0;
}
@endcode


- Parse the package manifest file and update the manifest DB with the parsed data.

@code
#include <pkgmgr-info.h>

static int parse_manifest_file_for_upgrade(const char *manifest)
{
	int ret = 0;
	ret = pkgmgr_parser_parse_manifest_for_upgrade(manifest, NULL);
	if (ret)
		return -1;
	return 0;
}
@endcode

- Parse the package manifest file and delete the parsed data from manifest DB.

@code
#include <pkgmgr-info.h>

static int parse_manifest_file_for_uninstallation(const char *manifest)
{
	int ret = 0;
	ret = pkgmgr_parser_parse_manifest_for_uninstallation(manifest, NULL);
	if (ret)
		return -1;
	return 0;
}
@endcode


*/

/**
@}
*/


