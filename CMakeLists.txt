CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
#SET(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS true)

PROJECT(pkgmgr-info C)

INCLUDE(TizenCommon)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(INCLUDEDIR "\${prefix}/include")

set(CMAKE_SKIP_BUILD_RPATH true)

### Local include directories
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/parser)

### Required packages
INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED glib-2.0 dlog vconf sqlite3 db-util libxml-2.0 dbus-1 dbus-glib-1 libtzplatform-config libsmack bundle)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)


pkg_check_modules(libpkgs REQUIRED glib-2.0 dlog vconf sqlite3 db-util libxml-2.0 dbus-1 dbus-glib-1 libtzplatform-config libsmack bundle)

FOREACH(flag ${libpkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

## About debug
SET(debug_type "-DPM_CONSOLE_USE") 		# for debug - use console window

## Additional flag
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -g -Wall")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

################## ## build comm libraries
add_subdirectory(parser)

## build pkgmgr-info library
add_library(pkgmgr-info SHARED
	src/pkgmgrinfo_client.c
	src/pkgmgrinfo_db.c
	src/pkgmgrinfo_certinfo.c
	src/pkgmgrinfo_pkginfo.c
	src/pkgmgrinfo_appinfo.c
	src/pkgmgrinfo_private.c
	src/pkgmgrinfo_basic.c
	src/pkgmgrinfo_resource.c)


SET_TARGET_PROPERTIES(pkgmgr-info PROPERTIES SOVERSION ${MAJORVER})
SET_TARGET_PROPERTIES(pkgmgr-info PROPERTIES VERSION ${FULLVER})
TARGET_LINK_LIBRARIES(pkgmgr-info pkgmgr_parser ${libpkgs_LDFLAGS})

CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/pkgmgr-info.pc.in ${CMAKE_BINARY_DIR}/pkgmgr-info.pc @ONLY)
configure_file(parser_path.conf.in parser_path.conf @ONLY)
configure_file(mdparser_list.txt.in mdparser_list.txt @ONLY)
configure_file(category_parser_list.txt.in category_parser_list.txt @ONLY)
configure_file(tag_parser_list.txt.in tag_parser_list.txt @ONLY)

INSTALL(TARGETS pkgmgr-info DESTINATION ${LIB_INSTALL_DIR} COMPONENT RuntimeLibraries)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/pkgmgr-info.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/pkgmgr-info.h DESTINATION include)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/pkgmgrinfo_basic.h DESTINATION include)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/pkgmgrinfo_type.h DESTINATION include)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/pkgmgrinfo_resource.h DESTINATION include)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/parser_path.conf DESTINATION ${SYSCONFDIR}/package-manager/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/mdparser_list.txt DESTINATION ${SYSCONFDIR}/package-manager/parserlib/metadata)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/category_parser_list.txt DESTINATION ${SYSCONFDIR}/package-manager/parserlib/category)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/tag_parser_list.txt DESTINATION ${SYSCONFDIR}/package-manager/parserlib)
