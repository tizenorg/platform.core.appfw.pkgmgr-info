/*
 * pkgmgr-info-debug
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
  * Contact: junsuk. oh <junsuk77.oh@samsung.com>
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

#ifndef __PKGMGR_INFO_DEBUG_H__
#define __PKGMGR_INFO_DEBUG_H__

#include <dlog.h>

#undef LOG_TAG
#define LOG_TAG		"PKGMGR_INFO"
#define _LOGE(fmt, arg...) LOGE(fmt, ##arg)
#define _LOGD(fmt, arg...) LOGD(fmt, ##arg)

#define PKGMGR_INFO_ENABLE_DLOG

#define COLOR_RED 		"\033[0;31m"
#define COLOR_BLUE 		"\033[0;34m"
#define COLOR_END		"\033[0;m"

#ifdef PKGMGR_INFO_ENABLE_DLOG
#define PKGMGR_INFO_DEBUG(fmt, ...)\
	do\
	{\
		LOGD(fmt, ##__VA_ARGS__);\
	} while (0)

#define PKGMGR_INFO_DEBUG_ERR(fmt, ...)\
	do\
	{\
		LOGE(COLOR_RED fmt COLOR_END, ##__VA_ARGS__);\
	}while (0)

#define PKGMGR_INFO_BEGIN() \
	do\
    {\
		LOGD(COLOR_BLUE"BEGIN >>>>"COLOR_END);\
    } while( 0 )

#define PKGMGR_INFO_END() \
	do\
    {\
		LOGD(COLOR_BLUE"END <<<<"COLOR_END);\
    } \
    while( 0 )

#else
#define PKGMGR_INFO_DEBUG(fmt, ...) \
	do\
	{\
		printf("\n [%s: %s(): %d] " fmt"\n",  rindex(__FILE__, '/')+1, __FUNCTION__, __LINE__, ##__VA_ARGS__);\
	} while (0)

#define PKGMGR_INFO_BEGIN() \
	do\
    {\
        printf("\n [%s: %d] : BEGIN >>>> %s() \n", rindex(__FILE__, '/')+1,  __LINE__ , __FUNCTION__);\
    } while( 0 )

#define PKGMGR_INFO_END() \
	do\
    {\
        printf("\n [%s: %d]: END   <<<< %s()\n", rindex(__FILE__, '/')+1,  __LINE__ , __FUNCTION__); \
    } \
    while( 0 )
#endif


#define ret_if(expr) do { \
	if (expr) { \
		PKGMGR_INFO_DEBUG_ERR("(%s) ", #expr); \
		return; \
	} \
} while (0)

#define retm_if(expr, fmt, arg...) do { \
	 if (expr) { \
		 PKGMGR_INFO_DEBUG_ERR("(%s) "fmt, #expr, ##arg); \
		 return; \
	 } \
 } while (0)

#define retv_if(expr, val) do { \
		if (expr) { \
			PKGMGR_INFO_DEBUG_ERR("(%s) ", #expr); \
			return (val); \
		} \
	} while (0)

#define retvm_if(expr, val, fmt, arg...) do { \
	if (expr) { \
		PKGMGR_INFO_DEBUG_ERR("(%s) "fmt, #expr, ##arg); \
		return (val); \
	} \
} while (0)

#define tryvm_if(expr, val, fmt, arg...) do { \
	if (expr) { \
		PKGMGR_INFO_DEBUG_ERR("(%s) "fmt, #expr, ##arg); \
		val; \
		goto catch; \
	} \
} while (0)

#endif  /* __PKGMGR_INFO_DEBUG_H__ */
