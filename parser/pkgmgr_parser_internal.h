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





#ifndef __PKGMGR_PARSER_INTERNAL_H__
#define __PKGMGR_PARSER_INTERNAL_H__


/* debug output */
#if defined(NDEBUG)
#define DBG(fmt, args...)
#define __SET_DBG_OUTPUT(fp)
#elif defined(PRINT)
#include <stdio.h>
FILE *___log = NULL;
#define DBG(fmt, args...) \
	{if (!___log) ___log = stderr; \
	 fprintf(___log, "[DBG:PMS]%s:%d:%s(): " fmt "\n",\
	 basename(__FILE__), __LINE__, __func__, ##args); fflush(___log); }
#define __SET_DBG_OUTPUT(fp) \
	(___log = fp)
#else
#include <dlog.h>
#undef LOG_TAG
#define LOG_TAG "PKGMGR_PARSER"

#define DBGE(fmt, arg...) LOGE(fmt,##arg)
#define DBG(fmt, arg...) LOGD(fmt,##arg)
#endif


#ifndef API
#define API __attribute__ ((visibility("default")))
#endif


#endif				/* __PKGMGR_PARSER_INTERNAL_H__ */
