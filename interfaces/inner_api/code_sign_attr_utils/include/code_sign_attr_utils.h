/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CODE_SIGN_ATTR_UTILS_H
#define CODE_SIGN_ATTR_UTILS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__LP64__)
#define XPM_REGION_LEN 0x100000000
#else
#define XPM_REGION_LEN 0x10000000
#endif

#define MAX_OWNERID_LEN 64

#define OWNERID_SYSTEM_TAG "SYSTEM_LIB_ID"
#define OWNERID_DEBUG_TAG  "DEBUG_LIB_ID"
#define OWNERID_SHARED_TAG "SHARED_LIB_ID"
#define OWNERID_COMPAT_TAG "COMPAT_LIB_ID"

enum FileOwneridType {
    FILE_OWNERID_UNINT = 0,
    FILE_OWNERID_SYSTEM,          // 1
    FILE_OWNERID_APP,             // 2
    FILE_OWNERID_DEBUG,           // 3
    FILE_OWNERID_SHARED,          // 4
    FILE_OWNERID_COMPAT,          // 5
    FILE_OWNERID_EXTEND,          // 6
    FILE_OWNERID_DEBUG_PLATFORM,  // 7
    FILE_OWNERID_PLATFORM,        // 8
    FILE_OWNERID_NWEB,            // 9
    FILE_OWNERID_APP_TEMP_ALLOW,  // 10
    FILE_OWNERID_ENT_RESIGN,      // 11
    FILE_OWNERID_MAX
};

/* process and file ownerid types need to correspond to each other */
enum ProcessOwneridType {
    PROCESS_OWNERID_UNINIT = FILE_OWNERID_UNINT,
    PROCESS_OWNERID_SYSTEM,          // 1
    PROCESS_OWNERID_APP,             // 2
    PROCESS_OWNERID_DEBUG,           // 3
    PROCESS_OWNERID_SHARED,          // 4
    PROCESS_OWNERID_COMPAT,          // 5
    PROCESS_OWNERID_EXTEND,          // 6
    PROCESS_OWNERID_DEBUG_PLATFORM,  // 7
    PROCESS_OWNERID_PLATFORM,        // 8
    PROCESS_OWNERID_NWEB,            // 9
    PROCESS_OWNERID_APP_TEMP_ALLOW,  // 10
    PROCESS_OWNERID_ENT_RESIGN,      // 11
    PROCESS_OWNERID_MAX
};

struct XpmConfig {
    uint64_t regionAddr;
    uint64_t regionLength;

    uint32_t idType;
    char ownerId[MAX_OWNERID_LEN];
    uint32_t apiTargetVersion;
};

int InitXpm(int enableJitFort, uint32_t idType, const char *ownerId, const char *apiTargetVersionStr,
            const char *appSignType);

int SetXpmOwnerId(uint32_t idType, const char *ownerId);

#ifdef __cplusplus
}
#endif

#endif // CODE_SIGN_ATTR_UTILS_H
