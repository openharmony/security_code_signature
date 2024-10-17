/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ownerid_utils.h"
#include "code_sign_attr_utils.h"
#include "parameter.h"
#include "log.h"

#include <string>
#include <unordered_set>

#define SECURE_SHIELD_MODE_KEY "ohos.boot.advsecmode.state"
#define VALUE_MAX_LEN 32

// the list will be removed before 930
static const std::unordered_set<std::string> g_tempAllowList;

static const std::unordered_set<std::string> g_secureShieldAllowList;

static uint32_t IsSecureShieldModeOn()
{
    char secureShieldModeValue[VALUE_MAX_LEN] = {0};
    (void)GetParameter(SECURE_SHIELD_MODE_KEY, "0", secureShieldModeValue, VALUE_MAX_LEN - 1);
    return (strcmp(secureShieldModeValue, "0") != 0);
}

uint32_t ConvertIdType(int idType, const char *ownerId)
{
    if (ownerId == nullptr) {
        return idType;
    }
    if ((idType != PROCESS_OWNERID_APP) && (idType != PROCESS_OWNERID_APP_TEMP_ALLOW)) {
        return idType;
    }
    idType = PROCESS_OWNERID_APP;
    std::string ownerIdStr(ownerId);
    // check different list on secure shield mode or normal mode
    if (IsSecureShieldModeOn()) {
        if (g_secureShieldAllowList.count(ownerIdStr) != 0) {
            LOG_INFO("Xpm: app in secure shield allow list");
            return PROCESS_OWNERID_APP_TEMP_ALLOW;
        }
    } else {
        if (g_tempAllowList.count(ownerIdStr) != 0) {
            LOG_INFO("Xpm: app in temporary allow list");
            return PROCESS_OWNERID_APP_TEMP_ALLOW;
        }
    }
    return idType;
}