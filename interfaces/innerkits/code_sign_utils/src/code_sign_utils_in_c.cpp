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

#include "code_sign_utils_in_c.h"

#include <string>

#include "code_sign_utils.h"
#include "errcode.h"
#include "log.h"

using EntryMap = std::unordered_map<std::string, std::string>;

extern "C" int EnforceCodeSignForApp(const char *hapPath, const struct EntryMapEntryData *entryMapEntryData,
    enum FileType type)
{
    if (hapPath == nullptr || entryMapEntryData == nullptr) {
        return CS_ERR_PARAM_INVALID;
    }
    std::string path(hapPath);
    EntryMap entryPathMap;
    int entryCount = entryMapEntryData->count;
    for (int i = 0; i < entryCount; ++i) {
        EntryMapEntry entry = entryMapEntryData->entries[i];
        if (entry.key == nullptr || entry.value == nullptr) {
            return CS_ERR_PARAM_INVALID;
        }
        std::string strKey(entry.key);
        std::string strValue(entry.value);
        if (entryPathMap.find(strKey) != entryPathMap.end()) {
            return CS_ERR_PARAM_INVALID;
        }
        entryPathMap[strKey] = strValue;
    }
    OHOS::Security::CodeSign::CodeSignUtils utils;
    return utils.EnforceCodeSignForApp(path, entryPathMap, static_cast<OHOS::Security::CodeSign::FileType>(type));
}