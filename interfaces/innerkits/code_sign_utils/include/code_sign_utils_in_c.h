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

#ifndef CODE_SIGN_UTILS_IN_C_H
#define CODE_SIGN_UTILS_IN_C_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum FileType {
    FILE_ALL, // Enable hap and so(new and historical records)
    FILE_SELF, // Only enable hap
    FILE_ENTRY_ONLY, // Only enable so(new and historical records)
    FILE_ENTRY_ADD, // Only record, not enable
    FILE_TYPE_MAX,
};

struct EntryMapEntry {
    char* key;
    char* value;
};

struct EntryMapEntryData {
    int count;
    struct EntryMapEntry *entries;
};

int EnforceCodeSignForApp(const char *hapPath, const struct EntryMapEntryData *entryMapEntryData, enum FileType type);

#ifdef __cplusplus
}
#endif

#endif // CODE_SIGN_UTILS_IN_C_H