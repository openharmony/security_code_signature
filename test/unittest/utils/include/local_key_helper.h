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

#ifndef CODE_SIGN_LOCAL_KEY_HELPER_H
#define CODE_SIGN_LOCAL_KEY_HELPER_H

#include <fstream>
#include <iostream>
#include <string>

#include "errcode.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {

const std::string PROC_KEYS_FILE = "/proc/keys";
const std::string LOCAL_KEY_NAME = "local_key";

int GetEnforceFileResult()
{
    std::ifstream in(PROC_KEYS_FILE);
    std::string line;
    while (in >> line) {
        if (line.find(LOCAL_KEY_NAME) != line.npos) {
            return CS_SUCCESS;
        }
    }
    LOG_WARN("local key not found");
    return CS_ERR_ENABLE;
}
}
}
}
#endif