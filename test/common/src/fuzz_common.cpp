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

#include "fuzz_common.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
namespace {
const uint32_t SIGN_PATH_LIMIT = 4095;
const uint64_t SIGN_MAX_SIZE_LEN = 32;
};

void SignInfoRandomGenerator::GenerateFilePath(std::string &str)
{
    uint32_t length = GetData<uint32_t>() % SIGN_PATH_LIMIT;
    str = "/";
    for (uint32_t i = 1; i < length; ++i) {
        str += GetData<char>();
    }
}

void SignInfoRandomGenerator::GenerateString(std::string &str)
{
    uint32_t length = GetData<uint32_t>() % SIGN_MAX_SIZE_LEN;
    for (uint32_t i = 1; i < length; ++i) {
        str += GetData<char>();
    }
}

}
}
}