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

#include <cstring>
#include "cert_path.h"
#include "enable_key_utils.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
constexpr int DEFUALT_CERT_CHAIN_LEN = 3;
constexpr int DEFUALT_CERT_PATH_TYPE = 0X103;

int32_t EnableTestKey(const char *signing, const char *issuer)
{
    CertPathInfo arg = { 0 };
    arg.signing = reinterpret_cast<uint64_t>(signing);
    arg.issuer = reinterpret_cast<uint64_t>(issuer);
    arg.signing_length = strlen(signing) + 1;
    arg.issuer_length = strlen(issuer) + 1;
    arg.path_len = DEFUALT_CERT_CHAIN_LEN;
    arg.path_type = DEFUALT_CERT_PATH_TYPE;
    return AddCertPath(arg);
}
}
}
}