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

#include "local_code_sign_kit.h"

#include "local_code_sign_client.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
int32_t LocalCodeSignKit::InitLocalCertificate(ByteBuffer &cert)
{
    return LocalCodeSignClient::GetInstance().InitLocalCertificate(cert);
}

int32_t LocalCodeSignKit::SignLocalCode(const std::string &filePath, ByteBuffer &signature)
{
    return LocalCodeSignClient::GetInstance().SignLocalCode("", filePath, signature);
}

int32_t LocalCodeSignKit::SignLocalCode(const std::string &ownerID, const std::string &filePath, ByteBuffer &signature)
{
    return LocalCodeSignClient::GetInstance().SignLocalCode(ownerID, filePath, signature);
}
}
}
}