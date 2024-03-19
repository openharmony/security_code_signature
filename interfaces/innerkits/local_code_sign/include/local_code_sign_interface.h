/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_LOCAL_CODE_SIGN_INTERFACE_H
#define OHOS_LOCAL_CODE_SIGN_INTERFACE_H

#include "byte_buffer.h"
#include "errcode.h"
#include "local_code_sign_ipc_interface_code.h"
#include "iremote_broker.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
constexpr int LOCAL_CODE_SIGN_SA_ID = 3507;

class LocalCodeSignInterface : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.LocalCodeSignInterface");
    virtual int32_t InitLocalCertificate(const ByteBuffer &challenge, ByteBuffer &cert) = 0;
    virtual int32_t SignLocalCode(const std::string &ownerID, const std::string &filePath, ByteBuffer &signature) = 0;
};
}
}
}
#endif
