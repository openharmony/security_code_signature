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

#ifndef OHOS_LOCAL_CODE_SIGN_PROXY_H
#define OHOS_LOCAL_CODE_SIGN_PROXY_H

#include "byte_buffer.h"
#include "iremote_proxy.h"
#include "local_code_sign_interface.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
class LocalCodeSignProxy : public IRemoteProxy<LocalCodeSignInterface> {
public:
    explicit LocalCodeSignProxy(const sptr<IRemoteObject> &impl)
        : IRemoteProxy<LocalCodeSignInterface>(impl) {}
    ~LocalCodeSignProxy() {}
    int32_t InitLocalCertificate(const ByteBuffer &challenge, ByteBuffer &cert) override;
    int32_t SignLocalCode(const std::string &ownerID, const std::string &filePath, ByteBuffer &signature) override;
private:
    static inline BrokerDelegator<LocalCodeSignProxy> delegator_;
    int32_t ReadResultFromReply(MessageParcel &reply, ByteBuffer &buffer);
};
}
}
}
#endif
