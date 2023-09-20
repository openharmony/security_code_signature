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

#ifndef OHOS_LOCAL_CODE_SIGN_STUB_H
#define OHOS_LOCAL_CODE_SIGN_STUB_H

#include "iremote_stub.h"
#include "local_code_sign_interface.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
class LocalCodeSignStub : public IRemoteStub<LocalCodeSignInterface> {
public:
    LocalCodeSignStub();
    ~LocalCodeSignStub();
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option) override;
    virtual void DelayUnloadTask()
    {
        return;
    }
private:
    int32_t InitLocalCertificateInner(MessageParcel &data, MessageParcel &reply);
    int32_t SignLocalCodeInner(MessageParcel &data, MessageParcel &reply);
};
}
}
}
#endif
