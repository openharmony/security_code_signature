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

#ifndef CODE_SIGN_PAC_SIGN_CTX_H
#define CODE_SIGN_PAC_SIGN_CTX_H

#include <cstdint>

namespace OHOS {
namespace Security {
namespace CodeSign {

enum CTXPurpose {
    SIGN,
    VERIFY
};

enum ContextType {
    SIGN_WITH_CONTEXT,
    SIGN_WITHOUT_CONTEXT,
    AUTH_CONTEXT
};

class PACSignCtx {
public:
    PACSignCtx(CTXPurpose purpose = CTXPurpose::VERIFY, uint32_t salt = 0);
    ~PACSignCtx();
    void Init(int index);
    void InitSalt();
    uint32_t Update(uint32_t value);
    uint32_t SignSingle(uint32_t value, uint32_t index);
    void SetIndex(uint32_t index);
    uint32_t GetSalt();

private:
    void SetContext(uint32_t context);
    uint64_t PaddingContext(ContextType type, int index = 0);
    uint64_t GetRealContext();
    uint32_t SignWithContext(uint32_t value);
    uint32_t GetRandomSalt();

    uint64_t context_;
    uint32_t salt_;
    int index_;
    CTXPurpose purpose_;
};
}
}
}
#endif