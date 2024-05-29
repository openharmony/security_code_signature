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

#ifndef CODE_SIGN_JIT_CODE_SIGNER_FACTORY_H
#define CODE_SIGN_JIT_CODE_SIGNER_FACTORY_H

#include "jit_code_signer_base.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
// The higher the level, the richer the signing context information
// and the higher the overhead when updating instrucions.
enum class JitBufferIntegrityLevel {
    Level0,
    Level1,
};

class JitCodeSignerFactory {
public:
    static JitCodeSignerFactory &GetInstance();
    JitCodeSignerBase *CreateJitCodeSigner(
        JitBufferIntegrityLevel level = JitBufferIntegrityLevel::Level0);

    bool IsSupportJitCodeSigner();

private:
    JitCodeSignerFactory();
    ~JitCodeSignerFactory() = default;
    bool isSupport_;
};
}
}
}
#endif