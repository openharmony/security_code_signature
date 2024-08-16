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

#include "jit_code_signer_factory.h"

#include "jit_fort_helper.h"
#ifdef JIT_CODE_SIGN_ENABLE
#include "jit_code_signer_hybrid.h"
#include "jit_code_signer_single.h"
#include "log.h"
#endif

namespace OHOS {
namespace Security {
namespace CodeSign {

JitCodeSignerFactory::JitCodeSignerFactory() {}

JitCodeSignerFactory &JitCodeSignerFactory::GetInstance()
{
    static JitCodeSignerFactory singleJitCodeSignerFactory;
    return singleJitCodeSignerFactory;
}

#ifdef JIT_CODE_SIGN_ENABLE
JitCodeSignerBase *JitCodeSignerFactory::CreateJitCodeSigner(
    JitBufferIntegrityLevel level)
{
    if (!IsSupportPACFeature()) {
        return nullptr;
    }
    switch (level) {
        case JitBufferIntegrityLevel::Level0:
            return new JitCodeSignerSingle();
        case JitBufferIntegrityLevel::Level1:
            return new JitCodeSignerHybrid();
        default:
            LOG_ERROR("Unsupport level of jit code signer.");
            return nullptr;
    }
}
#else   // !JIT_CODE_SIGN_ENABLE
JitCodeSignerBase *JitCodeSignerFactory::CreateJitCodeSigner(
    JitBufferIntegrityLevel level)
{
    return nullptr;
}
#endif
}
}
}