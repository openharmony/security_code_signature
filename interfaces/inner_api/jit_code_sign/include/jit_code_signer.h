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

#ifndef CODE_SIGN_JIT_CODE_SIGNER_H
#define CODE_SIGN_JIT_CODE_SIGNER_H

#include <queue>
#include <vector>
#include "pac_sign_ctx.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
using Instr = uint32_t;
using Byte = uint8_t;

constexpr int32_t INSTRUCTION_SIZE = 4;
constexpr int32_t LOG_2_INSTRUCTION_SIZE = 2;

static inline int GetIndexFromOffset(int offset)
{
    return static_cast<int>(static_cast<uint32_t>(offset) >> LOG_2_INSTRUCTION_SIZE);
}

class JitCodeSigner {
public:
    JitCodeSigner();
    ~JitCodeSigner() {};
    void Reset();
    void SignInstruction(Instr insn);
    void SkipNext(uint32_t n);
    int32_t PatchInstruction(int offset, Instr insn);
    int32_t ValidateCodeCopy(Instr *jitMemory, Byte *jitBuffer, int size);

    void RegisterTmpBuffer(Byte *tmpBuffer);
    int32_t SignData(const Byte *data, uint32_t size);
    int32_t PatchInstruction(Byte *jitBuffer, Instr insn);
    int32_t PatchData(int offset, const Byte *const data, uint32_t size);
    int32_t PatchData(Byte *buffer, const Byte *const data, uint32_t size);

protected:
    bool ConvertPatchOffsetToIndex(const int offset, int &curIndex);
    int32_t CheckDataCopy(Instr *jitMemory, Byte *jitBuffer, int size);

protected:
    Byte *tmpBuffer_;
    int offset_;
    std::queue<Byte> willSign_;
    std::vector<uint32_t> signTable_;
    PACSignCtx ctx_;
};
}
}
}
#endif