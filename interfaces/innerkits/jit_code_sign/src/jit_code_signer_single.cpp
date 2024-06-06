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

#include "jit_code_signer_single.h"

#include <sstream>
#include "errcode.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {

JitCodeSignerSingle::JitCodeSignerSingle()
{
    Reset();
}

void JitCodeSignerSingle::Reset()
{
    tmpBuffer_ = nullptr;
    ctx_.InitSalt();
    ctx_.Init(0);
    signTable_.clear();
    offset_ = 0;
}

void JitCodeSignerSingle::SignInstruction(Instr insn)
{
    int index = GetIndexFromOffset(offset_);
#ifdef JIT_CODE_SIGN_DEBUGGABLE
    LOG_INFO("Offset = %{public}x, insn = %{public}x", offset_, insn);
    if (static_cast<size_t>(index) != signTable_.size()) {
        LOG_ERROR("Index = %{public}d not equal signtable size = %{public}zu.",
            GetIndexFromOffset(offset_), signTable_.size());
    }
#endif
    signTable_.push_back(ctx_.SignSingle(insn, index));
    offset_ += INSTRUCTION_SIZE;
}

void JitCodeSignerSingle::SkipNext(uint32_t n) {}

int32_t JitCodeSignerSingle::PatchInstruction(int offset, Instr insn)
{
#ifdef JIT_CODE_SIGN_DEBUGGABLE
    LOG_INFO("offset = %{public}x, insn = %{public}x", offset, insn);
#endif
    int curIndex = 0;
    if (!ConvertPatchOffsetToIndex(offset, curIndex)) {
        LOG_ERROR("Offset invalid");
        return CS_ERR_PATCH_INVALID;
    }
    uint32_t signature = ctx_.SignSingle(insn, curIndex);
    signTable_[curIndex] = signature;
    return CS_SUCCESS;
}

int32_t JitCodeSignerSingle::ValidateCodeCopy(Instr *jitMemory,
    Byte *tmpBuffer, int size)
{
    int32_t ret = CheckDataCopy(jitMemory, tmpBuffer, size);
    if (ret != CS_SUCCESS) {
        return ret;
    }

    PACSignCtx verifyCtx(CTXPurpose::VERIFY, ctx_.GetSalt());
    int offset = 0;
    while (offset < size) {
        int index = GetIndexFromOffset(offset);
        Instr insn = *reinterpret_cast<const Instr *>(tmpBuffer_ + offset);
        uint32_t signature = verifyCtx.SignSingle(insn, index);
        if (signature != signTable_[index]) {
#ifdef JIT_FORT_DISABLE
            LOG_ERROR("validate insn(%{public}x) without context failed at index = " \
                "%{public}x, signature(%{public}x) != wanted(%{public}x)",
                insn, index * INSTRUCTION_SIZE, signature, signTable_[index]);
#endif
#ifndef JIT_CODE_SIGN_PERMISSIVE
            return CS_ERR_VALIDATE_CODE;
#endif
        }
        *(jitMemory + index) = insn;
        offset += INSTRUCTION_SIZE;
    }
    return CS_SUCCESS;
}
}
}
}