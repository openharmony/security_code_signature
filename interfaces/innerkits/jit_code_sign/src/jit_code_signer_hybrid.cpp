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

#include "jit_code_signer_hybrid.h"

#include <sstream>
#include "errcode.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
JitCodeSignerHybrid::JitCodeSignerHybrid()
{
    Reset();
}

void JitCodeSignerHybrid::Reset()
{
    tmpBuffer_ = nullptr;
    ctx_.InitSalt();
    ctx_.Init(0);
    ctxInited_ = true;
    skipSize_ = 0;
    offset_ = 0;
    signTable_.clear();
    skippedOffset_.clear();
    while (!willSign_.empty()) {
        willSign_.pop();
    }
}

void JitCodeSignerHybrid::SignInstruction(Instr insn)
{
#ifdef JIT_CODE_SIGN_DEBUGGABLE
    if (static_cast<size_t>(GetIndexFromOffset(offset_)) != signTable_.size()) {
        LOG_ERROR("Index = %{public}d not equal signtable size = %{public}zu.",
            GetIndexFromOffset(offset_), signTable_.size());
    }
    LOG_INFO("Offset = %{public}x, insn = %{public}x", offset_, insn);
#endif
    if (skipSize_ > 0) {
        skippedOffset_.push_back(offset_);
        signTable_.push_back(ctx_.SignSingle(insn, GetIndexFromOffset(offset_)));
        skipSize_ -= 1;
    } else {
        if (!ctxInited_) {
            ctx_.Init(GetIndexFromOffset(offset_));
            ctxInited_ = true;
        }
        uint32_t signature = ctx_.Update(insn);
        signTable_.push_back(signature);
    }
    offset_ += INSTRUCTION_SIZE;
}

void JitCodeSignerHybrid::SkipNext(uint32_t n)
{
    skipSize_ = std::max(skipSize_, n);
    ctxInited_ = false;
}

int32_t JitCodeSignerHybrid::PatchInstruction(int offset, Instr insn)
{
#ifdef JIT_CODE_SIGN_DEBUGGABLE
    if (std::find(skippedOffset_.begin(), skippedOffset_.end(), offset)
        == skippedOffset_.end()) {
        LOG_ERROR("Update no skipped instruction failed at offset" \
            "= %{public}x", offset);
    }
    LOG_INFO("offset = %{public}x, insn = %{public}x", offset, insn);
#endif
    int curIndex = 0;
    if (!ConvertPatchOffsetToIndex(offset, curIndex)) {
        LOG_ERROR("Offset invalid");
        return CS_ERR_PATCH_INVALID;
    }
    int signature = ctx_.SignSingle(insn, curIndex);
    signTable_[curIndex] = signature;
    return CS_SUCCESS;
}

int32_t JitCodeSignerHybrid::ValidateSubCode(Instr *jitMemory, PACSignCtx &verifyCtx,
    Byte *jitBuffer, int pos, int size)
{
    if (size == 0) {
        return CS_SUCCESS;
    }
#if defined(JIT_CODE_SIGN_DEBUGGABLE) && defined(JIT_FORT_DISABLE)
    LOG_INFO("Validate start = %{public}p, offset = %{public}x, size = %{public}d",
        jitBuffer, pos, size);
#endif
    int32_t index = GetIndexFromOffset(pos);
    verifyCtx.Init(index);
    auto insnPtr = reinterpret_cast<const Instr *>(jitBuffer + pos);
    while (size > 0) {
        uint32_t signature = verifyCtx.Update(*insnPtr);
        if (signature != signTable_[index]) {
#ifdef JIT_FORT_DISABLE
            LOG_ERROR("Validate insn (%{public}8x) failed at offset = %{public}x, " \
                "signature(%{public}x) != wanted(%{pucblic}x)",
                *(insnPtr), index * INSTRUCTION_SIZE, signature, signTable_[index]);
#endif
#ifndef JIT_CODE_SIGN_PERMISSIVE
            return CS_ERR_VALIDATE_CODE;
#else
            break;
#endif
        }
        *(jitMemory + index) = *insnPtr;
        index++;
        insnPtr++;
        size -= INSTRUCTION_SIZE;
    }
    return CS_SUCCESS;
}

int32_t JitCodeSignerHybrid::ValidateCodeCopy(Instr *jitMemory,
    Byte *tmpBuffer, int size)
{
    int32_t ret = CheckDataCopy(jitMemory, tmpBuffer, size);
    if (ret != CS_SUCCESS) {
        return ret;
    }

    PACSignCtx verifyCtx(CTXPurpose::VERIFY, ctx_.GetSalt());
    int offset = 0;
    for (uint32_t i = 0; i < skippedOffset_.size(); i++) {
        if (ValidateSubCode(jitMemory, verifyCtx, tmpBuffer_, offset,
            skippedOffset_[i] - offset) != CS_SUCCESS) {
            return CS_ERR_VALIDATE_CODE;
        }

        int32_t index = GetIndexFromOffset(skippedOffset_[i]);
        Instr insn = *reinterpret_cast<const Instr *>(tmpBuffer_ + skippedOffset_[i]);
        uint32_t signature = verifyCtx.SignSingle(insn, index);
        if (signature != signTable_[index]) {
#ifdef JIT_FORT_DISABLE
            LOG_ERROR("Validate insn (%{public}x) without context failed at index = %{public}x," \
                "signature(%{public}x) != wanted(%{pucblic}x).",
                insn, index, signature, signTable_[index]);
#endif
#ifndef JIT_CODE_SIGN_PERMISSIVE
            return CS_ERR_VALIDATE_CODE;
#endif
        }
        *(jitMemory + index) = insn;
        offset = skippedOffset_[i] + INSTRUCTION_SIZE;
    }

    if (ValidateSubCode(jitMemory, verifyCtx, tmpBuffer_,
        offset, size - offset) != CS_SUCCESS) {
        return CS_ERR_VALIDATE_CODE;
    }
    return CS_SUCCESS;
}
}
}
}
