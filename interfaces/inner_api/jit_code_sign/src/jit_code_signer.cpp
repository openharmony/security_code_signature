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

#include "jit_code_signer.h"

#include <sstream>
#ifndef JIT_FORT_DISABLE
#include "securec.h"
#endif
#include "errcode.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {

constexpr int32_t BYTE_BIT_SIZE = 8;
constexpr uint32_t UNALIGNMENT_MASK = 0x3;

JitCodeSigner::JitCodeSigner()
{
    Reset();
}

void JitCodeSigner::Reset()
{
    tmpBuffer_ = nullptr;
    ctx_.InitSalt();
    ctx_.Init(0);
    signTable_.clear();
    offset_ = 0;
}

inline static Instr GetOneInstrForQueue(std::queue<Byte> &queue)
{
    Instr insn = 0;
    int i = 0;
    while ((i < INSTRUCTION_SIZE) && !queue.empty()) {
        insn |= (queue.front() << (BYTE_BIT_SIZE * i));
        queue.pop();
        i++;
    }
    return insn;
}

void JitCodeSigner::RegisterTmpBuffer(Byte *tmpBuffer)
{
    tmpBuffer_ = tmpBuffer;
}

int32_t JitCodeSigner::SignData(const Byte *const data, uint32_t size)
{
    if (data == nullptr) {
        return CS_ERR_INVALID_DATA;
    }
    uint32_t cur = 0;
    size_t unsignedSize = willSign_.size();
    if ((unsignedSize == 0) && (size >= INSTRUCTION_SIZE)) {
        auto insnPtr = reinterpret_cast<const Instr *const>(data);
        while (cur + INSTRUCTION_SIZE <= size) {
            SignInstruction(*insnPtr);
            insnPtr++;
            cur += INSTRUCTION_SIZE;
        }
    }

    if (cur == size) {
        return CS_SUCCESS;
    }
    unsignedSize += size - cur;
    while (cur < size) {
        willSign_.push(*(data + cur));
        cur++;
    }

    while (unsignedSize >= INSTRUCTION_SIZE) {
        Instr insn = GetOneInstrForQueue(willSign_);
        SignInstruction(insn);
        unsignedSize -= INSTRUCTION_SIZE;
    }
    return CS_SUCCESS;
}

int32_t JitCodeSigner::PatchInstruction(Byte *buffer, Instr insn)
{
    if ((buffer == nullptr) || (tmpBuffer_ == nullptr)) {
        return CS_ERR_PATCH_INVALID;
    }
    return PatchInstruction(static_cast<int>(buffer - tmpBuffer_), insn);
}

int32_t JitCodeSigner::PatchData(int offset, const Byte *const data, uint32_t size)
{
    if (size & UNALIGNMENT_MASK) {
        return CS_ERR_JIT_SIGN_SIZE;
    }
    if (data == nullptr) {
        return CS_ERR_INVALID_DATA;
    }
    auto insnPtr = reinterpret_cast<const Instr *const>(data);
    for (uint32_t i = 0; i < size; i += INSTRUCTION_SIZE) {
        int ret = PatchInstruction(offset + i, *insnPtr);
        if (ret != CS_SUCCESS) {
            return ret;
        }
        insnPtr += 1;
    }
    return CS_SUCCESS;
}

int32_t JitCodeSigner::PatchData(Byte *buffer, const Byte *const data, uint32_t size)
{
    if ((buffer == nullptr) || (tmpBuffer_ == nullptr)) {
        return CS_ERR_PATCH_INVALID;
    }
    return PatchData(static_cast<int>(buffer - tmpBuffer_), data, size);
}

#ifndef JIT_FORT_DISABLE
void JitCodeSigner::FlushLog()
{
    for (auto &log: deferredLogs) {
        LOG_LEVELED(log.level, "%{public}s", log.message);
    }
    deferredLogs.clear();
    // There's at most 1 log, for now. No need to shrink.
}
#endif

bool JitCodeSigner::ConvertPatchOffsetToIndex(const int offset, int &curIndex)
{
    if ((offset < 0) || ((static_cast<uint32_t>(offset) & UNALIGNMENT_MASK) != 0)) {
        return false;
    }
    curIndex = GetIndexFromOffset(offset);
    if (static_cast<size_t>(curIndex) >= signTable_.size()) {
        LOG_ERROR("Offset is out of range, index = %{public}d, signTable size = %{public}zu",
            curIndex, signTable_.size());
        return false;
    }
    return true;
}

int32_t JitCodeSigner::CheckDataCopy(Instr *jitMemory, Byte *tmpBuffer, int size)
{
    if (jitMemory == nullptr) {
        return CS_ERR_JIT_MEMORY;
    }
    if (tmpBuffer == nullptr) {
        return CS_ERR_TMP_BUFFER;
    }

    // update tmp buffer
    tmpBuffer_ = tmpBuffer;

    if (((static_cast<uint32_t>(size) & UNALIGNMENT_MASK) != 0) ||
        (static_cast<uint32_t>(size) > signTable_.size() * INSTRUCTION_SIZE)) {
#ifdef JIT_FORT_DISABLE
        LOG_ERROR("Range invalid, size = %{public}d, table size = %{public}zu",
            size, signTable_.size());
#else
        char *buffer = reinterpret_cast<char *>(malloc(MAX_DEFERRED_LOG_LENGTH));
        if (buffer == nullptr) {
            return CS_ERR_OOM;
        }

        int ret = sprintf_s(buffer, MAX_DEFERRED_LOG_LENGTH,
            "[%s]: Range invalid, size = %d, table size = %zu",
            __func__, size, signTable_.size());

        if (ret == -1) {
            free(buffer);
            buffer = nullptr;
            return CS_ERR_LOG_TOO_LONG;
        }

        deferredLogs.emplace_back(DeferredLog{buffer, LOG_ERROR});
#endif
        return CS_ERR_JIT_SIGN_SIZE;
    }
    return CS_SUCCESS;
}

void JitCodeSigner::SignInstruction(Instr insn)
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

void JitCodeSigner::SkipNext(uint32_t n) {}

int32_t JitCodeSigner::PatchInstruction(int offset, Instr insn)
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

int32_t JitCodeSigner::ValidateCodeCopy(Instr *jitMemory,
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
#else
        char *buffer = reinterpret_cast<char *>(malloc(MAX_DEFERRED_LOG_LENGTH));
        if (buffer == nullptr) {
            return CS_ERR_OOM;
        }

        int ret = sprintf_s(buffer, MAX_DEFERRED_LOG_LENGTH,
            "[%s]: validate insn(%x) without context failed at index = " \
            "%x, signature(%x) != wanted(%x)",
            __func__, insn, index * INSTRUCTION_SIZE, signature, signTable_[index]);

        if (ret == -1) {
            free(buffer);
            buffer = nullptr;
            return CS_ERR_LOG_TOO_LONG;
        }
        deferredLogs.emplace_back(DeferredLog{buffer, LOG_ERROR});
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