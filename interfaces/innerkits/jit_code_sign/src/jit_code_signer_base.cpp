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

#include "jit_code_signer_base.h"

#include <sstream>
#include "errcode.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {

constexpr int32_t BYTE_BIT_SIZE = 8;
constexpr uint32_t UNALIGNMENT_MASK = 0x3;

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

void JitCodeSignerBase::RegisterTmpBuffer(Byte *tmpBuffer)
{
    tmpBuffer_ = tmpBuffer;
}

int32_t JitCodeSignerBase::SignData(const Byte *const data, uint32_t size)
{
    if (data == nullptr) {
        return CS_ERR_INVALID_DATA;
    }
    uint32_t cur = 0;
    int unsignedSize = willSign_.size();
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

int32_t JitCodeSignerBase::PatchInstruction(Byte *buffer, Instr insn)
{
    if ((buffer == nullptr) || (tmpBuffer_ == nullptr)) {
        return CS_ERR_PATCH_INVALID;
    }
    return PatchInstruction(static_cast<int>(buffer - tmpBuffer_), insn);
}

int32_t JitCodeSignerBase::PatchData(int offset, const Byte *const data, uint32_t size)
{
    if (size & UNALIGNMENT_MASK) {
        return CS_ERR_JIT_SIGN_SIZE;
    }
    if (data == nullptr) {
        return CS_ERR_INVALID_DATA;
    }
    auto insnPtr = reinterpret_cast<const Instr *const>(data);
    int ret = 0;
    for (uint32_t i = 0; i < size; i += INSTRUCTION_SIZE) {
        ret = PatchInstruction(offset + i, *insnPtr);
        if (ret != CS_SUCCESS) {
            return ret;
        }
        insnPtr += 1;
    }
    return CS_SUCCESS;
}

int32_t JitCodeSignerBase::PatchData(Byte *buffer, const Byte *const data, uint32_t size)
{
    if ((buffer == nullptr) || (tmpBuffer_ == nullptr)) {
        return CS_ERR_PATCH_INVALID;
    }
    return PatchData(static_cast<int>(buffer - tmpBuffer_), data, size);
}

bool JitCodeSignerBase::ConvertPatchOffsetToIndex(const int offset, int &curIndex)
{
    if ((offset < 0) || ((offset & UNALIGNMENT_MASK) != 0)) {
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

int32_t JitCodeSignerBase::CheckDataCopy(Instr *jitMemory, Byte *tmpBuffer, int size)
{
    if (jitMemory == nullptr) {
        return CS_ERR_JIT_MEMORY;
    }
    if (tmpBuffer == nullptr) {
        return CS_ERR_TMP_BUFFER;
    }

    // update tmp buffer
    tmpBuffer_ = tmpBuffer;

    if (((size & UNALIGNMENT_MASK) != 0) ||
        (static_cast<uint32_t>(size) > signTable_.size() * INSTRUCTION_SIZE)) {
#ifdef JIT_FORT_DISABLE
        LOG_ERROR("Range invalid, size = %{public}d, table size = %{public}zu",
            size, signTable_.size());
#endif
        return CS_ERR_JIT_SIGN_SIZE;
    }
    return CS_SUCCESS;
}
}
}
}