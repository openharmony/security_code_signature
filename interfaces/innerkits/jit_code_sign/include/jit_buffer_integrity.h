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

#ifndef CODE_SIGN_JIT_BUFFER_INTEGRITY_H
#define CODE_SIGN_JIT_BUFFER_INTEGRITY_H

#include <cstdint>
#include <cstring>

#include "errcode.h"
#include "jit_code_signer_base.h"
#include "jit_code_signer_factory.h"
#include "jit_fort_helper.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace CodeSign {

#define CAST_TO_CONST_BYTES(buffer) (reinterpret_cast<const Byte *const>(buffer))
#define CAST_TO_BYTES(buffer) (reinterpret_cast<Byte *>(buffer))

#define CHECK_NULL_AND_RETURN_CODE(ptr) do { \
    if ((ptr) == nullptr) { \
        return JitCodeSignErrCode::CS_ERR_NO_SIGNER; \
    } \
} while (0)

/**
 * @brief Create Jit Code signer of specific level
 * @param level see jit_code_signer_factory.h
 * @return error code, see errcode.h
 */
static inline JitCodeSignerBase *CreateJitCodeSigner(JitBufferIntegrityLevel level)
{
    return JitCodeSignerFactory::CreateJitCodeSigner(level);
}

/**
 * @brief Register start address of tmp buffer if patching target address of buffer
 * @param signer jit code signer
 * @param tmpBuffer tmp buffer storing jit code
 * @return error code, see errcode.h
 */
static inline int32_t RegisterTmpBuffer(JitCodeSignerBase *signer, void *tmpBuffer)
{
    CHECK_NULL_AND_RETURN_CODE(signer);
    signer->RegisterTmpBuffer(CAST_TO_BYTES(tmpBuffer));
    return CS_SUCCESS;
}

/**
 * @brief Sign an intruction when appending it to tmp buffer
 * @param signer jit code signer
 * @param instr an instruction to be signed
 * @return error code, see errcode.h
 */
static inline int32_t AppendInstruction(JitCodeSignerBase *signer, Instr instr)
{
    CHECK_NULL_AND_RETURN_CODE(signer);
    signer->SignInstruction(instr);
    return CS_SUCCESS;
}

/**
 * @brief Sign data when appending it to tmp buffer
 * @param signer jit code signer
 * @param data data to be signed
 * @param size data size
 * @return error code, see errcode.h
 */
static inline int32_t AppendData(JitCodeSignerBase *signer, const void *const data, uint32_t size)
{
    CHECK_NULL_AND_RETURN_CODE(signer);
    return signer->SignData(CAST_TO_CONST_BYTES(data), size);
}

/**
 * @brief Declare the next intsructions to be fixed up later
 * @param signer jit code signer
 * @param n the amount of intsructions
 * @return error code, see errcode.h
 */
static inline int32_t WillFixUp(JitCodeSignerBase *signer, uint32_t n = 1)
{
    CHECK_NULL_AND_RETURN_CODE(signer);
    signer->SkipNext(n);
    return CS_SUCCESS;
}

/**
 * @brief Patch an intruction at offset
 * @param signer jit code signer
 * @param instr target intruction
 * @return error code, see errcode.h
 */
static inline int32_t PatchInstruction(JitCodeSignerBase *signer, int offset, Instr instr)
{
    CHECK_NULL_AND_RETURN_CODE(signer);
    return signer->PatchInstruction(offset, instr);
}

/**
 * @brief Patch an intruction at address
 * @param signer jit code signer
 * @param address address of patching instruction
 * @param instr target intruction
 * @return error code, see errcode.h
 */
static inline int32_t PatchInstruction(JitCodeSignerBase *signer,
    void *address, Instr insn)
{
    CHECK_NULL_AND_RETURN_CODE(signer);
    return signer->PatchInstruction(CAST_TO_BYTES(address), insn);
}

/**
 * @brief Patch data at offset of buffer
 * @param signer jit code signer
 * @param data data to be signed
 * @param size data size
 * @return error code, see errcode.h
 */
static inline int32_t PatchData(JitCodeSignerBase *signer, int offset,
    const void *const data, uint32_t size)
{
    CHECK_NULL_AND_RETURN_CODE(signer);
    return signer->PatchData(offset, CAST_TO_CONST_BYTES(data), size);
}

/**
 * @brief Patch data at address
 * @param signer jit code signer
 * @param address address of patching instruction
 * @param data data to be signed
 * @param size data size
 * @return error code, see errcode.h
 */
static inline int32_t PatchData(JitCodeSignerBase *signer, void *address,
    const void *const data, uint32_t size)
{
    CHECK_NULL_AND_RETURN_CODE(signer);
    return signer->PatchData(CAST_TO_BYTES(address),
        CAST_TO_CONST_BYTES(data), size);
}

/**
 * @brief Reset jit memory
 * @param jitMemory jit memory to be reset
 * @param size memory size
 * @return error code, see errcode.h
 */
static inline int32_t ResetJitCode(void *jitMemory, int size)
{
    if (jitMemory == nullptr) {
        return CS_ERR_JIT_MEMORY;
    }
#ifndef JIT_FORT_DISABLE
    int32_t prctlRet = PrctlWrapper(JITFORT_PRCTL_OPTION, JITFORT_SWITCH_IN, 0);
    if (prctlRet < 0) {
        return CS_ERR_JITFORT_IN;
    }
#endif
    (void) __builtin_memset(jitMemory, 0, size);
#ifndef JIT_FORT_DISABLE
    prctlRet = PrctlWrapper(JITFORT_PRCTL_OPTION, JITFORT_SWITCH_OUT, 0);
    if (prctlRet < 0) {
        return CS_ERR_JITFORT_OUT;
    }
#endif
    return CS_SUCCESS;
}

/**
 * @brief Copy jit code for cache to jit memory
 * @param signer jit code signer
 * @param jitMemory dest address
 * @param tmpBuffer tmp buffer stored jit code
 * @param size memory size
 * @return error code, see errcode.h
 */
static inline int32_t CopyToJitCode(JitCodeSignerBase *signer, void *jitMemory,
    void *tmpBuffer, int size)
{
    CHECK_NULL_AND_RETURN_CODE(signer);
    int32_t ret = CS_SUCCESS;
    // try not to depend on other dynamic library in JITFORT
#ifndef JIT_FORT_DISABLE
    int32_t prctlRet = PrctlWrapper(JITFORT_PRCTL_OPTION, JITFORT_SWITCH_IN, 0);
    if (prctlRet < 0) {
        return CS_ERR_JITFORT_IN;
    }
#endif
    ret = signer->ValidateCodeCopy(reinterpret_cast<Instr *>(jitMemory),
        reinterpret_cast<Byte *>(tmpBuffer), size);
#ifndef JIT_FORT_DISABLE
    prctlRet = PrctlWrapper(JITFORT_PRCTL_OPTION, JITFORT_SWITCH_OUT, 0);
    if (prctlRet < 0) {
        return CS_ERR_JITFORT_OUT;
    }
#endif
    return ret;
}
}
}
}
#endif