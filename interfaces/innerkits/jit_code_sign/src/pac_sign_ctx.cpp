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

#include "pac_sign_ctx.h"

#include <memory>
#include "errcode.h"
#include "log.h"
#include "random_helper.h"

namespace OHOS {
namespace Security {
namespace CodeSign {

constexpr uint64_t SIGN_WITH_CONTEXT_PREFIX = 0x2LL << 60;
constexpr uint64_t SIGN_WITHOUT_CONTEXT_PREFIX = 0x3LL << 60;
constexpr uint64_t AUTH_CONTEXT_PREFIX = 0x1LL << 60;
constexpr uint32_t HIGH_BITS_RIGHT_SHIFT = 32;

static inline uint64_t PACDB(uint64_t value, uint64_t modifier)
{
#ifdef ARCH_PAC_SUPPORT
    asm volatile("pacdb %0, %1" : "+r"(value) : "r"(modifier) :);
#endif
    return value;
}

static inline uint64_t AUTDB(uint64_t value, uint64_t modifier)
{
#ifdef ARCH_PAC_SUPPORT
    asm volatile("autdb %0, %1" : "+r"(value) : "r"(modifier) :);
#endif
    return value;
}

static inline uint32_t PACGA(uint64_t value, uint64_t modifier)
{
#ifdef ARCH_PAC_SUPPORT
    uint64_t ret = 0;
    asm volatile("pacga %0, %1, %2" : "=r"(ret) : "r"(value), "r"(modifier) :);
#else
    uint64_t ret = value;
#endif
    return static_cast<uint32_t>(ret >> HIGH_BITS_RIGHT_SHIFT);
}

PACSignCtx::PACSignCtx(CTXPurpose purpose, uint32_t salt)
    : context_(0), salt_(salt), index_(0), purpose_(purpose) {}

PACSignCtx::~PACSignCtx() {}

void PACSignCtx::InitSalt()
{
    static RandomHelper randomHelper;
    uint32_t random = 0;
    if (randomHelper.GetUint32(random) != CS_SUCCESS) {
        LOG_ERROR("Init salt failed.");
        int tmpAddr = 0;
        // use random address as salt
        random = static_cast<uint32_t>(
            reinterpret_cast<uintptr_t>(&tmpAddr));
    }
    salt_ = random;
}

void PACSignCtx::Init(int index)
{
    index_ = index;
    SetContext(GetSalt());
}

uint64_t PACSignCtx::PaddingContext(ContextType type, int index)
{
    uint32_t context;
    uint64_t prefix;
    switch (type) {
        case SIGN_WITH_CONTEXT:
            context = context_;
            prefix = SIGN_WITH_CONTEXT_PREFIX;
            index = index_;
            break;
        case SIGN_WITHOUT_CONTEXT:
            context = GetSalt();
            prefix = SIGN_WITHOUT_CONTEXT_PREFIX;
            break;
        case AUTH_CONTEXT:
            context = GetSalt();
            index = index_;
            prefix = AUTH_CONTEXT_PREFIX;
            break;
        default:
            return CS_ERR_UNSUPPORT;
    }
#if defined(JIT_CODE_SIGN_DEBUGGABLE) && defined(JIT_FORT_DISABLE)
    LOG_INFO("Padding prefix = %{public}lx, index = %{public}x, context = %{public}x",
        prefix, index_, context);
#endif
    uint64_t ret = prefix | ((static_cast<uint64_t>(index) & 0xfffffff) << 32) | context;
    return ret;
}

void PACSignCtx::SetContext(uint32_t context)
{
    if (purpose_ == CTXPurpose::VERIFY) {
        context_ = context;
        return;
    }
    uint64_t paddingContext = PaddingContext(AUTH_CONTEXT);
    context_ = PACDB(context, paddingContext);
}

uint64_t PACSignCtx::GetRealContext()
{
    uint64_t paddingContext = PaddingContext(AUTH_CONTEXT);
    return AUTDB(context_, paddingContext);
}

uint32_t PACSignCtx::SignWithContext(uint32_t value)
{
    uint64_t paddingContext = PaddingContext(SIGN_WITH_CONTEXT);
    return PACGA(value, paddingContext);
}

uint32_t PACSignCtx::Update(uint32_t value)
{
#if defined(JIT_CODE_SIGN_DEBUGGABLE) && defined(JIT_FORT_DISABLE)
    LOG_INFO("Before update context = %{public}lx", context_);
#endif
    if (purpose_ == CTXPurpose::SIGN) {
        context_ = GetRealContext();
    }
    index_ += 1;
    uint32_t signature = SignWithContext(value);
    SetContext(signature);
#if defined(JIT_CODE_SIGN_DEBUGGABLE) && defined(JIT_FORT_DISABLE)
    LOG_INFO("After update context = %{public}lx, signature = %{public}x",
        context_, signature);
#endif
    return signature;
}

uint32_t PACSignCtx::SignSingle(uint32_t value, uint32_t index)
{
    uint64_t paddingContext = PaddingContext(SIGN_WITHOUT_CONTEXT, index);
    uint32_t signature = PACGA(value, paddingContext);
#if defined(JIT_CODE_SIGN_DEBUGGABLE) && defined(JIT_FORT_DISABLE)
    LOG_ERROR("Get signature = %{public}x", signature);
#endif
    return signature;
}

uint32_t PACSignCtx::GetSalt()
{
    return salt_;
}
}
}
}