/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "permission_utils.h"

#include "accesstoken_kit.h"
#include "cs_hisysevent.h"
#include "parameter.h"
#include "ipc_skeleton.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
const std::vector<std::string> CERTIFICATE_CALLERS = {"key_enable"};
const std::vector<std::string> SIGN_CALLERS = {"compiler_service"};
constexpr int32_t VALUE_MAX_LEN = 32;
const char* ACCESS_TOKEN_SERVICE_INIT_KEY = "accesstoken.permission.init";
bool g_isAtmInited = false;

bool PermissionUtils::IsValidCallerOfCert()
{
    AccessToken::AccessTokenID callerTokenId = IPCSkeleton::GetCallingTokenID();
    if (VerifyCallingProcess(CERTIFICATE_CALLERS, callerTokenId)) {
        return true;
    }
    ReportInvalidCaller("Cert", callerTokenId);
    return false;
}

bool PermissionUtils::IsValidCallerOfLocalCodeSign()
{
    AccessToken::AccessTokenID callerTokenId = IPCSkeleton::GetCallingTokenID();
    if (VerifyCallingProcess(SIGN_CALLERS, callerTokenId)) {
        return true;
    }
    ReportInvalidCaller("Sign", callerTokenId);
    return false;
}

bool PermissionUtils::HasATMInitilized()
{
    char value[VALUE_MAX_LEN] = {0};
    int32_t ret = GetParameter(ACCESS_TOKEN_SERVICE_INIT_KEY, "", value, VALUE_MAX_LEN - 1);
    if ((ret < 0) || (static_cast<uint64_t>(std::atoll(value)) != 0)) {
        g_isAtmInited = true;
        return true;
    }
    return false;
}

bool PermissionUtils::VerifyCallingProcess(const std::vector<std::string> &validCallers,
    const AccessToken::AccessTokenID &callerTokenId)
{
    if (!g_isAtmInited && !HasATMInitilized()) {
        LOG_DEBUG("AccessTokenManager has not started yet.");
        return true;
    }
    for (const auto &caller: validCallers) {
        AccessToken::AccessTokenID tokenId = AccessToken::AccessTokenKit::GetNativeTokenId(caller);
        if (tokenId == callerTokenId) {
            return true;
        }
    }
    LOG_ERROR("Invalid caller.");
    return false;
}
}
}
}