/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef CODE_SIGN_PERMISSION_UTILS_H
#define CODE_SIGN_PERMISSION_UTILS_H

#include <string>
#include <vector>

#include "access_token.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
class PermissionUtils {
public:
    static bool IsValidCallerOfCert();
    static bool IsValidCallerOfLocalCodeSign();
private:
    static bool VerifyCallingProcess(const std::vector<std::string> &validCallers,
    const AccessToken::AccessTokenID &callerTokenID);
    static bool HasATMInitilized();
};
}
}
}
#endif