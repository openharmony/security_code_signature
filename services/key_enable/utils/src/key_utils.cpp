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

#include "key_utils.h"

#include <asm/unistd.h>
#include <cerrno>
#include <cstring>
#include <unistd.h>

#include "log_rust.h"

constexpr int KEYCTL_RESTRICT_KEYRING = 29;

using namespace OHOS::Security::CodeSign;

KeySerial AddKey(
    const char *type,
    const char *description,
    const unsigned char *payload,
    size_t pLen,
    KeySerial ringId)
{
    KeySerial ret = syscall(__NR_add_key,
        type, description, static_cast<const void *>(payload),
        pLen, ringId);
    if (ret < 0) {
        LOG_ERROR(LABEL, "Add certificate failed, errno = <%{public}d, %{public}s>",
            errno, strerror(errno));
    }
    return ret;
}

KeySerial KeyctlRestrictKeyring(
    KeySerial ringId,
    const char *type,
    const char *restriction)
{
    KeySerial ret = syscall(__NR_keyctl,
        KEYCTL_RESTRICT_KEYRING, ringId,
        type, restriction);
    if (ret < 0) {
        LOG_ERROR(LABEL, "Restrict keyring failed, errno = <%{public}d, %{public}s>",
            errno, strerror(errno));
    }
    return ret;
}
