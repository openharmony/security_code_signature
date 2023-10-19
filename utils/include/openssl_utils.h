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

#ifndef CODE_SIGN_OPENSSL_UTILS_H
#define CODE_SIGN_OPENSSL_UTILS_H

#include <vector>

#include "byte_buffer.h"
#include "openssl/x509.h"
#include "openssl/err.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
constexpr int OPENSSL_ERR_MESSAGE_MAX_LEN = 1024;

void GetOpensslErrorMessage();

#define ErrLogWithOpenSSLMsg(msg) do { \
    LOG_ERROR(LABEL, "%{public}s", msg); \
    GetOpensslErrorMessage(); \
} while (0)

X509 *LoadCertFromBuffer(const uint8_t *buffer, const uint32_t size);
STACK_OF(X509) *MakeStackOfCerts(const std::vector<ByteBuffer> &certChain);
}
}
}
#endif