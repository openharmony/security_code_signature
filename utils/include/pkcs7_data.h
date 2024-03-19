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

#ifndef CODE_SIGN_PKCS7_DATA_H
#define CODE_SIGN_PKCS7_DATA_H

#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include "byte_buffer.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
class PKCS7Data {
public:
    PKCS7Data(const char *digestAlgo);
    PKCS7Data(const EVP_MD *md, X509 *cert);
    ~PKCS7Data();
    bool GetPKCS7Data(ByteBuffer &pkcs7Data);
    bool AddSignerInfo(PKCS7_SIGNER_INFO *p7i);
    bool InitPKCS7Data(const std::vector<ByteBuffer> &certChain);
private:
    X509 *cert_ = nullptr;
    const EVP_MD *md_;
    PKCS7 *p7_ = nullptr;
};
}
}
}
#endif
