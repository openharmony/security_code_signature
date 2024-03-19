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

#include "pkcs7_data.h"

#include <string>
#include <openssl/asn1.h>
#include <securec.h>

#include "log.h"
#include "openssl_utils.h"


namespace OHOS {
namespace Security {
namespace CodeSign {
PKCS7Data::PKCS7Data(const EVP_MD *md, X509 *cert)
    : cert_(cert), md_(md)
{
}

PKCS7Data::~PKCS7Data()
{
    cert_ = nullptr;
    md_ = nullptr;
    if (p7_ != nullptr) {
        // signerinfo would be freed with p7
        PKCS7_free(p7_);
        p7_ = nullptr;
    }
}

bool PKCS7Data::InitPKCS7Data(const std::vector<ByteBuffer> &certChain)
{
    uint32_t flags = PKCS7_BINARY | PKCS7_DETACHED | PKCS7_NOATTR | PKCS7_PARTIAL;
    STACK_OF(X509) *certs = nullptr;
    if (certChain.empty()) {
        flags = flags | PKCS7_NOCERTS;
    } else {
        certs = MakeStackOfCerts(certChain);
    }
    p7_ = PKCS7_sign(nullptr, nullptr, certs, nullptr, static_cast<int>(flags));
    if (p7_ == nullptr) {
        sk_X509_pop_free(certs, X509_free);
        return false;
    }
    return true;
}

bool PKCS7Data::GetPKCS7Data(ByteBuffer &pkcs7Data)
{
    BIO *bio = BIO_new(BIO_s_mem());
    bool ret = false;
    do {
        if (bio == nullptr) {
            break;
        }
        if (!i2d_PKCS7_bio(bio, p7_)) {
            ERR_LOG_WITH_OPEN_SSL_MSG("Encode pkcs7 data failed.");
            break;
        }
        uint8_t *tmp = nullptr;
        long tmpSize = BIO_get_mem_data(bio, &tmp);
        if ((tmpSize < 0) || (tmpSize > UINT32_MAX)) {
            break;
        }
        if (!pkcs7Data.CopyFrom(tmp, static_cast<uint32_t>(tmpSize))) {
            break;
        }
        ret = true;
    } while (0);
    BIO_free(bio);
    return ret;
}

bool PKCS7Data::AddSignerInfo(PKCS7_SIGNER_INFO *p7i)
{
    if (!PKCS7_add_signer(p7_, p7i)) {
        PKCS7_SIGNER_INFO_free(p7i);
        LOG_ERROR("Add signer to pkcs7 failed");
        return false;
    }
    return true;
}
}
}
}