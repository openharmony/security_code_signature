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

#include "openssl_utils.h"

#include <openssl/pem.h>
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
void GetOpensslErrorMessage()
{
    unsigned long retOpenssl;
    char errOpenssl[OPENSSL_ERR_MESSAGE_MAX_LEN];
    while ((retOpenssl = ERR_get_error()) != 0) {
        // error string is written no more than OPENSSL_ERR_MESSAGE_MAX_LEN in errOpenssl
        ERR_error_string_n(retOpenssl, errOpenssl, OPENSSL_ERR_MESSAGE_MAX_LEN);
        LOG_ERROR("openssl err: %{public}lu, message: %{public}s", retOpenssl, errOpenssl);
    }
}

X509 *LoadCertFromBuffer(const uint8_t *buffer, const uint32_t size)
{
    BIO *mem = BIO_new_mem_buf(buffer, size);
    if (mem == nullptr) {
        LOG_ERROR("Fail to create bio for cert.");
        return nullptr;
    }
    X509 *cert = d2i_X509_bio(mem, nullptr);
    if (cert == nullptr) {
        ERR_LOG_WITH_OPEN_SSL_MSG("Certificate is invalid.");
    }
    BIO_free(mem);
    return cert;
}

bool ConvertCertToPEMString(const ByteBuffer &certBuffer, std::string &pemString)
{
    X509 *cert = LoadCertFromBuffer(certBuffer.GetBuffer(), certBuffer.GetSize());
    if (cert == nullptr) {
        return false;
    }
    BIO *mem = BIO_new(BIO_s_mem());
    if (mem == nullptr) {
        X509_free(cert);
        return false;
    }
    bool ret = false;
    do {
        if (!PEM_write_bio_X509(mem, cert)) {
            ERR_LOG_WITH_OPEN_SSL_MSG("convert to pem failed.");
            break;
        }
        uint8_t *outData = nullptr;
        int32_t len = BIO_get_mem_data(mem, &outData);
        if (len < 0) {
            break;
        }
        pemString = std::string(reinterpret_cast<char *>(outData), len);
        ret = true;
    } while (0);
    BIO_free(mem);
    X509_free(cert);
    return ret;
}

STACK_OF(X509) *MakeStackOfCerts(const std::vector<ByteBuffer> &certChain)
{
    STACK_OF(X509)* certs = sk_X509_new_null();
    if (certs == nullptr) {
        return nullptr;
    }

    for (const ByteBuffer &cert: certChain) {
        X509 *tmp = LoadCertFromBuffer(cert.GetBuffer(), cert.GetSize());

        if ((tmp == nullptr) || (!sk_X509_push(certs, tmp))) {
            // including each cert in certs and stack of certs
            sk_X509_pop_free(certs, X509_free);
            certs = nullptr;
            ERR_LOG_WITH_OPEN_SSL_MSG("Push cert failed.");
            break;
        }
    }
    return certs;
}

int CreateNIDFromOID(const std::string &oid, const std::string &shortName,
    const std::string &longName)
{
    int nid = OBJ_txt2nid(oid.c_str());
    if (nid == NID_undef) {
        nid = OBJ_create(oid.c_str(), shortName.c_str(), longName.c_str());
    }
    return nid;
}
}
}
}
