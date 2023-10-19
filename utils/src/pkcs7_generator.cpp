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

#include "pkcs7_generator.h"

#include "errcode.h"
#include "log.h"
#include "openssl/asn1.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl_utils.h"
#include "pkcs7_data.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
int32_t PKCS7Generator::GenerateSignature(const std::string &ownerID, SignKey &key, const char *hashAlg,
                                          const ByteBuffer &contentData, ByteBuffer &out)
{
    LOG_INFO(LABEL, "GenerateSignature called.");
    int32_t ret = CS_ERR_OPENSSL_PKCS7;
    X509 *cert = nullptr;
    do {
        const ByteBuffer *certBuffer = key.GetSignCert();
        if (certBuffer == nullptr) {
            ret = CS_ERR_HUKS_OBTAIN_CERT;
            break;
        }
        cert = LoadCertFromBuffer(certBuffer->GetBuffer(), certBuffer->GetSize());
        if (cert == nullptr) {
            ret = CS_ERR_OPENSSL_LOAD_CERT;
            break;
        }
        const EVP_MD *md = EVP_get_digestbyname(hashAlg);
        if (md == nullptr) {
            break;
        }
        PKCS7Data pkcs7(md, cert);
        if (!pkcs7.InitPKCS7Data(key.GetCarriedCerts())) {
            break;
        }
        SignerInfo signerInfo;
        if (!signerInfo.InitSignerInfo(ownerID, cert, md, contentData)) {
            break;
        }
        if (!pkcs7.AddSignerInfo(signerInfo.GetSignerInfo())) {
            break;
        }
        ret = SignData(key, signerInfo);
        if (ret != CS_SUCCESS) {
            break;
        }
        if (!pkcs7.GetPKCS7Data(out)) {
            ret = CS_ERR_OPENSSL_PKCS7;
            break;
        }
        ret = CS_SUCCESS;
    } while (0);
    X509_free(cert);
    if (ret != CS_SUCCESS) {
        LOG_ERROR(LABEL, "Generate signature failed, ret = %{public}d", ret);
    }
    return ret;
}

int32_t PKCS7Generator::SignData(SignKey &key, SignerInfo &signerInfo)
{
    uint32_t dataSize = 0;
    uint8_t *data = signerInfo.GetDataToSign(dataSize);
    if (data == nullptr) {
        LOG_ERROR(LABEL, "GetDataToSign fail");
        return CS_ERR_OPENSSL_PKCS7;
    }
    ByteBuffer unsignedData;
    if (!unsignedData.CopyFrom(data, dataSize)) {
        return CS_ERR_MEMORY;
    }
    ByteBuffer rawSignature;
    if (!key.Sign(unsignedData, rawSignature)) {
        return CS_ERR_HUKS_SIGN;
    }
    if (!signerInfo.AddSignatureInSignerInfo(rawSignature)) {
        LOG_ERROR(LABEL, "AddSignatureInSignerInfo fail");
        return CS_ERR_OPENSSL_PKCS7;
    }
    return CS_SUCCESS;
}
}
}
}