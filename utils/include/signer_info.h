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

#ifndef CODE_SIGN_SIGNER_INFO_H
#define CODE_SIGN_SIGNER_INFO_H

#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include "byte_buffer.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
class SignerInfo {
public:
    static const std::string OWNERID_OID;
    static const std::string OWNERID_OID_SHORT_NAME;
    static const std::string OWNERID_OID_LONG_NAME;
    
    static int ParseOwnerIdFromSignature(const ByteBuffer &sigbuffer, std::string &ownerID);
    bool InitSignerInfo(const std::string &ownerID, X509 *cert, const EVP_MD *md, const ByteBuffer &contentData,
                        bool carrySigningTime = false);
    bool AddSignatureInSignerInfo(const ByteBuffer &signature);
    uint8_t *GetDataToSign(uint32_t &len);
    PKCS7_SIGNER_INFO *GetSignerInfo();
    int AddOwnerID(const std::string &ownerID);
     
private:
    bool AddAttrsToSignerInfo(const std::string &ownerID, const ByteBuffer &contentData);
    bool ComputeDigest(const ByteBuffer &data, ByteBuffer &digest);
    int GetSignAlgorithmID(const X509 *cert);

    PKCS7_SIGNER_INFO *p7info_ = nullptr;
    const EVP_MD *md_ = nullptr;
    bool carrySigningTime_ = false;
    std::unique_ptr<ByteBuffer> unsignedData_ = nullptr;
};
}
}
}
#endif