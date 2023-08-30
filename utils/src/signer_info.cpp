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

#include "signer_info.h"
#include "log.h"
#include "openssl/asn1.h"
#include "openssl/pem.h"
#include "openssl_utils.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
static constexpr int INVALID_SIGN_ALGORITHM_NID = -1;

bool SignerInfo::InitSignerInfo(X509 *cert, const EVP_MD *md,
    const ByteBuffer &contentData, bool carrySigningTime)
{
    if ((cert == nullptr) || (md == nullptr)) {
        return false;
    }
    md_ = md;
    carrySigningTime_ = carrySigningTime;
    p7info_ = PKCS7_SIGNER_INFO_new();
    if (p7info_ == nullptr) {
        ErrLogWithOpenSSLMsg("Create pkcs7 signer info failed");
        return false;
    }
    bool ret = false;
    do {
        // set default information, pkcs7 signer info version is 1
        if (!ASN1_INTEGER_set(p7info_->version, 1)) {
            break;
        }

        // add sign cert info
        if (!X509_NAME_set(&p7info_->issuer_and_serial->issuer,
            X509_get_issuer_name(cert))) {
            break;
        }
        ASN1_INTEGER_free(p7info_->issuer_and_serial->serial);
        if (!(p7info_->issuer_and_serial->serial =
            ASN1_INTEGER_dup(X509_get_serialNumber(cert)))) {
            break;
        }

        // add digest and signature algorithm
        if (!X509_ALGOR_set0(p7info_->digest_alg, OBJ_nid2obj(EVP_MD_type(md)),
            V_ASN1_NULL, nullptr)) {
            break;
        }
        int signatureNid = GetSignAlgorithmID(cert);
        if (signatureNid < 0) {
            break;
        }
        if (!X509_ALGOR_set0(p7info_->digest_enc_alg, OBJ_nid2obj(signatureNid),
            V_ASN1_NULL, nullptr)) {
            break;
        }
        if (!AddAttrsToSignerInfo(contentData)) {
            ErrLogWithOpenSSLMsg("Add attributes to signer info failed");
            break;
        }
        ret = true;
    } while (0);
    if (!ret) {
        PKCS7_SIGNER_INFO_free(p7info_);
        ErrLogWithOpenSSLMsg("Init pkcs7 signer info failed");
    }
    return ret;
}

bool SignerInfo::AddAttrsToSignerInfo(const ByteBuffer &contentData)
{
    if (!carrySigningTime_) {
        unsignedData_ = std::make_unique<ByteBuffer>();
        if (!unsignedData_->CopyFrom(contentData.GetBuffer(), contentData.GetSize())) {
            unsignedData_.reset(nullptr);
            return false;
        }
        return true;
    }
    if (!PKCS7_add_attrib_content_type(p7info_, nullptr)) {
        return false;
    }
    if (!PKCS7_add0_attrib_signing_time(p7info_, nullptr)) {
        return false;
    }
    ByteBuffer digest;
    if (!ComputeDigest(contentData, digest)) {
        return false;
    }
    if (!PKCS7_add1_attrib_digest(p7info_, digest.GetBuffer(), digest.GetSize())) {
        return false;
    }
    return true;
}

uint8_t *SignerInfo::GetDataToSign(uint32_t &len)
{
    if (p7info_ == nullptr) {
        return nullptr;
    }

    uint8_t *data = nullptr;
    if (carrySigningTime_) {
        int itemLen = ASN1_item_i2d(reinterpret_cast<ASN1_VALUE *>(p7info_->auth_attr), &data,
            ASN1_ITEM_rptr(PKCS7_ATTR_SIGN));
        if (itemLen < 0) {
            return nullptr;
        }
        len = itemLen;
    } else {
        if (unsignedData_ == nullptr) {
            return nullptr;
        }
        data = unsignedData_->GetBuffer();
        len = unsignedData_->GetSize();
    }
    return data;
}

bool SignerInfo::AddSignatureInSignerInfo(const ByteBuffer &signature)
{
    if (p7info_ == nullptr) {
        return false;
    }
    uint32_t signatureSize = signature.GetSize();
    // tmp will be free when freeing p7info_
    if (signatureSize == 0) {
        return false;
    }
    uint8_t *tmp = static_cast<uint8_t *>(malloc(signatureSize));
    if (tmp == nullptr) {
        return false;
    }
    (void)memcpy_s(tmp, signatureSize, signature.GetBuffer(), signatureSize);
    ASN1_STRING_set0(p7info_->enc_digest, tmp, signatureSize);
    return true;
}

bool SignerInfo::ComputeDigest(const ByteBuffer &data, ByteBuffer &digest)
{
    uint8_t mdBuffer[EVP_MAX_MD_SIZE];
    uint32_t mdLen = 0;
    EVP_MD_CTX *mCtx = EVP_MD_CTX_new();
    bool ret = false;
    do {
        if (mCtx == nullptr) {
            break;
        }
        if (!EVP_DigestInit_ex(mCtx, md_, nullptr)) {
            break;
        }
        if (!EVP_DigestUpdate(mCtx, data.GetBuffer(), data.GetSize())) {
            break;
        }
        if (!EVP_DigestFinal_ex(mCtx, mdBuffer, &mdLen)) {
            break;
        }
        ret = true;
    } while (0);
    if (!ret) {
        ErrLogWithOpenSSLMsg("Compute digest failed.");
    } else if (!digest.CopyFrom(mdBuffer, mdLen)) {
        ret = false;
    }
    EVP_MD_CTX_free(mCtx);
    return ret;
}

int SignerInfo::GetSignAlgorithmID(const X509 *cert)
{
    X509_PUBKEY *xpkey = X509_get_X509_PUBKEY(cert);
    ASN1_OBJECT *koid = nullptr;
    if (!X509_PUBKEY_get0_param(&koid, nullptr, nullptr, nullptr, xpkey)) {
        return INVALID_SIGN_ALGORITHM_NID;
    }
    int signatureNid = OBJ_obj2nid(koid);
    if (signatureNid == NID_rsaEncryption) {
        return signatureNid;
    }
    OBJ_find_sigid_by_algs(&signatureNid, EVP_MD_type(md_), signatureNid);
    return signatureNid;
}

PKCS7_SIGNER_INFO *SignerInfo::GetSignerInfo()
{
    return p7info_;
}
}
}
}