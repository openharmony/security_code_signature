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

#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <securec.h>

#include "errcode.h"
#include "log.h"
#include "openssl_utils.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
static constexpr int INVALID_SIGN_ALGORITHM_NID = -1;
static constexpr int MAX_SIGNATURE_SIZE = 1024; // 1024: max signature length

// OID used for code signing to mark owner ID
const std::string SignerInfo::OWNERID_OID = "1.3.6.1.4.1.2011.2.376.1.4.1";
const std::string SignerInfo::OWNERID_OID_SHORT_NAME = "ownerID";
const std::string SignerInfo::OWNERID_OID_LONG_NAME = "Code Signature Owner ID";

bool SignerInfo::InitSignerInfo(const std::string &ownerID, X509 *cert, const EVP_MD *md,
    const ByteBuffer &contentData, bool carrySigningTime)
{
    if ((cert == nullptr) || (md == nullptr)) {
        return false;
    }
    md_ = md;
    carrySigningTime_ = carrySigningTime;
    p7info_ = PKCS7_SIGNER_INFO_new();
    if (p7info_ == nullptr) {
        ERR_LOG_WITH_OPEN_SSL_MSG("Create pkcs7 signer info failed");
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

        if (!AddAttrsToSignerInfo(ownerID, contentData)) {
            ERR_LOG_WITH_OPEN_SSL_MSG("Add attributes to signer info failed");
            break;
        }
        ret = true;
    } while (0);
    if (!ret) {
        PKCS7_SIGNER_INFO_free(p7info_);
        ERR_LOG_WITH_OPEN_SSL_MSG("Init pkcs7 signer info failed");
    }
    return ret;
}

bool SignerInfo::AddAttrsToSignerInfo(const std::string &ownerID, const ByteBuffer &contentData)
{
    if (!carrySigningTime_ && ownerID.empty()) {
        unsignedData_ = std::make_unique<ByteBuffer>();
        if (!unsignedData_->CopyFrom(contentData.GetBuffer(), contentData.GetSize())) {
            unsignedData_.reset(nullptr);
            return false;
        }
        return true;
    }

    if (!ownerID.empty()) {
        AddOwnerID(ownerID);
    }

    if (!PKCS7_add_attrib_content_type(p7info_, nullptr)) {
        return false;
    }
    
    if (carrySigningTime_) {
        if (!PKCS7_add0_attrib_signing_time(p7info_, nullptr)) {
            return false;
        }
    }

    ByteBuffer digest;
    if (!ComputeDigest(contentData, digest)) {
        return false;
    }
    if (!PKCS7_add1_attrib_digest(p7info_, digest.GetBuffer(), digest.GetSize())) {
        ERR_LOG_WITH_OPEN_SSL_MSG("PKCS7_add1_attrib_digest fail");
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
    if (p7info_->auth_attr != nullptr) {
        int itemLen = ASN1_item_i2d(reinterpret_cast<ASN1_VALUE *>(p7info_->auth_attr), &data,
            ASN1_ITEM_rptr(PKCS7_ATTR_SIGN));
        if (itemLen < 0) {
            return nullptr;
        }
        len = static_cast<uint32_t>(itemLen);
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
    if (signatureSize == 0 || signatureSize > MAX_SIGNATURE_SIZE) {
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
        ERR_LOG_WITH_OPEN_SSL_MSG("Compute digest failed.");
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

int SignerInfo::AddOwnerID(const std::string &ownerID)
{
    int nid = CreateNIDFromOID(OWNERID_OID, OWNERID_OID_SHORT_NAME, OWNERID_OID_LONG_NAME);
    ASN1_STRING *ownerIDAsn1 = ASN1_STRING_new();
    ASN1_STRING_set(ownerIDAsn1, ownerID.c_str(), ownerID.length());
    int ret = PKCS7_add_signed_attribute(p7info_, nid, V_ASN1_UTF8STRING, ownerIDAsn1);
    if (ret == 0) {
        ASN1_STRING_free(ownerIDAsn1);
        ERR_LOG_WITH_OPEN_SSL_MSG("PKCS7_add_signed_attribute failed");
        return CS_ERR_OPENSSL_PKCS7;
    }

    return CS_SUCCESS;
}

int SignerInfo::ParseOwnerIdFromSignature(const ByteBuffer &sigbuffer, std::string &ownerID)
{
    int nid = CreateNIDFromOID(OWNERID_OID, OWNERID_OID_SHORT_NAME, OWNERID_OID_LONG_NAME);
    BIO *bio = BIO_new_mem_buf(sigbuffer.GetBuffer(), sigbuffer.GetSize());
    if (bio == nullptr) {
        ERR_LOG_WITH_OPEN_SSL_MSG("BIO_new_mem_buf failed");
        return CS_ERR_OPENSSL_BIO;
    }
    PKCS7 *p7 = d2i_PKCS7_bio(bio, nullptr);
    if (p7 == nullptr) {
        BIO_free(bio);
        ERR_LOG_WITH_OPEN_SSL_MSG("d2i_PKCS7_bio failed");
        return CS_ERR_OPENSSL_PKCS7;
    }

    STACK_OF(PKCS7_SIGNER_INFO) *signerInfosk = PKCS7_get_signer_info(p7);
    if (signerInfosk == nullptr) {
        BIO_free(bio);
        PKCS7_free(p7);
        ERR_LOG_WITH_OPEN_SSL_MSG("PKCS7_get_signer_info failed");
        return CS_ERR_OPENSSL_PKCS7;
    }
    for (int i = 0; i < sk_PKCS7_SIGNER_INFO_num(signerInfosk); i++) {
        PKCS7_SIGNER_INFO *signerInfo = sk_PKCS7_SIGNER_INFO_value(signerInfosk, i);
        ASN1_TYPE *asn1Type = PKCS7_get_signed_attribute(signerInfo, nid);
        if (asn1Type != nullptr && asn1Type->type == V_ASN1_UTF8STRING) {
            ASN1_STRING *result = asn1Type->value.asn1_string;
            ownerID.assign(reinterpret_cast<const char *>(ASN1_STRING_get0_data(result)), ASN1_STRING_length(result));
            break;
        }
    }
    BIO_free(bio);
    PKCS7_free(p7);
    if (ownerID.empty()) {
        return CS_ERR_NO_OWNER_ID;
    }
    return CS_SUCCESS;
}
}
}
}
