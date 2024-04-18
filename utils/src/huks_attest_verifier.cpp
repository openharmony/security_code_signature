/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "huks_attest_verifier.h"

#include <openssl/asn1.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <string>
#include <vector>

#include "byte_buffer.h"
#include "cert_utils.h"
#include "log.h"
#include "openssl_utils.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
static const std::string ATTEST_ROOT_CA_PATH = "/system/etc/security/trusted_attest_root_ca.cer";
static const std::vector<std::string> ATTESTTATION_EXTENSION = {
    "1.3.6.1.4.1.2011.2.376.1.3",
    "AttestationInfo",
    "Attestation Information"
};

static const std::vector<std::string> SA_INFO_EXTENSION = {
    "1.3.6.1.4.1.2011.2.376.2.1.3.1",
    "SA INFO",
    "SystemAbiliy Information"
};

static const std::vector<std::string> CHALLENGE_EXTENSION = {
    "1.3.6.1.4.1.2011.2.376.2.1.4",
    "Challenge",
    "Challenge"
};

static const std::string LOCAL_CODE_SIGN_SA_NAME = "local_code_sign";

static constexpr uint32_t MIN_VECTOR_SIZE = 3;
static bool g_verifierInited = false;
static int g_saNid = 0;
static int g_challengeNid = 0;
static int g_attestationNid = 0;

static inline int GetNidFromDefination(const std::vector<std::string> &defVector)
{
    if (defVector.size() < MIN_VECTOR_SIZE) {
        return NID_undef;
    }
    return CreateNIDFromOID(defVector[0], defVector[1], defVector[defVector.size() - 1]);
}

static void InitVerifier()
{
    if (g_verifierInited) {
        return;
    }
    g_saNid = GetNidFromDefination(SA_INFO_EXTENSION);
    g_challengeNid = GetNidFromDefination(CHALLENGE_EXTENSION);
    g_attestationNid = GetNidFromDefination(ATTESTTATION_EXTENSION);
    LOG_DEBUG("g_saNid = %{public}d, g_challengeNid = %{public}d, g_attestationNid = %{public}d",
        g_saNid, g_challengeNid, g_attestationNid);
    g_verifierInited = true;
}

static bool AddCAToStore(X509_STORE *store)
{
    FILE *fp = fopen(ATTEST_ROOT_CA_PATH.c_str(), "r");
    if (fp == nullptr) {
        LOG_ERROR("Open file failed.");
        return false;
    }

    X509 *caCert = nullptr;
    do {
        caCert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
        if (caCert == nullptr) {
            break;
        }
        if (X509_STORE_add_cert(store, caCert) <= 0) {
            LOG_ERROR("add cert to X509 store failed");
            GetOpensslErrorMessage();
        }
        LOG_INFO("Add root CA subject name = %{public}s",
            X509_NAME_oneline(X509_get_subject_name(caCert), nullptr, 0));
    } while (caCert != nullptr);
    (void) fclose(fp);
    return true;
}

static bool VerifyIssurCert(X509 *cert, STACK_OF(X509) *chain)
{
    X509_STORE *store = X509_STORE_new();
    if (store == nullptr) {
        return false;
    }

    bool ret = false;
    X509_STORE_CTX *storeCtx = nullptr;
    
    do {
        if (!AddCAToStore(store)) {
            break;
        }
        storeCtx = X509_STORE_CTX_new();
        if (storeCtx == nullptr) {
            break;
        }

        if (!X509_STORE_CTX_init(storeCtx, store, cert, chain)) {
            LOG_ERROR("init X509_STORE_CTX failed.");
            break;
        }
        X509_STORE_CTX_set_purpose(storeCtx, X509_PURPOSE_ANY);
        // because user can set date of device, validation skip time check for fool-proofing
        X509_STORE_CTX_set_flags(storeCtx, X509_V_FLAG_NO_CHECK_TIME);
        int index = X509_verify_cert(storeCtx);
        if (index <= 0) {
            index = X509_STORE_CTX_get_error(storeCtx);
            LOG_ERROR("Verify cert failed, msg = %{public}s", X509_verify_cert_error_string(index));
            break;
        }
        ret = true;
    } while (0);
    if (!ret) {
        GetOpensslErrorMessage();
    }
    X509_STORE_CTX_free(storeCtx);
    X509_STORE_free(store);
    return ret;
}

static bool VerifySigningCert(X509 *signCert, X509 *issuerCert)
{
    EVP_PKEY *key = X509_get0_pubkey(issuerCert);
    if (key == nullptr) {
        LOG_ERROR("get pub key failed.");
        return false;
    }
    if (X509_verify(signCert, key) <= 0) {
        LOG_ERROR("verify signing cert failed.");
        GetOpensslErrorMessage();
        return false;
    }
    return true;
}

static bool CompareTargetValue(int nid, uint8_t *data, int size, const ByteBuffer &challenge)
{
    if (nid == g_saNid) {
        std::string str(reinterpret_cast<char *>(data), size);
        LOG_INFO("compare with proc = %{private}s", str.c_str());
        return str.find(LOCAL_CODE_SIGN_SA_NAME) != std::string::npos;
    } else if (nid == g_challengeNid) {
        LOG_INFO("compare with challenge");
        return (static_cast<uint32_t>(size) == challenge.GetSize())
                    || (memcmp(data, challenge.GetBuffer(), size) == 0);
    }
    return true;
}

static bool ParseASN1Sequence(uint8_t *data, int size, const ByteBuffer &challenge)
{
    STACK_OF(ASN1_TYPE) *types = d2i_ASN1_SEQUENCE_ANY(
        nullptr, const_cast<const uint8_t **>(&data), size);
    if (types == nullptr) {
        return false;
    }

    int num = sk_ASN1_TYPE_num(types);
    int curNid = -1;
    bool ret = true;
    for (int i = 0; i < num; i++) {
        ASN1_TYPE *type = sk_ASN1_TYPE_value(types, i);
        if (type->type == V_ASN1_SEQUENCE) {
            ret = ParseASN1Sequence(type->value.sequence->data, type->value.sequence->length,
                challenge);
        } else if (type->type == V_ASN1_OBJECT) {
            ASN1_OBJECT *obj = type->value.object;
            curNid = OBJ_obj2nid(obj);
        } else if (type->type == V_ASN1_OCTET_STRING) {
            ASN1_OCTET_STRING *value = type->value.octet_string;
            ret = CompareTargetValue(curNid, value->data, value->length, challenge);
        }
        if (!ret) {
            break;
        }
    }
    return true;
}

static bool VerifyExtension(X509 *cert, const ByteBuffer &challenge)
{
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(cert);
    int num;

    if ((num = sk_X509_EXTENSION_num(exts)) <= 0) {
        LOG_ERROR("Get extension failed.");
        return false;
    }

    InitVerifier();
    for (int i = 0; i < num; i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
        if (obj == nullptr) {
            LOG_ERROR("Get ans1 object faild");
            continue;
        }
        int curNid = OBJ_obj2nid(obj);
        if (g_attestationNid == curNid) {
            const ASN1_OCTET_STRING *extData = X509_EXTENSION_get_data(ext);
            ParseASN1Sequence(extData->data, extData->length, challenge);
        }
    }
    return true;
}

#ifdef CODE_SIGNATURE_DEBUGGABLE
static void ShowCertInfo(const std::vector<ByteBuffer> &certChainBuffer,
    const ByteBuffer &issuerBuffer, const ByteBuffer &certBuffer)
{
    std::string pem;
    LOG_INFO("Dump cert chain");
    for (auto cert: certChainBuffer) {
        if (ConvertCertToPEMString(cert, pem)) {
            LOG_INFO("%{private}s", pem.c_str());
        }
    }
    LOG_INFO("Dump issuer cert");
    if (ConvertCertToPEMString(issuerBuffer, pem)) {
        LOG_INFO("%{private}s", pem.c_str());
    }
    LOG_INFO("Dump signing cert");
    if (ConvertCertToPEMString(certBuffer, pem)) {
        LOG_INFO("%{private}s", pem.c_str());
    }
}
#endif

static bool VerifyCertAndExtension(X509 *signCert, X509 *issuerCert, const ByteBuffer &challenge)
{
    if (!VerifySigningCert(signCert, issuerCert)) {
        return false;
    }
    LOG_DEBUG("Verify sign cert pass");

    if (!VerifyExtension(signCert, challenge)) {
        LOG_ERROR("Verify extension failed.");
        return false;
    }
    LOG_INFO("Verify success");
    return true;
}


bool GetVerifiedCert(const ByteBuffer &buffer, const ByteBuffer &challenge, ByteBuffer &certBuffer)
{
    std::vector<ByteBuffer> certChainBuffer;
    ByteBuffer issuerBuffer;
    if (!GetCertChainFormBuffer(buffer, certBuffer, issuerBuffer, certChainBuffer)) {
        LOG_ERROR("Get cert chain failed.");
        return false;
    }

    X509 *issuerCert = LoadCertFromBuffer(issuerBuffer.GetBuffer(), issuerBuffer.GetSize());
    if (issuerCert == nullptr) {
        LOG_ERROR("Load issuerCert cert failed.");
        return false;
    }

    bool ret = false;
    X509 *signCert = nullptr;
    STACK_OF(X509 *) certChain = nullptr;
    do {
        certChain = MakeStackOfCerts(certChainBuffer);
        if (certChain == nullptr) {
            LOG_ERROR("Load cert chain failed.");
            break;
        }
        if (!VerifyIssurCert(issuerCert, certChain)) {
            LOG_ERROR("Verify issuer cert not pass.");
            break;
        }
        LOG_DEBUG("Verify issuer cert pass");

        signCert = LoadCertFromBuffer(certBuffer.GetBuffer(), certBuffer.GetSize());
        if (signCert == nullptr) {
            LOG_ERROR("Load signing cert failed.");
            break;
        }

        if (!VerifyCertAndExtension(signCert, issuerCert, challenge)) {
            break;
        }
        ret = true;
    } while (0);
    X509_free(signCert);
    X509_free(issuerCert);
    sk_X509_pop_free(certChain, X509_free);
#ifdef CODE_SIGNATURE_DEBUGGABLE
    if (!ret) {
        ShowCertInfo(certChainBuffer, issuerBuffer, certBuffer);
    }
#endif
    return ret;
}
}
}
}
