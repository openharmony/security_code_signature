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
#include <openssl/x509.h>
#include <openssl/objects.h>

#include "log_rust.h"
#include "errcode.h"

#define ENTERPRISE_RESIGN_OID "1.3.6.1.4.1.2011.2.376.1.9"
#define ENTERPRISE_RESIGN_SN "EnterpriseAppResignCertID"
#define ENTERPRISE_RESIGN_LN "Enterprise App Resign Cert ID"

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

int32_t CheckCertHasEnterpriseResignExtension(const uint8_t *certDer, uint32_t certSize)
{
    if (certDer == nullptr || certSize == 0) {
        LOG_ERROR(LABEL, "Invalid certificate DER input");
        return CS_ERR_PARAM_INVALID;
    }

    const unsigned char *certPtr = certDer;
    X509 *cert = d2i_X509(nullptr, &certPtr, certSize);
    if (cert == nullptr) {
        LOG_ERROR(LABEL, "Failed to parse certificate from DER");
        return CS_ERR_PARAM_INVALID;
    }

    const char *enterpriseResignOid = ENTERPRISE_RESIGN_OID;
    int nid = OBJ_txt2nid(enterpriseResignOid);
    if (nid == NID_undef) {
        nid = OBJ_create(ENTERPRISE_RESIGN_OID, ENTERPRISE_RESIGN_SN, ENTERPRISE_RESIGN_LN);
    }

    if (nid == NID_undef) {
        LOG_ERROR(LABEL, "Failed to create NID for enterprise resign OID");
        X509_free(cert);
        return CS_ERR_PARAM_INVALID;
    }

    ASN1_OBJECT *obj = OBJ_nid2obj(nid);
    if (obj == nullptr) {
        LOG_ERROR(LABEL, "Failed to get ASN1_OBJECT for NID");
        X509_free(cert);
        return CS_ERR_PARAM_INVALID;
    }

    int loc = X509_get_ext_by_OBJ(cert, obj, -1);
    X509_free(cert);

    if (loc >= 0) {
        LOG_INFO(LABEL, "Found enterprise resign extension in certificate");
        return CS_SUCCESS;
    } else {
        LOG_ERROR(LABEL, "Enterprise resign extension not found in certificate");
        return CS_ERR_PARAM_INVALID;
    }
}
