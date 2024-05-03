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

#include "local_sign_key.h"

#include <cstring>
#include <cstdio>
#include <climits>
#include <securec.h>
#include <string>

#include "byte_buffer.h"
#include "cert_utils.h"
#include "errcode.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
static const std::string ALIAS_NAME = "LOCAL_SIGN_KEY";
static const struct HksBlob LOCAL_SIGN_KEY_ALIAS = { ALIAS_NAME.size(), (uint8_t *)ALIAS_NAME.c_str()};
static const uint32_t SIGNATURE_COMMON_SIZE = 512;

static const std::string SUPPORTED_SIGN_ALGORITHM = "ECDSA256";
static constexpr uint32_t MAX_SIGN_SIZE = 65535;

static const struct HksParam ECC_KEY_PRARAM[] = {
    { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE }
};

static const struct HksParam ECC_SIGN_PRARAM[] = {
    { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_ECC },
    { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_ECC_KEY_SIZE_256 },
    { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
    { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE }
};

static const struct HksParam ECC_EXIST_PRARAM[] = {
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE }
};

LocalSignKey &LocalSignKey::GetInstance()
{
    static LocalSignKey singleLocalSignKey;
    return singleLocalSignKey;
}

LocalSignKey::LocalSignKey()
{
}

LocalSignKey::~LocalSignKey()
{
    if (cert_ != nullptr) {
        delete cert_;
        cert_ = nullptr;
    }
    if (certChain_ != nullptr) {
        FreeCertChain(&certChain_, certChain_->certsCount);
        certChain_ = nullptr;
    }
}

void LocalSignKey::SetChallenge(const ByteBuffer &challenge)
{
    std::lock_guard<std::mutex> lock(lock_);
    if (challenge_) {
        challenge_.reset(nullptr);
    }
    uint32_t len = challenge.GetSize();
    challenge_ = std::make_unique<ByteBuffer>(len);
    if (challenge_ == nullptr) {
        return;
    }
    if (memcpy_s(challenge_->GetBuffer(), len, challenge.GetBuffer(), len) != EOK) {
        LOG_ERROR("set challenge failed.");
    }
}

bool LocalSignKey::InitKey()
{
    HUKSParamSet paramSet;
    bool bRet = paramSet.Init(ECC_EXIST_PRARAM, sizeof(ECC_EXIST_PRARAM) / sizeof(HksParam));
    if (!bRet) {
        return false;
    }
    int32_t ret = HksKeyExist(&LOCAL_SIGN_KEY_ALIAS, paramSet.GetParamSet());
    if (ret == HKS_ERROR_NOT_EXIST) {
        if (!GenerateKey()) {
            return false;
        }
    } else if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksKeyExist fail, ret is %{public}d!", ret);
        return false;
    }
    certChain_ = QueryCertChain();
    if (certChain_ == nullptr) {
        return false;
    }
    return true;
}

const ByteBuffer *LocalSignKey::GetSignCert()
{
    if (cert_ != nullptr) {
        return cert_;
    }
    const HksCertChain *certChain = GetCertChain();
    if (certChain == nullptr) {
        return nullptr;
    }
    cert_ = new (std::nothrow) ByteBuffer();
    if (cert_ == nullptr) {
        LOG_ERROR("Alloc memory for cert blob failed.");
        return nullptr;
    }
    // get cert chain with 4 certs. the first is sign cert
    if (!cert_->CopyFrom(certChain->certs[0].data, certChain->certs[0].size)) {
        delete cert_;
        cert_ = nullptr;
    }
    return cert_;
}

const HksCertChain *LocalSignKey::GetCertChain()
{
    if (certChain_ != nullptr) {
        return certChain_;
    }
    certChain_ = QueryCertChain();
    if (certChain_ == nullptr) {
        LOG_ERROR("QueryCertChain failed.");
        return nullptr;
    }
    return certChain_;
}

HksCertChain *LocalSignKey::QueryCertChain()
{
    // init attest param
    HUKSParamSet paramSet;
    if (!GetAttestParamSet(paramSet)) {
        return nullptr;
    }

    HksCertChain *certChain = nullptr;
    // alloc memory for cert chain
    if (!ConstructDataToCertChain(&certChain)) {
        return nullptr;
    }

    // get cert chain by huks attest
    int32_t ret = HksAttestKey(&LOCAL_SIGN_KEY_ALIAS, paramSet.GetParamSet(), certChain);
    if (ret != HKS_SUCCESS) {
        FreeCertChain(&certChain, certChain->certsCount);
        LOG_ERROR("HksAttestKey fail, ret is %{public}d!", ret);
        return nullptr;
    }
    return certChain;
}

int32_t LocalSignKey::GetFormattedCertChain(ByteBuffer &buffer)
{
    if (GetCertChain() == nullptr) {
        return CS_ERR_HUKS_OBTAIN_CERT;
    }
    if (!FormattedCertChain(certChain_, buffer)) {
        return CS_ERR_MEMORY;
    }
    return CS_SUCCESS;
}

bool LocalSignKey::GetKeyParamSet(HUKSParamSet &paramSet)
{
    if (algorithm_.compare(SUPPORTED_SIGN_ALGORITHM) == 0) {
        return paramSet.Init(ECC_KEY_PRARAM, sizeof(ECC_KEY_PRARAM) / sizeof(HksParam));
    }
    return false;
}

bool LocalSignKey::GetAttestParamSet(HUKSParamSet &paramSet)
{
    std::lock_guard<std::mutex> lock(lock_);
    // init challenge data by secure random function
    if (challenge_ == nullptr) {
        challenge_ = GetRandomChallenge();
        if (challenge_ == nullptr) {
            return false;
        }
    }

    LOG_INFO("challenge in attest param.");
    struct HksBlob challengeBlob = {
        .size = challenge_->GetSize(),
        .data = challenge_->GetBuffer()
    };
    struct HksParam attestationParams[] = {
        { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = challengeBlob },
        { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = LOCAL_SIGN_KEY_ALIAS },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE }
    };
    return paramSet.Init(attestationParams, sizeof(attestationParams) / sizeof(HksParam));
}

bool LocalSignKey::GenerateKey()
{
    HUKSParamSet paramSet;
    if (!GetKeyParamSet(paramSet)) {
        return false;
    }
    int32_t ret = HksGenerateKey(&LOCAL_SIGN_KEY_ALIAS, paramSet.GetParamSet(), nullptr);
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksGenerateKey failed, ret is %{public}d!", ret);
        return false;
    }
    return true;
}

bool LocalSignKey::GetSignParamSet(HUKSParamSet &paramSet)
{
    if (algorithm_.compare(SUPPORTED_SIGN_ALGORITHM) == 0) {
        return paramSet.Init(ECC_SIGN_PRARAM, sizeof(ECC_SIGN_PRARAM) / sizeof(HksParam));
    }
    return false;
}

bool LocalSignKey::Sign(const ByteBuffer &data, ByteBuffer &signature)
{
    if (data.GetSize() > MAX_SIGN_SIZE) {
        LOG_ERROR("Data to sign is too long");
        return false;
    }
    struct HksBlob inData = {
        .size = data.GetSize(),
        .data = data.GetBuffer()
    };

    uint8_t tmpOut[SIGNATURE_COMMON_SIZE] = {0};
    struct HksBlob outData = {
        .size = SIGNATURE_COMMON_SIZE,
        .data = tmpOut
    };
    if (!SignByHUKS(&inData, &outData)) {
        return false;
    }
    if (!signature.CopyFrom(outData.data, outData.size)) {
        return false;
    }
    return true;
}

bool LocalSignKey::SignByHUKS(const struct HksBlob *inData, struct HksBlob *outData)
{
    HUKSParamSet paramSet;
    if (!GetSignParamSet(paramSet)) {
        return false;
    }

    // first stage: init, set key alias
    uint8_t tmpHandle[sizeof(uint64_t)] = {0};
    struct HksBlob handle = { sizeof(uint64_t), tmpHandle };
    int32_t ret = HksInit(&LOCAL_SIGN_KEY_ALIAS, paramSet.GetParamSet(), &handle, nullptr);
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksInit failed");
        return false;
    }

    // second stage: update, send input data to HUKS
    struct HksBlob tmpOutData = {
        .size = MAX_SIGN_SIZE,
        .data = nullptr
    };
    tmpOutData.data = static_cast<uint8_t *>(malloc(tmpOutData.size));
    if (tmpOutData.data == nullptr) {
        LOG_ERROR("Alloc memory for blob failed.");
        return false;
    }
    ret = HksUpdate(&handle, paramSet.GetParamSet(), inData, &tmpOutData);
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksUpdate Failed.");
        free(tmpOutData.data);
        return CS_ERR_PARAM_INVALID;
    }

    // third stage: finish, get signature from HUKS
    tmpOutData.size = 0;
    ret = HksFinish(&handle, paramSet.GetParamSet(), &tmpOutData, outData);
    free(tmpOutData.data);
    if (ret != HKS_SUCCESS) {
        LOG_ERROR("HksFinish Failed.");
        return false;
    }
    return true;
}
}
}
}
