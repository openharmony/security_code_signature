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

#include "cert_utils.h"

#include <cstring>
#include <memory>
#include <openssl/rand.h>
#include <securec.h>
#include <string>
#include <vector>

#include "byte_buffer.h"
#include "errcode.h"
#include "huks_param_set.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
static const uint32_t CERT_DATA_SIZE = 8192;
static const uint32_t CHALLENGE_LEN = 32;

static inline uint8_t *CastToUint8Ptr(uint32_t *ptr)
{
    return reinterpret_cast<uint8_t *>(ptr);
}

bool ConstructDataToCertChain(struct HksCertChain **certChain, int certsCount)
{
    *certChain = static_cast<struct HksCertChain *>(malloc(sizeof(struct HksCertChain)));
    if (*certChain == nullptr) {
        LOG_ERROR("malloc fail");
        return false;
    }
    (*certChain)->certsCount = CERT_COUNT;

    (*certChain)->certs = static_cast<struct HksBlob *>(malloc(sizeof(struct HksBlob) *
        ((*certChain)->certsCount)));
    if ((*certChain)->certs == nullptr) {
        free(*certChain);
        *certChain = nullptr;
        return false;
    }
    for (uint32_t i = 0; i < (*certChain)->certsCount; i++) {
        (*certChain)->certs[i].size = CERT_DATA_SIZE;
        (*certChain)->certs[i].data = static_cast<uint8_t *>(malloc((*certChain)->certs[i].size));
        if ((*certChain)->certs[i].data == nullptr) {
            LOG_ERROR("malloc fail");
            FreeCertChain(certChain, i);
            return false;
        }
    }
    return true;
}

void FreeCertChain(struct HksCertChain **certChain, const uint32_t pos)
{
    if (*certChain == nullptr) {
        return;
    }
    if ((*certChain)->certs == nullptr) {
        free(*certChain);
        *certChain = nullptr;
        return;
    }
    for (uint32_t j = 0; j < pos; j++) {
        if ((*certChain)->certs[j].data != nullptr) {
            free((*certChain)->certs[j].data);
            (*certChain)->certs[j].data = nullptr;
        }
    }
    free((*certChain)->certs);
    (*certChain)->certs = nullptr;
    free(*certChain);
    *certChain = nullptr;
}

bool FormattedCertChain(const HksCertChain *certChain, ByteBuffer &buffer)
{
    uint32_t certsCount = certChain->certsCount;
    uint32_t totalLen = sizeof(uint32_t);
    for (uint32_t i = 0; i < certsCount; i++) {
        totalLen += sizeof(uint32_t) + certChain->certs[i].size;
    }

    buffer.Resize(totalLen);
    if (!buffer.PutData(0, CastToUint8Ptr(&certsCount), sizeof(uint32_t))) {
        return false;
    }
    uint32_t pos = sizeof(uint32_t);
    for (uint32_t i = 0; i < certsCount; i++) {
        if (!buffer.PutData(pos, CastToUint8Ptr(&certChain->certs[i].size), sizeof(uint32_t))) {
            return false;
        }
        pos += sizeof(uint32_t);
        if (!buffer.PutData(pos, certChain->certs[i].data, certChain->certs[i].size)) {
            return false;
        }
        pos += certChain->certs[i].size;
    }
    return true;
}

static inline bool CheckSizeAndAssign(uint8_t *&bufferPtr, uint32_t &restSize, uint32_t &retSize)
{
    if (restSize < sizeof(uint32_t)) {
        return false;
    }
    retSize = *reinterpret_cast<uint32_t *>(bufferPtr);
    bufferPtr += sizeof(uint32_t);
    restSize -= sizeof(uint32_t);
    return true;
}

static inline bool CheckSizeAndCopy(uint8_t *&bufferPtr, uint32_t &restSize, const uint32_t size,
    ByteBuffer &ret)
{
    if (restSize < size) {
        return false;
    }
    if (!ret.CopyFrom(bufferPtr, size)) {
        return false;
    }
    bufferPtr += size;
    restSize -= size;
    return true;
}

bool GetCertChainFormBuffer(const ByteBuffer &certChainBuffer,
    ByteBuffer &signCert, ByteBuffer &issuer, std::vector<ByteBuffer> &chain)
{
    uint8_t *rawPtr = certChainBuffer.GetBuffer();
    if (rawPtr == nullptr || certChainBuffer.GetSize() < sizeof(uint32_t)) {
        return false;
    }
    uint32_t certsCount = *reinterpret_cast<uint32_t *>(rawPtr);
    rawPtr += sizeof(uint32_t);

    if (certsCount == 0) {
        return false;
    }

    uint32_t certSize;
    bool ret = true;
    uint32_t restSize = certChainBuffer.GetSize() - sizeof(uint32_t);
    for (uint32_t i = 0; i < certsCount - 1; i++) {
        if (!CheckSizeAndAssign(rawPtr, restSize, certSize)) {
            return false;
        }
        if (i == 0) {
            ret = CheckSizeAndCopy(rawPtr, restSize, certSize, signCert);
        } else if (i == 1) {
            ret = CheckSizeAndCopy(rawPtr, restSize, certSize, issuer);
        } else {
            ByteBuffer cert;
            ret = CheckSizeAndCopy(rawPtr, restSize, certSize, cert);
            chain.emplace_back(cert);
        }
        if (!ret) {
            break;
        }
    }
    return ret;
}

std::unique_ptr<ByteBuffer> GetRandomChallenge()
{
    std::unique_ptr<ByteBuffer> challenge = std::make_unique<ByteBuffer>(CHALLENGE_LEN);
    if (challenge == nullptr) {
        return nullptr;
    }
    RAND_bytes(challenge->GetBuffer(), CHALLENGE_LEN);
    return challenge;
}

bool CheckChallengeSize(uint32_t size)
{
    if (size > CHALLENGE_LEN) {
        return false;
    }
    return true;
}
}
}
}