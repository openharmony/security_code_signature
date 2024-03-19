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

#ifndef CODE_SIGN_CERT_UTILS_H
#define CODE_SIGN_CERT_UTILS_H

#include <cstdint>

#include "byte_buffer.h"
#include "hks_type.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
static const uint32_t CERT_COUNT = 4;

bool ConstructDataToCertChain(struct HksCertChain **certChain, int certsCount = CERT_COUNT);
void FreeCertChain(struct HksCertChain **certChain, const uint32_t pos);
bool FormattedCertChain(const HksCertChain *certChain, ByteBuffer &buffer);
bool GetCertChainFormBuffer(const ByteBuffer &certChainBuffer,
    ByteBuffer &signCert, ByteBuffer &issuer, std::vector<ByteBuffer> &chain);
int32_t VerifyAttestCertChain(const HksCertChain *certChain, const ByteBuffer &challenge);
bool GetSigningCertFromCerChain(const HksCertChain *certChain, ByteBuffer cert);
std::unique_ptr<ByteBuffer> GetRandomChallenge();
bool CheckChallengeSize(uint32_t size);
}
}
}

#endif