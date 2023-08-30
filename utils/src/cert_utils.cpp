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

#include "cert_utils.h"

#include <cstring>
#include <string>

#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
static const uint32_t CERT_DATA_SIZE = 8192;
static const uint32_t CERT_COUNT = 4;

bool ConstructDataToCertChain(struct HksCertChain **certChain)
{
    *certChain = static_cast<struct HksCertChain *>(malloc(sizeof(struct HksCertChain)));
    if (*certChain == nullptr) {
        LOG_ERROR(LABEL, "malloc fail");
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
            LOG_ERROR(LABEL, "malloc fail");
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
}
}
}