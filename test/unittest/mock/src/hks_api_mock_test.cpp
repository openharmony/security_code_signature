/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hks_api.h"

#include "hks_api_mock_helper.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
int g_count = 0;
int32_t HksKeyExist(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet)
{
    LOG_INFO("Mock HksKeyExist");
    if (g_count == KEYEXIST) {
        return -1;
    }
    if (g_count == ERROR) {
        return HKS_ERROR_NOT_EXIST;
    }
    return HKS_SUCCESS;
}

int32_t HksAttestKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksCertChain *certChain)
{
    LOG_INFO("Mock HksAttestKey");
    if (g_count == ATTESTKEY) {
        return -1;
    }

    bool ret = GetCertInDer(certChain->certs[0].data, certChain->certs[0].size);
    if (!ret) {
        LOG_ERROR("Failed to convert PEM to DER.\n");
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

int32_t HksGenerateKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, struct HksParamSet *paramSetOut)
{
    LOG_INFO("Mock HksGenerateKey");
    if (g_count == GENERATEKEY || g_count == ERROR) {
        return -1;
    }
    return HKS_SUCCESS;
}

int32_t HksInit(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksBlob *handle, struct HksBlob *token)
{
    LOG_INFO("Mock HksInit");
    if (g_count == INIT) {
        return -1;
    }
    return HKS_SUCCESS;
}


int32_t HksUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    LOG_INFO("Mock HksUpdate");
    if (g_count == UPDATE) {
        return -1;
    }
    return HKS_SUCCESS;
}

int32_t HksFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    LOG_INFO("Mock HksFinish");
    if (g_count == FINISH) {
        return -1;
    }
    return HKS_SUCCESS;
}
}
}
}