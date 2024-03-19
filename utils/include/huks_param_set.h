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

#ifndef CODE_SIGN_HUKS_PARAM_SET_H
#define CODE_SIGN_HUKS_PARAM_SET_H

#include "hks_type.h"
#include "hks_api.h"
#include "hks_param.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
class HUKSParamSet {
public:
    HUKSParamSet() : paramSet(nullptr)
    {
    }

    ~HUKSParamSet()
    {
        if (paramSet != nullptr) {
            HksFreeParamSet(&paramSet);
            paramSet = nullptr;
        }
    }

    bool Init(const struct HksParam tmpParams[], uint32_t paramCount)
    {
        int32_t ret = HksInitParamSet(&paramSet);
        if (ret != HKS_SUCCESS) {
            LOG_ERROR("HksInitParamSet failed");
            return false;
        }
        ret = HksAddParams(paramSet, tmpParams, paramCount);
        if (ret != HKS_SUCCESS) {
            LOG_ERROR("HksAddParams failed");
            return false;
        }

        ret = HksBuildParamSet(&paramSet);
        if (ret != HKS_SUCCESS) {
            LOG_ERROR("HksBuildParamSet failed");
            return false;
        }
        return true;
    }

    HksParamSet *GetParamSet() const
    {
        return paramSet;
    }
private:
    HksParamSet *paramSet = nullptr;
};
}
}
}
#endif