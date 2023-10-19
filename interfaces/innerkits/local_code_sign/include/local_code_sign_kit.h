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

#ifndef OHOS_LOCAL_CODE_SIGN_KIT_H
#define OHOS_LOCAL_CODE_SIGN_KIT_H

#include <cstdint>

#include "byte_buffer.h"
#include "errcode.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
/**
 * @brief Declares LocalCodeSignKit class
 */
class LocalCodeSignKit {
public:
    /**
     * @brief init local certificate and obtain it
     * @param cert certificate from local code sign SA
     * @return err code, see err_code.h
     */
    static int32_t InitLocalCertificate(ByteBuffer &cert);
    /**
     * @brief sign local code
     * @param filePath file path to sign
     * @param signature signature from local code sign SA
     * @return err code, see err_code.h
     */
    static int32_t SignLocalCode(const std::string &filePath, ByteBuffer &signature);
    /**
     * @brief sign local code with owner ID to the signature, so we can identify signature files using owner ID
     * @param ownerID owner ID written to the signature
     * @param filePath file path to sign
     * @param signature signature from local code sign SA
     * @return err code, see err_code.h
     */
    static int32_t SignLocalCode(const std::string &ownerID, const std::string &filePath, ByteBuffer &signature);
};
}
}
}
#endif