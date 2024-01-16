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

#ifndef CODE_SIGN_HELPER_H
#define CODE_SIGN_HELPER_H

#include "code_sign_block.h"
#include "code_sign_enable_multi_task.h"

namespace OHOS {
namespace Security {
namespace CodeSign {

class CodeSignHelper {
public:
    /**
     * @brief parse code sign block info
     * @param realPath hap real path on disk
     * @param entryMap map from entryname in hap to real path on disk
     * @param FileType signature file type
     * @return err code, see err_code.h
     */
    int32_t ParseCodeSignBlock(const std::string &realPath, const EntryMap &entryMap, FileType fileType);
    /**
     * @brief multithreading code signing enable task
     * @param ownerId string to abtain owner ID from the signature file
     * @param path hap real path on disk
     * @param CallbackFunc enforce code sign callback function address
     * @return err code, see err_code.h
     */
    int32_t ProcessMultiTask(const std::string &ownerId, const std::string &path, CallbackFunc &func);
private:
    int32_t ProcessOneFile();
    int32_t ExecuteMultiTask(int32_t ret, const std::string &ownerId, const std::string &path, CallbackFunc &func);
    void ShowCodeSignInfo(const std::string &path, const struct code_sign_enable_arg &arg);
private:
    CodeSignBlock codeSignBlock_;
    CodeSignEnableMultiTask multiTask_;
};
}
}
}

#endif