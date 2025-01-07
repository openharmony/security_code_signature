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

#include <linux/fsverity.h>

#include "code_sign_helper.h"
#include "constants.h"
#include "directory_ex.h"
#include "file_helper.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
int32_t CodeSignHelper::ParseCodeSignBlock(const std::string &realPath,
    const EntryMap &entryMap, FileType fileType)
{
    return codeSignBlock_.ParseCodeSignBlock(realPath, entryMap, fileType);
}

int32_t CodeSignHelper::ProcessMultiTask(const std::string &ownerId, const std::string &path,
    CallbackFunc &func, uint32_t flag)
{
    int32_t ret;
    do {
        ret = ProcessOneFile(flag);
        if (ret == CS_SUCCESS_END) {
            break;
        } else if (ret != CS_SUCCESS) {
            return ret;
        }
    } while (ret == CS_SUCCESS);
    return ExecuteMultiTask(ownerId, path, func);
}

int32_t CodeSignHelper::ProcessOneFile(uint32_t flag)
{
    std::string targetFile;
    struct code_sign_enable_arg arg = {0};
    int32_t ret = codeSignBlock_.GetOneFileAndCodeSignInfo(targetFile, arg, flag);
    if (ret != CS_SUCCESS) {
        return ret;
    }
    ShowCodeSignInfo(targetFile, arg);
    std::string realPath;
    if (!OHOS::PathToRealPath(targetFile, realPath)) {
        LOG_INFO("get real path failed, path = %{public}s", targetFile.c_str());
        return CS_ERR_FILE_PATH;
    }
    ret = CodeSignUtils::IsSupportFsVerity(targetFile);
    if (ret != CS_SUCCESS) {
        return ret;
    }
    multiTask_.AddTaskData(targetFile, arg);
    return ret;
}

int32_t CodeSignHelper::ExecuteMultiTask(const std::string &ownerId,
    const std::string &path, CallbackFunc &func)
{
    return multiTask_.ExecuteEnableCodeSignTask(ownerId, path, func);
}

void CodeSignHelper::ShowCodeSignInfo(const std::string &path, const struct code_sign_enable_arg &arg)
{
    uint8_t *salt = reinterpret_cast<uint8_t *>(arg.salt_ptr);
    uint8_t rootHash[64] = {0};
    uint8_t *rootHashPtr = rootHash;
    if (arg.flags & CodeSignBlock::CSB_SIGN_INFO_MERKLE_TREE
        && reinterpret_cast<uint8_t *>(arg.root_hash_ptr) != nullptr) {
        rootHashPtr = reinterpret_cast<uint8_t *>(arg.root_hash_ptr);
    }

    LOG_DEBUG("{ "
        "file:%{public}s version:%{public}d hash_algorithm:%{public}d block_size:%{public}d sig_size:%{public}d "
        "data_size:%{public}lld salt_size:%{public}d salt:[%{public}d, ..., %{public}d, ..., %{public}d] "
        "flags:%{public}d tree_offset:%{public}lld root_hash:[%{public}d, %{public}d, %{public}d, ..., %{public}d, "
        "..., %{public}d] pgtypeinfo_size:%{public}d pgtypeinfo_off:%{public}lld }",
        path.c_str(), arg.cs_version, arg.hash_algorithm, arg.block_size, arg.sig_size,
        arg.data_size, arg.salt_size, salt[0], salt[16], salt[31], arg.flags, arg.tree_offset, // 16, 31 data index
        rootHashPtr[0], rootHashPtr[1], rootHashPtr[2], rootHashPtr[32], rootHashPtr[63], // 2, 32, 63 data index
        arg.pgtypeinfo_size, arg.pgtypeinfo_off);
}
}
}
}