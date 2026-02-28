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

#include "code_sign_utils.h"
#include <fstream>
#include <string>
#include <asm/unistd.h>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/fsverity.h>
#include <linux/stat.h>
#include <linux/types.h>

#include "code_sign_attr_utils.h"
#include "cs_hisysevent.h"
#include "cs_hitrace.h"
#include "code_sign_helper.h"
#include "constants.h"
#include "directory_ex.h"
#include "extractor.h"
#include "file_helper.h"
#include "log.h"
#include "stat_utils.h"
#include "signer_info.h"
#include "rust_interface.h"
#include "data_size_report_adapter.h"
#include "elf_code_sign_block_v1.h"
#ifdef SUPPORT_BINARY_ENABLE
#include "elf_code_sign_block.h"
#endif
#include "fdsan.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
constexpr uint32_t DEFAULT_HASH_ALGORITHEM = FS_VERITY_HASH_ALG_SHA256;
constexpr uint32_t HASH_PAGE_SIZE = 4096;

#define NOT_SATISFIED_RETURN(CONDITION, ERROR_CODE, LOG_MESSAGE, ...) do { \
    if (!(CONDITION)) { \
        LOG_ERROR(LOG_MESSAGE, ##__VA_ARGS__); \
        return (ERROR_CODE); \
    } \
} while (0)

int32_t CodeSignUtils::EnforceCodeSignForApp(const EntryMap &entryPath,
    const std::string &signatureFile)
{
    LOG_INFO("Start to enforce");
    // no files to enable, return directly
    if (entryPath.empty()) {
        return CS_SUCCESS;
    }

    NOT_SATISFIED_RETURN(CheckFilePathValid(signatureFile, Constants::ENABLE_SIGNATURE_FILE_BASE_PATH),
        CS_ERR_FILE_PATH, "Signature file is invalid.");

    // check whether fs-verity is supported by kernel
    auto iter = entryPath.begin();
    int32_t ret = CodeSignUtils::IsSupportFsVerity(iter->second);
    if (ret != CS_SUCCESS) {
        return ret;
    }

    std::unique_ptr<AbilityBase::Extractor> extractor = std::make_unique<AbilityBase::Extractor>(signatureFile);
    std::vector<std::string> signatureFileList;
    NOT_SATISFIED_RETURN(extractor->Init(), CS_ERR_EXTRACT_FILES, "Init extractor failed.");
    // Get signature file entry name
    extractor->GetSpecifiedTypeFiles(signatureFileList, Constants::FSV_SIG_SUFFIX);

    for (const auto &pathPair: entryPath) {
        const std::string &entryName = pathPair.first;
        const std::string &targetFile = pathPair.second;
        LOG_DEBUG("Enable entry %{public}s, path = %{public}s", entryName.c_str(), targetFile.c_str());
        NOT_SATISFIED_RETURN(CheckFilePathValid(targetFile, Constants::ENABLE_APP_BASE_PATH),
            CS_ERR_FILE_PATH, "App file is invalid.");

        const std::string &signatureEntry = entryName + Constants::FSV_SIG_SUFFIX;
        NOT_SATISFIED_RETURN(std::find(signatureFileList.begin(), signatureFileList.end(), signatureEntry) !=
            signatureFileList.end(),
            CS_ERR_NO_SIGNATURE, "Fail to find signature for %{public}s", entryName.c_str());

        std::unique_ptr<uint8_t[]> signatureBuffer = nullptr;
        size_t signatureSize;
        NOT_SATISFIED_RETURN(extractor->ExtractToBufByName(signatureEntry, signatureBuffer, signatureSize),
            CS_ERR_EXTRACT_FILES, "Extract signature failed.");

        NOT_SATISFIED_RETURN(signatureSize < UINT32_MAX, CS_ERR_INVALID_SIGNATURE, "Signature is too long.");

        ret = EnforceCodeSignForFile(targetFile, signatureBuffer.get(), static_cast<const uint32_t>(signatureSize));
        if (ret != CS_SUCCESS) {
            return ret;
        }
    }
    LOG_INFO("Enforcing app complete");
    return CS_SUCCESS;
}

int32_t CodeSignUtils::IsSupportFsVerity(const std::string &path)
{
    struct statx stat = {};
    if (Statx(AT_FDCWD, path.c_str(), 0, STATX_ALL, &stat) != 0) {
        LOG_ERROR("Get attributes failed, errno = <%{public}d, %{public}s>",
            errno, strerror(errno));
        return CS_ERR_FILE_INVALID;
    }
    if (stat.stx_attributes_mask & STATX_ATTR_VERITY) {
        return CS_SUCCESS;
    }
    LOG_INFO("Fs-verity is not supported.");
    return CS_ERR_FSVREITY_NOT_SUPPORTED;
}

int32_t CodeSignUtils::EnforceCodeSignForFile(const std::string &path, const ByteBuffer &signature)
{
    return EnforceCodeSignForFile(path, signature.GetBuffer(), signature.GetSize());
}

int32_t CodeSignUtils::EnableCodeSignForFile(const std::string &path, const struct code_sign_enable_arg &arg)
{
    int32_t ret;
    int32_t error;
    int32_t fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        LOG_ERROR("Open file failed, path = %{public}s, errno = <%{public}d, %{public}s>",
            path.c_str(), errno, strerror(errno));
        return CS_ERR_FILE_OPEN;
    }
    FDSAN_MARK(fd);

    do {
        ret = CodeSignEnableMultiTask::IsFsVerityEnabled(fd);
        if (ret == CS_SUCCESS) {
            LOG_INFO("Fs-verity has been enabled.");
            break;
        } else if (ret == CS_ERR_FILE_INVALID) {
            break;
        }

        StartTrace(HITRACE_TAG_ACCESS_CONTROL, CODE_SIGN_ENABLE_START);
        if (!arg.cs_version) {
            error = ioctl(fd, FS_IOC_ENABLE_VERITY, &arg);
        } else {
            error = ioctl(fd, FS_IOC_ENABLE_CODE_SIGN, &arg);
        }
        FinishTrace(HITRACE_TAG_ACCESS_CONTROL);
        if (error < 0) {
            LOG_ERROR("Enable fs-verity failed, errno = <%{public}d, %{public}s>",
                errno, strerror(errno));
            ReportEnableError(path, errno);
            ret = CS_ERR_ENABLE;
            break;
        }
        ret = CS_SUCCESS;
    } while (0);
    FDSAN_CLOSE(fd);
    LOG_INFO("Enforcing file complete, path = %{public}s, ret = %{public}d", path.c_str(), ret);
    return ret;
}

int CodeSignUtils::ParseOwnerIdFromSignature(const ByteBuffer &sigbuffer, std::string &ownerID)
{
    return SignerInfo::ParseOwnerIdFromSignature(sigbuffer, ownerID);
}

int32_t CodeSignUtils::EnforceCodeSignForFile(const std::string &path, const uint8_t *signature,
    const uint32_t size)
{
    std::string realPath;

    if (signature == nullptr || size == 0) {
        return CS_ERR_NO_SIGNATURE;
    }
    if (!OHOS::PathToRealPath(path, realPath)) {
        return CS_ERR_FILE_PATH;
    }

    struct code_sign_enable_arg arg = {0};
    arg.version = 1; // version of fs-verity, must be 1
    arg.hash_algorithm = DEFAULT_HASH_ALGORITHEM;
    arg.block_size = HASH_PAGE_SIZE;
    arg.sig_size = size;
    arg.sig_ptr = reinterpret_cast<uintptr_t>(signature);
    return EnableCodeSignForFile(realPath, arg);
}

int32_t CodeSignUtils::EnforceCodeSignForAppWithOwnerId(const std::string &path,
    const EntryMap &entryPathMap, FileType type, const ByteBuffer &profileBuffer, uint32_t flag)
{
#ifdef SUPPORT_OH_CODE_SIGN
    if (profileBuffer.Empty()) {
        LOG_ERROR("Profile is empty.");
        return CS_ERR_PROFILE;
    }
    Verify::ProvisionInfo info;
    int ret = Verify::VerifyProfileByP7bBlock(profileBuffer.GetSize(),
        static_cast<unsigned char*>(profileBuffer.GetBuffer()), true, info);
    if (ret != Verify::VERIFY_SUCCESS) {
        LOG_ERROR("Profile verify failed. ret = %{public}d", ret);
        return CS_ERR_PROFILE;
    }
#else
    Verify::HapVerifyResult hapVerifyResult;
    int ret = Verify::ParseHapProfile(path, hapVerifyResult);
    if (ret != Verify::VERIFY_SUCCESS) {
        LOG_ERROR("ParseHapProfile ret = %{public}d", ret);
        return CS_ERR_PROFILE;
    }
    Verify::ProvisionInfo info = hapVerifyResult.GetProvisionInfo();
#endif
    std::string ownerId = info.bundleInfo.appIdentifier;
    if (info.type == Verify::ProvisionType::DEBUG) {
        ownerId = OWNERID_DEBUG_TAG;
    }
    return EnforceCodeSignForAppWithPluginId(ownerId, "", path, entryPathMap, type, flag);
}

int32_t CodeSignUtils::EnforceCodeSignForAppWithPluginId(const std::string &ownerId, const std::string &pluginId,
    const std::string &path, const EntryMap &entryPathMap, FileType type, uint32_t flag)
{
    LOG_INFO("Start to enforce codesign FileType:%{public}u, entryPathMap size:%{public}zu, path = %{public}s, "
        "flag = %{public}u", type, entryPathMap.size(), path.c_str(), flag);
    if (type == FILE_ENTRY_ADD || type == FILE_ENTRY_ONLY || type == FILE_ALL) {
        {
            std::lock_guard<std::mutex> lock(storedEntryMapLock_);
            storedEntryMap_.insert(entryPathMap.begin(), entryPathMap.end());
        }
        if (type == FILE_ENTRY_ADD) {
            LOG_DEBUG("Add entryPathMap complete");
            return CS_SUCCESS;
        }
    } else if (type >= FILE_TYPE_MAX) {
        return CS_ERR_PARAM_INVALID;
    }
    std::lock_guard<std::mutex> lock(storedEntryMapLock_);
    int ret = ProcessCodeSignBlock(ownerId, pluginId, path, type, flag);
    if (ret != CS_SUCCESS) {
        // retry once to make sure stability
        ret = ProcessCodeSignBlock(ownerId, pluginId, path, type, flag);
    }
    storedEntryMap_.clear();
    LOG_INFO("Enforcing done, ret = %{public}d", ret);
    return ret;
}

int32_t CodeSignUtils::ProcessCodeSignBlock(const std::string &ownerId, const std::string &pluginId,
    const std::string &path, FileType type, uint32_t flag)
{
    std::string realPath;
    if (!OHOS::PathToRealPath(path, realPath)) {
        return CS_ERR_FILE_PATH;
    }
    int32_t ret;
    CodeSignHelper codeSignHelper;
    ret = codeSignHelper.ParseCodeSignBlock(realPath, storedEntryMap_, type);
    if (ret != CS_SUCCESS) {
        return HandleCodeSignBlockFailure(realPath, ret);
    }
    ret = codeSignHelper.ProcessMultiTask(ownerId, pluginId, path, EnableCodeSignForFile, flag);
    return ret;
}

int32_t CodeSignUtils::HandleCodeSignBlockFailure(const std::string &realPath, int32_t ret)
{
    if ((ret == CS_CODE_SIGN_NOT_EXISTS) && InPermissiveMode()) {
        LOG_DEBUG("Code sign not exists");
        return CS_SUCCESS;
    }
    ReportParseCodeSig(realPath, ret);
    return ret;
}

int32_t CodeSignUtils::EnforceCodeSignForApp(const std::string &path, const EntryMap &entryPathMap,
    FileType type, uint32_t flag)
{
    return EnforceCodeSignForAppWithPluginId("", "", path, entryPathMap, type, flag);
}

int32_t CodeSignUtils::EnableKeyInProfile(const std::string &bundleName, const ByteBuffer &profileBuffer)
{
#ifdef SUPPORT_OH_CODE_SIGN
    Verify::ProvisionInfo info;
    int ret = Verify::VerifyProfileByP7bBlock(profileBuffer.GetSize(),
        static_cast<unsigned char*>(profileBuffer.GetBuffer()), false, info);
    if (ret != Verify::VERIFY_SUCCESS) {
        LOG_ERROR("Profile verify failed. ret = %{public}d", ret);
        return CS_ERR_PROFILE;
    }
#endif
    int result = EnableKeyInProfileByRust(bundleName.c_str(), profileBuffer.GetBuffer(), profileBuffer.GetSize());
    if (result == CS_SUCCESS) {
        ReportUserDataSize();
        return result;
    }
    LOG_ERROR("Enable key in profile failed. result = %{public}d", result);
    return CS_ERR_PROFILE;
}

int32_t CodeSignUtils::RemoveKeyInProfile(const std::string &bundleName)
{
    int ret = RemoveKeyInProfileByRust(bundleName.c_str());
    if (ret == CS_SUCCESS) {
        return ret;
    }
    LOG_ERROR("Remove key in profile failed. ret = %{public}d", ret);
    return CS_ERR_PROFILE;
}

int32_t CodeSignUtils::EnableKeyForEnterpriseResign(const ByteBuffer &certBuffer)
{
    int ret = EnableKeyForEnterpriseResignByRust(certBuffer.GetBuffer(), certBuffer.GetSize());
    if (ret != CS_SUCCESS) {
        LOG_ERROR("Enable key for enterprise resign failed. ret = %{public}d", ret);
    }
    return ret;
}

int32_t CodeSignUtils::RemoveKeyForEnterpriseResign(const ByteBuffer &certBuffer)
{
    int ret = RemoveKeyForEnterpriseResignByRust(certBuffer.GetBuffer(), certBuffer.GetSize());
    if (ret != CS_SUCCESS) {
        LOG_ERROR("Remove key for enterprise resign failed. ret = %{public}d", ret);
    }
    return ret;
}

#ifdef SUPPORT_BINARY_ENABLE
int32_t CodeSignUtils::EnableKey(const CertPathInfo &info)
{
    return static_cast<int32_t>(AddCertPath(info));
}

int32_t CodeSignUtils::RemoveKey(const CertPathInfo &info)
{
    return static_cast<int32_t>(RemoveCertPath(info));
}
#endif

int32_t CodeSignUtils::EnforceCodeSignForFile(const std::string &path)
{
    LOG_DEBUG("Start to enforce elf file, path = %{public}s", path.c_str());
    std::string realPath;
    if (!OHOS::PathToRealPath(path, realPath)) {
        return CS_ERR_FILE_PATH;
    }
    ElfCodeSignBlockV1 elfCodeSignBlockV1;
    int32_t ret = elfCodeSignBlockV1.EnforceCodeSign(realPath, EnableCodeSignForFile);
    if (ret != CS_ERR_BLOCK_MAGIC) {
        LOG_INFO("Enforcing elf file complete. ret = %{public}d", ret);
        return ret;
    }
    ret = CS_CODE_SIGN_NOT_EXISTS;
#ifdef SUPPORT_BINARY_ENABLE
    ElfCodeSignBlock elfCodeSignBlock;
    ret = elfCodeSignBlock.EnforceCodeSign(realPath, EnableCodeSignForFile);
#endif
    LOG_INFO("Enforcing elf file complete. ret = %{public}d", ret);
    return ret;
}

bool CodeSignUtils::InPermissiveMode()
{
#ifdef SUPPORT_PERMISSIVE_MODE
    // defaults to on if file does not exsit
    std::ifstream file(Constants::XPM_DEBUG_FS_MODE_PATH);
    if (!file.is_open()) {
        return false;
    }

    std::string content;
    file >> content;
    file.close();

    if (content == Constants::PERMISSIVE_CODE_SIGN_MODE) {
        LOG_DEBUG("Permissive mode is on.");
        return true;
    }
    return false;
#else
    return false;
#endif
}

bool CodeSignUtils::IsSupportOHCodeSign()
{
#ifdef SUPPORT_OH_CODE_SIGN
    return true;
#else
    return false;
#endif
}
}
}
}
