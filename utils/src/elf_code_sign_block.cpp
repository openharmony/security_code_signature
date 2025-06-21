/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "elf_code_sign_block.h"
#include <filesystem>
#include <fstream>
#include <securec.h>

#include "constants.h"
#include "directory_ex.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {

constexpr uint32_t PAGE_SIZE = 4096;
const std::string ElfCodeSignBlock::CODE_SIGN_SECTION = ".codesign";

ElfCodeSignBlock::ElfCodeSignBlock()
{
}

ElfCodeSignBlock::~ElfCodeSignBlock()
{
}

int32_t ElfCodeSignBlock::EnforceCodeSign(const std::string &realPath, CallbackFunc &func)
{
    int32_t ret = ParseSignBlock(realPath);
    if (ret != CS_SUCCESS) {
        return ret;
    }
    auto signInfo = signInfo_;
    struct code_sign_enable_arg arg = {0};
    arg.version = signInfo->version;
    arg.cs_version = signInfo->csVersion;
    arg.hash_algorithm = signInfo->hashAlgorithm;
    arg.block_size = 1 << signInfo->logBlockSize;
    arg.salt_ptr = reinterpret_cast<uintptr_t>(signInfo->salt);
    arg.salt_size = signInfo->saltSize;
    arg.sig_size = signInfo->signSize;
    arg.sig_ptr = reinterpret_cast<uintptr_t>(signInfo->signature);
    arg.data_size = signInfo->dataSize;
    arg.root_hash_ptr = reinterpret_cast<uintptr_t>(signInfo->rootHash);
    arg.flags |= signInfo->flags;
    return func(realPath, arg);
}

int32_t ElfCodeSignBlock::ParseSignBlock(const std::string &realPath)
{
    auto fileSize = std::filesystem::file_size(realPath);
    if (fileSize < PAGE_SIZE) {
        LOG_ERROR("file size is too small");
        return CS_CODE_SIGN_NOT_EXISTS;
    }
    ELFIO::elfio elfReader;
    if (!elfReader.load(realPath)) {
        LOG_ERROR("failed to load input ELF file");
        return CS_ERR_FILE_INVALID;
    }
    ELFIO::section *sec = elfReader.sections[CODE_SIGN_SECTION];
    if (!sec) {
        LOG_ERROR("codesign section is not found");
        return CS_CODE_SIGN_NOT_EXISTS;
    }
    ELFIO::Elf64_Off secOffElf64 = sec->get_offset();
    uint64_t secOff = static_cast<uint64_t>(secOffElf64);
    if (secOff % PAGE_SIZE != 0) {
        LOG_ERROR("codesign section offset is not aligned");
        return CS_ERR_SECTION_OFFSET;
    }
    const char *data = sec->get_data();
    uint64_t csBlockSize = sec->get_size();
    if (csBlockSize == 0 || csBlockSize % PAGE_SIZE != 0) {
        return CS_ERR_SECTION_SIZE;
    }
    signBlockBuffer_ = std::make_unique<uint8_t[]>(csBlockSize);
    if (memcpy_s(signBlockBuffer_.get(), csBlockSize, data, csBlockSize) != EOK) {
        return CS_ERR_MEMORY;
    }
    signInfo_ = reinterpret_cast<const ElfSignInfo *>(signBlockBuffer_.get());
    return CheckElfSignInfo(csBlockSize);
}

int32_t ElfCodeSignBlock::CheckElfSignInfo(const uint64_t csBlockSize)
{
    if (signInfo_->type != CSB_FS_VERITY_DESCRIPTOR_TYPE) {
        return CS_ERR_SEGMENT_FSVERITY_TYPE;
    }
    if (signInfo_->length > csBlockSize) {
        LOG_ERROR("signInfo length is larger than cs block size");
        return CS_ERR_BLOCK_SIZE;
    }
    if (signInfo_->version != 1) {
        return CS_ERR_FSVERITY_VERSION;
    }
    if (signInfo_->logBlockSize != CSB_FSVERITY_BLOCK_SIZE) {
        return CS_ERR_FSVERITY_BLOCK_SIZE;
    }
    if (signInfo_->csVersion != ELF_CS_VERSION) {
        LOG_ERROR("csVersion is not equal to ELF_CS_VERSION");
        return CS_ERR_BLOCK_VERSION;
    }
    if (signInfo_->signSize >= signInfo_->length || signInfo_->signSize == 0) {
        return CS_ERR_SO_SIGN_SIZE;
    }
    return CS_SUCCESS;
}
} // CodeSign namespace
} // Security namespace
} // OHOS namespace
