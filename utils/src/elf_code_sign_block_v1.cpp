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

#include "elf_code_sign_block_v1.h"
#include <filesystem>
#include <fstream>
#include <securec.h>

#include "constants.h"
#include "directory_ex.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {

ElfCodeSignBlockV1::ElfCodeSignBlockV1()
{
}

ElfCodeSignBlockV1::~ElfCodeSignBlockV1()
{
}

int32_t ElfCodeSignBlockV1::EnforceCodeSign(const std::string &realPath, CallbackFunc &func)
{
    int32_t ret = ParseSignBlock(realPath);
    if (ret != CS_SUCCESS) {
        return ret;
    }
    auto signInfo = signInfoSeg_;
    struct code_sign_enable_arg arg = {0};
    arg.version = 1;
    arg.cs_version = signInfo->csVersion;
    arg.hash_algorithm = signInfo->hashAlgorithm;
    arg.block_size = 1 << signInfo->logBlockSize;
    arg.salt_ptr = reinterpret_cast<uintptr_t>(signInfo->salt);
    arg.salt_size = signInfo->saltSize;
    arg.sig_size = signInfo->signSize;
    arg.sig_ptr = reinterpret_cast<uintptr_t>(signInfo->signature);
    arg.data_size = signInfo->dataSize;
    arg.tree_offset = signInfo->treeOffset;
    arg.root_hash_ptr = reinterpret_cast<uintptr_t>(signInfo->rootHash);
    arg.flags |= signInfo->flags;
    return func(realPath, arg);
}

int32_t ElfCodeSignBlockV1::ParseSignBlock(const std::string &realPath)
{
    LOG_INFO("Start to parse sign block v1");
    // open file
    std::ifstream fileStream(realPath, std::ios::in | std::ios::binary);
    if (!fileStream.is_open()) {
        LOG_ERROR("open file failed,code = %{public}d, path = %{public}s", fileStream.rdstate(), realPath.c_str());
        fileStream.close();
        return CS_ERR_FILE_READ;
    }
    uint32_t elfMagicLen = sizeof(ELF_HEADER_MAGIC) / sizeof(uint8_t);
    std::unique_ptr<uint8_t[]> fileHeaderMagic = std::make_unique<uint8_t[]>(elfMagicLen);
    fileStream.read(reinterpret_cast<char *>(fileHeaderMagic.get()), elfMagicLen);
    if (std::memcmp(fileHeaderMagic.get(), ELF_HEADER_MAGIC, elfMagicLen) != 0) {
        fileStream.close();
        return CS_ERR_FILE_INVALID;
    }
    auto fileSize = std::filesystem::file_size(realPath);
    if (fileSize < SIGN_BLOCK_HEADER_SIZE) {
        LOG_ERROR("file size is too small");
        fileStream.close();
        return CS_CODE_SIGN_NOT_EXISTS;
    }
    int32_t ret = ReadFile(fileStream, fileSize);
    fileStream.close();
    LOG_DEBUG("ifstream close");
    if (ret != CS_SUCCESS) {
        return ret;
    }
    ret = ParseSignData();
    return ret;
}

int32_t ElfCodeSignBlockV1::ReadFile(std::ifstream &fileStream, uintmax_t fileSize)
{
    // parse sign header
    fileStream.clear();
    fileStream.seekg(-SIGN_BLOCK_HEADER_SIZE, std::ios::end);
    signHeaderBuffer_ = std::make_unique<uint8_t[]>(SIGN_BLOCK_HEADER_SIZE);
    fileStream.read(reinterpret_cast<char *>(signHeaderBuffer_.get()), SIGN_BLOCK_HEADER_SIZE);
    long readCount = fileStream.gcount();
    if (readCount != SIGN_BLOCK_HEADER_SIZE) {
        LOG_ERROR("read sign block header failed : %{public}ld", readCount);
        return CS_ERR_FILE_READ;
    }
    auto signHeader = reinterpret_cast<const ElfSignHeader *>(signHeaderBuffer_.get());
    if (std::memcmp(signHeader->magic, SIGN_HEADER_MAGIC, sizeof(SIGN_HEADER_MAGIC) / sizeof(uint8_t)) != 0) {
        return CS_ERR_BLOCK_MAGIC;
    }
    if (std::memcmp(signHeader->version, SIGN_HEADER_VERSION, sizeof(SIGN_HEADER_VERSION) / sizeof(uint8_t)) != 0) {
        return CS_ERR_BLOCK_VERSION;
    }
    if (signHeader->blockNum < 1 || signHeader->blockNum > SIGN_BLOCK_NUM_MAX) {
        return CS_ERR_BLOCK_SEG_NUM;
    }
    if (fileSize - SIGN_BLOCK_HEADER_SIZE < signHeader->blockSize) {
        return CS_ERR_BLOCK_SIZE;
    }
    if (signHeader->blockNum * sizeof(ElfBlockHeader) > signHeader->blockSize) {
        return CS_ERR_BLOCK_SIZE;
    }
    fileStream.clear();
    int len = SIGN_BLOCK_HEADER_SIZE + signHeader->blockSize;
    fileStream.seekg(-len, std::ios::end);
    signBlockBuffer_ = std::make_unique<uint8_t[]>(signHeader->blockSize);
    fileStream.read(reinterpret_cast<char *>(signBlockBuffer_.get()), signHeader->blockSize);
    readCount = fileStream.gcount();
    if (static_cast<uint32_t>(readCount) != signHeader->blockSize) {
        LOG_ERROR("read sign block failed : %{public}ld", readCount);
        return CS_ERR_FILE_READ;
    }
    signHeader_ = signHeader;
    return CS_SUCCESS;
}

int32_t ElfCodeSignBlockV1::ParseSignData()
{
    // parse block header
    uint32_t off = 0;
    for (uint32_t i = 0; i < signHeader_->blockNum; i++) {
        uint32_t pos = i * sizeof(ElfBlockHeader);
        auto blockHeader = reinterpret_cast<const ElfBlockHeader *>(signBlockBuffer_.get() + pos);
        if (blockHeader->type == CSB_HEADER_TYPE) {
            off = blockHeader->offset;
            break;
        }
    }
    if (off == 0 || off >= signHeader_->blockSize) {
        return CS_ERR_SIGN_INFO_OFFSET;
    }
    // parse merkle tree segment
    auto merkleTreeSeg = reinterpret_cast<const ElfMerkleTreeSegment *>(signBlockBuffer_.get() + off);
    if (merkleTreeSeg->type != CSB_MERKLE_TREE_TYPE) {
        return CS_ERR_MERKLE_TREE_TYPE;
    }
    if (merkleTreeSeg->length > (signHeader_->blockSize - off)) {
        return CS_ERR_MERKLE_TREE_SIZE;
    }
    // parse sign info segment
    off += sizeof(ElfMerkleTreeSegment) + merkleTreeSeg->length;
    auto signInfo = reinterpret_cast<const ElfSignInfoSegment *>(signBlockBuffer_.get() + off);
    if (signInfo->type != CSB_FS_VERITY_DESCRIPTOR_TYPE) {
        return CS_ERR_SEGMENT_FSVERITY_TYPE;
    }
    if (signInfo->length > (signHeader_->blockSize - off)) {
        return CS_ERR_SIGN_INFO_SIZE;
    }
    if (signInfo->version != 1) {
        return CS_ERR_FSVERITY_VERSION;
    }
    if (signInfo->logBlockSize != CSB_FSVERITY_BLOCK_SIZE) {
        return CS_ERR_FSVERITY_BLOCK_SIZE;
    }
    if (signInfo->signSize >= signInfo->length) {
        return CS_ERR_SIGN_SIZE;
    }
    signInfoSeg_ = signInfo;
    return CS_SUCCESS;
}
} // CodeSign namespace
} // Security namespace
} // OHOS namespace
