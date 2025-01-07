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
#include "code_sign_block.h"
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include "cs_hisysevent.h"
#include "cs_hitrace.h"
#include "extractor.h"
#include "directory_ex.h"
#include "constants.h"
#include "file_helper.h"
#include "log.h"
#include "stat_utils.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
constexpr uint32_t HAP_CODE_SIGN_BLOCK_ID = 0x30000001;
constexpr uint32_t CSB_PROPERTY_BLOB = 0x20000003;

CodeSignBlock::CodeSignBlock()
{
    signatureInfo_.hapSigningBlockOffset = 0;
    signatureInfo_.hapCentralDirOffset = 0;
    signatureInfo_.hapEocdOffset = 0;
    signatureInfo_.version = 0;
}

CodeSignBlock::~CodeSignBlock() { }

int32_t CodeSignBlock::ProcessExtension(uintptr_t &extensionAddr,
    const uintptr_t blockAddrEnd, struct code_sign_enable_arg &arg)
{
    if (extensionAddr >= blockAddrEnd) {
        LOG_ERROR("Extension address is beyond the end of the block");
        return CS_ERR_INVALID_EXTENSION_OFFSET;
    }
    auto extensionHeader = reinterpret_cast<const ExtensionHeader *>(extensionAddr);
    extensionAddr = extensionAddr + sizeof(ExtensionHeader);
    if (extensionAddr > blockAddrEnd) {
        LOG_ERROR("Extension header size exceeds block boundary. ExtensionHeader size: %{public}zu bytes",
            sizeof(ExtensionHeader));
        return CS_ERR_INVALID_EXTENSION_OFFSET;
    }
    LOG_DEBUG("extensionHeader->type:%{public}d, extensionHeader->size:%{public}d", extensionHeader->type,
        extensionHeader->size);
    switch (extensionHeader->type) {
        case CSB_EXTENSION_TYPE_MERKLE_TREE: {
            auto merkleExtension = reinterpret_cast<const MerkleTreeExtension *>(extensionAddr);
            arg.tree_offset = merkleExtension->treeOffset;
            arg.root_hash_ptr = reinterpret_cast<uintptr_t>(merkleExtension->rootHash);
            arg.flags |= CSB_SIGN_INFO_MERKLE_TREE;
            break;
        }
        case CSB_EXTENSION_TYPE_PAGE_INFO: {
            auto pageInfoExtension = reinterpret_cast<const PageInfoExtension *>(extensionAddr);
            arg.sig_size = pageInfoExtension->sign_size;
            if (arg.sig_size > extensionHeader->size - sizeof(PageInfoExtension)) {
                return CS_ERR_EXTENSION_SIGN_SIZE;
            }
            if (pageInfoExtension->unitSize > CSB_SIGN_INFO_MAX_PAGEINFO_UNITSIZE) {
                return CS_ERR_INVALID_PAGE_INFO_EXTENSION;
            }
            arg.sig_ptr = reinterpret_cast<uintptr_t>(pageInfoExtension->signature);
            arg.pgtypeinfo_size = pageInfoExtension->mapSize;
            arg.pgtypeinfo_off = pageInfoExtension->mapOffset;
            arg.cs_version = CSB_EXTENSION_TYPE_PAGE_INFO_VERSION;
            arg.flags |= pageInfoExtension->unitSize << 1;
            LOG_DEBUG("arg.sig_size:%{public}u, arg.pgtypeinfo_size:%{public}u, "
                "arg.pgtypeinfo_off:%{public}llu, unitSize:%{public}u,arg.flags:%{public}u", arg.sig_size,
                arg.pgtypeinfo_size, arg.pgtypeinfo_off, pageInfoExtension->unitSize, arg.flags);
            break;
        }
        default:
            break;
    }
    extensionAddr += extensionHeader->size;
    return CS_SUCCESS;
}

int32_t CodeSignBlock::GetOneFileAndCodeSignInfo(std::string &targetFile,
    struct code_sign_enable_arg &arg, uint32_t flag)
{
    int32_t ret;
    uintptr_t signInfoAddr;
    auto blockHeader = GetCodeSignBlockHeader();
    auto blockAddrEnd = reinterpret_cast<uintptr_t>(blockHeader) + blockHeader->blockSize;

    ret = GetOneMapNodeFromSignMap(targetFile, signInfoAddr);
    if (ret == CS_SUCCESS_END) {
        return ret;
    }

    auto signInfo = reinterpret_cast<const SignInfo *>(signInfoAddr);
    auto verity = GetFsVerityInfo();
    arg.version = 1;
    arg.cs_version = verity->version;
    arg.hash_algorithm = verity->hashAlgorithm;
    arg.block_size = 1 << verity->logBlockSize;
    arg.salt_ptr = reinterpret_cast<uintptr_t>(signInfo->salt);
    arg.salt_size = signInfo->saltSize;
    arg.sig_size = signInfo->signSize;
    arg.sig_ptr = reinterpret_cast<uintptr_t>(signInfo->signature);
    arg.data_size = signInfo->dataSize;
    if (!signInfo->flags) {
        return CS_SUCCESS;
    }

    uint32_t extensionCount = 0;
    uint32_t extensionNum = signInfo->extensionNum;
    if ((flag & IS_UNCOMPRESSED_NATIVE_LIBS) == 0) {
        extensionNum = std::min(signInfo->extensionNum, 1u);
    }
    LOG_DEBUG("flag = %{public}u, extensionNum = %{public}u, signInfo->extensionNum = %{public}u",
        flag, extensionNum, signInfo->extensionNum);
    auto extensionAddr = reinterpret_cast<uintptr_t>(signInfo) + signInfo->extensionOffset;
    while (extensionCount < extensionNum) {
        ret = ProcessExtension(extensionAddr, blockAddrEnd, arg);
        if (ret != CS_SUCCESS) {
            return ret;
        }
        extensionCount++;
    }
    return CS_SUCCESS;
}

int32_t CodeSignBlock::ParseNativeLibSignInfo(const EntryMap &entryMap)
{
    auto soInfo = GetNativeLibSignInfo();
    LOG_DEBUG("So info sectionNum:%{public}d, entryMap size:%{public}u",
        soInfo->sectionNum, static_cast<uint32_t>(entryMap.size()));
    if ((soInfo->sectionNum == 0) && entryMap.empty()) {
        return CS_SUCCESS;
    } else if (!entryMap.empty() && (soInfo->sectionNum == 0)) {
        return CS_ERR_NO_SIGNATURE;
    }

    std::lock_guard<std::mutex> guard(signMapMutex_);
    size_t signMapPreSize = signMap_.size();
    auto entryInfo = soInfo->info;
    auto entryInfoEnd = soInfo->info + soInfo->sectionNum;
    auto dataInfo = CONST_STATIC_CAST(char, soInfo);
    do {
        if (entryInfo->fileNameOffset >= soInfo->length) {
            return CS_ERR_SO_FILE_OFFSET;
        }
        if (entryInfo->fileNameSize >= (soInfo->length - entryInfo->fileNameOffset)) {
            return CS_ERR_SO_FILE_SIZE;
        }
        const std::string fileName(dataInfo + entryInfo->fileNameOffset, entryInfo->fileNameSize);
        auto pathPair = entryMap.find(fileName);
        if (pathPair == entryMap.end()) {
            entryInfo++;
            continue;
        }

        if (entryInfo->signOffset >= soInfo->length) {
            return CS_ERR_SO_SIGN_OFFSET;
        }
        if (entryInfo->signSize >= soInfo->length) {
            return CS_ERR_SO_SIGN_SIZE;
        }
        auto info = reinterpret_cast<uintptr_t>(dataInfo + entryInfo->signOffset);
        const std::string &targetFile = pathPair->second;
        signMap_.emplace(targetFile, info);
        entryInfo++;
    } while (entryInfo < entryInfoEnd);

    if (entryMap.size() != signMap_.size() - signMapPreSize) {
        LOG_ERROR("Libs signature not found: signMap_ size:%{public}u, signMapPreSize:%{public}u",
            static_cast<uint32_t>(signMap_.size()), static_cast<uint32_t>(signMapPreSize));
        return CS_ERR_NO_SIGNATURE;
    }

    return CS_SUCCESS;
}

int32_t CodeSignBlock::ParseHapSignInfo(const std::string &path)
{
    auto hapInfo = GetHapSignInfo();
    std::lock_guard<std::mutex> guard(signMapMutex_);
    signMap_.emplace(path, reinterpret_cast<uintptr_t>(&hapInfo->signInfo));
    return CS_SUCCESS;
}

int32_t CodeSignBlock::ParseCodeSignBlockBaseInfo(ReadBuffer codeSignBlock, uint32_t &blockSize)
{
    int32_t ret = SetCodeSignBlockHeader(CONST_STATIC_CAST(CodeSignBlockHeader, codeSignBlock), blockSize);
    if (ret != CS_SUCCESS) {
        return ret;
    }

    auto segHeader = CONST_STATIC_CAST(SegmentHeader, codeSignBlock + sizeof(CodeSignBlockHeader));
    if (segHeader->type != CSB_FSVERITY_INFO_SEG) {
        return CS_ERR_SEGMENT_FSVERITY_TYPE;
    }
    if (segHeader->offset >= blockSize) {
        return CS_ERR_SEGMENT_FSVERITY_OFFSET;
    }
    ret = SetFsVerityInfo(CONST_STATIC_CAST(FsVerityInfo, codeSignBlock + segHeader->offset));
    if (ret != CS_SUCCESS) {
        return ret;
    }
    segHeader++;

    if (segHeader->type != CSB_HAP_META_SEG) {
        return CS_ERR_SEGMENT_HAP_TYPE;
    }
    if (segHeader->offset >= blockSize) {
        return CS_ERR_SEGMENT_HAP_OFFSET;
    }
    ret = SetHapSignInfo(CONST_STATIC_CAST(HapSignInfo, codeSignBlock + segHeader->offset));
    if (ret != CS_SUCCESS) {
        return ret;
    }
    segHeader++;

    if (segHeader->type != CSB_NATIVE_LIB_INFO_SEG) {
        return CS_ERR_SEGMENT_SO_TYPE;
    }
    if (segHeader->offset >= blockSize) {
        return CS_ERR_SEGMENT_SO_OFFSET;
    }
    return SetNativeLibSignInfo(CONST_STATIC_CAST(NativeLibSignInfo, codeSignBlock + segHeader->offset));
}

int32_t CodeSignBlock::GetCodeSignBlockBuffer(const std::string &path, ReadBuffer &signBuffer, uint32_t &size)
{
    ReadBuffer blobBuffer = nullptr;
    uint32_t blobSize = 0;
    ReadBuffer signBlockBuffer = nullptr;
    uint32_t signBlockSize = 0;

    int32_t ret = Verify::ParseHapSignatureInfo(path, signatureInfo_);
    if (ret != Verify::VERIFY_SUCCESS) {
        LOG_ERROR("find code sign block buffer failed. errno = %{public}d ", ret);
        return CS_ERR_FILE_INVALID;
    }

    for (const auto &value : signatureInfo_.optionBlocks) {
        if (value.optionalType != CSB_PROPERTY_BLOB) {
            continue;
        }

        blobBuffer = value.optionalBlockValue.GetBufferPtr();
        blobSize = static_cast<uint32_t>(value.optionalBlockValue.GetCapacity());
        break;
    }

    if ((blobBuffer == nullptr) || (blobSize <= sizeof(PropertyBlobHeader))) {
        return CS_CODE_SIGN_NOT_EXISTS;
    }

    size_t length = 0;
    do {
        auto blobHeader = CONST_STATIC_CAST(PropertyBlobHeader, blobBuffer + length);
        if (blobHeader->type == HAP_CODE_SIGN_BLOCK_ID) {
            signBlockBuffer = CONST_STATIC_CAST(char, blobHeader) + sizeof(PropertyBlobHeader);
            signBlockSize = blobHeader->size;
            break;
        }
        length += blobHeader->size + sizeof(PropertyBlobHeader);
    } while (length < blobSize);

    if ((signBlockBuffer == nullptr) || !signBlockSize) {
        return CS_CODE_SIGN_NOT_EXISTS;
    }

    signBuffer = signBlockBuffer;
    size = signBlockSize;
    return CS_SUCCESS;
}

int32_t CodeSignBlock::ParseCodeSignBlock(const std::string &realPath,
    const EntryMap &entryMap, FileType fileType)
{
    int32_t ret;
    ReadBuffer codeSignBlock = nullptr;
    uint32_t codeSignSize;

    ret = GetCodeSignBlockBuffer(realPath, codeSignBlock, codeSignSize);
    if (ret != CS_SUCCESS) {
        LOG_ERROR("Get code sign block buffer failed. errno = %{public}d ", ret);
        return ret;
    }

    ret = ParseCodeSignBlockBaseInfo(codeSignBlock, codeSignSize);
    if (ret != CS_SUCCESS) {
        return ret;
    }
    if ((fileType == FILE_SELF) || (fileType == FILE_ALL)) {
        ret = ParseHapSignInfo(realPath);
        if (ret != CS_SUCCESS) {
            return ret;
        }
    }
    if ((fileType == FILE_ENTRY_ONLY) || (fileType == FILE_ALL)) {
        ret = ParseNativeLibSignInfo(entryMap);
        if (ret != CS_SUCCESS) {
            return ret;
        }
    }
    return CS_SUCCESS;
}
} // CodeSign namespace
} // Security namespace
} // OHOS namespace
