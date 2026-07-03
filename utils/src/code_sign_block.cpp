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
constexpr uint32_t ENTERPRISE_CODE_RE_SIGN_BLOB = 0x20000005;

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
        LOG_ERROR("ExtensionHeader size exceeds block boundary. size: %{public}zu bytes", sizeof(ExtensionHeader));
        return CS_ERR_INVALID_EXTENSION_OFFSET;
    }
    LOG_DEBUG("ExtensionHeader type:%{public}d, size:%{public}d", extensionHeader->type, extensionHeader->size);
    if (extensionHeader->size > blockAddrEnd - extensionAddr) {
        LOG_ERROR("Extension size exceeds block boundary. size: %{public}d", extensionHeader->size);
        return CS_ERR_INVALID_EXTENSION_OFFSET;
    }
    switch (extensionHeader->type) {
        case CSB_EXTENSION_TYPE_MERKLE_TREE: {
            if (extensionHeader->size < sizeof(MerkleTreeExtension)) {
                LOG_ERROR("MerkleTreeExtension size too small: %{public}u", extensionHeader->size);
                return CS_ERR_INVALID_EXTENSION_OFFSET;
            }
            auto merkleExtension = reinterpret_cast<const MerkleTreeExtension *>(extensionAddr);
            arg.tree_offset = merkleExtension->treeOffset;
            arg.root_hash_ptr = reinterpret_cast<uintptr_t>(merkleExtension->rootHash);
            arg.flags |= CSB_SIGN_INFO_MERKLE_TREE;
            break;
        }
        case CSB_EXTENSION_TYPE_PAGE_INFO: {
            if (extensionHeader->size < sizeof(PageInfoExtension)) {
                LOG_ERROR("PageInfoExtension size too small: %{public}u", extensionHeader->size);
                return CS_ERR_INVALID_PAGE_INFO_EXTENSION;
            }
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
    if (blockHeader == nullptr) {
        LOG_ERROR("Block header is null");
        return CS_ERR_BLOCK_SIZE;
    }
    auto blockAddrEnd = reinterpret_cast<uintptr_t>(blockHeader) + blockHeader->blockSize;

    ret = GetOneMapNodeFromSignMap(targetFile, signInfoAddr);
    if (ret == CS_SUCCESS_END) {
        return ret;
    }

    if (!CheckPtrBounds(reinterpret_cast<const void *>(signInfoAddr), sizeof(SignInfo))) {
        LOG_ERROR("SignInfo exceeds code sign block boundary");
        return CS_ERR_INVALID_EXTENSION_OFFSET;
    }
    auto signInfo = reinterpret_cast<const SignInfo *>(signInfoAddr);
    if (signInfo->saltSize > sizeof(signInfo->salt)) {
        LOG_ERROR("saltSize exceeds salt array size");
        return CS_ERR_SALT_SIZE;
    }
    if (signInfo->signSize > 0 && !CheckPtrBounds(reinterpret_cast<const void *>(signInfo->signature),
        signInfo->signSize)) {
        LOG_ERROR("Signature data exceeds code sign block boundary");
        return CS_ERR_INVALID_SIGNATURE;
    }
    auto verity = GetFsVerityInfo();
    if (verity == nullptr) {
        LOG_ERROR("FsVerityInfo is null");
        return CS_ERR_FSVERITY_MAGIC;
    }
    arg.version = 1;
    arg.cs_version = verity->version;
    arg.hash_algorithm = verity->hashAlgorithm;
    arg.block_size = 1 << verity->logBlockSize;
    arg.salt_ptr = reinterpret_cast<uintptr_t>(signInfo->salt);
    arg.salt_size = signInfo->saltSize;
    arg.sig_size = signInfo->signSize;
    arg.sig_ptr = reinterpret_cast<uintptr_t>(signInfo->signature);
    arg.data_size = signInfo->dataSize;
    if (flag & IS_LOCAL_HSP_PLUGIN) {
        arg.flags |= BINARY_CERT_FLAGS;
    }
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
    if (soInfo == nullptr) {
        LOG_ERROR("NativeLibSignInfo is null");
        return CS_ERR_SO_MAGIC;
    }
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

    // Check that the soInfo data region is within bounds
    if (!CheckPtrBounds(soInfo, sizeof(NativeLibSignInfo))) {
        LOG_ERROR("NativeLibSignInfo base exceeds code sign block boundary");
        return CS_ERR_SO_FILE_OFFSET;
    }
    // Check that the EntryInfo flexible array is within bounds
    if (!CheckPtrBounds(soInfo->info, static_cast<size_t>(soInfo->sectionNum) * sizeof(EntryInfo))) {
        LOG_ERROR("EntryInfo array exceeds code sign block boundary");
        return CS_ERR_SO_FILE_OFFSET;
    }

    do {
        if (entryInfo->fileNameOffset >= soInfo->length) {
            return CS_ERR_SO_FILE_OFFSET;
        }
        if (entryInfo->fileNameSize >= (soInfo->length - entryInfo->fileNameOffset)) {
            return CS_ERR_SO_FILE_SIZE;
        }
        // Check fileName data bounds
        if (!CheckPtrBounds(dataInfo + entryInfo->fileNameOffset, entryInfo->fileNameSize)) {
            LOG_ERROR("fileName data exceeds code sign block boundary");
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
        if (entryInfo->signOffset > soInfo->length - entryInfo->signSize) {
            return CS_ERR_SO_SIGN_SIZE;
        }
        // Check signature data bounds
        auto signAddr = dataInfo + entryInfo->signOffset;
        if (!CheckPtrBounds(signAddr, entryInfo->signSize)) {
            LOG_ERROR("Signature data exceeds code sign block boundary");
            return CS_ERR_SO_SIGN_SIZE;
        }
        auto info = reinterpret_cast<uintptr_t>(signAddr);
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
    if (hapInfo == nullptr) {
        LOG_ERROR("HapSignInfo is null");
        return CS_ERR_HAP_MAGIC;
    }
    std::lock_guard<std::mutex> guard(signMapMutex_);
    signMap_.emplace(path, reinterpret_cast<uintptr_t>(&hapInfo->signInfo));
    return CS_SUCCESS;
}

int32_t CodeSignBlock::ParseCodeSignBlockBaseInfo(uint32_t &blockSize)
{
    if (codeSignBlock_ == nullptr || codeSignSize_ == 0) {
        LOG_ERROR("Code sign block buffer is not set");
        return CS_ERR_BLOCK_SIZE;
    }

    int32_t ret = SetCodeSignBlockHeader(CONST_STATIC_CAST(CodeSignBlockHeader, codeSignBlock_), blockSize);
    if (ret != CS_SUCCESS) {
        return ret;
    }

    // Check SegmentHeader bounds
    if (!CheckPtrBounds(codeSignBlock_ + sizeof(CodeSignBlockHeader), sizeof(SegmentHeader))) {
        LOG_ERROR("SegmentHeader exceeds code sign block boundary");
        return CS_ERR_SEGMENT_FSVERITY_OFFSET;
    }
    auto segHeader = CONST_STATIC_CAST(SegmentHeader, codeSignBlock_ + sizeof(CodeSignBlockHeader));
    if (segHeader->type != CSB_FSVERITY_INFO_SEG) {
        return CS_ERR_SEGMENT_FSVERITY_TYPE;
    }
    if ((segHeader->offset >= blockSize) || (sizeof(FsVerityInfo) >= (blockSize - segHeader->offset))) {
        return CS_ERR_SEGMENT_FSVERITY_OFFSET;
    }
    auto fsVerityAddr = codeSignBlock_ + segHeader->offset;
    if (!CheckPtrBounds(fsVerityAddr, sizeof(FsVerityInfo))) {
        LOG_ERROR("FsVerityInfo exceeds code sign block boundary");
        return CS_ERR_SEGMENT_FSVERITY_OFFSET;
    }
    ret = SetFsVerityInfo(CONST_STATIC_CAST(FsVerityInfo, fsVerityAddr));
    if (ret != CS_SUCCESS) {
        return ret;
    }
    segHeader++;

    if (!CheckPtrBounds(reinterpret_cast<const void *>(segHeader), sizeof(SegmentHeader))) {
        LOG_ERROR("Second SegmentHeader exceeds code sign block boundary");
        return CS_ERR_SEGMENT_HAP_OFFSET;
    }
    if (segHeader->type != CSB_HAP_META_SEG) {
        return CS_ERR_SEGMENT_HAP_TYPE;
    }
    if ((segHeader->offset >= blockSize) || (sizeof(HapSignInfo) >= (blockSize - segHeader->offset))) {
        return CS_ERR_SEGMENT_HAP_OFFSET;
    }
    auto hapAddr = codeSignBlock_ + segHeader->offset;
    if (!CheckPtrBounds(hapAddr, sizeof(HapSignInfo))) {
        LOG_ERROR("HapSignInfo exceeds code sign block boundary");
        return CS_ERR_SEGMENT_HAP_OFFSET;
    }
    ret = SetHapSignInfo(CONST_STATIC_CAST(HapSignInfo, hapAddr));
    if (ret != CS_SUCCESS) {
        return ret;
    }
    segHeader++;

    if (!CheckPtrBounds(reinterpret_cast<const void *>(segHeader), sizeof(SegmentHeader))) {
        LOG_ERROR("Third SegmentHeader exceeds code sign block boundary");
        return CS_ERR_SEGMENT_SO_OFFSET;
    }
    if (segHeader->type != CSB_NATIVE_LIB_INFO_SEG) {
        return CS_ERR_SEGMENT_SO_TYPE;
    }
    if ((segHeader->offset >= blockSize) || (sizeof(NativeLibSignInfo) > (blockSize - segHeader->offset))) {
        return CS_ERR_SEGMENT_SO_OFFSET;
    }
    auto nativeAddr = codeSignBlock_ + segHeader->offset;
    if (!CheckPtrBounds(nativeAddr, sizeof(NativeLibSignInfo))) {
        LOG_ERROR("NativeLibSignInfo exceeds code sign block boundary");
        return CS_ERR_SEGMENT_SO_OFFSET;
    }
    return SetNativeLibSignInfo(CONST_STATIC_CAST(NativeLibSignInfo, nativeAddr));
}

int32_t CodeSignBlock::GetCodeSignBlockBuffer(const std::string &path, ReadBuffer &signBuffer, uint32_t &size,
    uint32_t flag)
{
    ReadBuffer blobBuffer = nullptr;
    uint32_t blobSize = 0;
    ReadBuffer signBlockBuffer = nullptr;
    uint32_t signBlockSize = 0;

    int32_t ret = Verify::ParseHapSignatureInfo(path, signatureInfo_);
    if (ret != Verify::VERIFY_SUCCESS) {
        LOG_ERROR("Verify sign block failed. errno = %{public}d ", ret);
        return CS_ERR_FILE_INVALID;
    }

    uint32_t targetBlobType = (flag & IS_ENTERPRISE_RESIGN) ? ENTERPRISE_CODE_RE_SIGN_BLOB : CSB_PROPERTY_BLOB;
    for (const auto &value : signatureInfo_.optionBlocks) {
        if (static_cast<uint32_t>(value.optionalType) != targetBlobType) {
            continue;
        }

        blobBuffer = value.optionalBlockValue.GetBufferPtr();
        blobSize = static_cast<uint32_t>(value.optionalBlockValue.GetCapacity());
        break;
    }

    if ((blobBuffer == nullptr) || (blobSize <= sizeof(PropertyBlobHeader))) {
        LOG_ERROR("Find code sign block failed. flag = %{public}u, blobType = %{public}u", flag, targetBlobType);
        return CS_CODE_SIGN_NOT_EXISTS;
    }

    size_t length = 0;
    do {
        if (length + sizeof(PropertyBlobHeader) > blobSize) {
            LOG_ERROR("PropertyBlobHeader size or blobSize is invalid.");
            return CS_ERR_BLOCK_SIZE;
        }
        auto blobHeader = CONST_STATIC_CAST(PropertyBlobHeader, blobBuffer + length);
        if (blobHeader->type == HAP_CODE_SIGN_BLOCK_ID) {
            signBlockBuffer = CONST_STATIC_CAST(char, blobHeader) + sizeof(PropertyBlobHeader);
            signBlockSize = blobHeader->size;
            if ((signBlockSize > blobSize) || ((signBlockBuffer - blobBuffer) > (blobSize - signBlockSize))) {
                return CS_ERR_BLOCK_SIZE;
            }
            break;
        }
        length += blobHeader->size + sizeof(PropertyBlobHeader);
    } while (length < blobSize);

    if ((signBlockBuffer == nullptr) || !signBlockSize) {
        LOG_ERROR("Find code sign block failed. blobType = %{public}u", HAP_CODE_SIGN_BLOCK_ID);
        return CS_CODE_SIGN_NOT_EXISTS;
    }

    signBuffer = signBlockBuffer;
    size = signBlockSize;
    return CS_SUCCESS;
}

int32_t CodeSignBlock::ParseCodeSignBlock(const std::string &realPath,
    const EntryMap &entryMap, FileType fileType, uint32_t flag)
{
    int32_t ret;
    ReadBuffer codeSignBlock = nullptr;
    uint32_t codeSignSize;

    ret = GetCodeSignBlockBuffer(realPath, codeSignBlock, codeSignSize, flag);
    if (ret != CS_SUCCESS) {
        LOG_ERROR("Get code sign block buffer failed. errno = %{public}d ", ret);
        return ret;
    }

    // Store as class variables for bounds checking across methods
    codeSignBlock_ = codeSignBlock;
    codeSignSize_ = codeSignSize;
    ret = ParseCodeSignBlockBaseInfo(codeSignSize);
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
