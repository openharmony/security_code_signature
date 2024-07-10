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

#ifndef CODE_SIGN_BLOCK_H
#define CODE_SIGN_BLOCK_H

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <linux/fsverity.h>
#include "code_sign_utils.h"
#include "interfaces/hap_verify.h"
#include "interfaces/hap_verify_result.h"

namespace OHOS {
namespace Security {
namespace CodeSign {

#pragma pack(push, 1)
typedef struct {
    uint32_t type;
    uint32_t size;
    uint32_t offset;
} PropertyBlobHeader;

typedef struct {
    uint64_t magic;
    uint32_t version;
    uint32_t blockSize;
    uint32_t segmentNum;
    uint32_t flags;
    uint8_t  reserved[8];
} CodeSignBlockHeader;

typedef struct {
    uint32_t type;
    uint32_t offset;
    uint32_t size;
} SegmentHeader;

typedef struct {
    uint32_t magic;
    uint8_t  version;
    uint8_t  hashAlgorithm;
    uint8_t  logBlockSize;
    uint8_t  reserved[1];
} FsVerityInfo;

typedef struct {
    uint32_t type;
    uint32_t size;
} ExtensionHeader;

typedef struct {
    uint64_t treeSize;
    uint64_t treeOffset;
    uint8_t  rootHash[64];
} MerkleTreeExtension;

typedef struct {
    uint64_t mapOffset;
    uint64_t mapSize;
    uint8_t  unitSize;
    uint8_t  reversed[3];
    uint32_t sign_size;
    uint8_t  signature[0];
} PageInfoExtension;

typedef struct {
    uint32_t saltSize;
    uint32_t signSize;
    uint32_t flags;
    uint64_t dataSize;
    uint8_t  salt[32];
    uint32_t extensionNum;
    uint32_t extensionOffset;
    uint8_t  signature[0];
} SignInfo;

typedef struct {
    uint32_t magic;
    SignInfo signInfo;
} HapSignInfo;

typedef struct {
    uint32_t fileNameOffset;
    uint32_t fileNameSize;
    uint32_t signOffset;
    uint32_t signSize;
} EntryInfo;

typedef struct {
    uint32_t  magic;
    uint32_t  length;
    uint32_t  sectionNum;
    EntryInfo info[0];
} NativeLibSignInfo;
#pragma pack(pop)

using SignMap = std::unordered_map<std::string, uintptr_t>;
using ReadBuffer = const char *;
#define CONST_STATIC_CAST(type, ptr) static_cast<const type *>(static_cast<const void *>(ptr))

class CodeSignBlock {
public:
    CodeSignBlock();
    ~CodeSignBlock();

    static constexpr uint64_t CSB_BLOCK_HEADER_MAGIC = 0xE046C8C65389FCCD;
    static constexpr uint32_t CSB_FSVERITY_MAGIC = 0x1E3831AB;
    static constexpr uint32_t CSB_HAP_HEADER_MAGIC = 0xC1B5CC66;
    static constexpr uint32_t CSB_SO_HEADER_MAGIC = 0xED2E720;
    static constexpr uint32_t CSB_SIGN_INFO_MERKLE_TREE = 0x1;
    static constexpr uint32_t CSB_SIGN_INFO_RUNTIME_PAGE = 0x2;
    static constexpr uint32_t CSB_EXTENSION_TYPE_MERKLE_TREE = 1;
    static constexpr uint32_t CSB_EXTENSION_TYPE_PAGE_INFO = 2;
    static constexpr uint32_t CSB_SIGN_INFO_MAX_PAGEINFO_UNITSIZE = 7;
    static constexpr uint32_t CSB_EXTENSION_TYPE_PAGE_INFO_VERSION = 2;

    int32_t ParseCodeSignBlock(const std::string &realPath, const EntryMap &entryMap, FileType fileType);
    int32_t GetOneFileAndCodeSignInfo(std::string &targetFile, struct code_sign_enable_arg &arg);
    int32_t ProcessExtension(uintptr_t &extensionAddr, const uintptr_t blockAddrEnd, struct code_sign_enable_arg &arg);

private:
    int32_t ParseNativeLibSignInfo(const EntryMap &entryMap);
    int32_t ParseHapSignInfo(const std::string &path);
    int32_t ParseCodeSignBlockBaseInfo(ReadBuffer codeSignBlock, uint32_t &blockSize);
    int32_t GetCodeSignBlockBuffer(const std::string &path, ReadBuffer &signBuffer, uint32_t &size);

    static constexpr uint32_t CSB_HEADER_VERSION = 1;
    static constexpr uint32_t CSB_HEADER_FLAG_MERKLE_TREE = 0x1;
    static constexpr uint32_t CSB_HEADER_FLAG_SO = 0x2;
    static constexpr uint32_t CSB_FSVERITY_INFO_SEG = 0x1;
    static constexpr uint32_t CSB_HAP_META_SEG = 0x2;
    static constexpr uint32_t CSB_NATIVE_LIB_INFO_SEG = 0x3;
    static constexpr uint32_t CSB_SEGMENT_MAX = 3;
    static constexpr uint32_t CSB_FSVERITY_BLOCK_SIZE = 12;

    const CodeSignBlockHeader *GetCodeSignBlockHeader(void)
    {
        return blockHeader_;
    }
    const FsVerityInfo *GetFsVerityInfo(void)
    {
        return fsVerityInfo_;
    }
    const HapSignInfo *GetHapSignInfo(void)
    {
        return hapSignInfo_;
    }
    const NativeLibSignInfo *GetNativeLibSignInfo(void)
    {
        return nativeLibSignInfo_;
    }

    int32_t SetCodeSignBlockHeader(const CodeSignBlockHeader *header, uint32_t &blockSize)
    {
        if (header->magic != CSB_BLOCK_HEADER_MAGIC) {
            return CS_ERR_BLOCK_MAGIC;
        }
        if (header->version != CSB_HEADER_VERSION) {
            return CS_ERR_BLOCK_VERSION;
        }
        if ((header->segmentNum > CSB_SEGMENT_MAX) || (header->segmentNum == 0)) {
            return CS_ERR_BLOCK_SEG_NUM;
        }
        if (header->blockSize != blockSize) {
            return CS_ERR_BLOCK_SIZE;
        }
        blockHeader_ = header;
        return CS_SUCCESS;
    }

    int32_t SetFsVerityInfo(const FsVerityInfo *info)
    {
        if (info->magic != CSB_FSVERITY_MAGIC) {
            return CS_ERR_FSVERITY_MAGIC;
        }
        if (info->version != 1) {
            return CS_ERR_FSVERITY_VERSION;
        }
        if (info->logBlockSize != CSB_FSVERITY_BLOCK_SIZE) {
            return CS_ERR_FSVERITY_BLOCK_SIZE;
        }
        fsVerityInfo_ = info;
        return CS_SUCCESS;
    }

    int32_t SetHapSignInfo(const HapSignInfo *info)
    {
        if (info->magic != CSB_HAP_HEADER_MAGIC) {
            return CS_ERR_HAP_MAGIC;
        }
        const auto signInfo = &info->signInfo;
        if (blockHeader_->flags & CSB_HEADER_FLAG_MERKLE_TREE) {
            if (signInfo->extensionOffset >= blockHeader_->blockSize) {
                return CS_ERR_HAP_EXTERNSION;
            }
        }
        hapSignInfo_ = info;
        return CS_SUCCESS;
    }

    int32_t SetNativeLibSignInfo(const NativeLibSignInfo *info)
    {
        if (info->magic != CSB_SO_HEADER_MAGIC) {
            return CS_ERR_SO_MAGIC;
        }
        if ((blockHeader_->flags & CSB_HEADER_FLAG_SO) && !info->sectionNum) {
            return CS_ERR_SO_SECTION_NUM;
        }
        nativeLibSignInfo_ = info;
        return CS_SUCCESS;
    }

    int32_t GetOneMapNodeFromSignMap(std::string &fileName, uintptr_t &signInfo)
    {
        std::lock_guard<std::mutex> guard(signMapMutex_);
        if (signMap_.empty()) {
            return CS_SUCCESS_END;
        }

        auto info = signMap_.begin();
        fileName = info->first;
        signInfo = info->second;
        signMap_.erase(fileName);
        return CS_SUCCESS;
    }

    Verify::SignatureInfo signatureInfo_;
    const CodeSignBlockHeader *blockHeader_ = nullptr;
    const FsVerityInfo *fsVerityInfo_ = nullptr;
    const HapSignInfo *hapSignInfo_ = nullptr;
    const NativeLibSignInfo *nativeLibSignInfo_ = nullptr;
    std::mutex signMapMutex_;
    SignMap signMap_;
};
} // CodeSign namespace
} // Security namespace
} // OHOS namespace
#endif
