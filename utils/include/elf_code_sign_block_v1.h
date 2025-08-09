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

#ifndef ELF_CODE_SIGN_BLOCK_V1_H
#define ELF_CODE_SIGN_BLOCK_V1_H

#include <cstdint>
#include <cstdlib>
#include <string>
#include <linux/fsverity.h>
#include "errcode.h"

namespace OHOS {
namespace Security {
namespace CodeSign {

#pragma pack(push, 1)
typedef struct {
    uint16_t type;
    uint16_t tag;
    uint32_t size;
    uint32_t offset;
} ElfBlockHeader;

typedef struct {
    uint32_t type;
    uint32_t length;
    uint8_t  merkleTree[0];
} ElfMerkleTreeSegment;

typedef struct {
    uint32_t type;
    uint32_t length;
    uint8_t  version;
    uint8_t  hashAlgorithm;
    uint8_t  logBlockSize;
    uint8_t  saltSize;
    uint32_t signSize;
    uint64_t dataSize;
    uint8_t  rootHash[64];
    uint8_t  salt[32];
    uint32_t flags;
    uint8_t  reserved_1[4];
    uint64_t treeOffset;
    uint8_t  reserved_2[127];
    uint8_t  csVersion;
    uint8_t  signature[0];
} ElfSignInfoSegment;

typedef struct {
    uint8_t  magic[16];
    uint8_t  version[4];
    uint32_t blockSize;
    uint32_t blockNum;
    uint8_t  reserved[4];
} ElfSignHeader;

#pragma pack(pop)

typedef int32_t CallbackFunc(const std::string &path, const struct code_sign_enable_arg &arg);

class ElfCodeSignBlockV1 {
public:
    ElfCodeSignBlockV1();
    ~ElfCodeSignBlockV1();

    int32_t EnforceCodeSign(const std::string &realPath, CallbackFunc &func);

private:
    ElfCodeSignBlockV1(const ElfCodeSignBlockV1 &) = delete;
    ElfCodeSignBlockV1 &operator=(const ElfCodeSignBlockV1 &) = delete;

    static constexpr uint8_t ELF_HEADER_MAGIC[4] = {0x7f, 0x45, 0x4c, 0x46};
    static constexpr uint8_t SIGN_HEADER_MAGIC[16] = {
        0x65, 0x6c, 0x66, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x20
    };
    static constexpr uint8_t SIGN_HEADER_VERSION[4] = {0x31, 0x30, 0x30, 0x30};
    static constexpr uint16_t CSB_HEADER_TYPE = 0x3;
    static constexpr uint32_t CSB_MERKLE_TREE_TYPE = 0x2;
    static constexpr uint32_t CSB_FS_VERITY_DESCRIPTOR_TYPE = 0x1;
    static constexpr int SIGN_BLOCK_HEADER_SIZE = 32;
    static constexpr uint32_t SIGN_BLOCK_NUM_MAX = 2;
    static constexpr uint32_t CSB_FSVERITY_BLOCK_SIZE = 12;

    int32_t ParseSignBlock(const std::string &realPath);
    int32_t ReadFile(std::ifstream &fileStream, uintmax_t fileSize);
    int32_t ParseSignData();

    std::unique_ptr<uint8_t[]> signHeaderBuffer_;
    std::unique_ptr<uint8_t[]> signBlockBuffer_;
    const ElfSignHeader *signHeader_ = nullptr;
    const ElfSignInfoSegment *signInfoSeg_ = nullptr;
};
} // CodeSign namespace
} // Security namespace
} // OHOS namespace
#endif
