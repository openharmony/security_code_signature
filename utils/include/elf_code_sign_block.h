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

#ifndef ELF_CODE_SIGN_BLOCK_H
#define ELF_CODE_SIGN_BLOCK_H

#include <cstdint>
#include <cstdlib>
#include <string>
#include <linux/fsverity.h>
#include <elfio.hpp>
#include "errcode.h"

namespace OHOS {
namespace Security {
namespace CodeSign {

#pragma pack(push, 1)

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
    uint8_t  reserved_1[12];
    uint8_t  reserved_2[127];
    uint8_t  csVersion;
    uint8_t  signature[0];
} ElfSignInfo;

#pragma pack(pop)

typedef int32_t CallbackFunc(const std::string &path, const struct code_sign_enable_arg &arg);

class ElfCodeSignBlock {
public:
    ElfCodeSignBlock();
    ~ElfCodeSignBlock();

    int32_t EnforceCodeSign(const std::string &realPath, CallbackFunc &func);

private:

    static constexpr uint16_t ELF_CS_VERSION = 0x3;
    static constexpr uint32_t CSB_FS_VERITY_DESCRIPTOR_TYPE = 0x1;
    static constexpr uint32_t CSB_FSVERITY_BLOCK_SIZE = 12;
    static const std::string CODE_SIGN_SECTION;

    int32_t ParseSignBlock(const std::string &realPath);
    int32_t CheckElfSignInfo(const uint64_t csBlockSize);

    std::unique_ptr<uint8_t[]> signBlockBuffer_;
    const ElfSignInfo *signInfo_ = nullptr;
};
} // CodeSign namespace
} // Security namespace
} // OHOS namespace
#endif
