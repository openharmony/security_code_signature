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
#include "fsverity_utils_helper.h"
#include <common_defs.h>
#include <fcntl.h>
#include <fsverity_uapi.h>
#include <sys/types.h>
#include <unistd.h>
#include "errcode.h"
#include "file_helper.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
static constexpr int MAX_DIGEST_SIZE = 64; // size of sha512
static constexpr int FSVERITY_HASH_PAGE_SIZE = 4096;
static const char *FSVERITY_DIGEST_MAGIC = "FSVerity";
static constexpr uint32_t FSVERITY_DIGEST_MAGIC_LENGTH = 8;

FsverityUtilsHelper &FsverityUtilsHelper::GetInstance()
{
    static FsverityUtilsHelper singleFsverityUtilsHelper;
    return singleFsverityUtilsHelper;
}

FsverityUtilsHelper::FsverityUtilsHelper()
{
    Init();
}

FsverityUtilsHelper::~FsverityUtilsHelper() {}

void FsverityUtilsHelper::Init()
{
    libfsverity_set_error_callback(ErrorMsgLogCallback);
}

void FsverityUtilsHelper::ErrorMsgLogCallback(const char *msg)
{
    LOG_ERROR(LABEL, "fsverity_utils error = %{public}s", msg);
}

bool FsverityUtilsHelper::FormatDigest(libfsverity_digest *digest, uint8_t *buffer)
{
    struct fsverity_formatted_digest *ret = reinterpret_cast<struct fsverity_formatted_digest *>(buffer);
    if (memcpy_s(ret->magic, FSVERITY_DIGEST_MAGIC_LENGTH, FSVERITY_DIGEST_MAGIC,
        FSVERITY_DIGEST_MAGIC_LENGTH) != EOK) {
        return false;
    }
    ret->digest_algorithm = cpu_to_le16(digest->digest_algorithm);
    ret->digest_size = cpu_to_le16(digest->digest_size);
    if (memcpy_s(ret->digest, MAX_DIGEST_SIZE, digest->digest, digest->digest_size) != EOK) {
        return false;
    }
    return true;
}

bool FsverityUtilsHelper::ComputeDigest(const char *path, struct libfsverity_digest **digest)
{
    struct libfsverity_merkle_tree_params tree_params = {
        .version = 1,
        .hash_algorithm = FS_VERITY_HASH_ALG_SHA256,
        .block_size = FSVERITY_HASH_PAGE_SIZE
    };

    FileReader reader;
    if (!reader.Open(path)) {
        return false;
    }
    if (!reader.GetFileSize(&tree_params.file_size)) {
        return false;
    }
    // compute digest by fsverity-utils and use callback to read data in file
    if (libfsverity_compute_digest(&reader, FileReader::ReadFileCallback, &tree_params, digest)) {
        LOG_ERROR(LABEL, "Compute digest failed.");
        return false;
    }
    return true;
}

bool FsverityUtilsHelper::GenerateFormattedDigest(const char *path, ByteBuffer &digestBuffer)
{
    LOG_INFO(LABEL, "GenerateFormattedDigest called.");
    struct libfsverity_digest *digest = nullptr;
    if (!ComputeDigest(path, &digest)) {
        return false;
    }
    uint32_t digestLen = sizeof(struct fsverity_formatted_digest) + digest->digest_size;
    if (!digestBuffer.Resize(digestLen)) {
        free(digest);
        return false;
    }
    bool ret = FormatDigest(digest, digestBuffer.GetBuffer());
    free(digest);
    return ret;
}
}
}
}