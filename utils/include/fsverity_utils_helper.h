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

#ifndef CODE_SIGN_FSVERITY_UTILS_HELPER_H
#define CODE_SIGN_FSVERITY_UTILS_HELPER_H

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <libfsverity.h>
#include <sys/stat.h>
#include <unistd.h>

#include "errcode.h"
#include "byte_buffer.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
class FsverityUtilsHelper {
public:
    static FsverityUtilsHelper &GetInstance();
    bool GenerateFormattedDigest(const char *path, ByteBuffer &ret);
    static void ErrorMsgLogCallback(const char *msg);

private:
    FsverityUtilsHelper();
    ~FsverityUtilsHelper();

    FsverityUtilsHelper(const FsverityUtilsHelper &source) = delete;
    FsverityUtilsHelper &operator = (const FsverityUtilsHelper &source) = delete;

    void Init();
    bool ComputeDigest(const char *path, struct libfsverity_digest **digest);
    bool FormatDigest(libfsverity_digest *digest, uint8_t *buffer);

    class FileReader {
    public:
        bool Open(const char *path)
        {
            if (fd_ > 0) {
                LOG_ERROR("File is already opened.");
                return false;
            }
            fd_ = open(path, O_RDONLY);
            if (fd_ <= 0) {
                LOG_ERROR("Open file failed, path = %{public}s, errno = <%{public}d, %{public}s>",
                    path, errno, strerror(errno));
                return false;
            }
            return true;
        }

        bool GetFileSize(uint64_t *size)
        {
            struct stat st;
            if (fstat(fd_, &st) != 0) {
                LOG_ERROR("Stat file failed, errno = <%{public}d, %{public}s>",
                    errno, strerror(errno));
                return false;
            }
            *size = st.st_size;
            return true;
        }

        ~FileReader()
        {
            if (fd_ > 0) {
                close(fd_);
                fd_ = -1;
            }
        }

        static int ReadFileCallback(void *f, void *buf, size_t count)
        {
            FileReader *reader = static_cast<FileReader *>(f);
            return reader->ReadBytes(static_cast<uint8_t *>(buf), count);
        }

    private:
        int ReadBytes(uint8_t *buf, size_t count)
        {
            if (fd_ <= 0) {
                return CS_ERR_FILE_READ;
            }
            while (count) {
                ssize_t bytesRead = read(fd_, buf, count);
                if (bytesRead <= 0) {
                    return CS_ERR_FILE_READ;
                }
                buf += bytesRead;
                count -= static_cast<size_t>(bytesRead);
            }
            return CS_SUCCESS;
        }

        int fd_ = -1;
    };
};
}
}
}
#endif