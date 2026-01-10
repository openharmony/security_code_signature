/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CODE_SIGN_RANDOM_HELPER_H
#define CODE_SIGN_RANDOM_HELPER_H

#include <cstdlib>
#include <fcntl.h>
#include <mutex>
#include <unistd.h>
#include "errcode.h"
#include "fdsan.h"

namespace OHOS {
namespace Security {
namespace CodeSign {

static constexpr uint32_t XORSHITF32_FIRST_STEP_LEFT = 13;
static constexpr uint32_t XORSHITF32_SECOND_STEP_RIGHT = 17;
static constexpr uint32_t XORSHITF32_THIRD_STEP_LEFT = 5;

class RandomHelper {
public:
    int32_t GetUint32(uint32_t &randomNum)
    {
        if (curStat_ == 0) {
            if (!Init()) {
                return CS_ERR_FILE_READ;
            }
        }
        randomNum = XorShift32();
        return CS_SUCCESS;
    }

private:
    bool Init()
    {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) {
            LOG_ERROR("open /dev/urandom failed. errno = <%{public}d, %{public}s>",
                errno, strerror(errno));
            return false;
        }
        FDSAN_MARK(fd);
        uint32_t ret = 0;
        ssize_t len = read(fd, &ret, sizeof(ret));
        FDSAN_CLOSE(fd);
        if (len != sizeof(ret)) {
            return false;
        }
        curStat_ = ret;
        return true;
    }
    uint32_t XorShift32()
    {
        uint32_t nextStat = curStat_;
        nextStat ^= nextStat << XORSHITF32_FIRST_STEP_LEFT;
        nextStat ^= nextStat >> XORSHITF32_SECOND_STEP_RIGHT;
        nextStat ^= nextStat << XORSHITF32_THIRD_STEP_LEFT;
        curStat_ = nextStat;
        return curStat_;
    }
    std::atomic<uint32_t> curStat_ = 0;
};
}
}
}
#endif