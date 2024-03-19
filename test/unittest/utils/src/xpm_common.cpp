/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "xpm_common.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <securec.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "code_sign_attr_utils.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
struct XpmRegionArea {
    uint64_t start;
    uint64_t end;
};

const std::string XPM_PROC_PREFIX_PATH = "/proc/";
const std::string XPM_PROC_SUFFIX_PATH = "/xpm_region";

constexpr unsigned long XPM_PROC_LENGTH = 50;

static int GetXpmRegion(struct XpmRegionArea &area)
{
    if (InitXpmRegion() != 0) {
        LOG_ERROR("init xpm region failed");
        return -1;
    }

    pid_t pid = getpid();
    std::string path = XPM_PROC_PREFIX_PATH + std::to_string(pid) + XPM_PROC_SUFFIX_PATH;
    int fd = open(path.c_str(), O_RDWR);
    if (fd < 0) {
        LOG_ERROR("open xpm proc file failed(%{public}s)", strerror(errno));
        return -1;
    }

    char xpmRegion[XPM_PROC_LENGTH] = {0};
    int ret = read(fd, xpmRegion, sizeof(xpmRegion));
    if (ret < 0) {
        LOG_ERROR("read xpm proc file failed(%{public}s)", strerror(errno));
        return -1;
    }

    ret = sscanf_s(xpmRegion, "%llx-%llx", &area.start, &area.end);
    if (ret < 0) {
        LOG_ERROR("sscanf xpm region string failed(%{public}s)", strerror(errno));
        return -1;
    }

    close(fd);
    return 0;
}

bool AllocXpmRegion()
{
    struct XpmRegionArea area = {0};

    if (GetXpmRegion(area)) {
        return false;
    }
    if (!area.start) {
        return false;
    }
    if (!area.end) {
        return false;
    }

    return true;
}
} // namespace CodeSign
} // namespace Security
} // namespace OHOS