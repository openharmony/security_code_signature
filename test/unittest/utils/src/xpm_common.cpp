/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <sys/mman.h>
#include <sys/stat.h>
#include "log.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
struct XpmRegionInfo {
    uint64_t base;
    uint64_t length;
};

struct XpmRegionArea {
    uint64_t start;
    uint64_t end;
};

const std::string XPM_DEV_PATH = "/dev/xpm";
const std::string XPM_PROC_PREFIX_PATH = "/proc/";
const std::string XPM_PROC_SUFFIX_PATH = "/xpm_region";

constexpr unsigned long XPM_PROC_LENGTH = 50;
constexpr unsigned long XPM_REGION_LEN = 0x8000000;
constexpr unsigned long SET_XPM_REGION = _IOW('x', 0x01, struct XpmRegionInfo);

static int SetXpmRegion(void)
{
    struct XpmRegionInfo info = { 0, XPM_REGION_LEN };

    int fd = open(XPM_DEV_PATH.c_str(), O_RDWR);
    if (fd < 0) {
        LOG_ERROR(LABEL, "open xpm dev file failed(%{public}s)", strerror(errno));
        return -1;
    }

    int ret = ioctl(fd, SET_XPM_REGION, &info);
    if (ret < 0) {
        LOG_ERROR(LABEL, "xpm set region failed(%{public}s)", strerror(errno));
        return -1;
    }

    close(fd);
    return 0;
}

static int GetXpmRegion(struct XpmRegionArea *area)
{
    if (area == nullptr) {
        LOG_ERROR(LABEL, "input area is NULL");
        return -1;
    }

    pid_t pid = getpid();
    std::string path = XPM_PROC_PREFIX_PATH + std::to_string(pid) + XPM_PROC_SUFFIX_PATH;
    int fd = open(path.c_str(), O_RDWR);
    if (fd < 0) {
        LOG_ERROR(LABEL, "open xpm proc file failed(%{public}s)", strerror(errno));
        return -1;
    }

    char xpm_region[XPM_PROC_LENGTH] = {0};
    int ret = read(fd, xpm_region, sizeof(xpm_region));
    if (ret < 0) {
        LOG_ERROR(LABEL, "read xpm proc file failed(%{public}s)", strerror(errno));
        return -1;
    }

    ret = sscanf_s(xpm_region, "%llx-%llx", &area->start, &area->end);
    if (ret < 0) {
        LOG_ERROR(LABEL, "sscanf xpm region string failed(%{public}s)", strerror(errno));
        return -1;
    }

    close(fd);
    return 0;
}

static int InitXpmRegion(struct XpmRegionArea *area)
{
    if (area == nullptr) {
        LOG_ERROR(LABEL, "input area is NULL");
        return -1;
    }

    int ret = SetXpmRegion();
    if (ret != 0) {
        LOG_ERROR(LABEL, "set xpm region failed");
        return ret;
    }

    ret = GetXpmRegion(area);
    if (ret != 0) {
        LOG_ERROR(LABEL, "get xpm region failed");
        return ret;
    }

    return 0;
}

bool AllocXpmRegion()
{
    struct XpmRegionArea area = {0};

    if (InitXpmRegion(&area)) {
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