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

#include "code_sign_attr_utils.h"

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <securec.h>
#include <sys/ioctl.h>

#include "errcode.h"
#include "log.h"

#define XPM_DEV_PATH "/dev/xpm"

#define XPM_SET_REGION _IOW('x', 0x01, struct XpmConfig)
#define XPM_SET_OWNERID _IOW('x', 0x02, struct XpmConfig)

static int XpmIoctl(uint32_t cmd, struct XpmConfig *config)
{
    int fd = open(XPM_DEV_PATH, O_RDWR);
    if (fd == -1) {
        LOG_INFO("Open device file failed: %{public}s (ignore)", strerror(errno));
        return CS_SUCCESS;
    }

    int ret = ioctl(fd, cmd, config);
    if (ret == -1) {
        LOG_ERROR("Ioctl cmd %{public}x failed: %{public}s (ignore)", cmd, strerror(errno));
    } else {
        LOG_DEBUG("Ioctl cmd %{public}x success", cmd);
    }
    close(fd);

    return CS_SUCCESS;
}

int InitXpmRegion(void)
{
    struct XpmConfig config = {0};

    config.regionAddr = 0;
    config.regionLength = XPM_REGION_LEN;
    return XpmIoctl(XPM_SET_REGION, &config);
}

int SetXpmOwnerId(uint32_t idType, const char *ownerId)
{
    struct XpmConfig config = {0};

    if (idType >= PROCESS_OWNERID_MAX) {
        LOG_ERROR("Input idType is invalid: %{public}u", idType);
        return CS_ERR_PARAM_INVALID;
    }

    config.idType = idType;
    if ((ownerId != NULL) && (strlen(ownerId) != 0)) {
        if (memcpy_s(config.ownerId, sizeof(config.ownerId) - 1, ownerId, strlen(ownerId)) != EOK) {
            LOG_ERROR("Memcpy ownerId failed, ownerId: %{public}s", ownerId);
            return CS_ERR_MEMORY;
        }
    }

    LOG_DEBUG("Set type = %{public}u, ownerId = %{public}s", idType, ownerId ? ownerId : "NULL");
    return XpmIoctl(XPM_SET_OWNERID, &config);
}
