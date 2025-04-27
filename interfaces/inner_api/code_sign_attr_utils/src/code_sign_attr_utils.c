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
#include "ownerid_utils.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <securec.h>
#include <sys/ioctl.h>

#include "errcode.h"
#include "log.h"

#define XPM_DEV_PATH "/dev/xpm"

#define XPM_SET_REGION _IOW('x', 0x01, struct XpmConfig)
#define XPM_SET_OWNERID _IOW('x', 0x02, struct XpmConfig)
#define XPM_SET_JITFORT_ENABLE _IOW('x', 0x3, unsigned long)

static int XpmIoctl(int fd, uint32_t cmd, struct XpmConfig *config)
{
    int ret = ioctl(fd, cmd, config);
    if (ret == -1) {
        LOG_ERROR("Ioctl cmd %{public}x failed: %{public}s (ignore)", cmd, strerror(errno));
    } else {
        LOG_DEBUG("Ioctl cmd %{public}x success", cmd);
    }
    return CS_SUCCESS;
}

static int DoSetXpmOwnerId(int fd, uint32_t idType, const char *ownerId, uint32_t apiTargetVersion)
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
    config.apiTargetVersion = apiTargetVersion;
    LOG_DEBUG("Set type = %{public}u, ownerId = %{public}s, apiTargetVersion is %{public}u",
        idType, ownerId ? ownerId : "NULL", apiTargetVersion);
    (void)XpmIoctl(fd, XPM_SET_OWNERID, &config);
    return CS_SUCCESS;
}

#define API_VERSION_DECIMAL 10
int InitXpm(int enableJitFort, uint32_t idType, const char *ownerId, const char *apiTargetVersionStr)
{
    // open /dev/xpm
    int fd = open(XPM_DEV_PATH, O_RDWR);
    if (fd == -1) {
        LOG_INFO("Open device file failed: %{public}s (ignore)", strerror(errno));
        return CS_SUCCESS;
    }

    // init xpm region
    struct XpmConfig config = {0};
    config.regionAddr = 0;
    config.regionLength = XPM_REGION_LEN;
    (void)XpmIoctl(fd, XPM_SET_REGION, &config);

    // enable jitfort
    if (enableJitFort != 0) {
        (void)XpmIoctl(fd, XPM_SET_JITFORT_ENABLE, NULL);
    }

    // set owner id
    int ret = CS_SUCCESS;
    uint32_t apiTargetVersion = 0;
    if (idType != PROCESS_OWNERID_UNINIT) {
        idType = ConvertIdType(idType, ownerId);
        if (apiTargetVersionStr != NULL) {
            char *endPtr = NULL;
            // we use 0 as default, and strtoul returns 0 if failed
            apiTargetVersion = strtoul(apiTargetVersionStr, &endPtr, API_VERSION_DECIMAL);
        }
        ret = DoSetXpmOwnerId(fd, idType, ownerId, apiTargetVersion);
    }

    // close /dev/xpm
    close(fd);
    return ret;
}

int SetXpmOwnerId(uint32_t idType, const char *ownerId)
{
    int fd = open(XPM_DEV_PATH, O_RDWR);
    if (fd == -1) {
        LOG_INFO("Open device file failed: %{public}s (ignore)", strerror(errno));
        return CS_SUCCESS;
    }
    int ret = DoSetXpmOwnerId(fd, idType, ownerId, 0);
    close(fd);
    return ret;
}
