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
#include "fdsan.h"

#define XPM_DEV_PATH "/dev/xpm"

#define XPM_SET_REGION _IOW('x', 0x01, struct XpmConfig)
#define XPM_SET_OWNERID _IOW('x', 0x02, struct XpmConfig)
#define XPM_SET_JITFORT_ENABLE _IOW('x', 0x3, unsigned long)
#define SET_EXT_XPM_INFO_ID 0x08
#define XPM_SET_EXT_XPM_INFO _IOW('x', SET_EXT_XPM_INFO_ID, struct XpmExtInfo)
#define ENTERPRISE_RESIGN "enterpriseReSign"

struct XpmOwnerIdParam {
    uint32_t idType;
    const char *ownerId;
    uint32_t apiTargetVersion;
    const char *appSignType;
    enum XPMDistributionEnum distributionType;
};

static enum XPMDistributionEnum GetAppDistributionTypeEnum(const char *appDistributionType)
{
    if (appDistributionType == NULL) {
        return XPM_DISTRIBUTION_DEFAULT;
    }

    if (strcmp(appDistributionType, XPM_DISTRIBUTION_STR_APP_GALLERY) == 0) {
        return XPM_DISTRIBUTION_APP_GALLERY;
    }
    if (strcmp(appDistributionType, XPM_DISTRIBUTION_STR_OS_INTEGRATION) == 0) {
        return XPM_DISTRIBUTION_OS_INTEGRATION;
    }
    if (strcmp(appDistributionType, XPM_DISTRIBUTION_STR_INTERNALTESTING) == 0) {
        return XPM_DISTRIBUTION_INTERNALTESTING;
    }
    if (strcmp(appDistributionType, XPM_DISTRIBUTION_STR_CROWDTESTING) == 0) {
        return XPM_DISTRIBUTION_CROWDTESTING;
    }
    if (strcmp(appDistributionType, XPM_DISTRIBUTION_STR_ENTERPRISE) == 0) {
        return XPM_DISTRIBUTION_ENTERPRISE;
    }
    if (strcmp(appDistributionType, XPM_DISTRIBUTION_STR_ENTERPRISE_NORMAL) == 0) {
        return XPM_DISTRIBUTION_ENTERPRISE_NORMAL;
    }
    if (strcmp(appDistributionType, XPM_DISTRIBUTION_STR_ENTERPRISE_MDM) == 0) {
        return XPM_DISTRIBUTION_ENTERPRISE_MDM;
    }
    if (strcmp(appDistributionType, XPM_DISTRIBUTION_STR_NONE) == 0) {
        return XPM_DISTRIBUTION_DEFAULT;
    }
    return XPM_DISTRIBUTION_DEFAULT;
}

static int XpmIoctl(int fd, uint32_t cmd, void *data)
{
    int ret = ioctl(fd, cmd, data);
    if (ret == -1) {
        LOG_ERROR("Ioctl cmd %{public}x failed: %{public}s (ignore)", cmd, strerror(errno));
    } else {
        LOG_DEBUG("Ioctl cmd %{public}x success", cmd);
    }
    return CS_SUCCESS;
}

static int DoSetXpmOwnerId(int fd, const struct XpmOwnerIdParam *ownerIdParam)
{
    struct XpmConfig config = {0};
    uint32_t idType = ownerIdParam->idType;
    const char *ownerId = ownerIdParam->ownerId;
    const char *appSignType = ownerIdParam->appSignType;
    enum XPMDistributionEnum xpmDistributionType = ownerIdParam->distributionType;

    if (idType >= PROCESS_OWNERID_MAX) {
        LOG_ERROR("Input idType is invalid: %{public}u", idType);
        return CS_ERR_PARAM_INVALID;
    }

    if (appSignType != NULL && strcmp(appSignType, ENTERPRISE_RESIGN) == 0) {
        idType = PROCESS_OWNERID_ENT_RESIGN;
    }
    config.idType = idType;

    if ((ownerId != NULL) && (strlen(ownerId) != 0)) {
        if (memcpy_s(config.ownerId, sizeof(config.ownerId) - 1, ownerId, strlen(ownerId)) != EOK) {
            LOG_ERROR("Memcpy ownerId failed, ownerId: %{public}s", ownerId);
            return CS_ERR_MEMORY;
        }
    }
    config.apiTargetVersion = ownerIdParam->apiTargetVersion;

    LOG_DEBUG("Set type = %{public}u, ownerId = %{public}s, apiTargetVersion is %{public}u, "
              "appDistributionType = %{public}d",
        config.idType, ownerId ? ownerId : "NULL", config.apiTargetVersion, xpmDistributionType);
    (void)XpmIoctl(fd, XPM_SET_OWNERID, &config);

    struct XpmExtInfo extInfo = {0};
    if ((xpmDistributionType >= XPM_DISTRIBUTION_DEFAULT) &&
        (xpmDistributionType < XPM_DISTRIBUTION_MAX)) {
        extInfo.distributionType = (uint8_t)xpmDistributionType;
    } else {
        LOG_ERROR("Input appDistributionType is invalid: %{public}d", xpmDistributionType);
    }
    (void)XpmIoctl(fd, XPM_SET_EXT_XPM_INFO, &extInfo);

    return CS_SUCCESS;
}

#define API_VERSION_DECIMAL 10
int InitXpmWithParam(const struct XpmInitParam *initParam)
{
    if (initParam == NULL) {
        LOG_ERROR("Input initParam is null");
        return CS_ERR_PARAM_INVALID;
    }

    // open /dev/xpm
    int fd = open(XPM_DEV_PATH, O_RDWR);
    if (fd == -1) {
        LOG_INFO("Open device file failed: %{public}s (ignore)", strerror(errno));
        return CS_SUCCESS;
    }
    FDSAN_MARK(fd);

    // init xpm region
    struct XpmConfig config = {0};
    config.regionAddr = 0;
    config.regionLength = XPM_REGION_LEN;
    (void)XpmIoctl(fd, XPM_SET_REGION, &config);

    // set owner id
    int ret = CS_SUCCESS;
    uint32_t apiTargetVersion = 0;
    uint32_t idType = initParam->idType;
    const char *ownerId = initParam->ownerId;
    if (idType != PROCESS_OWNERID_UNINIT) {
        struct XpmOwnerIdParam ownerIdParam = {0};
        idType = ConvertIdType(idType, ownerId);
        if (initParam->apiTargetVersionStr != NULL) {
            char *endPtr = NULL;
            // we use 0 as default, and strtoul returns 0 if failed
            apiTargetVersion = strtoul(initParam->apiTargetVersionStr, &endPtr, API_VERSION_DECIMAL);
        }
        ownerIdParam.idType = idType;
        ownerIdParam.ownerId = ownerId;
        ownerIdParam.apiTargetVersion = apiTargetVersion;
        ownerIdParam.appSignType = initParam->appSignType;
        ownerIdParam.distributionType = GetAppDistributionTypeEnum(initParam->appDistributionType);
        ret = DoSetXpmOwnerId(fd, &ownerIdParam);
    }

    // enable jitfort
    if (initParam->enableJitFort != 0) {
        (void)XpmIoctl(fd, XPM_SET_JITFORT_ENABLE, NULL);
    }

    // close /dev/xpm
    FDSAN_CLOSE(fd);
    return ret;
}

int InitXpm(int enableJitFort, uint32_t idType, const char *ownerId, const char *apiTargetVersionStr,
            const char *appSignType)
{
    struct XpmInitParam initParam = XPM_INIT_PARAM_DEFAULT;
    initParam.enableJitFort = enableJitFort;
    initParam.idType = idType;
    initParam.ownerId = ownerId;
    initParam.apiTargetVersionStr = apiTargetVersionStr;
    initParam.appSignType = appSignType;
    return InitXpmWithParam(&initParam);
}

int SetXpmOwnerId(uint32_t idType, const char *ownerId)
{
    int fd = open(XPM_DEV_PATH, O_RDWR);
    if (fd == -1) {
        LOG_INFO("Open device file failed: %{public}s (ignore)", strerror(errno));
        return CS_SUCCESS;
    }
    FDSAN_MARK(fd);
    struct XpmOwnerIdParam ownerIdParam = {
        .idType = idType,
        .ownerId = ownerId,
        .apiTargetVersion = 0,
        .appSignType = NULL,
        .distributionType = XPM_DISTRIBUTION_DEFAULT,
    };
    int ret = DoSetXpmOwnerId(fd, &ownerIdParam);
    FDSAN_CLOSE(fd);
    return ret;
}
