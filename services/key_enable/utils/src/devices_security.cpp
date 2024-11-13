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

#include "key_utils.h"

#include <cstdlib>
#include <dlfcn.h>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <securec.h>

#include "log.h"

using namespace OHOS::Security::CodeSign;

enum DeviceMode {
    NOT_INITIALIZE = 0,
    DEVICE_MODE_RD,
    DEVICE_MODE_NOT_RD
};

constexpr int32_t CMDLINE_MAX_BUF_LEN = 4096;
#ifndef KEY_ENABLE_UTILS_TEST
static const std::string PROC_CMDLINE_FILE_PATH = "/proc/cmdline";
static int32_t g_isRdDevice = NOT_INITIALIZE;
#else
const std::string PROC_CMDLINE_FILE_PATH = "/data/test/tmp/cmdline";
int32_t g_isRdDevice = NOT_INITIALIZE;
#endif

static bool CheckDeviceMode(char *buf, ssize_t bufLen)
{
    bool status = false;
    char *onStr = strstr(buf, "oemmode=rd");
    char *offStr = strstr(buf, "oemmode=user");
    char *statusStr = strstr(buf, "oemmode=");
    if (onStr == nullptr && offStr == nullptr) {
        LOG_INFO(LABEL, "Not rd mode, cmdline = %{private}s", buf);
    } else if (offStr != nullptr && statusStr != nullptr && offStr != statusStr) {
        LOG_ERROR(LABEL, "cmdline attacked, cmdline = %{private}s", buf);
    } else if (onStr != nullptr && offStr == nullptr) {
        status = true;
        LOG_DEBUG(LABEL, "Oemode is rd");
    }
    return status;
}

static bool CheckEfuseStatus(char *buf, ssize_t bufLen)
{
    bool status = false;
    char *onStr = strstr(buf, "efuse_status=1");
    char *offStr = strstr(buf, "efuse_status=0");
    char *statusStr = strstr(buf, "efuse_status=");
    if (onStr == nullptr && offStr == nullptr) {
        LOG_INFO(LABEL, "device is efused, cmdline = %{private}s", buf);
    } else if (offStr != nullptr && statusStr != nullptr && offStr != statusStr) {
        LOG_ERROR(LABEL, "cmdline attacked, cmdline = %{private}s", buf);
    } else if (onStr != nullptr && offStr == nullptr) {
        status = true;
        LOG_DEBUG(LABEL, "device is not efused");
    }
    return status;
}

static void ParseCMDLine()
{
    int32_t fd = open(PROC_CMDLINE_FILE_PATH.c_str(), O_RDONLY);
    if (fd < 0) {
        g_isRdDevice = DEVICE_MODE_NOT_RD;
        LOG_ERROR(LABEL, "open %{public}s failed, %{public}s",
            PROC_CMDLINE_FILE_PATH.c_str(), strerror(errno));
        return;
    }
    char *buf = nullptr;
    int32_t status = DEVICE_MODE_NOT_RD;
    do {
        buf = static_cast<char *>(malloc(CMDLINE_MAX_BUF_LEN));
        if (buf == nullptr) {
            LOG_ERROR(LABEL, "Alloc buffer for reading cmdline failed.");
            break;
        }
        (void) memset_s(buf, CMDLINE_MAX_BUF_LEN, 0, CMDLINE_MAX_BUF_LEN);
        ssize_t bufLen = read(fd, buf, CMDLINE_MAX_BUF_LEN - 1);
        if (bufLen < 0) {
            LOG_ERROR(LABEL, "Read %{public}s failed, %{public}s.",
                PROC_CMDLINE_FILE_PATH.c_str(), strerror(errno));
            break;
        }
        if (CheckDeviceMode(buf, bufLen) || CheckEfuseStatus(buf, bufLen)) {
            status = DEVICE_MODE_RD;
        }
    } while (0);
    g_isRdDevice = status;
    (void) close(fd);
    free(buf);
}

bool IsRdDevice()
{
    if (g_isRdDevice == NOT_INITIALIZE) {
        ParseCMDLine();
    }
    return g_isRdDevice == DEVICE_MODE_RD;
}