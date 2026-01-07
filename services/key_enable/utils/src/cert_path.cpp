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

#include "cert_path.h"

#include <sys/types.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <sys/ioctl.h>
#include <chrono>
#include <thread>
#include <parameters.h>
#include <parameter.h>
#include "log_rust.h"
#include "errcode.h"

#define BMS_ENTERPRISE_PARAM "const.edm.is_enterprise_device"
#define ENTERPRISE_PARAM_WAIT_TIMEOUT_SECONDS 600
#define ENTERPRISE_PARAM_WAIT_TIME_MILLISECONDS 200

using namespace OHOS::Security::CodeSign;

static int IoctlCertOperation(const void *arg, int cmd, const char *operation)
{
    int fd = open(CERT_DEVICE_PATH, O_WRONLY);
    if (fd == -1) {
        LOG_ERROR(LABEL, "Error opening device, errno = <%{public}d, %{public}s>", errno, strerror(errno));
        return CS_ERR_FILE_OPEN;
    }

    int ret = ioctl(fd, cmd, arg);
    if (ret < 0) {
        LOG_ERROR(
            LABEL, "%s cert ioctl error, errno = <%{public}d, %{public}s>", operation, errno, strerror(errno));
        close(fd);
        return ret;
    }

    close(fd);
    return CS_SUCCESS;
}

int AddCertPath(const CertPathInfo &info)
{
    return IoctlCertOperation(&info, ADD_CERT_PATH_CMD, "add");
}

int RemoveCertPath(const CertPathInfo &info)
{
    return IoctlCertOperation(&info, REMOVE_CERT_PATH_CMD, "remove");
}

bool IsDeveloperModeOn()
{
    bool ret = false;
    if (OHOS::system::GetBoolParameter("const.security.developermode.state", false)) {
        ret = true;
    }
    return ret;
}

int CodeSignGetUdid(char *udid)
{
    return GetDevUdid(udid, UDID_SIZE);
}

int ActivateCert(const CertActivationInfo &info)
{
    return IoctlCertOperation(&info, ACTIVATE_CERT_PATH_CMD, "activate");
}

int AddEnterpriseResignCert(const EnterpriseResignCertInfo &info)
{
    return IoctlCertOperation(&info, ADD_ENTERPRISE_RESIGN_CERT_CMD, "add_enterprise_cert");
}

int RemoveEnterpriseResignCert(const EnterpriseResignCertInfo &info)
{
    return IoctlCertOperation(&info, REMOVE_ENTERPRISE_RESIGN_CERT_CMD, "remove_enterprise_cert");
}

bool IsEnterpriseDevice()
{
    return OHOS::system::GetBoolParameter(BMS_ENTERPRISE_PARAM, false);
}

bool WaitForEnterpriseParam()
{
    const auto start = std::chrono::system_clock::now();
    while (OHOS::system::GetParameter(BMS_ENTERPRISE_PARAM, "") == "") {
        std::this_thread::sleep_for(std::chrono::milliseconds(ENTERPRISE_PARAM_WAIT_TIME_MILLISECONDS));
        const auto now = std::chrono::system_clock::now();
        const std::chrono::duration<double> duration = now - start;
        if (duration.count() > ENTERPRISE_PARAM_WAIT_TIMEOUT_SECONDS) {
            LOG_ERROR(LABEL, "Wait for enterprise sysparam timeout");
            return false;
        }
    }
    const auto param = OHOS::system::GetParameter(BMS_ENTERPRISE_PARAM, "");
    LOG_INFO(LABEL, "Get enterprise sysparam %{public}s", param.c_str());
    return true;
}