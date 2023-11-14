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

#include <sys/types.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <sys/ioctl.h>
#include <parameters.h>
#include <parameter.h>
#include "log.h"
#include "errcode.h"
#include "cert_path.h"

using namespace OHOS::Security::CodeSign;

static int IoctlCertPathOperation(const CertPathInfo &info, int cmd, const char *operation)
{
    int fd = open(CERT_DEVICE_PATH, O_WRONLY);
    if (fd == -1) {
        LOG_ERROR(LABEL, "Error opening device, errno = <%{public}d, %{public}s>", errno, strerror(errno));
        return CS_ERR_FILE_OPEN;
    }

    int ret = ioctl(fd, cmd, &info);
    if (ret < 0) {
        LOG_ERROR(
            LABEL, "%s cert path ioctl error, errno = <%{public}d, %{public}s>", operation, errno, strerror(errno));
        close(fd);
        return ret;
    }

    close(fd);
    return CS_SUCCESS;
}

int AddCertPath(const CertPathInfo &info)
{
    return IoctlCertPathOperation(info, ADD_CERT_PATH_CMD, "add");
}

int RemoveCertPath(const CertPathInfo &info)
{
    return IoctlCertPathOperation(info, REMOVE_CERT_PATH_CMD, "remove");
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