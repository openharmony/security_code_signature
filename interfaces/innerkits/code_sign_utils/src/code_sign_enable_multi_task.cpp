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

#include "code_sign_enable_multi_task.h"

#include <fcntl.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "byte_buffer.h"
#include "cs_hisysevent.h"
#include "errcode.h"
#include "log.h"
#include "signer_info.h"
#include "stat_utils.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
constexpr uint32_t CODE_SIGN_TASK_TIMEOUT_MS = 300000;
constexpr uint32_t DEFAULT_THREADS_NUM = 8;

CodeSignEnableMultiTask::CodeSignEnableMultiTask(): enableCodeSignTaskWorker_("EnableCodeSign"), taskCallBack_(0)
{
    LOG_INFO("Tasks init.");
    enableCodeSignTaskWorker_.Start(DEFAULT_THREADS_NUM);
}

CodeSignEnableMultiTask::~CodeSignEnableMultiTask()
{
    LOG_INFO("Tasks finish.");
    enableCodeSignTaskWorker_.Stop();
}

void CodeSignEnableMultiTask::AddTaskData(const std::string &targetFile, const struct code_sign_enable_arg &arg)
{
    enableData_.push_back(std::pair<std::string, code_sign_enable_arg>(targetFile, arg));
}

int32_t CodeSignEnableMultiTask::IsFsVerityEnabled(int fd)
{
    unsigned int flags;
    int ret = ioctl(fd, FS_IOC_GETFLAGS, &flags);
    if (ret < 0) {
        LOG_ERROR("Get verity flags by ioctl failed. errno = <%{public}d, %{public}s>",
            errno, strerror(errno));
        return CS_ERR_FILE_INVALID;
    }
    if (flags & FS_VERITY_FL) {
        return CS_SUCCESS;
    }
    return CS_ERR_FSVERITY_NOT_ENABLED;
}

int32_t CodeSignEnableMultiTask::IsFsVerityEnabled(const std::string &path)
{
    int32_t fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        LOG_ERROR("Open file failed, path = %{public}s, errno = <%{public}d, %{public}s>",
            path.c_str(), errno, strerror(errno));
        return CS_ERR_FILE_OPEN;
    }
    int32_t ret = IsFsVerityEnabled(fd);
    if (ret != CS_SUCCESS) {
        LOG_INFO("Fs-verity is not enable for file = %{public}s.", path.c_str());
    }
    close(fd);
    return ret;
}

int32_t CodeSignEnableMultiTask::ExecuteEnableCodeSignTask(const std::string &ownerId,
    const std::string &path, CallbackFunc &func)
{
    SortTaskData();

    LOG_INFO("Tasks num = %{public}zu", enableData_.size());
    int32_t taskRet = CS_SUCCESS;
    for (uint32_t i = 0; i < enableData_.size(); i++) {
        LOG_DEBUG("index: %{public}d, name:%{public}s, %{public}lld",
            i, enableData_[i].first.c_str(), enableData_[i].second.data_size);
        ExecuteEnableCodeSignTask(i, taskRet, ownerId, path, func);
    }

    std::unique_lock<std::mutex> lock(cvLock_);
    auto waitStatus = taskfinish_.wait_for(lock, std::chrono::milliseconds(CODE_SIGN_TASK_TIMEOUT_MS),
        [this]() { return this->enableData_.size() == this->taskCallBack_; });
    if (!waitStatus) {
        LOG_ERROR("enable code sign timeout, finished tasks = %{public}u", taskCallBack_);
        return CS_ERR_ENABLE_TIMEOUT;
    }
    if (taskRet != CS_SUCCESS) {
        return taskRet;
    }
    int32_t ret = CS_SUCCESS;
    for (auto &data : enableData_) {
        const std::string &filePath = data.first;
        if (IsFsVerityEnabled(filePath) != CS_SUCCESS) {
            ret = CS_ERR_FSVERITY_NOT_ENABLED;
            ReportEnableError(filePath, ret);
        }
    }
    return ret;
}

void CodeSignEnableMultiTask::SortTaskData()
{
    auto compareFileDataSize = [](const std::pair<std::string, code_sign_enable_arg> &a,
        const std::pair<std::string, code_sign_enable_arg> &b) {
        return a.second.data_size > b.second.data_size;
    };
    sort(enableData_.begin(), enableData_.end(), compareFileDataSize);
}

void CodeSignEnableMultiTask::ExecuteEnableCodeSignTask(uint32_t &index, int32_t &taskRet,
    const std::string &ownerId, const std::string &path, CallbackFunc &func)
{
    auto enableCodeSignTask = [this, index, &ownerId, &path, &func, &taskRet]() {
        LOG_DEBUG("ExecuteEnableCodeSignTask task called");
        {
            std::unique_lock<std::mutex> lock(cvLock_);
            if (taskRet != CS_SUCCESS) {
                this->taskCallBack_++;
                if (this->taskCallBack_ == this->enableData_.size()) {
                    this->taskfinish_.notify_one();
                }
                return;
            }
        }

        int32_t ret = CheckOwnerId(path, ownerId,
            reinterpret_cast<const uint8_t *>(this->enableData_[index].second.sig_ptr),
            this->enableData_[index].second.sig_size);
        if (ret == CS_SUCCESS) {
            ret = func(this->enableData_[index].first, this->enableData_[index].second);
        }
        LOG_DEBUG("Task return info index: %{public}d, ret: %{public}d", index, ret);

        std::unique_lock<std::mutex> lock(cvLock_);
        if (taskRet == CS_SUCCESS) {
            taskRet = ret;
        }
        this->taskCallBack_++;
        if (this->taskCallBack_ == this->enableData_.size()) {
            this->taskfinish_.notify_one();
        }
    };
    enableCodeSignTaskWorker_.AddTask(enableCodeSignTask);
}

int32_t CodeSignEnableMultiTask::CheckOwnerId(const std::string &path, const std::string &ownerId,
    const uint8_t *sigPtr, uint32_t sigSize)
{
    if (ownerId.empty()) {
        return CS_SUCCESS;
    }

    int32_t ret;
    ByteBuffer sigBuffer;
    sigBuffer.CopyFrom(sigPtr, sigSize);
    std::string retId;
    ret = SignerInfo::ParseOwnerIdFromSignature(sigBuffer, retId);
    if (ret != CS_SUCCESS) {
        ReportInvalidOwner(path, ownerId, "invalid");
        LOG_ERROR("get ownerId from signature failed, ret %{public}d", ret);
    } else if (retId != ownerId) {
        ret = CS_ERR_INVALID_OWNER_ID;
        ReportInvalidOwner(path, ownerId, retId);
        LOG_ERROR("invalid ownerId retId %{public}s ownerId %{public}s", retId.c_str(), ownerId.c_str());
    }
    return ret;
}
}
}
}