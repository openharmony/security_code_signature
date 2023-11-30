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

#include "code_sign_enable_multi_task.h"

#include "byte_buffer.h"
#include "cs_hisysevent.h"
#include "errcode.h"
#include "log.h"
#include "signer_info.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
constexpr uint32_t CODE_SIGN_TASK_TIMEOUT_MS = 300000;
constexpr uint32_t DEFAULT_THREADS_NUM = 8;

CodeSignEnableMultiTask::CodeSignEnableMultiTask(): enableCodeSignTaskWorker_("EnableCodeSign"), taskCallBack_(0)
{
    enableCodeSignTaskWorker_.Start(DEFAULT_THREADS_NUM);
}

CodeSignEnableMultiTask::~CodeSignEnableMultiTask()
{
    enableCodeSignTaskWorker_.Stop();
}

void CodeSignEnableMultiTask::AddTaskData(const std::string &targetFile, const struct code_sign_enable_arg &arg)
{
    enableData_.push_back(std::pair<std::string, code_sign_enable_arg>(targetFile, arg));
}

bool CodeSignEnableMultiTask::ExecuteEnableCodeSignTask(int32_t &taskRet, const std::string &ownerId,
    const std::string &path, CallbackFunc &func)
{
    SortTaskData();

    for (uint32_t i = 0; i < enableData_.size(); i++) {
        LOG_DEBUG(LABEL, "index: %{public}d, name:%{public}s, %{public}lld",
            i, enableData_[i].first.c_str(), enableData_[i].second.data_size);
        ExecuteEnableCodeSignTask(i, taskRet, ownerId, path, func);
    }

    std::unique_lock<std::mutex> lock(cvLock_);
    auto waitStatus = taskfinish_.wait_for(lock, std::chrono::milliseconds(CODE_SIGN_TASK_TIMEOUT_MS),
        [this]() { return this->enableData_.size() == this->taskCallBack_; });
    return waitStatus;
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
        LOG_DEBUG(LABEL, "ExecuteEnableCodeSignTask task called");
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
        LOG_DEBUG(LABEL, "Task return info index: %{public}d, ret: %{public}d", index, ret);

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
        LOG_ERROR(LABEL, "get ownerId from signature failed, ret %{public}d", ret);
    } else if (retId != ownerId) {
        ret = CS_ERR_INVALID_OWNER_ID;
        ReportInvalidOwner(path, ownerId, retId);
        LOG_ERROR(LABEL, "invalid ownerId retId %{public}s ownerId %{public}s", retId.c_str(), ownerId.c_str());
    }
    return ret;
}
}
}
}