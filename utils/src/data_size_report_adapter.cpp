/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "data_size_report_adapter.h"
#include "hisysevent.h"

#include <sstream>
#include <thread>
#include <vector>
#include <sys/statfs.h>
#include <sys/stat.h>
#include "directory_ex.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
namespace {
using namespace OHOS::HiviewDFX;

static const std::string CODE_SIGN_NAME = "code_signature";
static const std::string SYS_EL1_CODE_SIGN_DIR = "/data/service/el1/public/profiles";
static const std::string USER_DATA_DIR = "/data";
static const double UNITS = 1024.0;
}

double GetPartitionRemainSize(const std::string& path)
{
    struct statfs stat;
    if (statfs(path.c_str(), &stat) != 0) {
        LOG_ERROR("Failed to get %{public}s's remaining size.", path.c_str());
        return 0;
    }

    /* change B to MB */
    return (static_cast<double>(stat.f_bfree) * static_cast<double>(stat.f_bsize)) / (UNITS * UNITS);
}

void ReportTask()
{
    int ret = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::FILEMANAGEMENT, "USER_DATA_SIZE",
        HiviewDFX::HiSysEvent::EventType::STATISTIC, "COMPONENT_NAME", CODE_SIGN_NAME, "PARTITION_NAME",
        USER_DATA_DIR, "REMAIN_PARTITION_SIZE", GetPartitionRemainSize(USER_DATA_DIR),
        "FILE_OR_FOLDER_PATH", SYS_EL1_CODE_SIGN_DIR, "FILE_OR_FOLDER_SIZE", GetFolderSize(SYS_EL1_CODE_SIGN_DIR));
    if (ret != 0) {
        LOG_ERROR("Hisysevent report data size failed!");
    }
}

void ReportUserDataSize()
{
    std::thread task(ReportTask);
    task.join();
}
} // namespace CodeSign
} // namespace Security
} // OHOS