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

#include "file_helper.h"

#include <climits>
#include <cstdlib>
#include <unistd.h>

#include "directory_ex.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
bool CheckFilePathValid(const std::string &path, const std::string &baseRealPath)
{
    std::string realPath;
    if (!OHOS::PathToRealPath(path, realPath)) {
        LOG_INFO("Get real path failed, path = %{public}s", path.c_str());
        return false;
    }
    return (realPath.size() > baseRealPath.size()) &&
        (realPath.compare(0, baseRealPath.size(), baseRealPath) == 0);
}
}
}
}