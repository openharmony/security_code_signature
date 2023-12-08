/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef XPM_COMMON_TEST_H
#define XPM_COMMON_TEST_H

#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>
#include <sys/ioctl.h>

namespace OHOS {
namespace Security {
namespace CodeSign {
constexpr unsigned long MAP_XPM = 0x40;
const unsigned long PAGE_SIZE = (sysconf(_SC_PAGESIZE));
const unsigned long PAGE_MASK = ~(PAGE_SIZE - 1);

const std::string XPM_DEBUG_FS_MODE_PATH = "/proc/sys/kernel/xpm/xpm_mode";
const std::string SELINUX_MODE_PATH = "/sys/fs/selinux/enforce";
const std::string PERMISSIVE_MODE = "0";
const std::string ENFORCE_MODE = "1";

inline void SaveStringToFile(const std::string &filePath,
    const std::string &value)
{
    std::fstream fout;
    fout.open(filePath, std::ios::out);
    fout << value;
    fout.close();
}

bool AllocXpmRegion();
} // namespace CodeSign
} // namespace Security
} // namespace OHOS

#endif