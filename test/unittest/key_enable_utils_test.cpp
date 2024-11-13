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

#include <cstdlib>
#include <gtest/gtest.h>
#include <string>

#include "key_utils.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace Security {
namespace CodeSign {

static const std::string RD_DEVICE_1 = "oemmode=rd efuse_status=0";
static const std::string RD_DEVICE_2 = "oemmode=user efuse_status=1";
static const std::string NOT_RD_DEVICE = "oemmode=user efuse_status=0";
static const std::string DEVICE_MODE_ATTACKED = "oemmode=rd oemmode=user";
static const std::string EFUSED_ATTACKED = "efuse_status=1 efuse_status=0";
constexpr int32_t NOT_INITIALIZE = 0;

class KeyEnableUtilsTest : public testing::Test {
public:
    KeyEnableUtilsTest() {};
    virtual ~KeyEnableUtilsTest() {};
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

static bool OverWriteCMDLine(const std::string &content)
{
    FILE *file = fopen(PROC_CMDLINE_FILE_PATH.c_str(), "w+");
    if (file == nullptr) {
        return false;
    }
    size_t result = fwrite(content.c_str(), 1, content.size(), file);
    if (result != content.size()) {
        (void)fclose(file);
        return false;
    }
    (void)fclose(file);
    return true;
}

/**
 * @tc.name: KeyEnableUtilsTest_0001
 * @tc.desc: check status of device
 * @tc.type: Func
 * @tc.require: issueI8FCGF
 */
HWTEST_F(KeyEnableUtilsTest, KeyEnableUtilsTest_0001, TestSize.Level0)
{
    ASSERT_EQ(OverWriteCMDLine(RD_DEVICE_1), true);
    EXPECT_EQ(IsRdDevice(), true);
    g_isRdDevice = NOT_INITIALIZE;
    ASSERT_EQ(OverWriteCMDLine(RD_DEVICE_2), true);
    EXPECT_EQ(IsRdDevice(), true);
    g_isRdDevice = NOT_INITIALIZE;
    ASSERT_EQ(OverWriteCMDLine(NOT_RD_DEVICE), true);
    EXPECT_EQ(IsRdDevice(), false);
    g_isRdDevice = NOT_INITIALIZE;
    ASSERT_EQ(OverWriteCMDLine(DEVICE_MODE_ATTACKED), true);
    EXPECT_EQ(IsRdDevice(), false);
    g_isRdDevice = NOT_INITIALIZE;
    ASSERT_EQ(OverWriteCMDLine(EFUSED_ATTACKED), true);
    EXPECT_EQ(IsRdDevice(), false);
}
} // namespace CodeSign
} // namespace Security
} // namespace OHOS
