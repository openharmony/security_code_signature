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

#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <gtest/hwext/gtest-multithread.h>
#include <random>
#include <securec.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "errcode.h"
#include "code_sign_attr_utils.h"
#include "ownerid_utils.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
using namespace std;
using namespace testing::ext;
using namespace testing::mt;

class CodeSignAttrUtilsTest : public testing::Test {
public:
    CodeSignAttrUtilsTest() {};
    virtual ~CodeSignAttrUtilsTest() {};
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: CodeSignAttrUtilsTest_0001
 * @tc.desc: test InitXpm with valid param should success
 * @tc.type: Func
 * @tc.require: IAHWOP
 */
HWTEST_F(CodeSignAttrUtilsTest, CodeSignAttrUtilsTest_0001, TestSize.Level0)
{
    EXPECT_EQ(InitXpm(0, PROCESS_OWNERID_APP, NULL), CS_SUCCESS);
    EXPECT_EQ(InitXpm(0, PROCESS_OWNERID_COMPAT, NULL), CS_SUCCESS);
    EXPECT_EQ(InitXpm(0, PROCESS_OWNERID_DEBUG, NULL), CS_SUCCESS);
    EXPECT_EQ(InitXpm(0, PROCESS_OWNERID_EXTEND, NULL), CS_SUCCESS);
    EXPECT_EQ(InitXpm(0, PROCESS_OWNERID_DEBUG_PLATFORM, NULL), CS_SUCCESS);
    EXPECT_EQ(InitXpm(0, PROCESS_OWNERID_PLATFORM, NULL), CS_SUCCESS);
    EXPECT_EQ(InitXpm(0, PROCESS_OWNERID_NWEB, NULL), CS_SUCCESS);
    EXPECT_EQ(InitXpm(0, PROCESS_OWNERID_SHARED, NULL), CS_SUCCESS);
    EXPECT_EQ(InitXpm(0, PROCESS_OWNERID_SYSTEM, NULL), CS_SUCCESS);
    EXPECT_EQ(InitXpm(0, PROCESS_OWNERID_APP, "test"), CS_SUCCESS);
}

/**
 * @tc.name: CodeSignAttrUtilsTest_0002
 * @tc.desc: test InitXpm with invalid params should fail
 * @tc.type: Func
 * @tc.require: IAHWOP
 */
HWTEST_F(CodeSignAttrUtilsTest, CodeSignAttrUtilsTest_0002, TestSize.Level0)
{
    // test invalid ownerid type
    EXPECT_EQ(InitXpm(0, PROCESS_OWNERID_MAX, NULL), CS_ERR_PARAM_INVALID);
    // test invalid ownerid valud
    char ownerid[MAX_OWNERID_LEN + 1] = { 0 };
    (void)memset_s(ownerid, MAX_OWNERID_LEN + 1, 'a', MAX_OWNERID_LEN + 1);
    EXPECT_EQ(InitXpm(0, PROCESS_OWNERID_APP, ownerid), CS_ERR_MEMORY);
}

/**
 * @tc.name: CodeSignAttrUtilsTest_0003
 * @tc.desc: test ConvertIdType
 * @tc.type: Func
 * @tc.require: IALFAX
 */
HWTEST_F(CodeSignAttrUtilsTest, CodeSignAttrUtilsTest_0003, TestSize.Level0)
{
    // test non OWNERID_APP, retval is origin idType
    EXPECT_EQ(ConvertIdType(PROCESS_OWNERID_DEBUG, nullptr), PROCESS_OWNERID_DEBUG);
    EXPECT_EQ(ConvertIdType(PROCESS_OWNERID_DEBUG, "1"), PROCESS_OWNERID_DEBUG);
    // test app not in list, retval is OWNERID_APP
    EXPECT_EQ(ConvertIdType(PROCESS_OWNERID_APP, "1"), PROCESS_OWNERID_APP);
    // test OWNERID_APP_TEMPA_ALLOW, retval is OWNERID_APP
    EXPECT_EQ(ConvertIdType(PROCESS_OWNERID_APP_TEMP_ALLOW, "1"), PROCESS_OWNERID_APP);
    // test nullptr
    EXPECT_EQ(ConvertIdType(PROCESS_OWNERID_APP, nullptr), PROCESS_OWNERID_APP);
}
}
}
}
