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

#include "cert_utils.h"
#include "directory_ex.h"
#include "fsverity_utils_helper.h"
#include "local_sign_key.h"
#include "log.h"
#include "pkcs7_generator.h"

using namespace OHOS::Security::CodeSign;
using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace Security {
namespace CodeSign {
static const std::string AN_BASE_PATH = "/data/local/ark-cache/tmp/";
static const std::string DEMO_AN_PATH2 = AN_BASE_PATH + "demo2.an";
static const std::string DEFAULT_HASH_ALGORITHM = "sha256";

class LocalCodeSignUtilsTest : public testing::Test {
public:
    LocalCodeSignUtilsTest() {};
    virtual ~LocalCodeSignUtilsTest() {};
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: LocalCodeSignUtilsTest_0001
 * @tc.desc: Sign local code successfully, owner ID is empty
 * @tc.type: Func
 * @tc.require: issueI8FCGF
 */
HWTEST_F(LocalCodeSignUtilsTest, LocalCodeSignUtilsTest_0001, TestSize.Level0)
{
    ByteBuffer digest;
    std::string realPath;
    std::string ownerID = "";
    bool bRet = OHOS::PathToRealPath(DEMO_AN_PATH2, realPath);
    EXPECT_EQ(bRet, true);
    bRet = FsverityUtilsHelper::GetInstance().GenerateFormattedDigest(realPath.c_str(), digest);
    EXPECT_EQ(bRet, true);

    ByteBuffer signature;
    int ret = PKCS7Generator::GenerateSignature(ownerID, LocalSignKey::GetInstance(), DEFAULT_HASH_ALGORITHM.c_str(),
        digest, signature);
    EXPECT_EQ(ret, CS_SUCCESS);
}

/**
 * @tc.name: LocalCodeSignUtilsTest_0002
 * @tc.desc: Sign local code with owner ID successfully
 * @tc.type: Func
 * @tc.require: issueI88PPA
 */
HWTEST_F(LocalCodeSignUtilsTest, LocalCodeSignUtilsTest_0002, TestSize.Level0)
{
    ByteBuffer digest;
    std::string realPath;
    std::string ownerID = "AppName123";
    bool bRet = OHOS::PathToRealPath(DEMO_AN_PATH2, realPath);
    EXPECT_EQ(bRet, true);
    bRet = FsverityUtilsHelper::GetInstance().GenerateFormattedDigest(realPath.c_str(), digest);
    EXPECT_EQ(bRet, true);

    ByteBuffer signature;
    int ret = PKCS7Generator::GenerateSignature(ownerID, LocalSignKey::GetInstance(), DEFAULT_HASH_ALGORITHM.c_str(),
        digest, signature);
    EXPECT_EQ(ret, CS_SUCCESS);
}

/**
 * @tc.name: LocalCodeSignUtilsTest_0003
 * @tc.desc: Generate formatted digest failed with wrong path
 * @tc.type: Func
 * @tc.require: issueI8FCGF
 */
HWTEST_F(LocalCodeSignUtilsTest, LocalCodeSignUtilsTest_0003, TestSize.Level0)
{
    ByteBuffer digest;
    std::string realPath = DEMO_AN_PATH2 + "invalid";
    bool bRet = FsverityUtilsHelper::GetInstance().GenerateFormattedDigest(realPath.c_str(), digest);
    EXPECT_EQ(bRet, false);
}
} // namespace CodeSign
} // namespace Security
} // namespace OHOS
