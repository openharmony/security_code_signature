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

#include <cstdlib>
#include <gtest/gtest.h>
#include <string>

#include "access_token_setter.h"
#include "byte_buffer.h"
#include "code_sign_utils.h"
#include "local_code_sign_client.h"
#include "local_code_sign_kit.h"
#include "local_code_sign_load_callback.h"
#include "log.h"

using namespace OHOS::Security::CodeSign;
using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace Security {
namespace CodeSign {
static const std::string AN_BASE_PATH = "/data/local/ark-cache/tmp/";
static const std::string DEMO_AN_PATH = AN_BASE_PATH + "demo.an";

class LocalCodeSignTest : public testing::Test {
public:
    LocalCodeSignTest() {};
    virtual ~LocalCodeSignTest() {};
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: LocalCodeSignTest_0001
 * @tc.desc: init local certificate successfully
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(LocalCodeSignTest, LocalCodeSignTest_0001, TestSize.Level0)
{
    ByteBuffer cert;
    uint64_t selfTokenId = NativeTokenSet("key_enable");
    int ret = LocalCodeSignKit::InitLocalCertificate(cert);
    NativeTokenReset(selfTokenId);
    EXPECT_EQ(ret, CS_SUCCESS);
}

/**
 * @tc.name: LocalCodeSignTest_0002
 * @tc.desc: init local certificate failed with invalid caller
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(LocalCodeSignTest, LocalCodeSignTest_0002, TestSize.Level0)
{
    ByteBuffer cert;
    int ret = LocalCodeSignKit::InitLocalCertificate(cert);
    EXPECT_EQ(ret, CS_ERR_NO_PERMISSION);
}

/**
 * @tc.name: LocalCodeSignTest_0003
 * @tc.desc: sign local code successfully
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(LocalCodeSignTest, LocalCodeSignTest_0003, TestSize.Level0)
{
    ByteBuffer sig;
    uint64_t selfTokenId = NativeTokenSet("installs");
    int ret = LocalCodeSignKit::SignLocalCode(DEMO_AN_PATH, sig);
    NativeTokenReset(selfTokenId);
    EXPECT_EQ(ret, CS_SUCCESS);
    ret = CodeSignUtils::EnforceCodeSignForFile(DEMO_AN_PATH, sig);
    EXPECT_EQ(ret, CS_SUCCESS);
}

/**
 * @tc.name: LocalCodeSignTest_0004
 * @tc.desc: sign local code failed with invalid caller
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(LocalCodeSignTest, LocalCodeSignTest_0004, TestSize.Level0)
{
    ByteBuffer sig;
    int ret = LocalCodeSignKit::SignLocalCode(DEMO_AN_PATH, sig);
    EXPECT_EQ(ret, CS_ERR_NO_PERMISSION);
}

/**
 * @tc.name: LocalCodeSignTest_0005
 * @tc.desc: sign local code failed with wrong path
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(LocalCodeSignTest, LocalCodeSignTest_0005, TestSize.Level0)
{
    ByteBuffer sig;
    uint64_t selfTokenId = NativeTokenSet("installs");
    int ret = LocalCodeSignKit::SignLocalCode(DEMO_AN_PATH + "invalid", sig);
    NativeTokenReset(selfTokenId);
    EXPECT_EQ(ret, CS_ERR_FILE_PATH);
}

/**
 * @tc.name: LocalCodeSignTest_0006
 * @tc.desc: local codesignsvr died
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(LocalCodeSignTest, LocalCodeSignTest_0006, TestSize.Level0)
{
    LocalCodeSignClient *client = GetLocalCodeSignClient();
    EXPECT_NE(client, nullptr);
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    EXPECT_NE(systemAbilityManager, nullptr);
    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(LOCAL_CODE_SIGN_SA_ID);
    client->OnRemoteLocalCodeSignSvrDied(remoteObject);
}

/**
 * @tc.name: LocalCodeSignTest_0007
 * @tc.desc: load sa fail
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(LocalCodeSignTest, LocalCodeSignTest_0007, TestSize.Level0)
{
    LocalCodeSignLoadCallback cb;
    cb.OnLoadSystemAbilityFail(LOCAL_CODE_SIGN_SA_ID);
}

/**
 * @tc.name: LocalCodeSignTest_0008
 * @tc.desc: load sa success and return sa id not code sign sa id
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(LocalCodeSignTest, LocalCodeSignTest_0008, TestSize.Level0)
{
    LocalCodeSignLoadCallback cb;
    cb.OnLoadSystemAbilitySuccess(LOCAL_CODE_SIGN_SA_ID - 1, nullptr);
}

/**
 * @tc.name: LocalCodeSignTest_0009
 * @tc.desc: load sa success and return remote object is null
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(LocalCodeSignTest, LocalCodeSignTest_0009, TestSize.Level0)
{
    LocalCodeSignLoadCallback cb;
    cb.OnLoadSystemAbilitySuccess(LOCAL_CODE_SIGN_SA_ID, nullptr);
}
} // namespace CodeSign
} // namespace Security
} // namespace OHOS
