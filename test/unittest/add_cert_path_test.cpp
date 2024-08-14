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

#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <ctime>
#include <unistd.h>

#include "cert_path.h"
#include "selinux/selinux.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
using namespace std;
using namespace testing::ext;

static const uint32_t MAX_CERT_CHAIN = 3;
static const uint32_t CERT_PATH_TYPE = 0x103;
static const uint32_t GREATER_THAN_MAX_CERT_CHAIN = 4;
static const uint32_t LESS_THAN_MIN_CERT_CHAIN = -1;

static const string DEV_NAME = "/dev/code_sign";
static const string TEST_SUBJECT = "OpenHarmony Application Release";
static const string TEST_ISSUER = "OpenHarmony Application CA";
static const string KEY_ENABLE_CTX = "u:r:key_enable:s0";
static const string FAKE_SUBJECT = "Fake subject";
static const string FAKE_ISSUER = "Fake issuer";
static const string SUBJECT_AS_SYSTEM_TYPE = "System subject";
static const string ISSUER_AS_SYSTEM_TYPE = "System issuer";

class AddCertPathTest : public testing::Test {
public:
    AddCertPathTest() {};
    virtual ~AddCertPathTest() {};
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

static CertPathInfo MakeCertPathInfo(const char *signing, const char *issuer,
    uint32_t max_cert_chain, uint32_t cert_path_type)
{
    CertPathInfo arg = { 0 };
    arg.signing = reinterpret_cast<uint64_t>(signing);
    arg.issuer = reinterpret_cast<uint64_t>(issuer);
    arg.signing_length = strlen(signing);
    arg.issuer_length = strlen(issuer);
    arg.path_len = max_cert_chain;
    arg.path_type = cert_path_type;
    return arg;
}

/**
 * @tc.name: AddCertPathTest_0001
 * @tc.desc: calling interface with greater than path len
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(AddCertPathTest, AddCertPathTest_0001, TestSize.Level0)
{
    CertPathInfo certPathInfo = MakeCertPathInfo(TEST_SUBJECT.c_str(), TEST_ISSUER.c_str(),
        GREATER_THAN_MAX_CERT_CHAIN, CERT_PATH_TYPE);
    EXPECT_NE(AddCertPath(certPathInfo), 0);
}

/**
 * @tc.name: AddCertPathTest_0002
 * @tc.desc: calling interface with invalid path len
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(AddCertPathTest, AddCertPathTest_0002, TestSize.Level0)
{
    CertPathInfo certPathInfo = MakeCertPathInfo(TEST_SUBJECT.c_str(), TEST_ISSUER.c_str(),
        LESS_THAN_MIN_CERT_CHAIN, CERT_PATH_TYPE);
    EXPECT_NE(AddCertPath(certPathInfo), 0);
}

/**
 * @tc.name: AddCertPathTest_0003
 * @tc.desc: add cert path success
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(AddCertPathTest, AddCertPathTest_0003, TestSize.Level0)
{
    // type = developer in release
    CertPathInfo certPathInfo = MakeCertPathInfo(FAKE_SUBJECT.c_str(), FAKE_ISSUER.c_str(), MAX_CERT_CHAIN, 0x3);
    EXPECT_EQ(AddCertPath(certPathInfo), 0);
    EXPECT_EQ(RemoveCertPath(certPathInfo), 0);

    // type = developer in debug
    certPathInfo = MakeCertPathInfo(FAKE_SUBJECT.c_str(), FAKE_ISSUER.c_str(), MAX_CERT_CHAIN, 0x103);
    EXPECT_EQ(AddCertPath(certPathInfo), 0);
    EXPECT_EQ(RemoveCertPath(certPathInfo), 0);

    // remove unexists
    EXPECT_NE(RemoveCertPath(certPathInfo), 0);
}

/**
 * @tc.name: AddCertPathTest_0004
 * @tc.desc: cannot add system cert except key_enable
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(AddCertPathTest, AddCertPathTest_0004, TestSize.Level0)
{
    // release
    CertPathInfo certPathInfo = MakeCertPathInfo(SUBJECT_AS_SYSTEM_TYPE.c_str(),
        ISSUER_AS_SYSTEM_TYPE.c_str(), MAX_CERT_CHAIN, 1);
    // cannot add except key_enable
    EXPECT_NE(AddCertPath(certPathInfo), 0);
}
} // namespace CodeSign
} // namespace Security
} // namespace OHOS