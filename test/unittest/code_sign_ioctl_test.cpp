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
#include <unistd.h>

namespace OHOS {
namespace Security {
namespace CodeSign {
using namespace std;
using namespace testing::ext;

struct cert_chain_info {
    uint32_t signing_length;
    uint32_t issuer_length;
    uint64_t signing;
    uint64_t issuer;
    uint32_t max_cert_chain;
    uint8_t reserved[36];
};

#define WRITE_CERT_CHAIN _IOW('k', 1, cert_chain_info)

static const uint32_t MAX_CERT_CHAIN = 3;
static const uint32_t GREATER_THAN_MAX_CERT_CHAIN = 4;
static const uint32_t LESS_THAN_MIN_CERT_CHAIN = -1;

static const string DEV_NAME = "/dev/code_sign";
static const string TEST_SUBJECT = "OpenHarmony Application Release";
static const string TEST_ISSUER = "OpenHarmony Application CA";

static bool CallIoctl(const char *signing, const char *issuer, uint32_t max_cert_chain)
{
    int fd = open(DEV_NAME.c_str(), O_WRONLY);
    EXPECT_GE(fd, 0);

    cert_chain_info arg = { 0 };
    arg.signing = reinterpret_cast<uint64_t>(signing);
    arg.issuer = reinterpret_cast<uint64_t>(issuer);
    arg.signing_length = strlen(signing) + 1;
    arg.issuer_length = strlen(issuer) + 1;
    arg.max_cert_chain = max_cert_chain;
    int ret = ioctl(fd, WRITE_CERT_CHAIN, &arg);

    close(fd);
    return ret;
}

class CodeSignIoctlTest : public testing::Test {
public:
    CodeSignIoctlTest() {};
    virtual ~CodeSignIoctlTest() {};
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: CodeSignIoctlTest_0001
 * @tc.desc: successfully called interface
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignIoctlTest, CodeSignIoctlTest_0001, TestSize.Level0)
{
    int ret = CallIoctl(TEST_SUBJECT.c_str(), TEST_ISSUER.c_str(), MAX_CERT_CHAIN);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: CodeSignIoctlTest_0002
 * @tc.desc: calling interface with greater than path len
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignIoctlTest, CodeSignIoctlTest_0002, TestSize.Level0)
{
    int ret = CallIoctl(TEST_SUBJECT.c_str(), TEST_ISSUER.c_str(), GREATER_THAN_MAX_CERT_CHAIN);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: CodeSignIoctlTest_0003
 * @tc.desc: calling interface with invalid path len
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignIoctlTest, CodeSignIoctlTest_0003, TestSize.Level0)
{
    int ret = CallIoctl(TEST_SUBJECT.c_str(), TEST_ISSUER.c_str(), LESS_THAN_MIN_CERT_CHAIN);
    EXPECT_NE(ret, 0);
}
} // namespace CodeSign
} // namespace Security
} // namespace OHOS