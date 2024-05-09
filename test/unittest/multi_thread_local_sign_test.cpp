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

#include <cstdlib>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <gtest/hwext/gtest-multithread.h>
#include <string>

#include "access_token_setter.h"
#include "byte_buffer.h"
#include "code_sign_utils.h"
#include "local_code_sign_kit.h"
#include "local_key_helper.h"
#include "log.h"

using namespace OHOS::Security::CodeSign;
using namespace std;
using namespace testing::ext;
using namespace testing::mt;

namespace OHOS {
namespace Security {
namespace CodeSign {
static constexpr uint32_t MULTI_THREAD_NUM = 10;
static constexpr int64_t BUFFER_SIZE = 1024;
static const std::string AN_BASE_PATH = "/data/local/ark-cache/tmp/multi_thread/";
static const std::string ORIGIN_AN_FILE = AN_BASE_PATH + "demo.an";
static const std::string DEMO_WITHOWNER_ID = AN_BASE_PATH + "demoWithownerID.an";

static const char *VALID_CALLER = "compiler_service";

uint64_t GetFileSize(int32_t fd)
{
    struct stat st;
    if (fstat(fd, &st) != 0) {
        LOG_ERROR("Stat file failed, errno = <%{public}d, %{public}s>",
            errno, strerror(errno));
        return 0;
    }
    return st.st_size;
}

static bool DupFile(const std::string &path)
{
    int32_t fin = open(ORIGIN_AN_FILE.c_str(), O_RDONLY);
    if (fin < 0) {
        return false;
    }
    uint32_t fileSize = GetFileSize(fin);
    int32_t fout = open(path.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0777);
    if (fout < 0) {
        close(fin);
        return false;
    }
    ssize_t curSize = 0;
    char buffer[BUFFER_SIZE];
    bool ret = true;
    while (curSize < fileSize) {
        ssize_t len = read(fin, buffer, BUFFER_SIZE);
        if (len <= 0) {
            break;
        }
        curSize += len;
        write(fout, buffer, len);
    }
    close(fin);
    close(fout);
    return ret;
}

void LocalCodeSignAndEnforce()
{
    ByteBuffer sig;
    uint64_t selfTokenId = NativeTokenSet(VALID_CALLER);
    int ret = LocalCodeSignKit::SignLocalCode(ORIGIN_AN_FILE, sig);
    std::thread::id thisId = std::this_thread::get_id();
    std::ostringstream oss;
    oss << thisId;
    std::string thisIdStr = oss.str();
    std::string tmpFileName = AN_BASE_PATH + thisIdStr + ".an";
    EXPECT_EQ(DupFile(tmpFileName), true);
    NativeTokenReset(selfTokenId);
    EXPECT_EQ(ret, CS_SUCCESS);
    ret = CodeSignUtils::EnforceCodeSignForFile(tmpFileName, sig);
    EXPECT_EQ(ret, GetEnforceFileResult());
}

void LocalCodeSignAndEnforceWithOwnerID()
{
    ByteBuffer sig;
    uint64_t selfTokenId = NativeTokenSet(VALID_CALLER);
    std::string ownerID = "AppName123";
    int ret = LocalCodeSignKit::SignLocalCode(ownerID, DEMO_WITHOWNER_ID, sig);
    std::thread::id thisId = std::this_thread::get_id();
    std::ostringstream oss;
    oss << thisId;
    std::string thisIdStr = oss.str();
    std::string tmpFileName = AN_BASE_PATH + thisIdStr + "demoWithownerID.an";
    EXPECT_EQ(DupFile(tmpFileName), true);
    NativeTokenReset(selfTokenId);
    EXPECT_EQ(ret, CS_SUCCESS);
    ret = CodeSignUtils::EnforceCodeSignForFile(tmpFileName, sig);
    EXPECT_EQ(ret, GetEnforceFileResult());
}

class MultiThreadLocalSignTest : public testing::Test {
public:
    MultiThreadLocalSignTest() {};
    virtual ~MultiThreadLocalSignTest() {};
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: MultiThreadLocalSignTest_0001
 * @tc.desc: sign AN files and enforce using multi threads
 * @tc.type: Func
 * @tc.require:
 */
HWMTEST_F(MultiThreadLocalSignTest, MultiThreadLocalSignTest_0001, TestSize.Level1, MULTI_THREAD_NUM)
{
    LocalCodeSignAndEnforce();
}

/**
 * @tc.name: MultiThreadLocalSignTest_0002
 * @tc.desc: sign AN files with owner ID and enforce using multi threads
 * @tc.type: Func
 * @tc.require:
 */
HWMTEST_F(MultiThreadLocalSignTest, MultiThreadLocalSignTest_0002, TestSize.Level1, MULTI_THREAD_NUM)
{
    LocalCodeSignAndEnforceWithOwnerID();
}
} // namespace CodeSign
} // namespace Security
} // namespace OHOS