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

#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "code_sign_utils_in_c.h"
#include "errcode.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
using namespace testing::ext;
using namespace std;

static constexpr int32_t ENTRYMAP_COUNT = 2;
static const std::string APP_BASE_PATH = "/data/app/el1/bundle/public/tmp";

class CodeSignUtilsInCTest : public testing::Test {
public:
    CodeSignUtilsInCTest() {};
    virtual ~CodeSignUtilsInCTest() {};
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: CodeSignUtilsInCTest_0001
 * @tc.desc: enable code signature for app with the c interface
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsInCTest, CodeSignUtilsInCTest_0001, TestSize.Level0)
{
    std::string hapRealPath = APP_BASE_PATH + "/demo_with_multi_lib/demo_with_code_sign_block.hap";
    std::string filePath1("libs/arm64-v8a/libc++_shared.so");
    std::string targetPath1 = APP_BASE_PATH + "/demo_with_multi_lib/libs/arm64-v8a/code_sign_block/libc++_shared.so";
    std::string filePath2("libs/arm64-v8a/libentry.so");
    std::string targetPath2 = APP_BASE_PATH + "/demo_with_multi_lib/libs/arm64-v8a/code_sign_block/libentry.so";

    EntryMapEntryData *entryMapEntryData = static_cast<EntryMapEntryData *>(malloc(sizeof(EntryMapEntryData)));
    (void)memset_s(entryMapEntryData, sizeof(EntryMapEntryData), 0, sizeof(EntryMapEntryData));

    int32_t length = sizeof(EntryMapEntry) * ENTRYMAP_COUNT;
    EntryMapEntry *entryMapEntry = static_cast<EntryMapEntry *>(malloc(length));
    (void)memset_s(entryMapEntry, length, 0, length);

    entryMapEntry[0].key = const_cast<char *>(filePath1.c_str());
    entryMapEntry[0].value = const_cast<char *>(targetPath1.c_str());
    entryMapEntry[1].key = const_cast<char *>(filePath2.c_str());
    entryMapEntry[1].value = const_cast<char *>(targetPath2.c_str());

    entryMapEntryData->count = ENTRYMAP_COUNT;
    entryMapEntryData->entries = entryMapEntry;

    int32_t ret = EnforceCodeSignForApp(hapRealPath.c_str(), entryMapEntryData, FILE_ALL);
    EXPECT_EQ(ret, CS_SUCCESS);

    free(entryMapEntry);
    free(entryMapEntryData);
    entryMapEntry = nullptr;
    entryMapEntryData = nullptr;
}

/**
 * @tc.name: CodeSignUtilsInCTest_0002
 * @tc.desc: enable code signature for app with the c interface, nullptr
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsInCTest, CodeSignUtilsInCTest_0002, TestSize.Level0)
{
    std::string hapRealPath = APP_BASE_PATH + "/demo_with_multi_lib/demo_with_code_sign_block.hap";
    int32_t ret = EnforceCodeSignForApp(nullptr, nullptr, FILE_ALL);
    EXPECT_EQ(ret, CS_ERR_PARAM_INVALID);

    ret = EnforceCodeSignForApp(hapRealPath.c_str(), nullptr, FILE_ALL);
    EXPECT_EQ(ret, CS_ERR_PARAM_INVALID);
}

/**
 * @tc.name: CodeSignUtilsInCTest_0003
 * @tc.desc: enable code signature for app with the c interface, entryMapEntry is nullptr
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsInCTest, CodeSignUtilsInCTest_0003, TestSize.Level0)
{
    std::string hapRealPath = APP_BASE_PATH + "/demo_with_multi_lib/demo_with_code_sign_block.hap";
    std::string filePath1("libs/arm64-v8a/libc++_shared.so");
    std::string targetPath1 = APP_BASE_PATH + "/demo_with_multi_lib/libs/arm64-v8a/code_sign_block/libc++_shared.so";
    std::string filePath2("libs/arm64-v8a/libentry.so");
    std::string targetPath2 = APP_BASE_PATH + "/demo_with_multi_lib/libs/arm64-v8a/code_sign_block/libentry.so";

    EntryMapEntryData *entryMapEntryData = static_cast<EntryMapEntryData *>(malloc(sizeof(EntryMapEntryData)));
    (void)memset_s(entryMapEntryData, sizeof(EntryMapEntryData), 0, sizeof(EntryMapEntryData));

    int32_t length = sizeof(EntryMapEntry) * ENTRYMAP_COUNT;
    EntryMapEntry *entryMapEntry = static_cast<EntryMapEntry *>(malloc(length));
    (void)memset_s(entryMapEntry, length, 0, length);

    entryMapEntry[0].key = nullptr;
    entryMapEntry[0].value = nullptr;
    entryMapEntry[1].key = nullptr;
    entryMapEntry[1].value = nullptr;

    entryMapEntryData->count = ENTRYMAP_COUNT;
    entryMapEntryData->entries = entryMapEntry;

    int32_t ret = EnforceCodeSignForApp(hapRealPath.c_str(), entryMapEntryData, FILE_ALL);
    EXPECT_EQ(ret, CS_ERR_PARAM_INVALID);

    entryMapEntry[0].key = const_cast<char *>(filePath1.c_str());
    entryMapEntryData->entries = entryMapEntry;

    ret = EnforceCodeSignForApp(hapRealPath.c_str(), entryMapEntryData, FILE_ALL);
    EXPECT_EQ(ret, CS_ERR_PARAM_INVALID);

    entryMapEntry[0].value = const_cast<char *>(targetPath1.c_str());
    entryMapEntryData->entries = entryMapEntry;

    ret = EnforceCodeSignForApp(hapRealPath.c_str(), entryMapEntryData, FILE_ALL);
    EXPECT_EQ(ret, CS_ERR_PARAM_INVALID);

    free(entryMapEntry);
    free(entryMapEntryData);
    entryMapEntry = nullptr;
    entryMapEntryData = nullptr;
}
}  // namespace CodeSign
}  // namespace Security
}  // namespace OHOS
