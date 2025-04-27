/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "code_sign_utils.h"
#include "code_sign_block.h"
#include "directory_ex.h"
#include "enable_key_utils.h"
#include "xpm_common.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
using namespace testing::ext;
using namespace std;

static const std::string TMP_BASE_PATH = "/data/service/el1/public/bms/bundle_manager_service/tmp";
static const std::string TEST_APP_DTAT_DIR = "/data/app/el1/bundle/public/com.example.codesignaturetest";
static const std::string APP_BASE_PATH = "/data/app/el1/bundle/public/tmp";
static const string SUBJECT = "Huawei: HarmonyOS Application Code Signature";
static const string ISSUER = "Huawei CBG Software Signing Service CA Test";
static const string OH_SUBJECT = "OpenHarmony Application Release";
static const string OH_ISSUER = "OpenHarmony Application CA";
static const std::string PROFILE_BASE_PATH = "/data/service/el0/profiles/tmp";

static const EntryMap g_hapWithoutLibRetSuc = {
    {"Hap", APP_BASE_PATH + "/demo_without_lib/demo_without_lib.hap"},
};
static const std::string g_sigWithoutLibRetSucPath =
    TMP_BASE_PATH + "/demo_without_lib/demo_without_lib.sig";

static EntryMap g_hapWithMultiLibRetSuc = {
    {"Hap",
        APP_BASE_PATH + "/demo_with_multi_lib/demo_with_multi_lib.hap"},
    {"libs/arm64-v8a/libc++_shared.so",
        APP_BASE_PATH + "/demo_with_multi_lib/libs/arm64-v8a/libc++_shared.so"},
    {"libs/arm64-v8a/libentry.so",
        APP_BASE_PATH + "/demo_with_multi_lib/libs/arm64-v8a/libentry.so"}
};
static const std::string g_sigWithMultiLibRetSucPath =
    TMP_BASE_PATH + "/demo_with_multi_lib/demo_with_multi_lib.sig";

// wrong hap and wrong lib
static EntryMap g_wrongHapWithMultiLibRetFail = {
    {"Hap",
     APP_BASE_PATH + "/demo_with_multi_lib_error/demo_with_multi_lib.hap"},
    {"libs/arm64-v8a/libc++_shared.so",
     APP_BASE_PATH + "/demo_with_multi_lib_error/libs/arm64-v8a/libc++_shared.so"},
    {"libs/arm64-v8a/libentry.so",
     APP_BASE_PATH + "/demo_with_multi_lib_error/libs/arm64-v8a/libentry.so"}};

// examples of Enforce code signature for app
static const std::vector<std::string> g_HapWithoutLibSigPkcs7ErrorPath = {
    TMP_BASE_PATH + "/demo_without_lib/pkcs7_error/demo_without_lib_001.sig", // Ilegal pkcs7 format
    TMP_BASE_PATH + "/demo_without_lib/pkcs7_error/demo_without_lib_002.sig", // Disable to find cert chain
    TMP_BASE_PATH + "/demo_without_lib/pkcs7_error/demo_without_lib_003.sig", // Don't support digest algorithm
    TMP_BASE_PATH + "/demo_without_lib/pkcs7_error/demo_without_lib_004.sig", // Don't support signature algorithm
    TMP_BASE_PATH + "/demo_without_lib/pkcs7_error/demo_without_lib_005.sig", // Wrong signature
    TMP_BASE_PATH + "/demo_without_lib/pkcs7_error/demo_without_lib_006.sig", // Expired signature
    TMP_BASE_PATH + "/demo_without_lib/pkcs7_error/demo_without_lib_007.sig", // Cert chain validate fail
    TMP_BASE_PATH + "/demo_without_lib/pkcs7_error/demo_without_lib_008.sig", // Wrong issuer
};

static const std::vector<std::string> g_HapWithMultiLibSigPkcs7ErrorPath = {
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/demo_with_multi_lib_001.sig", // Ilegal pkcs7 format
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/demo_with_multi_lib_002.sig", // Disable to find cert chain
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/demo_with_multi_lib_003.sig", // Don't support digest algorithm
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/demo_with_multi_lib_004.sig", // Don't support signature algorithm
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/demo_with_multi_lib_005.sig", // Wrong signature
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/demo_with_multi_lib_006.sig", // Expired signature
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/demo_with_multi_lib_007.sig", // Cert chain validate fail
};

// examples of Enforce code signature for file
static const std::string g_fileEnableSuc = APP_BASE_PATH + "/demo_with_multi_lib/libs/arm64-v8a/libentry.so";
static const std::string g_filesigEnablePath =
    TMP_BASE_PATH + "/demo_with_multi_lib/libs/arm64-v8a/libentry.so.fsv-sig";

// wrong format file
static const std::string g_wrongFileEnableFail =
    APP_BASE_PATH + "/demo_with_multi_lib_error/libs/arm64-v8a/libentry.so";

static const std::vector<std::string> g_fileSigEnableFailPath = {
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/file/libentry_01.so.fsv-sig", // ilegal pkcs7 format
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/file/libentry_02.so.fsv-sig", // Disable to find cert chain
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/file/libentry_03.so.fsv-sig", // Don't support digest algorithm
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/file/libentry_04.so.fsv-sig", // Don't support signature algorithm
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/file/libentry_05.so.fsv-sig", // Wrong signature
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/file/libentry_06.so.fsv-sig", // Expired signature
    TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/file/libentry_07.so.fsv-sig", // Cert chain validate fail
};

// examples of can't find the signature file
static const EntryMap g_hapSigNotExist = {
    {"sigNotExist", APP_BASE_PATH + "/demo_without_lib/demo_without_lib.hap"},
};

static bool g_isPermissive = false;

class CodeSignUtilsTest : public testing::Test {
public:
    CodeSignUtilsTest() {};
    virtual ~CodeSignUtilsTest() {};
    static void SetUpTestCase()
    {
        EXPECT_EQ(EnableTestKey(SUBJECT.c_str(), ISSUER.c_str()), 0);
        EXPECT_EQ(EnableTestKey(OH_SUBJECT.c_str(), OH_ISSUER.c_str()), 0);
        g_isPermissive = CodeSignUtils::InPermissiveMode();
        if (g_isPermissive) {
            SaveStringToFile(XPM_DEBUG_FS_MODE_PATH, ENFORCE_MODE);
        }
    };
    static void TearDownTestCase()
    {
        if (g_isPermissive) {
            SaveStringToFile(XPM_DEBUG_FS_MODE_PATH, PERMISSIVE_MODE);
        }
    };
    void SetUp() {};
    void TearDown() {};
};

static bool ReadSignatureFromFile(const std::string &path, ByteBuffer &data)
{
    FILE *file = fopen(path.c_str(), "rb");
    if (file == nullptr) {
        return false;
    }
    if (fseek(file, 0L, SEEK_END) != 0) {
        fclose(file);
        return false;
    }

    size_t fileSize = ftell(file);
    rewind(file);
    if (!data.Resize(fileSize)) {
        fclose(file);
        return false;
    }
    size_t ret = fread(data.GetBuffer(), 1, fileSize, file);
    (void)fclose(file);
    return ret == fileSize;
}

// excute the exceptional examples first, because of it's always successful
// once the same file signature verified successfully

/**
 * @tc.name: CodeSignUtilsTest_0001
 * @tc.desc: enable code signature for app failed, reason = zip file wrong foramt
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0001, TestSize.Level0)
{
    std::string sigPath = TMP_BASE_PATH + "/demo_with_multi_lib/pkcs7_error/file/libentry_01.so.fsv-sig";
    int ret = CodeSignUtils::EnforceCodeSignForApp(g_hapWithoutLibRetSuc, sigPath);
    EXPECT_EQ(ret, CS_ERR_EXTRACT_FILES);
}

/**
 * @tc.name: CodeSignUtilsTest_0002
 * @tc.desc: enable code signature for app failed, reason = no signature in the signatrue file
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0002, TestSize.Level0)
{
    int ret = CodeSignUtils::EnforceCodeSignForApp(g_hapSigNotExist, g_sigWithoutLibRetSucPath);
    EXPECT_EQ(ret, CS_ERR_NO_SIGNATURE);
}

/**
 * @tc.name: CodeSignUtilsTest_0003
 * @tc.desc: enable code signature for app failed, reason = invalied signature path
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0003, TestSize.Level0)
{
    int ret = CodeSignUtils::EnforceCodeSignForApp(
        g_hapWithoutLibRetSuc, g_sigWithoutLibRetSucPath + "invalid");
    EXPECT_EQ(ret, CS_ERR_FILE_PATH);
}


/**
 * @tc.name: CodeSignUtilsTest_0004
 * @tc.desc: enable code signature for app failed, reason = invalied hap path
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0004, TestSize.Level0)
{
    EntryMap invalid;
    invalid["Hap"] = "InvalidPath";
    int ret = CodeSignUtils::EnforceCodeSignForApp(invalid, g_sigWithoutLibRetSucPath);
    EXPECT_EQ(ret, CS_ERR_FILE_INVALID);
}

/**
 * @tc.name: CodeSignUtilsTest_0005
 * @tc.desc: enable code signature for app failed, reason = wrong format hap
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0005, TestSize.Level0)
{
    int ret = CodeSignUtils::EnforceCodeSignForApp(
        g_wrongHapWithMultiLibRetFail, g_sigWithMultiLibRetSucPath);
    EXPECT_EQ(ret, CS_ERR_ENABLE);
}

/**
 * @tc.name: CodeSignUtilsTest_0006
 * @tc.desc: enable code signature for app failed, reason = enable failed
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0006, TestSize.Level0)
{
    size_t num = g_HapWithoutLibSigPkcs7ErrorPath.size();
    int ret;
    // wrong hap signature
    for (size_t i = 0; i < num; i++) {
        ret = CodeSignUtils::EnforceCodeSignForApp(g_hapWithoutLibRetSuc, g_HapWithoutLibSigPkcs7ErrorPath[i]);
        EXPECT_EQ(ret, CS_ERR_ENABLE);
    }

    // wrong so signature
    num = g_HapWithMultiLibSigPkcs7ErrorPath.size();
    for (size_t i = 0; i < num; i++) {
        ret = CodeSignUtils::EnforceCodeSignForApp(g_hapWithMultiLibRetSuc, g_HapWithMultiLibSigPkcs7ErrorPath[i]);
        EXPECT_EQ(ret, CS_ERR_ENABLE);
    }
}

/**
 * @tc.name: CodeSignUtilsTest_0007
 * @tc.desc: enable code signature for file, reason = wrong foramt pkcs7
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0007, TestSize.Level0)
{
    ByteBuffer buffer;
    bool flag = ReadSignatureFromFile(g_filesigEnablePath, buffer);
    EXPECT_EQ(flag, true);
    int ret = CodeSignUtils::EnforceCodeSignForFile(g_wrongFileEnableFail, buffer);
    EXPECT_EQ(ret, CS_ERR_ENABLE);
}

/**
 * @tc.name: CodeSignUtilsTest_0008
 * @tc.desc: enable code signature for file, reason = enable failed
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0008, TestSize.Level0)
{
    size_t num = g_fileSigEnableFailPath.size();
    int ret;
    for (size_t i = 0; i < num; i++) {
        ByteBuffer buffer;
        bool flag = ReadSignatureFromFile(g_fileSigEnableFailPath[i], buffer);
        EXPECT_EQ(flag, true);
        ret = CodeSignUtils::EnforceCodeSignForFile(g_fileEnableSuc, buffer);
        EXPECT_EQ(ret, CS_ERR_ENABLE);
    }
}

/**
 * @tc.name: CodeSignUtilsTest_0009
 * @tc.desc: enable code signature for file failed, reason = invalid path
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0009, TestSize.Level0)
{
    ByteBuffer buffer;
    bool flag = ReadSignatureFromFile(g_filesigEnablePath, buffer);
    EXPECT_EQ(flag, true);
    int ret = CodeSignUtils::EnforceCodeSignForFile("invalidPath", buffer);
    EXPECT_EQ(ret, CS_ERR_FILE_PATH);
}

/**
 * @tc.name: CodeSignUtilsTest_0010
 * @tc.desc: enable code signature for file failed, reason = no signature
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0010, TestSize.Level0)
{
    ByteBuffer buffer;
    bool flag = ReadSignatureFromFile(g_filesigEnablePath, buffer);
    EXPECT_EQ(flag, true);

    int ret = CodeSignUtils::EnforceCodeSignForFile(g_fileEnableSuc, NULL, buffer.GetSize());
    EXPECT_EQ(ret, CS_ERR_NO_SIGNATURE);

    ret = CodeSignUtils::EnforceCodeSignForFile(g_fileEnableSuc, buffer.GetBuffer(), 0);
    EXPECT_EQ(ret, CS_ERR_NO_SIGNATURE);
}

/**
 * @tc.name: CodeSignUtilsTest_0011
 * @tc.desc: enable code signature for file successfully
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0011, TestSize.Level0)
{
    ByteBuffer buffer;
    bool flag = ReadSignatureFromFile(g_filesigEnablePath, buffer);
    EXPECT_EQ(flag, true);

    int32_t ret = CodeSignUtils::EnforceCodeSignForFile(g_fileEnableSuc, buffer);
    EXPECT_EQ(ret, CS_SUCCESS);
}

/**
 * @tc.name: CodeSignUtilsTest_0012
 * @tc.desc: enable code signature for app successfully
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0012, TestSize.Level0)
{
    int32_t ret = CodeSignUtils::EnforceCodeSignForApp(g_hapWithoutLibRetSuc, g_sigWithoutLibRetSucPath);
    EXPECT_EQ(ret, CS_SUCCESS);

    ret = CodeSignUtils::EnforceCodeSignForApp(g_hapWithMultiLibRetSuc, g_sigWithMultiLibRetSucPath);
    EXPECT_EQ(ret, CS_SUCCESS);
}

/**
 * @tc.name: CodeSignUtilsTest_0013
 * @tc.desc: parse owner ID from signature failed, reason = invalid signature
 * @tc.type: Func
 * @tc.require: issueI88PPA
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0013, TestSize.Level0)
{
    ByteBuffer buffer;
    std::string ownerID;
    std::string invalid = "invalid msg";
    buffer.CopyFrom((const uint8_t *)invalid.c_str(), invalid.length());
    int ret = CodeSignUtils::ParseOwnerIdFromSignature(buffer, ownerID);
    EXPECT_EQ(ret, CS_ERR_OPENSSL_PKCS7);
}

/**
 * @tc.name: CodeSignUtilsTest_0014
 * @tc.desc: Parse code signature for hap successfully
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0014, TestSize.Level0)
{
    std::string hapRealPath = APP_BASE_PATH + "/demo_with_multi_lib/demo_with_code_sign_block.hap";
    EntryMap entryMap;

    CodeSignBlock codeSignBlock;
    int32_t ret = codeSignBlock.ParseCodeSignBlock(hapRealPath, entryMap, FILE_SELF);
    EXPECT_EQ(ret, CS_SUCCESS);

    std::string targetFile;
    struct code_sign_enable_arg arg = {0};

    ret = codeSignBlock.GetOneFileAndCodeSignInfo(targetFile, arg, 0);
    EXPECT_EQ(ret, CS_SUCCESS);
    EXPECT_EQ(arg.version, 1);
    EXPECT_EQ(arg.cs_version, 1);
    EXPECT_EQ(arg.hash_algorithm, 1);
    EXPECT_EQ(arg.block_size, 0x1000);
    EXPECT_EQ(arg.sig_size, 0x862);
    EXPECT_EQ(arg.data_size, 0x5000);
    EXPECT_EQ(arg.salt_size, 0);
    EXPECT_EQ(arg.flags, 1);
    EXPECT_EQ(arg.tree_offset, 0x10c000);

    ret = codeSignBlock.GetOneFileAndCodeSignInfo(targetFile, arg, 0);
    EXPECT_EQ(ret, CS_SUCCESS_END);
}

/**
 * @tc.name: CodeSignUtilsTest_0015
 * @tc.desc: parse code signature for native libs successfully
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0015, TestSize.Level0)
{
    std::string hapRealPath = APP_BASE_PATH + "/demo_with_multi_lib/demo_with_code_sign_block.hap";
    EntryMap entryMap;
    std::string filePath1("libs/arm64-v8a/libc++_shared.so");
    std::string targetPath1 = TEST_APP_DTAT_DIR + "libs/arm64/libc++_shared.so";
    entryMap.emplace(filePath1, targetPath1);
    std::string filePath2("libs/arm64-v8a/libentry.so");
    std::string targetPath2 = TEST_APP_DTAT_DIR + "libs/arm64/libentry.so";
    entryMap.emplace(filePath2, targetPath2);

    CodeSignBlock codeSignBlock;
    int32_t ret = codeSignBlock.ParseCodeSignBlock(hapRealPath, entryMap, FILE_ENTRY_ONLY);
    EXPECT_EQ(ret, CS_SUCCESS);

    int32_t count = 0;
    do {
        std::string targetFile;
        struct code_sign_enable_arg arg = {0};
        ret = codeSignBlock.GetOneFileAndCodeSignInfo(targetFile, arg, 0);
        if (ret != CS_SUCCESS_END) {
            EXPECT_EQ(ret, CS_SUCCESS);
            EXPECT_EQ(arg.version, 1);
            EXPECT_EQ(arg.cs_version, 1);
            EXPECT_EQ(arg.hash_algorithm, 1);
            EXPECT_EQ(arg.block_size, 0x1000);
            EXPECT_EQ(arg.salt_size, 0);
            EXPECT_EQ(arg.flags, 0);
            EXPECT_EQ(arg.tree_offset, 0);
            count++;
            continue;
        }
    } while (ret == CS_SUCCESS);
    EXPECT_EQ(count, 0x2);
}

/**
 * @tc.name: CodeSignUtilsTest_0016
 * @tc.desc: enable code signature for app
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0016, TestSize.Level0)
{
    std::string hapRealPath = APP_BASE_PATH + "/demo_with_multi_lib/demo_with_code_sign_block.hap";
    EntryMap entryMap;
    CodeSignUtils utils;
    int32_t ret = utils.EnforceCodeSignForApp(hapRealPath, entryMap, FILE_SELF);
    EXPECT_EQ(ret, CS_SUCCESS);

    std::string filePath1("libs/arm64-v8a/libc++_shared.so");
    std::string targetPath1 = TEST_APP_DTAT_DIR + "libs/arm64/libc++_shared.so";
    entryMap.emplace(filePath1, targetPath1);
    std::string filePath2("libs/arm64-v8a/libentry.so");
    std::string targetPath2 = TEST_APP_DTAT_DIR + "libs/arm64/libentry.so";
    entryMap.emplace(filePath2, targetPath2);

    ret = utils.EnforceCodeSignForApp(hapRealPath, entryMap, FILE_ENTRY_ADD);
    EXPECT_EQ(ret, CS_SUCCESS);

    ret = utils.EnforceCodeSignForApp(hapRealPath, entryMap, FILE_ALL);
    EXPECT_EQ(ret, CS_ERR_FILE_PATH);
}

/**
 * @tc.name: CodeSignUtilsTest_0017
 * @tc.desc: enable code signature for debug app with libs
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0017, TestSize.Level0)
{
    std::string hapRealPath = APP_BASE_PATH + "/demo_with_multi_lib/entry-default-signed-debug.hap";
    EntryMap entryMap;
    CodeSignUtils utils;
    int32_t ret = utils.EnforceCodeSignForAppWithOwnerId("DEBUG_LIB_ID",
        hapRealPath, entryMap, FILE_SELF);
    EXPECT_EQ(ret, CS_SUCCESS);
}

/**
 * @tc.name: CodeSignUtilsTest_0018
 * @tc.desc: enable code signature for release app with libs
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0018, TestSize.Level0)
{
    std::string hapRealPath = APP_BASE_PATH + "/demo_with_multi_lib/entry-default-signed-release.hap";
    EntryMap entryMap;
    CodeSignUtils utils;
    int32_t ret = utils.EnforceCodeSignForAppWithOwnerId("test-app-identifier",
        hapRealPath, entryMap, FILE_SELF);
    EXPECT_EQ(ret, CS_SUCCESS);
}

/**
 * @tc.name: CodeSignUtilsTest_0019
 * @tc.desc: enable code signature for debug app with libs
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0019, TestSize.Level0)
{
    std::string hapRealPath = APP_BASE_PATH + "/demo_with_multi_lib/entry-default-signed-debug.hap";
    EntryMap entryMap;
    CodeSignUtils utils;
    int32_t ret = utils.EnforceCodeSignForAppWithOwnerId("INVALID_ID",
        hapRealPath, entryMap, FILE_SELF);
    EXPECT_EQ(ret, CS_ERR_INVALID_OWNER_ID);
}

/**
 * @tc.name: CodeSignUtilsTest_0020
 * @tc.desc: enable code signature for release app with libs
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0020, TestSize.Level0)
{
    std::string hapRealPath = APP_BASE_PATH + "/demo_with_multi_lib/entry-default-signed-release.hap";
    EntryMap entryMap;
    CodeSignUtils utils;
    int32_t ret = utils.EnforceCodeSignForAppWithOwnerId("INVALID_ID",
        hapRealPath, entryMap, FILE_SELF);
    EXPECT_EQ(ret, CS_ERR_INVALID_OWNER_ID);
}

/**
 * @tc.name: CodeSignUtilsTest_0023
 * @tc.desc: enable code signature for app
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0023, TestSize.Level0)
{
    std::string hapRealPath = APP_BASE_PATH + "/demo_with_multi_lib/demo_with_code_sign_block.hap";
    EntryMap entryMap;

    std::string filePath1("libs/arm64-v8a/libc++_shared.so");
    std::string targetPath1 = APP_BASE_PATH + "/demo_with_multi_lib/libs/arm64-v8a/code_sign_block/libc++_shared.so";
    entryMap.emplace(filePath1, targetPath1);

    CodeSignUtils utils;
    int32_t ret = utils.EnforceCodeSignForApp(hapRealPath, entryMap, FILE_ENTRY_ONLY);
    EXPECT_EQ(ret, CS_SUCCESS);

    std::string filePath2("libs/arm64-v8a/libentry.so");
    std::string targetPath2 = APP_BASE_PATH + "/demo_with_multi_lib/libs/arm64-v8a/code_sign_block/libentry.so";
    entryMap.emplace(filePath2, targetPath2);

    ret = utils.EnforceCodeSignForApp(hapRealPath, entryMap, FILE_ENTRY_ADD);
    EXPECT_EQ(ret, CS_SUCCESS);

    entryMap.clear();
    ret = utils.EnforceCodeSignForApp(hapRealPath, entryMap, FILE_ALL);
    EXPECT_EQ(ret, CS_SUCCESS);
}

/**
 * @tc.name: CodeSignUtilsTest_0024
 * @tc.desc: success without signature in permissive mode
 * @tc.type: Func
 * @tc.require: I8R8V7
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0024, TestSize.Level0)
{
    if (!SaveStringToFile(XPM_DEBUG_FS_MODE_PATH, PERMISSIVE_MODE)) {
        return;
    }
    if (!CodeSignUtils::InPermissiveMode()) {
        SaveStringToFile(XPM_DEBUG_FS_MODE_PATH, ENFORCE_MODE);
        return;
    }
    EntryMap entryMap;
    CodeSignUtils utils;
    std::string hapRealPath = APP_BASE_PATH + "/demo_without_lib/demo_without_lib.hap";
    int32_t ret = utils.EnforceCodeSignForApp(hapRealPath, entryMap, FILE_SELF);
    EXPECT_EQ(ret, CS_SUCCESS);
    SaveStringToFile(XPM_DEBUG_FS_MODE_PATH, ENFORCE_MODE);
}

/**
 * @tc.name: CodeSignUtilsTest_0025
 * @tc.desc: failed without signature in enforcing mode
 * @tc.type: Func
 * @tc.require: I8R8V7
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0025, TestSize.Level0)
{
    if (CodeSignUtils::InPermissiveMode()) {
        return;
    }
    std::string hapRealPath = APP_BASE_PATH + "/demo_without_lib/demo_without_lib.hap";
    EntryMap entryMap;
    CodeSignUtils utils;
    int32_t ret = utils.EnforceCodeSignForApp(hapRealPath, entryMap, FILE_SELF);
    EXPECT_EQ(ret, CS_CODE_SIGN_NOT_EXISTS);
}

/**
 * @tc.name: CodeSignUtilsTest_0026
 * @tc.desc: hap so mismatch scenarios
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0026, TestSize.Level0)
{
    EntryMap entryMap;
    CodeSignUtils utils;
    std::string hapRealPath = APP_BASE_PATH + "/demo_with_multi_lib/entry-default-signed-release.hap";

    std::string filePath1("libs/arm64-v8a/code_sign_block/libc++_shared.so");
    std::string targetPath1 = APP_BASE_PATH + "/demo_with_multi_lib/libs/arm64-v8a/code_sign_block/libc++_shared.so";
    entryMap.emplace(filePath1, targetPath1);
    std::string filePath2("libs/arm64-v8a/code_sign_block/libentry.so");
    std::string targetPath2 = APP_BASE_PATH + "/demo_with_multi_lib/libs/arm64-v8a/code_sign_block/libentry.so";
    entryMap.emplace(filePath2, targetPath2);

    int32_t ret = utils.EnforceCodeSignForApp(hapRealPath, entryMap, FILE_ENTRY_ADD);
    EXPECT_EQ(ret, CS_SUCCESS);
    entryMap.clear();

    ret = utils.EnforceCodeSignForAppWithOwnerId("test-app-identifier", hapRealPath, entryMap, FILE_ALL);
    EXPECT_EQ(ret, CS_ERR_NO_SIGNATURE);
}

/**
 * @tc.name: CodeSignUtilsTest_0027
 * @tc.desc: test Extension address is beyond the end of the block
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0027, TestSize.Level0)
{
    CodeSignBlock codeSignBlock;
    uintptr_t block[100] = {0};
    uintptr_t blockAddrEnd = reinterpret_cast<uintptr_t>(block + sizeof(block));
    uintptr_t extensionAddr = blockAddrEnd + 1;
    code_sign_enable_arg arg = {};

    int32_t ret = codeSignBlock.ProcessExtension(extensionAddr, blockAddrEnd, arg);
    EXPECT_EQ(ret, CS_ERR_INVALID_EXTENSION_OFFSET);
}

/**
 * @tc.name: CodeSignUtilsTest_0028
 * @tc.desc: test Extension header size exceeds block boundary
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0028, TestSize.Level0)
{
    CodeSignBlock codeSignBlock;
    uintptr_t block[100] = {0};
    uintptr_t blockAddrEnd = reinterpret_cast<uintptr_t>(block + sizeof(block));
    uintptr_t extensionAddr = blockAddrEnd - sizeof(ExtensionHeader) + 1;
    code_sign_enable_arg arg = {};

    int32_t ret = codeSignBlock.ProcessExtension(extensionAddr, blockAddrEnd, arg);
    EXPECT_EQ(ret, CS_ERR_INVALID_EXTENSION_OFFSET);
}

/**
 * @tc.name: CodeSignUtilsTest_0029
 * @tc.desc: test Process Merkle Tree Extension
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0029, TestSize.Level0)
{
    CodeSignBlock codeSignBlock;
    struct {
        ExtensionHeader header;
        MerkleTreeExtension merkleTree;
    } block;
    block.header.type = CodeSignBlock::CSB_EXTENSION_TYPE_MERKLE_TREE;
    block.header.size = sizeof(MerkleTreeExtension);
    block.merkleTree.treeOffset = 123;

    uint8_t fakeRootHash[64] = {0xde, 0xad, 0xbe, 0xef};
    std::copy(std::begin(fakeRootHash), std::end(fakeRootHash), std::begin(block.merkleTree.rootHash));

    uintptr_t blockAddrEnd = reinterpret_cast<uintptr_t>(&block + 1);
    uintptr_t extensionAddr = reinterpret_cast<uintptr_t>(&block);
    code_sign_enable_arg arg = {};

    int32_t ret = codeSignBlock.ProcessExtension(extensionAddr, blockAddrEnd, arg);
    EXPECT_EQ(ret, CS_SUCCESS);
    EXPECT_EQ(arg.tree_offset, 123);
    EXPECT_EQ(arg.root_hash_ptr, reinterpret_cast<uintptr_t>(block.merkleTree.rootHash));
    EXPECT_EQ(arg.flags, CodeSignBlock::CSB_SIGN_INFO_MERKLE_TREE);
}

/**
 * @tc.name: CodeSignUtilsTest_0030
 * @tc.desc: test Process Page Info Extension
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0030, TestSize.Level0)
{
    CodeSignBlock codeSignBlock;
    struct {
        ExtensionHeader header;
        PageInfoExtension pageInfo;
    } block;
    block.header.type = CodeSignBlock::CSB_EXTENSION_TYPE_PAGE_INFO;
    block.header.size = sizeof(PageInfoExtension) + 50;
    block.pageInfo.sign_size = 30;
    block.pageInfo.unitSize = 2;

    uint8_t fakeSignature[64] = {0xde, 0xad, 0xbe, 0xef};
    std::copy(std::begin(fakeSignature), std::begin(fakeSignature)
            + block.pageInfo.sign_size, block.pageInfo.signature);

    block.pageInfo.mapSize = 100;
    block.pageInfo.mapOffset = 200;

    uintptr_t blockAddrEnd = reinterpret_cast<uintptr_t>(&block + 1);
    uintptr_t extensionAddr = reinterpret_cast<uintptr_t>(&block);
    code_sign_enable_arg arg = {};

    int32_t ret = codeSignBlock.ProcessExtension(extensionAddr, blockAddrEnd, arg);
    EXPECT_EQ(ret, CS_SUCCESS);
    EXPECT_EQ(arg.sig_size, 30);
    EXPECT_EQ(arg.sig_ptr, reinterpret_cast<uintptr_t>(block.pageInfo.signature));
    EXPECT_EQ(arg.pgtypeinfo_size, 100);
    EXPECT_EQ(arg.pgtypeinfo_off, 200);
    EXPECT_EQ(arg.cs_version, CodeSignBlock::CSB_EXTENSION_TYPE_PAGE_INFO_VERSION);
    EXPECT_EQ(arg.flags, 2 << 1);
}

/**
 * @tc.name: CodeSignUtilsTest_0031
 * @tc.desc: test Invalid Page Info Extension Sign Size
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0031, TestSize.Level0)
{
    CodeSignBlock codeSignBlock;
    struct {
        ExtensionHeader header;
        PageInfoExtension pageInfo;
    } block;
    block.header.type = CodeSignBlock::CSB_EXTENSION_TYPE_PAGE_INFO;
    block.header.size = sizeof(PageInfoExtension);
    block.pageInfo.sign_size = sizeof(PageInfoExtension) + 1;

    uintptr_t blockAddrEnd = reinterpret_cast<uintptr_t>(&block + 1);
    uintptr_t extensionAddr = reinterpret_cast<uintptr_t>(&block);
    code_sign_enable_arg arg = {};

    int32_t ret = codeSignBlock.ProcessExtension(extensionAddr, blockAddrEnd, arg);
    EXPECT_EQ(ret, CS_ERR_EXTENSION_SIGN_SIZE);
}

/**
 * @tc.name: CodeSignUtilsTest_0032
 * @tc.desc: test invalid PageInfoExtension UnitSize
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0032, TestSize.Level0)
{
    CodeSignBlock codeSignBlock;
    struct {
        ExtensionHeader header;
        PageInfoExtension pageInfo;
    } block;
    block.header.type = CodeSignBlock::CSB_EXTENSION_TYPE_PAGE_INFO;
    block.header.size = sizeof(PageInfoExtension);
    block.pageInfo.unitSize = CodeSignBlock::CSB_SIGN_INFO_MAX_PAGEINFO_UNITSIZE + 1;

    uintptr_t blockAddrEnd = reinterpret_cast<uintptr_t>(&block + 1);
    uintptr_t extensionAddr = reinterpret_cast<uintptr_t>(&block);
    code_sign_enable_arg arg = {};

    int32_t ret = codeSignBlock.ProcessExtension(extensionAddr, blockAddrEnd, arg);
    EXPECT_EQ(ret, CS_ERR_INVALID_PAGE_INFO_EXTENSION);
}

/**
 * @tc.name: CodeSignUtilsTest_0033
 * @tc.desc: enable code signature for app, entryPath is nullptr
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0033, TestSize.Level0)
{
    EntryMap entryPath = {};
    int32_t ret = CodeSignUtils::EnforceCodeSignForApp(entryPath, g_sigWithMultiLibRetSucPath);
    EXPECT_EQ(ret, CS_SUCCESS);
}

/**
 * @tc.name: CodeSignUtilsTest_0034
 * @tc.desc: Enable key in profile content data and dump profile buffer
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0034, TestSize.Level0)
{
    std::string bundleName = "";
    const ByteBuffer profileBuffer;
    int32_t ret = CodeSignUtils::EnableKeyInProfile(bundleName, profileBuffer);
#ifdef NO_USE_CLANG_COVERAGE
    EXPECT_EQ(ret, CS_ERR_PROFILE);
#else
    EXPECT_EQ(ret, CS_SUCCESS);
#endif
}

/**
 * @tc.name: CodeSignUtilsTest_0035
 * @tc.desc: Remove key in profile content data and remove profile
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0035, TestSize.Level0)
{
    std::string bundleName = "";
    int32_t ret = CodeSignUtils::RemoveKeyInProfile(bundleName);
#ifdef NO_USE_CLANG_COVERAGE
    EXPECT_EQ(ret, CS_ERR_PROFILE);
#else
    EXPECT_EQ(ret, CS_SUCCESS);
#endif
}

/**
 * @tc.name: CodeSignUtilsTest_0036
 * @tc.desc: enabling code signing for app compiled by oh-sdk
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0036, TestSize.Level0)
{
#ifdef SUPPORT_OH_CODE_SIGN
    EXPECT_EQ(CodeSignUtils::IsSupportOHCodeSign(), true);
#else
    EXPECT_EQ(CodeSignUtils::IsSupportOHCodeSign(), false);
#endif
}

/**
 * @tc.name: CodeSignUtilsTest_0037
 * @tc.desc: succ with signature in enforcing mode
 * @tc.type: Func
 * @tc.require: I8R8V7
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0037, TestSize.Level0)
{
    if (CodeSignUtils::InPermissiveMode()) {
        return;
    }
    std::string hapRealPath = APP_BASE_PATH + "/demo_without_lib_signed/demo_without_lib_signed.hap";
    EntryMap entryMap;
    CodeSignUtils utils;
    int32_t ret = utils.EnforceCodeSignForApp(hapRealPath, entryMap, FILE_SELF);
    EXPECT_EQ(ret, CS_SUCCESS);
}

/**
 * @tc.name: CodeSignUtilsTest_0038
 * @tc.desc: enable code signature for app with hnp
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(CodeSignUtilsTest, CodeSignUtilsTest_0038, TestSize.Level0)
{
    EntryMap entryMap;
    CodeSignUtils utils;
    std::string hapRealPath = APP_BASE_PATH + "/demo_with_hnp/demo_with_hnp_signed.hap";

    std::string filePath1("hnp/armeabi-v7a/hnpsample.hnp!///bin//hnpsample");
    std::string targetPath1 = APP_BASE_PATH + "/demo_with_hnp/bins/hnpsample";
    entryMap.emplace(filePath1, targetPath1);
    std::string filePath2("hnp/armeabi-v7a/hnpsample.hnp!///lib//libhnpsamplelib.z.so");
    std::string targetPath2 = APP_BASE_PATH + "/demo_with_hnp/bins/libhnpsamplelib.z.so";
    entryMap.emplace(filePath2, targetPath2);

    int32_t ret = utils.EnforceCodeSignForApp(hapRealPath, entryMap, FILE_ENTRY_ONLY);
    EXPECT_EQ(ret, CS_SUCCESS);
    entryMap.clear();
}
}  // namespace CodeSign
}  // namespace Security
}  // namespace OHOS
