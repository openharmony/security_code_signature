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

#include <asm/unistd.h>
#include <cstdint>
#include <cstdlib>
#include <gtest/gtest.h>
#include <fcntl.h>
#include <iostream>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/fsverity.h>
#include <linux/types.h>
#include <linux/ioctl.h>

#include "byte_buffer.h"
#include "directory_ex.h"
#include "enable_key_utils.h"
#include "log.h"
#include "xpm_common.h"
#include "code_sign_attr_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace CodeSign {
constexpr uint32_t HASH_PAGE_SIZE = 4096;
constexpr uint32_t BUFFER_LENGTH = 4096;

const std::string TEST_FILES_DIR = "/data/test/tmp/";
const std::string TEST_FILES_LIST[] = {
    "file_4K/file_4K",
    "file_4K_greater/file_4K_greater",
    "file_4K_less/file_4K_less",
    "file_4M/file_4M",
    "file_4M_greater/file_4M_greater",
    "file_4M_less/file_4M_less"
};
const int TEST_FILE_NUM = sizeof(TEST_FILES_LIST) / sizeof(TEST_FILES_LIST[0]);
const std::string TEST_DEFAULT_FILE = TEST_FILES_DIR + "file_4M_greater/file_4M_greater";
const std::string FAKE_STRING = "AAAAA";

const std::string TEST_SUBJECT = "OpenHarmony Application Release";
const std::string TEST_ISSUER = "OpenHarmony Application CA";

const std::string DROP_CACHE_PROC_PATH = "/proc/sys/vm/drop_caches";
const std::string DROP_ALL_CACHE_LEVEL = "3";


static bool g_isXpmOn;

class EnableVerityTest : public testing::Test {
public:
    EnableVerityTest() {};
    virtual ~EnableVerityTest() {};
    static void SetUpTestCase()
    {
        EXPECT_EQ(EnableTestKey(TEST_SUBJECT.c_str(), TEST_ISSUER.c_str()), 0);
        EXPECT_EQ(SetXpmOwnerId(PROCESS_OWNERID_COMPAT, NULL), 0);
        g_isXpmOn = AllocXpmRegion();
        SaveStringToFile(SELINUX_MODE_PATH, PERMISSIVE_MODE);
        SaveStringToFile(XPM_DEBUG_FS_MODE_PATH, ENFORCE_MODE);
        if (g_isXpmOn) {
            std::string realPath;
            g_isXpmOn = OHOS::PathToRealPath(XPM_DEBUG_FS_MODE_PATH, realPath);
        }
    };
    static void TearDownTestCase()
    {
        SaveStringToFile(XPM_DEBUG_FS_MODE_PATH, PERMISSIVE_MODE);
    };
    void SetUp() {};
    void TearDown() {};
};
 
static size_t GetFileSize(const std::string &path)
{
    FILE *file = fopen(path.c_str(), "rb");
    if (file == nullptr) {
        return false;
    }
    if (fseek(file, 0L, SEEK_END) != 0) {
        (void)fclose(file);
        return false;
    }
    size_t fileSize = ftell(file);
    (void)fclose(file);
    return fileSize;
}

static bool ReadDataFromFile(const std::string &path, ByteBuffer &data)
{
    FILE *file = fopen(path.c_str(), "rb");
    if (file == nullptr) {
        return false;
    }
    if (fseek(file, 0L, SEEK_END) != 0) {
        (void)fclose(file);
        return false;
    }

    size_t fileSize = ftell(file);
    if (fileSize == 0) {
        (void)fclose(file);
        return true;
    }
    rewind(file);
    if (!data.Resize(fileSize)) {
        (void)fclose(file);
        return false;
    }
    size_t ret = fread(data.GetBuffer(), 1, fileSize, file);
    (void)fclose(file);
    if (ret < fileSize) {
        LOG_ERROR(LABEL, "Read size (%{public}zu) < file size", ret);
        return false;
    }
    return true;
}

static void CopyData(const std::string &srcPath, FILE *fout)
{
    ByteBuffer data;
    EXPECT_EQ(ReadDataFromFile(srcPath, data), true);
    if (data.GetSize() > 0) {
        int32_t ret = fwrite(data.GetBuffer(), 1, data.GetSize(), fout);
        EXPECT_EQ(static_cast<uint32_t>(ret), data.GetSize());
    }
}

static bool CopyFile(const std::string &srcPath, const std::string &dstPath)
{
    FILE *fout = fopen(dstPath.c_str(), "wb");
    if (fout == nullptr) {
        return false;
    }
    CopyData(srcPath, fout);
    (void)fclose(fout);
    return true;
}

static void CleanFile(const std::string &filePath)
{
    EXPECT_EQ(OHOS::RemoveFile(filePath), true);
}

static bool ExpandFile(const std::string &srcPath, const std::string &expandDataFile,
    size_t gapSize, const std::string &dstPath)
{
    FILE *fout = fopen(dstPath.c_str(), "wb");
    if (fout == nullptr) {
        return false;
    }
    CopyData(srcPath, fout);
    uint8_t buffer[BUFFER_LENGTH];
    (void)memset_s(buffer, BUFFER_LENGTH, 0, BUFFER_LENGTH);
    size_t writeSize = BUFFER_LENGTH;
    size_t totalSize = 0;
    size_t ret;
    while (totalSize < gapSize) {
        if (gapSize - totalSize < BUFFER_LENGTH) {
            writeSize = gapSize - totalSize;
        }
        ret = fwrite(buffer, 1, writeSize, fout);
        if (ret != writeSize) {
            (void)fclose(fout);
            return false;
        }
        LOG_ERROR(LABEL, "write padding = %{public}zu", writeSize);
        totalSize += writeSize;
    }
    CopyData(expandDataFile, fout);
    (void)fclose(fout);
    return true;
}

static void CheckEnableSuccess(const std::string &filePath)
{
    // drop all caches
    SaveStringToFile(DROP_CACHE_PROC_PATH, DROP_ALL_CACHE_LEVEL);
    FILE *fout = fopen(filePath.c_str(), "wb");
    EXPECT_EQ(fout, nullptr);

    ByteBuffer tmp;
    EXPECT_EQ(ReadDataFromFile(filePath, tmp), true);
}

static inline size_t GetRoundUp(size_t fileSize)
{
    return ceil(static_cast<double>(fileSize) / HASH_PAGE_SIZE) *
        HASH_PAGE_SIZE;
}

static bool TamperFileTail(const std::string &filePath)
{
    FILE *file = fopen(filePath.c_str(), "ab");
    if (file == nullptr) {
        return false;
    }
    if (fseek(file, 0L, SEEK_END) != 0) {
        (void)fclose(file);
        return false;
    }

    size_t fileSize = ftell(file);
    if (fseek(file, fileSize - FAKE_STRING.size(), SEEK_SET)) {
        (void)fclose(file);
        return false;
    }
    int32_t ret = fwrite(FAKE_STRING.c_str(), 1, FAKE_STRING.size(), file);
    EXPECT_EQ(ret, FAKE_STRING.size());
    (void)fclose(file);
    return true;
}

static bool TamperFileHead(const std::string &filePath)
{
    FILE *file = fopen(filePath.c_str(), "ab");
    if (file == nullptr) {
        return false;
    }
    if (fseek(file, 0L, SEEK_SET) != 0) {
        (void)fclose(file);
        return false;
    }

    int32_t ret = fwrite(FAKE_STRING.c_str(), 1, FAKE_STRING.size(), file);
    EXPECT_EQ(ret, FAKE_STRING.size());
    (void)fclose(file);
    return true;
}

int32_t EnableVerityOnOneFile(const std::string filePath,
    struct code_sign_enable_arg *arg)
{
    int fd = open(filePath.c_str(), O_RDONLY);
    int ret = 0;

    int error = ioctl(fd, FS_IOC_ENABLE_CODE_SIGN, arg);
    if (error < 0) {
        LOG_ERROR(LABEL, "Enable fs-verity failed, errno = <%{public}d, %{public}s>",
            errno, strerror(errno));
        ret = errno;
    }
    close(fd);
    return ret;
}

static std::string MakeExpandTreeFile(const std::string &filePath,
    struct code_sign_enable_arg *arg)
{
    size_t treeOffset = GetRoundUp(arg->data_size);
    std::string expandFilePath = filePath + "_expand_tree";
    EXPECT_EQ(ExpandFile(filePath, filePath + ".tree",
        treeOffset - arg->data_size, expandFilePath), true);
    return expandFilePath;
}

static void FillCommonArgs(const std::string &filePath, bool isInsideTree,
    struct code_sign_enable_arg *arg, ByteBuffer &signature)
{
    bool ret;

    if (isInsideTree) {
        ret = ReadDataFromFile(filePath + "_inside_tree.sig", signature);
    } else {
        ret = ReadDataFromFile(filePath + "_no_tree.sig", signature);
    }
    EXPECT_EQ(ret, true);

    size_t fileSize = GetFileSize(filePath);
    arg->version = 1;
    arg->cs_version = 1;    // version of code signing features
    arg->hash_algorithm = 1;
    arg->block_size = HASH_PAGE_SIZE;
    arg->salt_ptr = 0;
    arg->salt_size = 0;
    arg->data_size = fileSize;
    arg->sig_size = signature.GetSize();
    arg->sig_ptr = reinterpret_cast<uintptr_t>(signature.GetBuffer());
}

static void FillOptional(const std::string &filePath, struct code_sign_enable_arg *arg,
    ByteBuffer &rootHash)
{
    EXPECT_EQ(ReadDataFromFile(filePath + ".hash", rootHash), true);
    arg->flags = 1;
    arg->tree_offset = GetRoundUp(arg->data_size);
    arg->root_hash_ptr = reinterpret_cast<uintptr_t>(rootHash.GetBuffer());
}

static void EnableExpandedTamperFile(const std::string &filePath,
    bool (*tamperFileFunc)(const std::string &filePath))
{
    struct code_sign_enable_arg arg = {};
    ByteBuffer signature;
    ByteBuffer rootHash;
    FillCommonArgs(filePath, true, &arg, signature);
    FillOptional(filePath, &arg, rootHash);

    // tamper file
    std::string tmpFilePath = filePath + "_tmp";
    EXPECT_EQ(CopyFile(filePath, tmpFilePath), true);
    EXPECT_EQ(tamperFileFunc(tmpFilePath), true);

    // expand tampered file
    std::string treeFile = filePath + ".tree";
    std::string expandFilePath = filePath + "_expand_tree";
    size_t treeOffset = GetRoundUp(arg.data_size);
    EXPECT_EQ(ExpandFile(tmpFilePath, treeFile,
        treeOffset - arg.data_size, expandFilePath), true);

    // Enable successully but cannot read
    EXPECT_EQ(EnableVerityOnOneFile(expandFilePath, &arg), 0);
    SaveStringToFile(DROP_CACHE_PROC_PATH, DROP_ALL_CACHE_LEVEL);
    ByteBuffer tmp;
    EXPECT_EQ(ReadDataFromFile(expandFilePath, tmp), false);

    CleanFile(expandFilePath);
    CleanFile(tmpFilePath);
}

/**
 * @tc.name: CodeSignUtilsTest_0001
 * @tc.desc: enable all data in file successfully
 * @tc.type: Func
 * @tc.require:I8DH28
 */
HWTEST_F(EnableVerityTest, EnableVerityTest_0001, TestSize.Level0)
{
    for (int i = 0; i < TEST_FILE_NUM; i++) {
        std::string filePath = TEST_FILES_DIR + TEST_FILES_LIST[i];
        LOG_INFO(LABEL, "Test on file path = %{public}s", filePath.c_str());
        struct code_sign_enable_arg arg = {};
        ByteBuffer signature;
        FillCommonArgs(filePath, false, &arg, signature);
        std::string copiedFile = filePath + "_copy";
        EXPECT_EQ(CopyFile(filePath, copiedFile), true);
        EXPECT_EQ(EnableVerityOnOneFile(copiedFile, &arg), 0);
        CheckEnableSuccess(copiedFile);
        CleanFile(copiedFile);
    }
}

/**
 * @tc.name: CodeSignUtilsTest_0002
 * @tc.desc: enable orignial file with wrong file size
 * @tc.type: Func
 * @tc.require:I8DH28
 */
HWTEST_F(EnableVerityTest, EnableVerityTest_0002, TestSize.Level0)
{
    std::string filePath = TEST_DEFAULT_FILE;

    struct code_sign_enable_arg arg = {};
    ByteBuffer signature;
    FillCommonArgs(filePath, false, &arg, signature);

    std::string copiedFile = filePath + "_copy";
    EXPECT_EQ(CopyFile(filePath, copiedFile), true);

    uint32_t fileSize = arg.data_size;
    // size is set to less than file size
    // descriptor is unmatched, signature verification failed.
    arg.data_size = fileSize - 1;
    EXPECT_EQ(EnableVerityOnOneFile(copiedFile, &arg), EKEYREJECTED);

    // size is set to greater than file size
    // unable to pass parameter check
    arg.data_size = fileSize + 1;
    EXPECT_EQ(EnableVerityOnOneFile(copiedFile, &arg), EINVAL);

    CleanFile(copiedFile);
}

/**
 * @tc.name: CodeSignUtilsTest_0003
 * @tc.desc: enable expanded file successfully
 * @tc.type: Func
 * @tc.require:I8DH28
 */
HWTEST_F(EnableVerityTest, EnableVerityTest_0003, TestSize.Level0)
{
    for (int i = 0; i < TEST_FILE_NUM; i++) {
        std::string filePath = TEST_FILES_DIR + TEST_FILES_LIST[i];
        struct code_sign_enable_arg arg = {};
        ByteBuffer signature;
        FillCommonArgs(filePath, false, &arg, signature);

        std::string expandFilePath = MakeExpandTreeFile(filePath, &arg);
        EXPECT_EQ(EnableVerityOnOneFile(expandFilePath, &arg), 0);
        CheckEnableSuccess(expandFilePath);
        CleanFile(expandFilePath);
    }
}

/**
 * @tc.name: CodeSignUtilsTest_0004
 * @tc.desc: enable expanded file with inside tree successfully
 * @tc.type: Func
 * @tc.require:I8DH28
 */
HWTEST_F(EnableVerityTest, EnableVerityTest_0004, TestSize.Level0)
{
    for (int i = 0; i < TEST_FILE_NUM; i++) {
        std::string filePath = TEST_FILES_DIR + TEST_FILES_LIST[i];
        LOG_INFO(LABEL, "Test on file path = %{public}s", filePath.c_str());

        struct code_sign_enable_arg arg = {};
        ByteBuffer signature;
        ByteBuffer rootHash;
        FillCommonArgs(filePath, true, &arg, signature);
        FillOptional(filePath, &arg, rootHash);
        std::string expandFilePath = MakeExpandTreeFile(filePath, &arg);
        EXPECT_EQ(EnableVerityOnOneFile(expandFilePath, &arg), 0);
        CheckEnableSuccess(expandFilePath);
        CleanFile(expandFilePath);
    }
}

/**
 * @tc.name: CodeSignUtilsTest_0005
 * @tc.desc: enable expanded file with wrong tree offset
 * @tc.type: Func
 * @tc.require:I8DH28
 */
HWTEST_F(EnableVerityTest, EnableVerityTest_0005, TestSize.Level0)
{
    std::string filePath = TEST_DEFAULT_FILE;
    struct code_sign_enable_arg arg = {};
    ByteBuffer signature;
    ByteBuffer rootHash;
    FillCommonArgs(filePath, true, &arg, signature);
    FillOptional(filePath, &arg, rootHash);
    std::string expandFilePath = MakeExpandTreeFile(filePath, &arg);

    uint32_t treeOffset = arg.tree_offset;
    // byte alignment check failed
    arg.tree_offset = treeOffset + 1;
    EXPECT_EQ(EnableVerityOnOneFile(expandFilePath, &arg), EINVAL);

    // unmatched fsverity descriptor
    arg.tree_offset = treeOffset - HASH_PAGE_SIZE;
    EXPECT_EQ(EnableVerityOnOneFile(expandFilePath, &arg), EKEYREJECTED);

    CleanFile(expandFilePath);
}

/**
 * @tc.name: CodeSignUtilsTest_0006
 * @tc.desc: enable expanded file with wrong root hash
 * @tc.type: Func
 * @tc.require:I8DH28
 */
HWTEST_F(EnableVerityTest, EnableVerityTest_0006, TestSize.Level0)
{
    std::string filePath = TEST_DEFAULT_FILE;
    struct code_sign_enable_arg arg = {};
    ByteBuffer signature;
    ByteBuffer rootHash;
    FillCommonArgs(filePath, true, &arg, signature);
    FillOptional(filePath, &arg, rootHash);
    std::string expandFilePath = MakeExpandTreeFile(filePath, &arg);

    (void)memcpy_s(reinterpret_cast<void *>(arg.root_hash_ptr),
        FAKE_STRING.size(), FAKE_STRING.c_str(), FAKE_STRING.size());

    EXPECT_EQ(EnableVerityOnOneFile(expandFilePath, &arg), EKEYREJECTED);

    CleanFile(expandFilePath);
}

/**
 * @tc.name: CodeSignUtilsTest_0007
 * @tc.desc: enable expanded file with wrong file
 * @tc.type: Func
 * @tc.require:I8DH28
 */
HWTEST_F(EnableVerityTest, EnableVerityTest_0007, TestSize.Level0)
{
    std::string filePath = TEST_DEFAULT_FILE;
    EnableExpandedTamperFile(filePath, TamperFileHead);

    EnableExpandedTamperFile(filePath, TamperFileTail);
}

/**
 * @tc.name: CodeSignUtilsTest_0008
 * @tc.desc: mmap signed data in xpm region success
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(EnableVerityTest, EnableVerityTest_0008, TestSize.Level0)
{
    if (!g_isXpmOn) {
        return;
    }
    std::string filePath = TEST_DEFAULT_FILE;
    struct code_sign_enable_arg arg = {};
    ByteBuffer signature;
    ByteBuffer rootHash;
    FillCommonArgs(filePath, true, &arg, signature);
    FillOptional(filePath, &arg, rootHash);
    std::string expandFilePath = MakeExpandTreeFile(filePath, &arg);
    EXPECT_EQ(EnableVerityOnOneFile(expandFilePath, &arg), 0);

    int fd = open(expandFilePath.c_str(), O_RDONLY);
    // mmap with MAP_XPM flag, success
    void *addr = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE | MAP_XPM,
        fd, 0);
    EXPECT_NE(MAP_FAILED, addr);

    // release resource
    munmap(addr, PAGE_SIZE);
    close(fd);
    CleanFile(expandFilePath);
}

/**
 * @tc.name: CodeSignUtilsTest_0009
 * @tc.desc: mmap unsigned data in xpm region failed
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(EnableVerityTest, EnableVerityTest_0009, TestSize.Level0)
{
    if (!g_isXpmOn) {
        return;
    }
    std::string filePath = TEST_DEFAULT_FILE;
    struct code_sign_enable_arg arg = {};
    ByteBuffer signature;
    ByteBuffer rootHash;
    FillCommonArgs(filePath, true, &arg, signature);
    FillOptional(filePath, &arg, rootHash);
    std::string expandFilePath = MakeExpandTreeFile(filePath, &arg);
    EXPECT_EQ(EnableVerityOnOneFile(expandFilePath, &arg), 0);

    int fd = open(expandFilePath.c_str(), O_RDONLY);
    // mmap with MAP_XPM flag, over verity range
    void *addr = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE | MAP_XPM,
        fd, arg.tree_offset & PAGE_MASK);
    EXPECT_EQ(MAP_FAILED, addr);

    close(fd);
    CleanFile(expandFilePath);
}

/**
 * @tc.name: CodeSignUtilsTest_0010
 * @tc.desc: mmap signed data as executable success
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(EnableVerityTest, EnableVerityTest_0010, TestSize.Level0)
{
    if (!g_isXpmOn) {
        return;
    }
    std::string filePath = TEST_FILES_DIR + "elf/elf";
    struct code_sign_enable_arg arg = {};
    ByteBuffer signature;
    ByteBuffer rootHash;
    FillCommonArgs(filePath, true, &arg, signature);
    FillOptional(filePath, &arg, rootHash);
    std::string expandFilePath = MakeExpandTreeFile(filePath, &arg);
    EXPECT_EQ(EnableVerityOnOneFile(expandFilePath, &arg), 0);

    int fd = open(expandFilePath.c_str(), O_RDONLY);
    // readelf from elf
    // [19] .text             PROGBITS        000063ec 0053ec 002168 00  AX  0   0  4
    int codeOffset = 0x53ec;
    // mmap success at enforce mode
    void *addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_PRIVATE,
        fd, codeOffset & PAGE_MASK);
    EXPECT_NE(MAP_FAILED, addr);

    // release resource
    munmap(addr, PAGE_SIZE);

    close(fd);
    CleanFile(expandFilePath);
}

/**
 * @tc.name: CodeSignUtilsTest_00011
 * @tc.desc: mmap unsigned data as executable failed
 * @tc.type: Func
 * @tc.require
 */
HWTEST_F(EnableVerityTest, EnableVerityTest_0011, TestSize.Level0)
{
    if (!g_isXpmOn) {
        return;
    }
    std::string filePath = TEST_FILES_DIR + "elf/elf";
    struct code_sign_enable_arg arg = {};
    ByteBuffer signature;
    ByteBuffer rootHash;
    FillCommonArgs(filePath, true, &arg, signature);
    FillOptional(filePath, &arg, rootHash);
    std::string expandFilePath = MakeExpandTreeFile(filePath, &arg);
    EXPECT_EQ(EnableVerityOnOneFile(expandFilePath, &arg), 0);

    int fd = open(expandFilePath.c_str(), O_RDONLY);
    void *addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_PRIVATE,
        fd, arg.tree_offset & PAGE_MASK);
    EXPECT_EQ(MAP_FAILED, addr);

    close(fd);
    CleanFile(expandFilePath);
}
}  // namespace CodeSign
}  // namespace Security
}  // namespace OHOS
