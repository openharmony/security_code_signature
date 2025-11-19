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
#include <parameters.h>
#include <string>
#include <vector>

#include "log.h"
#include "errcode.h"
#include "byte_buffer.h"
#include "cert_path.h"
#include "key_utils.h"
#include "cert_path.h"
#include "key_enable_adapter.h"

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
static const std::string TEST_CA_CERT_PATH = "/data/test/tmp/testcacert.der";

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

/**
 * @tc.name: KeyEnableUtilsTest_0002
 * @tc.desc: activate cert with invalid cert
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, KeyEnableUtilsTest_0002, TestSize.Level0)
{
    const char *cert = "error";
    CertActivationInfo info;
    info.cert_type = 0;
    info.status = 0;
    info.cert = (uint64_t)cert;
    info.cert_length = strlen(cert);
    int ret = ActivateCert(info);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(errno, 1);
}

static bool ReadDataFromFile(const std::string &path, ByteBuffer &data)
{
    FILE *file = fopen(path.c_str(), "rb");
    if (file == nullptr) {
        LOG_ERROR("Fail to read file %{public}s", path.c_str());
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
        LOG_ERROR("Read size (%{public}zu) < file size", ret);
        return false;
    }
    return true;
}

/**
 * @tc.name: KeyEnableUtilsTest_0003
 * @tc.desc: activate cert with invalid cert_type
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, KeyEnableUtilsTest_0003, TestSize.Level0)
{
    ByteBuffer cert_data;
    ReadDataFromFile(TEST_CA_CERT_PATH, cert_data);
    uint8_t *cert = cert_data.GetBuffer();
    CertActivationInfo info;
    info.cert_type = 3;
    info.status = 0;
    info.cert = (uint64_t)cert;
    info.cert_length = cert_data.GetSize();
    int ret = ActivateCert(info);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(errno, 1);
}

/**
 * @tc.name: KeyEnableUtilsTest_0004
 * @tc.desc: activate cert with invalid status
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, KeyEnableUtilsTest_0004, TestSize.Level0)
{
    ByteBuffer cert_data;
    ReadDataFromFile(TEST_CA_CERT_PATH, cert_data);
    uint8_t *cert = cert_data.GetBuffer();
    CertActivationInfo info;
    info.cert_type = 0;
    info.status = 3;
    info.cert = (uint64_t)cert;
    info.cert_length = cert_data.GetSize();
    int ret = ActivateCert(info);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(errno, 1);
}

/**
 * @tc.name: KeyEnableUtilsTest_0005
 * @tc.desc: activate cert with wrong cert length
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, KeyEnableUtilsTest_0005, TestSize.Level0)
{
    ByteBuffer cert_data;
    ReadDataFromFile(TEST_CA_CERT_PATH, cert_data);
    uint8_t *cert = cert_data.GetBuffer();
    CertActivationInfo info;
    info.cert_type = 0;
    info.status = 0;
    info.cert = (uint64_t)cert;
    info.cert_length = cert_data.GetSize() + 5;
    int ret = ActivateCert(info);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(errno, 1);
}

/**
 * @tc.name: KeyEnableUtilsTest_0006
 * @tc.desc: activate cert with wrong type
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, KeyEnableUtilsTest_0006, TestSize.Level0)
{
    ByteBuffer cert_data;
    ReadDataFromFile(TEST_CA_CERT_PATH, cert_data);
    uint8_t *cert = cert_data.GetBuffer();
    CertActivationInfo info;
    info.cert_type = 1;
    info.status = 0;
    info.cert = (uint64_t)cert;
    info.cert_length = cert_data.GetSize();
    int ret = ActivateCert(info);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(errno, 1);
}

/**
 * @tc.name: KeyEnableUtilsTest_0007
 * @tc.desc: activate cert with wrong status
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, KeyEnableUtilsTest_0007, TestSize.Level0)
{
    ByteBuffer cert_data;
    ReadDataFromFile(TEST_CA_CERT_PATH, cert_data);
    uint8_t *cert = cert_data.GetBuffer();
    CertActivationInfo info;
    info.cert_type = 0;
    info.status = 1;
    info.cert = (uint64_t)cert;
    info.cert_length = cert_data.GetSize();
    int ret = ActivateCert(info);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(errno, 1);
}

/**
 * @tc.name: KeyEnableUtilsTest_0008
 * @tc.desc: activate cert with NULL cert
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, KeyEnableUtilsTest_0008, TestSize.Level0)
{
    const char *cert = nullptr;
    CertActivationInfo info;
    info.cert_type = 0;
    info.status = 0;
    info.cert = (uint64_t)cert;
    info.cert_length = 5;
    int ret = ActivateCert(info);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(errno, 1);
}

/**
 * @tc.name: KeyEnableUtilsTest_0009
 * @tc.desc: Activate cert non-exist
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, KeyEnableUtilsTest_0009, TestSize.Level0)
{
    ByteBuffer cert_data;
    ReadDataFromFile(TEST_CA_CERT_PATH, cert_data);
    uint8_t *cert = cert_data.GetBuffer();
    CertActivationInfo info;
    info.cert_type = 0;
    info.status = 0;
    info.cert = (uint64_t)cert;
    info.cert_length = cert_data.GetSize();
    int ret = ActivateCert(info);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(errno, 1);
}

/**
 * @tc.name: KeyEnableUtilsTest_0010
 * @tc.desc: Test init local cert
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, KeyEnableUtilsTest_0010, TestSize.Level0)
{
    std::vector<uint8_t> buffer;
    buffer.resize(8192);
    uint32_t size;
    ASSERT_EQ(InitLocalCertificate(buffer.data(), &size), CS_ERR_NO_PERMISSION);
}

/**
 * @tc.name: KeyEnableUtilsTest_0011
 * @tc.desc: check device enterprise type
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, KeyEnableUtilsTest_0011, TestSize.Level0)
{
    std::string key = "const.edm.is_enterprise_device";
    bool param = OHOS::system::GetBoolParameter(key, false);
    bool deviceCheck = IsEnterpriseDevice();
    ASSERT_EQ(param, deviceCheck);
}
} // namespace CodeSign
} // namespace Security
} // namespace OHOS
