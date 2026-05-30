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

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>

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

static EVP_PKEY *GenerateRsaKey()
{
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (ctx == nullptr) {
        return nullptr;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static X509 *CreateTestCert(EVP_PKEY *pkey, const char *cnName)
{
    X509 *cert = X509_new();
    if (cert == nullptr) {
        return nullptr;
    }
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
    X509_set_pubkey(cert, pkey);
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<unsigned char *>(const_cast<char *>(cnName)), -1, -1, 0);
    X509_set_issuer_name(cert, name);
    return cert;
}

static X509_EXTENSION *CreateExtension(const char *oid, const char *shortName,
    const char *longName, const unsigned char *data, int dataLen)
{
    int nid = OBJ_txt2nid(oid);
    if (nid == NID_undef) {
        nid = OBJ_create(oid, shortName, longName);
    }
    if (nid == NID_undef) {
        return nullptr;
    }
    ASN1_OCTET_STRING *octet = ASN1_OCTET_STRING_new();
    if (octet == nullptr) {
        return nullptr;
    }
    ASN1_OCTET_STRING_set(octet, data, dataLen);
    X509_EXTENSION *ext = X509_EXTENSION_create_by_NID(nullptr, nid, 0, octet);
    ASN1_OCTET_STRING_free(octet);
    return ext;
}

static bool AddExtensionToCert(X509 *cert, X509_EXTENSION *ext)
{
    if (cert == nullptr || ext == nullptr) {
        return false;
    }
    bool result = X509_add_ext(cert, ext, -1) > 0;
    X509_EXTENSION_free(ext);
    return result;
}

static std::vector<uint8_t> SignCertAndSerialize(X509 *&cert, EVP_PKEY *&pkey)
{
    std::vector<uint8_t> derData;
    if (X509_sign(cert, pkey, EVP_sha256()) <= 0) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        cert = nullptr;
        pkey = nullptr;
        return derData;
    }
    int len = i2d_X509(cert, nullptr);
    if (len <= 0) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        cert = nullptr;
        pkey = nullptr;
        return derData;
    }
    derData.resize(len);
    unsigned char *p = derData.data();
    i2d_X509(cert, &p);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    cert = nullptr;
    pkey = nullptr;
    return derData;
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

/**
 * @tc.name: KeyEnableUtilsTest_0012
 * @tc.desc: test enterprise resign cert
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, KeyEnableUtilsTest_0012, TestSize.Level0)
{
    EnterpriseResignCertInfo info = {};
    int ret = AddEnterpriseResignCert(info);
    ASSERT_EQ(ret == 0, false);
    
    ret = RemoveEnterpriseResignCert(info);
    ASSERT_EQ(ret == 0, false);
}

/**
 * @tc.name: UnlockEventHelperTest_0001
 * @tc.desc: check device unlocked
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, UnlockEventHelperTest_0001, TestSize.Level0)
{
    ASSERT_EQ(CheckUserUnlock(), true);
}

/**
 * @tc.name: CheckCertHasEnterpriseResignExtension_0001
 * @tc.desc: test with nullptr and zero certificate size
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, CheckCertHasEnterpriseResignExtension_0001, TestSize.Level0)
{
    int32_t ret = CheckCertHasEnterpriseResignExtension(nullptr, 100);
    ASSERT_EQ(ret, CS_ERR_PARAM_INVALID);
    uint8_t certData[] = {0x01, 0x02, 0x03};
    ret = CheckCertHasEnterpriseResignExtension(certData, 0);
    ASSERT_EQ(ret, CS_ERR_PARAM_INVALID);
}

/**
 * @tc.name: CheckCertHasEnterpriseResignExtension_0002
 * @tc.desc: test with invalid certificate data
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, CheckCertHasEnterpriseResignExtension_0002, TestSize.Level0)
{
    uint8_t invalidCertData[] = {0x01, 0x02, 0x03, 0x04};
    int32_t ret = CheckCertHasEnterpriseResignExtension(invalidCertData, sizeof(invalidCertData));
    ASSERT_EQ(ret, CS_ERR_PARAM_INVALID);
}

/**
 * @tc.name: CheckCertHasEnterpriseResignExtension_0003
 * @tc.desc: test with valid certificate without enterprise resign extension
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, CheckCertHasEnterpriseResignExtension_0003, TestSize.Level0)
{
    ByteBuffer certData;
    ASSERT_TRUE(ReadDataFromFile(TEST_CA_CERT_PATH, certData));
    int32_t ret = CheckCertHasEnterpriseResignExtension(certData.GetBuffer(), certData.GetSize());
    ASSERT_EQ(ret, CS_ERR_PARAM_INVALID);
}

/**
 * @tc.name: CheckCertHasEnterpriseResignExtension_0005
 * @tc.desc: test with certificate containing other custom OID but not enterprise resign
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, CheckCertHasEnterpriseResignExtension_0005, TestSize.Level0)
{
    EVP_PKEY *pkey = GenerateRsaKey();
    ASSERT_NE(pkey, nullptr);
    X509 *cert = CreateTestCert(pkey, "OtherOidTest");
    ASSERT_NE(cert, nullptr);
    X509_EXTENSION *ext = CreateExtension("1.3.6.1.4.1.2011.2.376.1.8", "BinaryCertID", "Binary Cert ID",
        reinterpret_cast<const unsigned char *>("test"), 4);
    ASSERT_NE(ext, nullptr);
    ASSERT_TRUE(AddExtensionToCert(cert, ext));
    std::vector<uint8_t> derData = SignCertAndSerialize(cert, pkey);
    ASSERT_GT(derData.size(), 0);
    int32_t ret = CheckCertHasEnterpriseResignExtension(derData.data(), derData.size());
    EXPECT_EQ(ret, CS_ERR_PARAM_INVALID);
}

/**
 * @tc.name: CheckCertHasEnterpriseResignExtension_0006
 * @tc.desc: test with truncated DER data
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, CheckCertHasEnterpriseResignExtension_0006, TestSize.Level0)
{
    EVP_PKEY *pkey = GenerateRsaKey();
    ASSERT_NE(pkey, nullptr);
    X509 *cert = CreateTestCert(pkey, "TruncTest");
    ASSERT_NE(cert, nullptr);
    std::vector<uint8_t> derData = SignCertAndSerialize(cert, pkey);
    ASSERT_GT(derData.size(), 0);
    uint32_t truncatedSize = derData.size() / 2;
    int32_t ret = CheckCertHasEnterpriseResignExtension(derData.data(), truncatedSize);
    EXPECT_EQ(ret, CS_ERR_PARAM_INVALID);
}

/**
 * @tc.name: CheckCertHasEnterpriseResignExtension_0007
 * @tc.desc: test with certificate containing enterprise resign extension
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, CheckCertHasEnterpriseResignExtension_0007, TestSize.Level0)
{
    EVP_PKEY *pkey = GenerateRsaKey();
    ASSERT_NE(pkey, nullptr);
    X509 *cert = CreateTestCert(pkey, "EnterpriseTest");
    ASSERT_NE(cert, nullptr);
    X509_EXTENSION *ext = CreateExtension("1.3.6.1.4.1.2011.2.376.1.9", "EnterpriseAppResignCertID",
        "Enterprise App Resign Cert ID", reinterpret_cast<const unsigned char *>("test"), 4);
    ASSERT_NE(ext, nullptr);
    ASSERT_TRUE(AddExtensionToCert(cert, ext));
    std::vector<uint8_t> derData = SignCertAndSerialize(cert, pkey);
    ASSERT_GT(derData.size(), 0);
    int32_t ret = CheckCertHasEnterpriseResignExtension(derData.data(), derData.size());
    EXPECT_EQ(ret, CS_SUCCESS);
}

/**
 * @tc.name: CheckCertHasBinaryCertExtension_0001
 * @tc.desc: test with nullptr and zero certificate size
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, CheckCertHasBinaryCertExtension_0001, TestSize.Level0)
{
    int32_t ret = CheckCertHasBinaryCertExtension(nullptr, 100);
    ASSERT_EQ(ret, CS_ERR_PARAM_INVALID);
    uint8_t certData[] = {0x01, 0x02, 0x03};
    ret = CheckCertHasBinaryCertExtension(certData, 0);
    ASSERT_EQ(ret, CS_ERR_PARAM_INVALID);
}

/**
 * @tc.name: CheckCertHasBinaryCertExtension_0002
 * @tc.desc: test with invalid certificate data
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, CheckCertHasBinaryCertExtension_0002, TestSize.Level0)
{
    uint8_t invalidCertData[] = {0x01, 0x02, 0x03, 0x04};
    int32_t ret = CheckCertHasBinaryCertExtension(invalidCertData, sizeof(invalidCertData));
    ASSERT_EQ(ret, CS_ERR_PARAM_INVALID);
}

/**
 * @tc.name: CheckCertHasBinaryCertExtension_0003
 * @tc.desc: test with valid certificate without binary cert extension
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, CheckCertHasBinaryCertExtension_0003, TestSize.Level0)
{
    ByteBuffer certData;
    ASSERT_TRUE(ReadDataFromFile(TEST_CA_CERT_PATH, certData));
    int32_t ret = CheckCertHasBinaryCertExtension(certData.GetBuffer(), certData.GetSize());
    ASSERT_EQ(ret, CS_ERR_PARAM_INVALID);
}

/**
 * @tc.name: CheckCertHasBinaryCertExtension_0004
 * @tc.desc: test with certificate containing binary cert extension
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, CheckCertHasBinaryCertExtension_0004, TestSize.Level0)
{
    EVP_PKEY *pkey = GenerateRsaKey();
    ASSERT_NE(pkey, nullptr);
    X509 *cert = CreateTestCert(pkey, "BinaryCertTest");
    ASSERT_NE(cert, nullptr);
    X509_EXTENSION *ext = CreateExtension("1.3.6.1.4.1.2011.2.376.1.8", "BinaryCertID", "Binary Cert ID",
        reinterpret_cast<const unsigned char *>("test"), 4);
    ASSERT_NE(ext, nullptr);
    ASSERT_TRUE(AddExtensionToCert(cert, ext));
    std::vector<uint8_t> derData = SignCertAndSerialize(cert, pkey);
    ASSERT_GT(derData.size(), 0);
    int32_t ret = CheckCertHasBinaryCertExtension(derData.data(), derData.size());
    EXPECT_EQ(ret, CS_SUCCESS);
}

/**
 * @tc.name: CheckCertHasBinaryCertExtension_0005
 * @tc.desc: test with certificate containing enterprise resign OID but not binary cert OID
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, CheckCertHasBinaryCertExtension_0005, TestSize.Level0)
{
    EVP_PKEY *pkey = GenerateRsaKey();
    ASSERT_NE(pkey, nullptr);
    X509 *cert = CreateTestCert(pkey, "NoBinaryExtTest");
    ASSERT_NE(cert, nullptr);
    X509_EXTENSION *ext = CreateExtension("1.3.6.1.4.1.2011.2.376.1.9", "EnterpriseAppResignCertID",
        "Enterprise App Resign Cert ID", reinterpret_cast<const unsigned char *>("test"), 4);
    ASSERT_NE(ext, nullptr);
    ASSERT_TRUE(AddExtensionToCert(cert, ext));
    std::vector<uint8_t> derData = SignCertAndSerialize(cert, pkey);
    ASSERT_GT(derData.size(), 0);
    int32_t ret = CheckCertHasBinaryCertExtension(derData.data(), derData.size());
    EXPECT_EQ(ret, CS_ERR_PARAM_INVALID);
}

/**
 * @tc.name: CheckCertHasBinaryCertExtension_0006
 * @tc.desc: test with truncated DER data
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, CheckCertHasBinaryCertExtension_0006, TestSize.Level0)
{
    EVP_PKEY *pkey = GenerateRsaKey();
    ASSERT_NE(pkey, nullptr);
    X509 *cert = CreateTestCert(pkey, "TruncBinaryTest");
    ASSERT_NE(cert, nullptr);
    std::vector<uint8_t> derData = SignCertAndSerialize(cert, pkey);
    ASSERT_GT(derData.size(), 0);
    uint32_t truncatedSize = derData.size() / 2;
    int32_t ret = CheckCertHasBinaryCertExtension(derData.data(), truncatedSize);
    EXPECT_EQ(ret, CS_ERR_PARAM_INVALID);
}

/**
 * @tc.name: CheckCertHasBinaryCertExtension_0007
 * @tc.desc: test with certificate containing both binary cert and enterprise resign extensions
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(KeyEnableUtilsTest, CheckCertHasBinaryCertExtension_0007, TestSize.Level0)
{
    EVP_PKEY *pkey = GenerateRsaKey();
    ASSERT_NE(pkey, nullptr);
    X509 *cert = CreateTestCert(pkey, "DualExtTest");
    ASSERT_NE(cert, nullptr);
    X509_EXTENSION *ext1 = CreateExtension("1.3.6.1.4.1.2011.2.376.1.9", "EnterpriseAppResignCertID",
        "Enterprise App Resign Cert ID", reinterpret_cast<const unsigned char *>("ent"), 3);
    ASSERT_NE(ext1, nullptr);
    ASSERT_TRUE(AddExtensionToCert(cert, ext1));
    X509_EXTENSION *ext2 = CreateExtension("1.3.6.1.4.1.2011.2.376.1.8", "BinaryCertID",
        "Binary Cert ID", reinterpret_cast<const unsigned char *>("bin"), 3);
    ASSERT_NE(ext2, nullptr);
    ASSERT_TRUE(AddExtensionToCert(cert, ext2));
    std::vector<uint8_t> derData = SignCertAndSerialize(cert, pkey);
    ASSERT_GT(derData.size(), 0);
    int32_t ret = CheckCertHasBinaryCertExtension(derData.data(), derData.size());
    EXPECT_EQ(ret, CS_SUCCESS);
}

} // namespace CodeSign
} // namespace Security
} // namespace OHOS
