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
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "byte_buffer.h"
#include "openssl_utils.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
using namespace testing::ext;
using namespace std;

const std::string SIGNING_CERT_CHAIN_PEM =
"----------\n" \
"MIIDgzCCAm2gAwIBAgIBATALBgkqhkiG9w0BAQswfzELMAkGA1UEBhMCQ04xEzAR\n" \
"BgNVBAgMCmhlbGxvd29ybGQxEzARBgNVBAoMCmhlbGxvd29ybGQxEzARBgNVBAsM\n" \
"CmhlbGxvd29ybGQxFjAUBgNVBAMMDWhlbGxvd29ybGQxMTExGTAXBgkqhkiG9w0B\n" \
"CQEWCmhlbGxvd29ybGQwHhcNMjQwODA5MDkzMDEyWhcNMzQwODA5MDkzMDEyWjAa\n" \
"MRgwFgYDVQQDEw9BIEtleW1hc3RlciBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMB\n" \
"MwNCAATJqTRIhGKhLmXuJbPI311/5gEljqPbpJpXNp6oe8dOmnyJ9SQQZmMomB5u\n" \
"lC5aZIoNrCuKHTAgY1PpNNcFSBBpo4IBPDCCATgwCwYDVR0PBAQDAgeAMAgGA1Ud\n" \
"HwQBADCCAR0GDCsGAQQBj1sCgngBAwSCAQswggEHAgEAMDQCAQAGDSsGAQQBj1sC\n" \
"gngCAQQEIOIC9EG2Dn3zqle0WWjiHwk2CIP3hJuPjjQwi7z4FaFFMCICAQIGDSsG\n" \
"AQQBj1sCgngCAQIEDkxPQ0FMX1NJR05fS0VZMFwCAQIGDSsGAQQBj1sCgngCAQMw\n" \
"SAYOKwYBBAGPWwKCeAIBAwEENnsicHJvY2Vzc05hbWUiOiJsb2NhbF9jb2RlX3Np\n" \
"Z24iLCJBUEwiOiJzeXN0ZW1fYmFzaWMifTAYAgECBg0rBgEEAY9bAoJ4AgELBAQA\n" \
"AAAAMBgCAQIGDSsGAQQBj1sCgngCAQUEBAIAAAAwFgIBAgYOKwYBBAGPWwKCeAIE\n" \
"AQUB/A8wCwYJKoZIhvcNAQELA4IBAQB8zqqeaXux3qkQF0GFax7I4YWtTpoeQeJU\n" \
"BjyMk/eGmeX+ZD9absOQDzH/wH6MddzPLjoaIuoR+oxDXn2yqQ5xyGQp6uN0E8IB\n" \
"OFCjeTbRBR86A+CulTGuitszOpfyKF7SvmzfGx+ij2OtQnZ7QZp+I2YEr1Jc4ESr\n" \
"xXXt0zPslidnf7qso+f09C6U9YOnaxISfjxEqFn25+yWX2tXBJ62L6R7+zpKU3ee\n" \
"0ljf4jYtlza7s5mYJ2+OHlwdXuF38cpS59cG48UpsL0DAqywqjs5uaGthkrWo2YB\n" \
"FlAL4bVfBj2FmcqNhz+j3dgLTNA3VczwkNbj/FIY1T+FDTqnsCED\n" \
"-----END CERTIFICATE-----";

const std::string ISSUER_CERT_CHAIN_PEM =
"-----BEGIN CERTIFICATE-----\n" \
"MIIDyzCCArOgAwIBAgIBAzANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJDTjET\n" \
"MBEGA1UECAwKaGVsbG93b3JsZDETMBEGA1UECgwKaGVsbG93b3JsZDETMBEGA1UE\n" \
"CwwKaGVsbG93b3JsZDEVMBMGA1UEAwwMaGVsbG93b3JsZDExMRkwFwYJKoZIhvcN\n" \
"AQkBFgpoZWxsb3dvcmxkMB4XDTIyMDEyMjA5MjUzM1oXDTMyMDEyMDA5MjUzM1ow\n" \
"fzELMAkGA1UEBhMCQ04xEzARBgNVBAgMCmhlbGxvd29ybGQxEzARBgNVBAoMCmhl\n" \
"bGxvd29ybGQxEzARBgNVBAsMCmhlbGxvd29ybGQxFjAUBgNVBAMMDWhlbGxvd29y\n" \
"bGQxMTExGTAXBgkqhkiG9w0BCQEWCmhlbGxvd29ybGQwggEiMA0GCSqGSIb3DQEB\n" \
"AQUAA4IBDwAwggEKAoIBAQC8HHhVEbY3uuriW3wAcAMFwIUd+VImAUKnWAYlsiHL\n" \
"Ps3BhpHHb671jzP3rcQbZ2l1LSMWjoV8jXckVMOFqOlTlrYlGM3G80bVaWcEgw4c\n" \
"+nkSk+ApGmNUa69HK3h+5vfz81fVmJL1zX0VaYiA+wCzrFc1w5aGKhsFIcIY8FUo\n" \
"i15xrwAURQ+/EylzeF302qGwkCHYy4zQqn3ohku25rPLUOyOp6gJNs/3BVh76b9/\n" \
"1iTyP7ldDD7VV4UQCTDppFtrDQY/UrBhe9sPn0+6GWBfkkjz5n1aGE7JP2vmB3qM\n" \
"gxIpEkmVLVIxh6dwBOmtr+sT7xJ+UzmTWbbhNGCkzSPxAgMBAAGjUzBRMB0GA1Ud\n" \
"DgQWBBSDTqp6QOdxk9zF2H+7IGOckq/A1DAfBgNVHSMEGDAWgBRNYAEJlwxPOj5F\n" \
"B7M4mTsMpokRLzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB4\n" \
"CkKbJQWuC2pj0cS+zb4v8fRq8OPjRVPylqjHX4IMpmnl2VM0DkNXD0SYPC5IxkK4\n" \
"bgtglG0Rkr4blYf+PdNenbebWZvw4Y3JUoQgSasfdIA/rJXZtf3mVUNLmPlcRWZC\n" \
"OtGJmvlntp7/qWl7JCIaiD732baJU1DZchy3am2WWGariBESBOtoSvdywG+T0xQQ\n" \
"cXzYQ+mHPsym30JCzChvZCKz+QJlIZUJ3XgoKH7MVviASXGcWLKOBYYUDt3J8/PM\n" \
"shbsqb+rm+VqU5ohV8Rr/nQ+QLvEFa8rrz7qY6/2QSbUy7QvFCv7MXFD1kCH92FL\n" \
"GwkmWDavM1kdVMXZmV54\n" \
"-----END CERTIFICATE-----";

static ByteBuffer g_signingCert;
static ByteBuffer g_issuerCert;

static X509 *LoadPemString(const std::string &pemData)
{
    BIO *mem = BIO_new_mem_buf(pemData.c_str(), pemData.length());
    if (mem == nullptr) {
        return nullptr;
    }

    X509 *x509 = PEM_read_bio_X509(mem, nullptr, nullptr, nullptr);
    BIO_free(mem);
    return x509;
}

static void LoadDerFormPemString(const std::string &pemData, ByteBuffer &certBuffer)
{
    X509 *x509 = LoadPemString(pemData);
    if (x509 == nullptr) {
        return;
    }
    uint8_t *derTemp = nullptr;
    int32_t derTempLen = i2d_X509(x509, &derTemp);
    if (derTempLen < 0) {
        X509_free(x509);
        return;
    }

    certBuffer.CopyFrom(derTemp, static_cast<uint32_t>(derTempLen));

    X509_free(x509);
    OPENSSL_free(derTemp);
}

class OpensslUtilsTest : public testing::Test {
public:
    OpensslUtilsTest() {};
    virtual ~OpensslUtilsTest() {};
    static void SetUpTestCase()
    {
        LoadDerFormPemString(SIGNING_CERT_CHAIN_PEM, g_signingCert);
        LoadDerFormPemString(ISSUER_CERT_CHAIN_PEM, g_issuerCert);
    }
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: OpensslUtilsTest_0001
 * @tc.desc: Load cert from buffer with nullptr
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(OpensslUtilsTest, OpensslUtilsTest_0001, TestSize.Level0)
{
    X509 *cert = LoadCertFromBuffer(nullptr, 0);
    EXPECT_EQ(cert, nullptr);

    uint8_t data[1] = {0};
    cert = LoadCertFromBuffer(data, 0);
    EXPECT_EQ(cert, nullptr);
}

/**
 * @tc.name: OpensslUtilsTest_0002
 * @tc.desc: Load cert from buffer with invalid data
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(OpensslUtilsTest, OpensslUtilsTest_0002, TestSize.Level0)
{
    uint8_t invalidData[10] = {0};
    X509 *cert = LoadCertFromBuffer(invalidData, sizeof(invalidData));
    EXPECT_EQ(cert, nullptr);
}

/**
 * @tc.name: OpensslUtilsTest_0003
 * @tc.desc: Load cert from buffer with valid data
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(OpensslUtilsTest, OpensslUtilsTest_0003, TestSize.Level0)
{
    X509 *cert = LoadCertFromBuffer(g_signingCert.GetBuffer(), g_signingCert.GetSize());
    EXPECT_NE(cert, nullptr);
    if (cert != nullptr) {
        X509_free(cert);
    }
}

/**
 * @tc.name: OpensslUtilsTest_0004
 * @tc.desc: Convert cert to PEM string with empty buffer
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(OpensslUtilsTest, OpensslUtilsTest_0004, TestSize.Level0)
{
    ByteBuffer emptyCert;
    std::string pemString;
    bool ret = ConvertCertToPEMString(emptyCert, pemString);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: OpensslUtilsTest_0005
 * @tc.desc: Convert cert to PEM string with invalid data
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(OpensslUtilsTest, OpensslUtilsTest_0005, TestSize.Level0)
{
    uint8_t invalidData[10] = {0};
    ByteBuffer invalidCert;
    invalidCert.CopyFrom(invalidData, sizeof(invalidData));
    std::string pemString;
    bool ret = ConvertCertToPEMString(invalidCert, pemString);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: OpensslUtilsTest_0006
 * @tc.desc: Convert cert to PEM string with valid data
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(OpensslUtilsTest, OpensslUtilsTest_0006, TestSize.Level0)
{
    std::string pemString;
    bool ret = ConvertCertToPEMString(g_signingCert, pemString);
    EXPECT_EQ(ret, true);
    EXPECT_GT(pemString.length(), 0);
    EXPECT_NE(pemString.find("BEGIN CERTIFICATE"), std::string::npos);
    EXPECT_NE(pemString.find("END CERTIFICATE"), std::string::npos);
}

/**
 * @tc.name: OpensslUtilsTest_0007
 * @tc.desc: Make stack of certs with empty vector
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(OpensslUtilsTest, OpensslUtilsTest_0007, TestSize.Level0)
{
    std::vector<ByteBuffer> emptyChain;
    STACK_OF(X509) *certs = MakeStackOfCerts(emptyChain);
    EXPECT_NE(certs, nullptr);
    if (certs != nullptr) {
        EXPECT_EQ(sk_X509_num(certs), 0);
        sk_X509_pop_free(certs, X509_free);
    }
}

/**
 * @tc.name: OpensslUtilsTest_0008
 * @tc.desc: Make stack of certs with invalid cert
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(OpensslUtilsTest, OpensslUtilsTest_0008, TestSize.Level0)
{
    std::vector<ByteBuffer> certChain;
    uint8_t invalidData[10] = {0};
    ByteBuffer invalidCert;
    invalidCert.CopyFrom(invalidData, sizeof(invalidData));
    certChain.push_back(invalidCert);
    
    STACK_OF(X509) *certs = MakeStackOfCerts(certChain);
    EXPECT_EQ(certs, nullptr);
}

/**
 * @tc.name: OpensslUtilsTest_0009
 * @tc.desc: Make stack of certs with valid certs
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(OpensslUtilsTest, OpensslUtilsTest_0009, TestSize.Level0)
{
    std::vector<ByteBuffer> certChain;
    certChain.push_back(g_signingCert);
    certChain.push_back(g_issuerCert);
    
    STACK_OF(X509) *certs = MakeStackOfCerts(certChain);
    EXPECT_NE(certs, nullptr);
    if (certs != nullptr) {
        EXPECT_EQ(sk_X509_num(certs), 2);
        sk_X509_pop_free(certs, X509_free);
    }
}

/**
 * @tc.name: OpensslUtilsTest_0010
 * @tc.desc: Make stack of certs with mixed valid and invalid certs
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(OpensslUtilsTest, OpensslUtilsTest_0010, TestSize.Level0)
{
    std::vector<ByteBuffer> certChain;
    certChain.push_back(g_signingCert);
    uint8_t invalidData[10] = {0};
    ByteBuffer invalidCert;
    invalidCert.CopyFrom(invalidData, sizeof(invalidData));
    certChain.push_back(invalidCert);
    
    STACK_OF(X509) *certs = MakeStackOfCerts(certChain);
    EXPECT_EQ(certs, nullptr);
}

/**
 * @tc.name: OpensslUtilsTest_0011
 * @tc.desc: Create NID from OID with empty strings
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(OpensslUtilsTest, OpensslUtilsTest_0011, TestSize.Level0)
{
    int nid = CreateNIDFromOID("", "", "");
    EXPECT_NE(nid, NID_undef);
}

/**
 * @tc.name: OpensslUtilsTest_0012
 * @tc.desc: Create NID from OID with valid OID
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(OpensslUtilsTest, OpensslUtilsTest_0012, TestSize.Level0)
{
    std::string oid = "1.2.840.113549.1.9.1";
    std::string shortName = "emailAddress";
    std::string longName = "Email Address";
    int nid = CreateNIDFromOID(oid, shortName, longName);
    EXPECT_NE(nid, NID_undef);
}

/**
 * @tc.name: OpensslUtilsTest_0013
 * @tc.desc: Create NID from OID with custom OID
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(OpensslUtilsTest, OpensslUtilsTest_0013, TestSize.Level0)
{
    std::string oid = "1.2.3.4.5.6.7.8.9";
    std::string shortName = "customShortName";
    std::string longName = "Custom Long Name";
    int nid = CreateNIDFromOID(oid, shortName, longName);
    EXPECT_NE(nid, NID_undef);
}

/**
 * @tc.name: OpensslUtilsTest_0014
 * @tc.desc: Create NID from OID with same OID multiple times
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(OpensslUtilsTest, OpensslUtilsTest_0014, TestSize.Level0)
{
    std::string oid = "1.2.3.4.5.1";
    std::string shortName = "testShortName";
    std::string longName = "Test Long Name";
    int nid1 = CreateNIDFromOID(oid, shortName, longName);
    int nid2 = CreateNIDFromOID(oid, shortName, longName);
    EXPECT_NE(nid1, NID_undef);
    EXPECT_EQ(nid1, nid2);
}
}  // namespace CodeSign
}  // namespace Security
}  // namespace OHOS
