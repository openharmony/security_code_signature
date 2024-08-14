/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#include <string>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "access_token_setter.h"
#include "byte_buffer.h"
#include "huks_attest_verifier.h"
#include "log.h"

using namespace OHOS::Security::CodeSign;
using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace CodeSign {
const std::string SIGNING_CERT_CHAIN_PEM =
"-----BEGIN CERTIFICATE-----\n" \
"MIIDgzCCAm2gAwIBAgIBATALBgkqhkiG9w0BAQswfzELMAkGA1UEBhMCQ04xEzAR\n" \
"BgNVBAgMCmhlbGxvd29ybGQxEzARBgNVBAoMCmhlbGxvd29ybGQxEzARBgNVBAsM\n" \
"CmhlbGxvd29ybGQxFjAUBgNVBAMMDWhlbGxvd29ybGQxMTExGTAXBgkqhkiG9w0B\n" \
"CQEWCmhlbGxvd29ybGQwHhcNMjQwODA5MDkzMDEyWhcNMzQwODA5MDkzMDEyWjAa\n" \
"MRgwFgYDVQQDEw9BIEtleW1hc3RlciBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMB\n" \
"BwNCAATJqTRIhGKhLmXuJbPI311/5gEljqPbpJpXNp6oe8dOmnyJ9SQQZmMomB5u\n" \
"lC5aZIoNrCuKHTAgY1PpNNcFSBBpo4IBPDCCATgwCwYDVR0PBAQDAgeAMAgGA1Ud\n" \
"HwQBADCCAR0GDCsGAQQBj1sCgngBAwSCAQswggEHAgEAMDQCAQAGDSsGAQQBj1sC\n" \
"gngCAQQEIOIC9EG2Dn3zqle0WWjiHwk2CIP3hJuPjjQwi7z4FaFFMCICAQIGDSsG\n" \
"AQQBj1sCgngCAQIEDkxPQ0FMX1NJR05fS0VZMFwCAQIGDSsGAQQBj1sCgngCAQMw\n" \
"SAYOKwYBBAGPWwKCeAIBAwEENnsicHJvY2Vzc05hbWUiOiJsb2NhbF9jb2RlX3Np\n" \
"Z24iLCJBUEwiOiJzeXN0ZW1fYmFzaWMifTAYAgECBg0rBgEEAY9bAoJ4AgELBAQA\n" \
"AAAAMBgCAQIGDSsGAQQBj1sCgngCAQUEBAIAAAAwFgIBAgYOKwYBBAGPWwKCeAIE\n" \
"AQUBAf8wCwYJKoZIhvcNAQELA4IBAQB8zqqeaXux3qkQF0GFax7I4YWtTpoeQeJU\n" \
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
"Ps3BhpHHb67kjzP3rcQbZ2l1LSMWjoV8jXckVMOFqOlTlrYlGM3G80bVaWcEgw4c\n" \
"+nkSk+ApGmNUa69HK3h+5vfz81fVmJL1zX0VaYiA+wCzrFc1w5aGKhsFIcIY8FUo\n" \
"i15xrwAURQ+/EylzeF302qGwkCHYy4zQqn3ohku25rPLUOyOp6gJNs/3BVh76b9/\n" \
"1iTyP7ldDD7VV4UQCTDppFtrDQY/UrBhe9sPn0+6GWBfkkjz5n1aGE7JP2vmB3qM\n" \
"gxIpEkmVLVIxh6dwBOmtr+sT7xJ+UzmTWbbhNGCkzSPxAgMBAAGjUzBRMB0GA1Ud\n" \
"DgQWBBSDTqp6QOdxk9zF2H+7IGOckq/A1DAfBgNVHSMEGDAWgBRNYAEJlwxPOj5F\n" \
"B7M4mTsMpokRLzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB4\n" \
"CkKbJQWuC2pj0cS+zb4v8fRq8OPjRVPylqjHX4IMpmnl2VM0DkNXD0SYPC5IxkK4\n" \
"bgtglG0Rkr4blYf+PdNenbebWZvw4Y3JUoQgSasfdIA/rJXZtf3mVUNLmPlcRWZC\n" \
"OtGJmvlntp7/qWl7JCIaiD732baJU1DZchy3am2WWGpchBESBOtoSvdywG+T0xQQ\n" \
"cXzYQ+mHPsym30JCzChvZCKz+QJlIZUJ3XgoKH7MVviASXGcWLKOBYYUDt3J8/PM\n" \
"shbsqb+rm+VqU5ohV8Rr/nQ+QLvEFa8rrz7qY6/2QSbUy7QvFCv7MXFD1kCH92FL\n" \
"GwkmWDavM1kdVMXZmV54\n" \
"-----END CERTIFICATE-----";

const std::string INTER_CA_CHAIN_PEM =
"-----BEGIN CERTIFICATE-----\n" \
"MIID3zCCAsegAwIBAgIBAjANBgkqhkiG9w0BAQsFADCBkjELMAkGA1UEBhMCQ04x\n" \
"EzARBgNVBAgMCmhlbGxvd29ybGQxEzARBgNVBAcMCmhlbGxvd29ybGQxEzARBgNV\n" \
"BAoMCmhlbGxvd29ybGQxEzARBgNVBAsMCmhlbGxvd29ybGQxFDASBgNVBAMMC2hl\n" \
"bGxvd29ybGQxMRkwFwYJKoZIhvcNAQkBFgpoZWxsb3dvcmxkMB4XDTIyMDEyMjA5\n" \
"MjM0OFoXDTMyMDEyMDA5MjM0OFowfjELMAkGA1UEBhMCQ04xEzARBgNVBAgMCmhl\n" \
"bGxvd29ybGQxEzARBgNVBAoMCmhlbGxvd29ybGQxEzARBgNVBAsMCmhlbGxvd29y\n" \
"bGQxFTATBgNVBAMMDGhlbGxvd29ybGQxMTEZMBcGCSqGSIb3DQEJARYKaGVsbG93\n" \
"b3JsZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALTJF+SAh/ccmcxF\n" \
"+le0m8Wx7N9kclMYoUVGyJOPDv0L9kE/1hg9HEavCBWal9ZK69r+i1YiH18Y0F5o\n" \
"AuqP0teedDByPii8IaDquJKZ1hlMi13vPY1cgUcG77cKzC5TMlmNTLes0ddn9/lY\n" \
"4ajl4kgUr3bCEXlp4uhBQPYlntujctcjmEdMtcJQmhHpr2Js9cq2kZney59ae5kk\n" \
"LCzpFqpj7cunz5Rs3RZs1+Njw5oABS18qAy1CEBnecLOi6lIPvIckngBHduwczOM\n" \
"5YBBXeqOeNk7FWTiIf5MuXlqOSlZ57Wp8SqfDzwS49awwI9dvGpjgyGh3ZQA5TXX\n" \
"GGIsn5cCAwEAAaNTMFEwHQYDVR0OBBYEFE1gAQmXDE86PkUHsziZOwymiREvMB8G\n" \
"A1UdIwQYMBaAFJp3c+VFpGlC/r/UiPCozoH1UcgMMA8GA1UdEwEB/wQFMAMBAf8w\n" \
"DQYJKoZIhvcNAQELBQADggEBAArLbWZWG3cHuCnMBGo28F0KVKctxjLVOCzDhKnH\n" \
"IusLVqTnZ7AHeUU56NyoRfSRSIEJ2TNXkHO8MyxNN3lP4RapQavOvENLE99s269I\n" \
"suLPCp3k6znJX1ZW7MIrSp7Bz+6rBTuh2H874H/BcvPXaCZB4X3Npjfu4tRcKEtS\n" \
"JKdVmIlotjX1qM5eYHY5BDSR0MvRYvSlH7/wA9FEGJ8GHI7vaHxIMxf4+OOz+E4w\n" \
"qKIZZfYeVBdEpZvfVGHRbS5dEofqc4NthlObTWlwAIhFgTzLqy8y2Y2jDWcJk91/\n" \
"y9u8F1jQAuoemDCY5BalZ+Bn0eZQQHlXujwyZfoIK+oCuUo=\n" \
"-----END CERTIFICATE-----";

const uint8_t CHALLENGE[] = {
    0xe2, 0x2, 0xf4, 0x41, 0xb6, 0xe, 0x7d, 0xf3,
    0xaa, 0x57, 0xb4, 0x59, 0x68, 0xe2, 0x1f, 0x9,
    0x36, 0x8, 0x83, 0xf7, 0x84, 0x9b, 0x8f, 0x8e,
    0x34, 0x30, 0x8b, 0xbc, 0xf8, 0x15, 0xa1, 0x45
};

static ByteBuffer g_issuerCert;
static ByteBuffer g_signingCert;
static ByteBuffer g_interCA;
static ByteBuffer g_invalidCert;
static ByteBuffer g_rootCA;

static inline uint8_t *CastToUint8Ptr(uint32_t *ptr)
{
    return reinterpret_cast<uint8_t *>(ptr);
}

static X509 *LoadPemString(const std::string &pemData)
{
    BIO *mem = BIO_new_mem_buf(pemData.c_str(), pemData.length());
    if (mem == nullptr) {
        return nullptr;
    }

    X509 *x509 = PEM_read_bio_X509(mem, nullptr, nullptr, nullptr);
    EXPECT_NE(x509, nullptr);
    BIO_free(mem);
    return x509;
}

void LoadDerFormPemString(const std::string &pemData, ByteBuffer &certBuffer)
{
    X509 *x509 = LoadPemString(pemData);
    uint8_t *derTemp = nullptr;
    int32_t derTempLen = i2d_X509(x509, &derTemp);
    EXPECT_NE(derTemp, nullptr);
    if (derTempLen < 0) {
        X509_free(x509);
        return;
    }

    certBuffer.CopyFrom(derTemp, static_cast<uint32_t>(derTempLen));

    X509_free(x509);
    OPENSSL_free(derTemp);
}

static void FormattedCertChain(const std::vector<ByteBuffer> &certChain, ByteBuffer &buffer)
{
    uint32_t certsCount = certChain.size();
    uint32_t totalLen = sizeof(uint32_t);
    for (uint32_t i = 0; i < certsCount; i++) {
        totalLen += sizeof(uint32_t) + certChain[i].GetSize();
    }
    buffer.Resize(totalLen);
    if (!buffer.PutData(0, CastToUint8Ptr(&certsCount), sizeof(uint32_t))) {
        return;
    }
    uint32_t pos = sizeof(uint32_t);
    for (uint32_t i = 0; i < certsCount; i++) {
        uint32_t size = certChain[i].GetSize();
        if (!buffer.PutData(pos, CastToUint8Ptr(&size), sizeof(uint32_t))) {
            return;
        }
        pos += sizeof(uint32_t);
        if (!buffer.PutData(pos, certChain[i].GetBuffer(), certChain[i].GetSize())) {
            return;
        }
        pos += certChain[i].GetSize();
    }
}

class CertChainVerifierTest : public testing::Test {
public:
    CertChainVerifierTest() {};
    virtual ~CertChainVerifierTest() {};
    static void SetUpTestCase()
    {
        LoadDerFormPemString(SIGNING_CERT_CHAIN_PEM, g_signingCert);
        LoadDerFormPemString(ISSUER_CERT_CHAIN_PEM, g_issuerCert);
        LoadDerFormPemString(INTER_CA_CHAIN_PEM, g_interCA);
        // fake root CA, no use in verifying
        uint8_t tmp = 0;
        g_rootCA.CopyFrom(&tmp, sizeof(tmp));
        g_invalidCert.CopyFrom(&tmp, sizeof(tmp));
    }
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: CertChainVerifierTest_001
 * @tc.desc: Get chain from empty buffer
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_001, TestSize.Level0)
{
    ByteBuffer cert, challenge, certBuffer;
    EXPECT_EQ(GetVerifiedCert(cert, challenge, certBuffer), false);
}

/**
 * @tc.name: CertChainVerifierTest_0002
 * @tc.desc: Get chain from empty cert chain
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_002, TestSize.Level0)
{
    ByteBuffer cert, challenge, certBuffer;
    uint32_t count = 0;
    cert.CopyFrom(reinterpret_cast<uint8_t *>(&count), sizeof(count));
    EXPECT_EQ(GetVerifiedCert(cert, challenge, certBuffer), false);
}


/**
 * @tc.name: CertChainVerifierTest_0003
 * @tc.desc: Get chain from invalid formatted buffer
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_003, TestSize.Level0)
{
    ByteBuffer cert, challenge, certBuffer;
    std::vector<uint32_t> tmpBuffer = {0};
    cert.CopyFrom(reinterpret_cast<uint8_t *>(tmpBuffer.data()), tmpBuffer.size() * sizeof(uint32_t));
    EXPECT_EQ(GetVerifiedCert(cert, challenge, certBuffer), false);

    // one cert in cert chain, classify as root CA
    tmpBuffer[0] = 1;
    // load issuer failed
    cert.CopyFrom(reinterpret_cast<uint8_t *>(tmpBuffer.data()), tmpBuffer.size() * sizeof(uint32_t));
    EXPECT_EQ(GetVerifiedCert(cert, challenge, certBuffer), false);

    // two certs in cert chain
    tmpBuffer[0] = 2;
    // cert size
    tmpBuffer.push_back(sizeof(uint32_t));
    cert.CopyFrom(reinterpret_cast<uint8_t *>(tmpBuffer.data()), tmpBuffer.size() * sizeof(uint32_t));
    // no content to load cert, convert from formatted buffer failed
    EXPECT_EQ(GetVerifiedCert(cert, challenge, certBuffer), false);

    // fill issuer
    tmpBuffer.push_back(0);
    cert.CopyFrom(reinterpret_cast<uint8_t *>(tmpBuffer.data()), tmpBuffer.size() * sizeof(uint32_t));
    // invalid content, convert content to x509 failed
    EXPECT_EQ(GetVerifiedCert(cert, challenge, certBuffer), false);
}

/**
 * @tc.name: CertChainVerifierTest_0004
 * @tc.desc: Get verified failed with invalid issuer format
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_004, TestSize.Level0)
{
    ByteBuffer formattedCert, challenge, certBuffer;
    std::vector<ByteBuffer> certs;
    certs.push_back(g_signingCert);
    certs.push_back(g_invalidCert);
    certs.push_back(g_interCA);
    certs.push_back(g_rootCA);
    FormattedCertChain(certs, formattedCert);
    EXPECT_EQ(GetVerifiedCert(formattedCert, challenge, certBuffer), false);
}

/**
 * @tc.name: CertChainVerifierTest_0005
 * @tc.desc: Get verified failed with invalid interCA format
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_005, TestSize.Level0)
{
    ByteBuffer formattedCert, challenge, certBuffer;
    std::vector<ByteBuffer> certs;
    certs.push_back(g_signingCert);
    certs.push_back(g_issuerCert);
    certs.push_back(g_invalidCert);
    certs.push_back(g_rootCA);
    FormattedCertChain(certs, formattedCert);
    EXPECT_EQ(GetVerifiedCert(formattedCert, challenge, certBuffer), false);
}

/**
 * @tc.name: CertChainVerifierTest_0006
 * @tc.desc: verifying issuer cert failed
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_006, TestSize.Level0)
{
    ByteBuffer formattedCert, challenge, certBuffer;
    std::vector<ByteBuffer> certs;
    certs.push_back(g_signingCert);
    certs.push_back(g_signingCert);
    certs.push_back(g_interCA);
    certs.push_back(g_rootCA);
    FormattedCertChain(certs, formattedCert);
    EXPECT_EQ(GetVerifiedCert(formattedCert, challenge, certBuffer), false);
}

/**
 * @tc.name: CertChainVerifierTest_0007
 * @tc.desc: verify signing cert failed
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_007, TestSize.Level0)
{
    ByteBuffer challenge;
    //parse pub key of failed
    EXPECT_EQ(VerifyCertAndExtension(nullptr, nullptr, challenge), false);
    
    X509 *signingCert = LoadPemString(SIGNING_CERT_CHAIN_PEM);
    X509 *issuerCert = LoadPemString(ISSUER_CERT_CHAIN_PEM);
    // verify signature failed
    EXPECT_EQ(VerifyCertAndExtension(issuerCert, signingCert, challenge), false);

    // verify extension failed
    const char *invalidChallenge = "invalid";
    challenge.CopyFrom(reinterpret_cast<const uint8_t *>(invalidChallenge),
        sizeof(invalidChallenge));
    EXPECT_EQ(VerifyCertAndExtension(signingCert, issuerCert, challenge), false);

    // verify extension success
    challenge.CopyFrom(CHALLENGE, sizeof(CHALLENGE));
    EXPECT_EQ(VerifyCertAndExtension(signingCert, issuerCert, challenge), true);
    X509_free(signingCert);
    X509_free(issuerCert);
}

/**
 * @tc.name: CertChainVerifierTest_0008
 * @tc.desc: verifying issuer cert success
 * @tc.type: Func
 * @tc.require: IAJ4QG
 */
HWTEST_F(CertChainVerifierTest, CertChainVerifierTest_008, TestSize.Level0)
{
    ByteBuffer formattedCert, challenge, certBuffer;
    std::vector<ByteBuffer> certs;
    certs.push_back(g_signingCert);
    certs.push_back(g_issuerCert);
    certs.push_back(g_interCA);
    certs.push_back(g_rootCA);
    FormattedCertChain(certs, formattedCert);
    // verify extension success
    challenge.CopyFrom(CHALLENGE, sizeof(CHALLENGE));
#ifdef CODE_SIGNATURE_OH_ROOT_CA
    EXPECT_EQ(GetVerifiedCert(formattedCert, challenge, certBuffer), true);
#else
    EXPECT_EQ(GetVerifiedCert(formattedCert, challenge, certBuffer), false);
#endif
}

} // namespace CodeSign
} // namespace Security
} // namespace OHOS