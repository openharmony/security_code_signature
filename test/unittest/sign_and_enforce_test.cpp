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
#include <gtest/gtest.h>
#include <string>

#include <openssl/asn1.h>
#include <openssl/pkcs7.h>
#include <openssl/x509v3.h>
#include <sys/utsname.h>
#include "access_token_setter.h"
#include "byte_buffer.h"
#include "code_sign_utils.h"
#include "local_code_sign_kit.h"
#include "local_key_helper.h"
#include "log.h"

using namespace OHOS::Security::CodeSign;
using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace Security {
namespace CodeSign {
static const std::string AN_BASE_PATH = "/data/local/ark-cache/tmp/";
static const std::string DEMO_AN_PATH = AN_BASE_PATH + "demo.an";
static const std::string DEMO_TAMPER_AN_PATH = AN_BASE_PATH + "fake_demo.an";

static const char *VALID_CALLER = "compiler_service";

static const std::string FAKE_SERIAL_NUMBER = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static const std::string FAKE_CONTENT = "FAKE";

static const int MAX_TEST_BUF_LEN = 1024;

static bool g_isKernelLinux = false;

static void ModifySignatureFormat(ByteBuffer &pkcs7Data)
{
    uint8_t *data = pkcs7Data.GetBuffer();
    (void) memcpy_s(data, pkcs7Data.GetSize(), FAKE_CONTENT.c_str(), FAKE_CONTENT.length());
}

static void ModifySignatureValue(PKCS7_SIGNER_INFO *p7info)
{
    const uint8_t *data = ASN1_STRING_get0_data(p7info->enc_digest);
    int len = ASN1_STRING_length(p7info->enc_digest);
    if (len <= 0 || len > MAX_TEST_BUF_LEN) {
        return;
    }
    uint8_t *fdata = static_cast<uint8_t *>(malloc(len));
    if (fdata == nullptr) {
        return;
    }
    (void)memcpy_s(fdata, len, data, len);
    (void)memcpy_s(fdata, len, FAKE_CONTENT.c_str(), FAKE_CONTENT.length());
    ASN1_STRING_set0(p7info->enc_digest, fdata, len);
}

static void ModifySignatureSigner(PKCS7_SIGNER_INFO *p7info)
{
    ASN1_INTEGER *serial = s2i_ASN1_INTEGER(nullptr, FAKE_SERIAL_NUMBER.c_str());
    ASN1_INTEGER_free(p7info->issuer_and_serial->serial);
    p7info->issuer_and_serial->serial = ASN1_INTEGER_dup(serial);
}

static PKCS7_SIGNER_INFO *GetSignerInfo(PKCS7 *p7)
{
    STACK_OF(PKCS7_SIGNER_INFO) *signInfos = PKCS7_get_signer_info(p7);
    // only one signer
    if (sk_PKCS7_SIGNER_INFO_num(signInfos) < 1) {
        return nullptr;
    }
    return sk_PKCS7_SIGNER_INFO_value(signInfos, 0);
}

static PKCS7 *LoadPKCS7Data(ByteBuffer &pkcs7Data)
{
    BIO *mem = BIO_new_mem_buf(pkcs7Data.GetBuffer(), pkcs7Data.GetSize());
    return d2i_PKCS7_bio(mem, nullptr);
}

static bool DumpPKCS7Data(PKCS7 *p7, ByteBuffer &pkcs7Data)
{
    BIO *bio = BIO_new(BIO_s_mem());
    bool ret = false;
    do {
        if (bio == nullptr) {
            break;
        }
        if (!i2d_PKCS7_bio(bio, p7)) {
            break;
        }
        uint8_t *tmp = nullptr;
        long tmpSize = BIO_get_mem_data(bio, &tmp);
        if ((tmpSize < 0) || (tmpSize > UINT32_MAX)) {
            break;
        }
        if (!pkcs7Data.CopyFrom(tmp, static_cast<uint32_t>(tmpSize))) {
            break;
        }
        ret = true;
    } while (0);
    BIO_free(bio);
    return ret;
}

static bool ModifyPkcs7SignerwithTargetFunc(ByteBuffer &src, ByteBuffer &dst,
    void (*modifyFunc)(PKCS7_SIGNER_INFO *p7))
{
    PKCS7 *p7 = LoadPKCS7Data(src);
    if (p7 == nullptr) {
        return false;
    }
    PKCS7_SIGNER_INFO *signer = GetSignerInfo(p7);
    if (signer == nullptr) {
        return false;
    }
    modifyFunc(signer);
    if (!DumpPKCS7Data(p7, dst)) {
        return false;
    }
    PKCS7_free(p7);
    return true;
}

static void InvokeLocalCodeSign(const std::string &filePath, ByteBuffer &sig)
{
    uint64_t selfTokenId = NativeTokenSet(VALID_CALLER);
    int ret = LocalCodeSignKit::SignLocalCode(filePath, sig);
    NativeTokenReset(selfTokenId);
    EXPECT_EQ(ret, CS_SUCCESS);
}

class SignAndEnforceTest : public testing::Test {
public:
    SignAndEnforceTest() {};
    virtual ~SignAndEnforceTest() {};
    static void SetUpTestCase()
    {
        struct utsname uts;
        if (uname(&uts) == 0 && strcmp(uts.sysname, "Linux") == 0) {
            g_isKernelLinux = true;
        }
    };
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: SignAndEnforceTest_0001
 * @tc.desc: sign AN file and enforce with null
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(SignAndEnforceTest, SignAndEnforceTest_0001, TestSize.Level0)
{
    ByteBuffer sig;
    InvokeLocalCodeSign(DEMO_AN_PATH, sig);
    ByteBuffer empty;
    int32_t ret = CodeSignUtils::EnforceCodeSignForFile(DEMO_AN_PATH, empty);
    EXPECT_EQ(ret, CS_ERR_NO_SIGNATURE);
}

/**
 * @tc.name: SignAndEnforceTest_0002
 * @tc.desc: sign AN file and enforce tampered one
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(SignAndEnforceTest, SignAndEnforceTest_0002, TestSize.Level0)
{
    if (!g_isKernelLinux) {
        return;
    }
    ByteBuffer sig;
    InvokeLocalCodeSign(DEMO_AN_PATH, sig);
    int32_t ret = CodeSignUtils::EnforceCodeSignForFile(DEMO_TAMPER_AN_PATH, sig);
    EXPECT_EQ(ret, CS_ERR_ENABLE);
}

/**
 * @tc.name: SignAndEnforceTest_0003
 * @tc.desc: sign AN file and enforce it with wrong signature fromat
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(SignAndEnforceTest, SignAndEnforceTest_0003, TestSize.Level0)
{
    if (!g_isKernelLinux) {
        return;
    }
    ByteBuffer sig;
    InvokeLocalCodeSign(DEMO_AN_PATH, sig);
    ModifySignatureFormat(sig);
    int32_t ret = CodeSignUtils::EnforceCodeSignForFile(DEMO_AN_PATH, sig);
    EXPECT_EQ(ret, CS_ERR_ENABLE);
}

/**
 * @tc.name: SignAndEnforceTest_0004
 * @tc.desc: sign AN file and enforce it with wrong signature value
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(SignAndEnforceTest, SignAndEnforceTest_0004, TestSize.Level0)
{
    if (!g_isKernelLinux) {
        return;
    }
    ByteBuffer sig;
    InvokeLocalCodeSign(DEMO_AN_PATH, sig);;
    ByteBuffer wrongSig;
    EXPECT_EQ(ModifyPkcs7SignerwithTargetFunc(sig, wrongSig, ModifySignatureValue), true);
    int32_t ret = CodeSignUtils::EnforceCodeSignForFile(DEMO_AN_PATH, wrongSig);
    EXPECT_EQ(ret, CS_ERR_ENABLE);
}

/**
 * @tc.name: SignAndEnforceTest_0005
 * @tc.desc: sign AN file and enforce it using signature with wrong signer
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(SignAndEnforceTest, SignAndEnforceTest_0005, TestSize.Level0)
{
    if (!g_isKernelLinux) {
        return;
    }
    ByteBuffer sig;
    InvokeLocalCodeSign(DEMO_AN_PATH, sig);
    ByteBuffer wrongSig;
    EXPECT_EQ(ModifyPkcs7SignerwithTargetFunc(sig, wrongSig, ModifySignatureSigner), true);
    int32_t ret = CodeSignUtils::EnforceCodeSignForFile(DEMO_AN_PATH, wrongSig);
    EXPECT_EQ(ret, CS_ERR_ENABLE);
}

/**
 * @tc.name: SignAndEnforceTest_0006
 * @tc.desc: sign AN file and enforce it
 * @tc.type: Func
 * @tc.require:
 */
HWTEST_F(SignAndEnforceTest, SignAndEnforceTest_0006, TestSize.Level0)
{
    ByteBuffer sig;
    InvokeLocalCodeSign(DEMO_AN_PATH, sig);
    int32_t ret = CodeSignUtils::EnforceCodeSignForFile(DEMO_AN_PATH, sig);
    EXPECT_EQ(ret, GetEnforceFileResult());
}
} // namespace CodeSign
} // namespace Security
} // namespace OHOS