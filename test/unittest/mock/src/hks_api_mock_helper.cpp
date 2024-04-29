/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hks_api_mock_helper.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
static const uint32_t CERT_DATA_SIZE = 8192;
static const std::string EFFECTIVE_PEM_DATA =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDgzCCAm2gAwIBAgIBATALBgkqhkiG9w0BAQswfzELMAkGA1UEBhMCQ04xEzAR\n"
    "BgNVBAgMCmhlbGxvd29ybGQxEzARBgNVBAoMCmhlbGxvd29ybGQxEzARBgNVBAsM\n"
    "CmhlbGxvd29ybGQxFjAUBgNVBAMMDWhlbGxvd29ybGQxMTExGTAXBgkqhkiG9w0B\n"
    "CQEWCmhlbGxvd29ybGQwHhcNMjQwNDI1MTM0NzI0WhcNMzQwNDI1MTM0NzI0WjAa\n"
    "MRgwFgYDVQQDEw9BIEtleW1hc3RlciBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMB\n"
    "BwNCAAS2Ke53DuesDI11IflM1ewmsMgmFODEWo91i3rJ1DN00XkDZWnbpPBC4vTU\n"
    "ghEBJyaL0Llf8sAnOIhREXd9F3VIo4IBPDCCATgwCwYDVR0PBAQDAgeAMAgGA1Ud\n"
    "HwQBADCCAR0GDCsGAQQBj1sCgngBAwSCAQswggEHAgEAMDQCAQAGDSsGAQQBj1sC\n"
    "gngCAQQEIL1Mz84BeHuSz7BXsT7VV13vY+yHxj3bHm04Ts5FUzJbMCICAQIGDSsG\n"
    "AQQBj1sCgngCAQIEDkxPQ0FMX1NJR05fS0VZMFwCAQIGDSsGAQQBj1sCgngCAQMw\n"
    "SAYOKwYBBAGPWwKCeAIBAwEENnsicHJvY2Vzc05hbWUiOiJsb2NhbF9jb2RlX3Np\n"
    "Z24iLCJBUEwiOiJzeXN0ZW1fYmFzaWMifTAYAgECBg0rBgEEAY9bAoJ4AgELBAQA\n"
    "AAAAMBgCAQIGDSsGAQQBj1sCgngCAQUEBAIAAAAwFgIBAgYOKwYBBAGPWwKCeAIE\n"
    "AQUBAf8wCwYJKoZIhvcNAQELA4IBAQB/VnD1eZWph2/JcQU4QFvdn0P1xrbsT3XP\n"
    "dcIG4q3qWbrMBSq3DVmMWj3GZS+P+kW/Ni/ArnOzt/rUrui37yYWYylFOq9hBxcf\n"
    "Q9tSPOgXcB6EuxKF4O0mw7lS3rsvUaPtEG299ggV2UzkTmw8T+nX3OvUt5f7VN4i\n"
    "GY9u5Ou8DJNgr3gsF7Y1NaoC3zmnh9vAN03rUOWRBbCejf8hG6OY77TMaNIdfwwk\n"
    "1kM3ZM0+dUfKaKjU767kxPYdAbxrp9zGCd3Nu3B9WqJIz/RD+JaZGhugY6rrQZ6S\n"
    "ipcaNXzDYm10ccKjm/CSXoxE5PDikiUnK1vLUOPb6w3akQxwFOgZ\n"
    "-----END CERTIFICATE-----\n";

bool PemToDer(const char *pemData, const uint32_t size, uint8_t *derData, uint32_t derLen)
{
    if (pemData == nullptr) {
        LOG_ERROR("PemData is nullptr");
        return false;
    }

    if (derData == nullptr) {
        LOG_ERROR("Transferred in after malloc derData address.");
        return false;
    }

    if (derLen != CERT_DATA_SIZE) {
        LOG_ERROR("The length of derData is not equal to %{public}d", derLen);
        return false;
    }
    
    BIO *mem = BIO_new_mem_buf(pemData, size);
    if (mem == nullptr) {
        LOG_ERROR("Fail to create bio for cert.");
        return false;
    }

    X509 *x509 = PEM_read_bio_X509(mem, nullptr, 0, nullptr);
    if (x509 == nullptr) {
        LOG_ERROR("Fail to read bio");
        BIO_free(mem);
        return false;
    }

    uint8_t *derTemp = nullptr;
    int32_t derTempLen = i2d_X509(x509, &derTemp);
    if (derTempLen < 0) {
        X509_free(x509);
        BIO_free(mem);
        return false;
    }

    if (memcpy_s(derData, derLen, derTemp, static_cast<uint32_t>(derTempLen)) != EOK) {
        LOG_ERROR("Memcpy failed");
        return false;
    }

    X509_free(x509);
    BIO_free(mem);
    OPENSSL_free(derTemp);

    return true;
}

bool GetCertInDer(uint8_t *derData, uint32_t derLen)
{
    return PemToDer(EFFECTIVE_PEM_DATA.c_str(), EFFECTIVE_PEM_DATA.size(), derData, derLen);
}
}
}
}