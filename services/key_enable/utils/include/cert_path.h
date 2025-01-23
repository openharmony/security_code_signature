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

#ifndef CODE_SIGN_IOCTL_UTILS_H
#define CODE_SIGN_IOCTL_UTILS_H

#ifndef LOG_RUST
#define LOG_RUST
#endif

#include <cstdint>

#define CERT_DEVICE_PATH "/dev/code_sign"
#define CERT_IOCTL_MAGIC_NUMBER 'k'
#define UDID_SIZE 65

struct CertPathInfo {
    uint32_t signing_length;
    uint32_t issuer_length;
    uint64_t signing;
    uint64_t issuer;
    uint32_t path_len;
    uint32_t path_type;
    uint64_t app_id;
    uint32_t app_id_length;
    uint8_t __reserved[20];
};

#define ADD_CERT_PATH_CMD _IOW(CERT_IOCTL_MAGIC_NUMBER, 1, CertPathInfo)
#define REMOVE_CERT_PATH_CMD _IOW(CERT_IOCTL_MAGIC_NUMBER, 2, CertPathInfo)
#ifdef __cplusplus
extern "C" {
#endif
    int AddCertPath(const CertPathInfo &info);
    int RemoveCertPath(const CertPathInfo &info);
    bool IsDeveloperModeOn();
    int CodeSignGetUdid(char *udid);
#ifdef __cplusplus
}
#endif

#endif