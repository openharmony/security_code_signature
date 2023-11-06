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

use super::cert_chain_utils::PemCollection;
use super::cert_path_utils::TrustCertPath;
const TRUSTED_ROOT_CERT: &str = "/system/etc/security/trusted_root_ca.json";
const ALLOWED_ROOT_CERT_MEMBER_NAMES: &[&str] = &[
    "C=CN, O=Huawei, OU=Huawei CBG, CN=Huawei CBG Root CA G2",
    "C=CN, O=OpenHarmony, OU=OpenHarmony Team, CN=OpenHarmony Application Root CA",
];
const TRUSTED_ROOT_CERT_TEST: &str = "/system/etc/security/trusted_root_ca_test.json";
const ALLOWED_ROOT_CERT_MEMBER_NAMES_TEST: &[&str] =
    &["C=CN, O=Huawei, OU=Huawei CBG, CN=Huawei CBG Root CA G2 Test"];
const TRUSTED_CERT_PATH: &str = "/system/etc/security/trusted_cert_path.json";
const TRUSTED_CERT_PATH_TEST: &str = "/system/etc/security/trusted_cert_path_test.json";

/// get trusted certs form json file
pub fn get_trusted_certs() -> PemCollection {
    let mut root_cert = PemCollection::new();
    root_cert.load_pem_certs_from_json_file(TRUSTED_ROOT_CERT, ALLOWED_ROOT_CERT_MEMBER_NAMES);
    if env!("code_signature_debuggable") == "on" {
        root_cert.load_pem_certs_from_json_file(
            TRUSTED_ROOT_CERT_TEST,
            ALLOWED_ROOT_CERT_MEMBER_NAMES_TEST
        );
    }
    root_cert
}

/// get cert path form json file
pub fn get_cert_path() -> TrustCertPath {
    let mut cert_paths = TrustCertPath::new();
    cert_paths.load_cert_path_from_json_file(TRUSTED_CERT_PATH);
    if env!("code_signature_debuggable") == "on" {
        cert_paths.load_cert_path_from_json_file(TRUSTED_CERT_PATH_TEST);
    }
    cert_paths
}
