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
extern crate key_enable;
use key_enable::cert_chain_utils::PemCollection;
use key_enable::cert_path_utils::TrustCertPath;

// pem_cert_file
const VALID_PEM_CERT: &str = "/data/test/tmp/valid_pem_cert.json";
const NON_EXISTEND_PEM_CERT: &str = "/data/test/tmp/non_existent_cert_path.json";
const INVALID_STRUCTURE_PEM_CERT: &str = "/data/test/tmp/invalid_structure_cert_path.json";
const EMPTY_PEM_CERT: &str = "/data/test/tmp/empty_pem_cert.json";
// cert_path_file
const VALID_CERT_PATH: &str = "/data/test/tmp/valid_cert_path.json";
const NON_EXISTEND_CERT_PATH: &str = "/data/test/tmp/non_existent_cert_path.json";
const INVALID_STRUCTURE_CERT_PATH: &str = "/data/test/tmp/invalid_structure_cert_path.json";
const EMPTY_CERT_PATH: &str = "/data/test/tmp/empty_cert_path.json";

const ALLOWED_ROOT_CERT_MEMBER_NAMES: &[&str] = &[
    "C=CN, O=Huawei, OU=Huawei CBG, CN=Huawei CBG Root CA G2",
    "C=CN, O=OpenHarmony, OU=OpenHarmony Team, CN=OpenHarmony Application Root CA",
    "C=CN, O=Huawei, OU=Huawei CBG, CN=Huawei CBG Root CA G2 Test",
];

#[test]
fn test_load_pem_cert_from_valid_json_file() {
    // test is_debuggable true
    let mut root_cert = PemCollection::new();
    root_cert.load_pem_certs_from_json_file(VALID_PEM_CERT, ALLOWED_ROOT_CERT_MEMBER_NAMES);
    assert_eq!(root_cert.pem_data.len(), 3);
}

#[test]
fn test_invalid_pem_cert_file_path() {
    let mut root_cert = PemCollection::new();
    root_cert.load_pem_certs_from_json_file(NON_EXISTEND_PEM_CERT, ALLOWED_ROOT_CERT_MEMBER_NAMES);
    assert!(root_cert.pem_data.is_empty());
}

#[test]
fn test_invalid_pem_cert_json_structure() {
    let mut root_cert = PemCollection::new();
    root_cert
        .load_pem_certs_from_json_file(INVALID_STRUCTURE_PEM_CERT, ALLOWED_ROOT_CERT_MEMBER_NAMES);
    assert!(root_cert.pem_data.is_empty());
}

#[test]
fn test_empty_pem_cert_json_file() {
    let mut root_cert = PemCollection::new();
    root_cert.load_pem_certs_from_json_file(EMPTY_PEM_CERT, ALLOWED_ROOT_CERT_MEMBER_NAMES);
    assert!(root_cert.pem_data.is_empty());
}

#[test]
fn test_successful_load_cert_path() {
    let mut cert_paths = TrustCertPath::new();
    cert_paths.load_cert_path_from_json_file(VALID_CERT_PATH);
    assert_eq!(cert_paths.profile_signers.len(), 4);
    assert_eq!(cert_paths.app_sources.len(), 6);
}
#[test]
fn test_invalid_cert_path_file_path() {
    let mut cert_paths = TrustCertPath::new();
    cert_paths.load_cert_path_from_json_file(NON_EXISTEND_CERT_PATH);
    assert!(
        cert_paths.app_sources.is_empty(),
        "Expected cert_paths.app_sources to be empty for an empty JSON file"
    );
}

#[test]
fn test_invalid_cert_path_json_structure() {
    let mut cert_paths = TrustCertPath::new();
    cert_paths.load_cert_path_from_json_file(INVALID_STRUCTURE_CERT_PATH);
    assert!(
        cert_paths.app_sources.is_empty(),
        "Expected cert_paths.app_sources to be empty for an empty JSON file"
    );
}

#[test]
fn test_empty_cert_path_json_file() {
    let mut cert_paths = TrustCertPath::new();
    cert_paths.load_cert_path_from_json_file(EMPTY_CERT_PATH);
    assert!(
        cert_paths.app_sources.is_empty(),
        "Expected cert_paths.app_sources to be empty for an empty JSON file"
    );
}
