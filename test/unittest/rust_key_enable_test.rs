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
extern crate ylong_json;

use std::thread;
use ylong_json::JsonValue;
use openssl::x509::X509;
use key_enable::cert_chain_utils::PemCollection;
use key_enable::cert_path_utils::{TrustCertPath, activate_cert, CertType, CertStatus};
use key_enable::profile_utils::{UDID, get_udid, validate_bundle_and_distribution_type};


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

#[test]
fn test_parse_enterprise_profile() {
    let profile_str = r#"
    {
        "version-name": "2.0.0",
        "version-code": 2,
        "app-distribution-type": "enterprise",
        "uuid": "",
        "validity": {
            "not-before": 1,
            "not-after": 2
        },
        "type": "release",
        "bundle-info": {
            "developer-id": "",
            "distribution-certificate": "",
            "bundle-name": "com.test.enterprise",
            "apl": "normal",
            "app-feature": "test_app",
            "app-identifier": "123123"
        },
        "acls": {
            "allowed-acls": [
                ""
            ]
        },
        "app-privilege-capabilities": [],
        "permissions": {
            "restricted-permissions": [
                ""
            ]
        }
    }
    "#;
    let profile_json =JsonValue::from_text(profile_str).unwrap();
    let result = validate_bundle_and_distribution_type(&profile_json, true);
    assert!(result.is_ok());
}

#[test]
fn test_parse_enterprise_normal_profile() {
    let profile_str = r#"
    {
        "version-name": "2.0.0",
        "version-code": 2,
        "app-distribution-type": "enterprise_normal",
        "uuid": "",
        "validity": {
            "not-before": 1,
            "not-after": 2
        },
        "type": "release",
        "bundle-info": {
            "developer-id": "",
            "distribution-certificate": "",
            "bundle-name": "com.test.enterprise_normal",
            "apl": "normal",
            "app-feature": "test_app",
            "app-identifier": "123123"
        },
        "acls": {
            "allowed-acls": [
                ""
            ]
        },
        "app-privilege-capabilities": [],
        "permissions": {
            "restricted-permissions": [
                ""
            ]
        }
    }
    "#;
    let profile_json =JsonValue::from_text(profile_str).unwrap();
    let result = validate_bundle_and_distribution_type(&profile_json, true);
    assert!(result.is_ok());
}

#[test]
fn test_parse_enterprise_mdm_profile() {
    let profile_str = r#"
    {
        "version-name": "2.0.0",
        "version-code": 2,
        "app-distribution-type": "enterprise_mdm",
        "uuid": "",
        "validity": {
            "not-before": 1,
            "not-after": 2
        },
        "type": "release",
        "bundle-info": {
            "developer-id": "",
            "distribution-certificate": "",
            "bundle-name": "com.test.enterprise_mdm",
            "apl": "normal",
            "app-feature": "test_app",
            "app-identifier": "123123"
        },
        "acls": {
            "allowed-acls": [
                ""
            ]
        },
        "app-privilege-capabilities": [],
        "permissions": {
            "restricted-permissions": [
                ""
            ]
        }
    }
    "#;
    let profile_json =JsonValue::from_text(profile_str).unwrap();
    let result = validate_bundle_and_distribution_type(&profile_json, true);
    assert!(result.is_ok());
}

#[test]
fn test_parse_debug_profile() {
    let profile_str = r#"
    {
        "version-name": "2.0.0",
        "version-code": 2,
        "app-distribution-type": "developer",
        "uuid": "",
        "validity": {
            "not-before": 1,
            "not-after": 2
        },
        "type": "debug",
        "bundle-info": {
            "developer-id": "",
            "development-certificate": "",
            "bundle-name": "com.test.developer",
            "apl": "normal",
            "app-feature": "test_app",
            "app-identifier": "123123"
        },
        "acls": {
            "allowed-acls": [
                ""
            ]
        },
        "app-privilege-capabilities": [],
        "permissions": {
            "restricted-permissions": [
                ""
            ]
        },
        "debug-info": {
            "device-ids": [],
            "device-id-type": "udid"
        }
    }
    "#;
    let udid = get_udid().expect("Failed to get UDID");
    let mut profile_json =JsonValue::from_text(profile_str).unwrap();
    profile_json["debug-info"]["device-ids"][0] = JsonValue::String(udid);
    let result = validate_bundle_and_distribution_type(&profile_json, true);
    assert!(result.is_ok());
}

#[test]
fn test_parse_iternaltesting_profile() {
    let profile_str = r#"
    {
        "version-name": "2.0.0",
        "version-code": 2,
        "app-distribution-type": "internaltesting",
        "uuid": "",
        "validity": {
            "not-before": 1,
            "not-after": 2
        },
        "type": "release",
        "bundle-info": {
            "developer-id": "",
            "distribution-certificate": "",
            "bundle-name": "com.test.internaltesting",
            "apl": "normal",
            "app-feature": "test_app",
            "app-identifier": "123123"
        },
        "acls": {
            "allowed-acls": [
                ""
            ]
        },
        "app-privilege-capabilities": [],
        "permissions": {
            "restricted-permissions": [
                ""
            ]
        },
        "debug-info": {
            "device-ids": [],
            "device-id-type": "udid"
        }
    }
    "#;
    let udid = get_udid().expect("Failed to get UDID");
    let mut profile_json =JsonValue::from_text(profile_str).unwrap();
    profile_json["debug-info"]["device-ids"][0] = JsonValue::String(udid);
    let result = validate_bundle_and_distribution_type(&profile_json, true);
    assert!(result.is_ok());
}

#[test]
fn test_parse_invalid_profile() {
    let no_type_profile = r#"
    {
        "version-name": "2.0.0",
        "version-code": 2,
        "app-distribution-type": "internaltesting",
        "uuid": "",
        "validity": {
            "not-before": 1,
            "not-after": 2
        },
        "bundle-info": {
            "developer-id": "",
            "distribution-certificate": "",
            "bundle-name": "com.test.internaltesting",
            "apl": "normal",
            "app-feature": "test_app",
            "app-identifier": "123123"
        },
        "acls": {
            "allowed-acls": [
                ""
            ]
        },
        "app-privilege-capabilities": [],
        "permissions": {
            "restricted-permissions": [
                ""
            ]
        },
        "debug-info": {
            "device-ids": [],
            "device-id-type": "udid"
        }
    }
    "#;
    let no_distribution_profile = r#"
    {
        "version-name": "2.0.0",
        "version-code": 2,
        "uuid": "",
        "validity": {
            "not-before": 1,
            "not-after": 2
        },
        "type": "release",
        "bundle-info": {
            "developer-id": "",
            "distribution-certificate": "",
            "bundle-name": "com.test.internaltesting",
            "apl": "normal",
            "app-feature": "test_app",
            "app-identifier": "123123"
        },
        "acls": {
            "allowed-acls": [
                ""
            ]
        },
        "app-privilege-capabilities": [],
        "permissions": {
            "restricted-permissions": [
                ""
            ]
        },
        "debug-info": {
            "device-ids": [],
            "device-id-type": "udid"
        }
    }
    "#;
    let no_debug_info_profile = r#"
    {
        "version-name": "2.0.0",
        "version-code": 2,
        "app-distribution-type": "internaltesting",
        "uuid": "",
        "validity": {
            "not-before": 1,
            "not-after": 2
        },
        "type": "release",
        "bundle-info": {
            "developer-id": "",
            "distribution-certificate": "",
            "bundle-name": "com.test.internaltesting",
            "apl": "normal",
            "app-feature": "test_app",
            "app-identifier": "123123"
        },
        "acls": {
            "allowed-acls": [
                ""
            ]
        },
        "app-privilege-capabilities": [],
        "permissions": {
            "restricted-permissions": [
                ""
            ]
        }
    }
    "#;
    let udid = get_udid().expect("Failed to get UDID");
    let mut no_type_profile_json =JsonValue::from_text(no_type_profile).unwrap();
    no_type_profile_json["debug-info"]["device-ids"][0] = JsonValue::String(udid.clone());
    let result = validate_bundle_and_distribution_type(&no_type_profile_json, true);
    assert!(result.is_err());

    let mut no_distribution_profile_json =JsonValue::from_text(no_distribution_profile).unwrap();
    no_distribution_profile_json["debug-info"]["device-ids"][0] = JsonValue::String(udid.clone());
    let result = validate_bundle_and_distribution_type(&no_distribution_profile_json, true);
    assert!(result.is_err());
    
    let no_debug_info_profile_json =JsonValue::from_text(no_debug_info_profile).unwrap();
    let result = validate_bundle_and_distribution_type(&no_debug_info_profile_json, true);
    assert!(result.is_err());
}

#[test]
fn test_get_udid_once() {
    let udid_from_get = get_udid().expect("Failed to get UDID");
    let udid_from_global = UDID.clone().expect("UDID is None");

    assert_eq!(udid_from_get, udid_from_global);
}

#[test]
fn test_get_udid_concurrent() {
    let num_threads = 10;
    let mut handles = vec![];

    for _ in 0..num_threads {
        let handle = thread::spawn(|| {
            let udid = get_udid().expect("Failed to get UDID");
            assert_eq!(udid, UDID.clone().expect("UDID is None"));
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

#[test]
fn test_activate_cert() {
    let cert_data = r#"
-----BEGIN CERTIFICATE-----
MIICGjCCAaGgAwIBAgIIShhpn519jNAwCgYIKoZIzj0EAwMwUzELMAkGA1UEBhMC
Q04xDzANBgNVBAoMBkh1YXdlaTETMBEGA1UECwwKSHVhd2VpIENCRzEeMBwGA1UE
AwwVSHVhd2VpIENCRyBSb290IENBIEcyMB4XDTIwMDMxNjAzMDQzOVoXDTQ5MDMx
NjAzMDQzOVowUzELMAkGA1UEBhMCQ04xDzANBgNVBAoMBkh1YXdlaTETMBEGA1UE
CwwKSHVhd2VpIENCRzEeMBwGA1UEAwwVSHVhd2VpIENCRyBSb290IENBIEcyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEWidkGnDSOw3/HE2y2GHl+fpWBIa5S+IlnNrs
GUvwC1I2QWvtqCHWmwFlFK95zKXiM8s9yV3VVXh7ivN8ZJO3SC5N1TCrvB2lpHMB
wcz4DA0kgHCMm/wDec6kOHx1xvCRo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUo45a9Vq8cYwqaiVyfkiS4pLcIAAwCgYIKoZI
zj0EAwMDZwAwZAIwMypeB7P0IbY7c6gpWcClhRznOJFj8uavrNu2PIoz9KIqr3jn
BlBHJs0myI7ntYpEAjBbm8eDMZY5zq5iMZUC6H7UzYSix4Uy1YlsLVV738PtKP9h
FTjgDHctXJlC5L7+ZDY=
-----END CERTIFICATE-----
"#;
    let cert = X509::from_pem(cert_data.as_bytes()).expect("Parse pem cert error");
    assert!(activate_cert(&cert.to_der().unwrap(), CertStatus::BeforeUnlock, CertType::Other).is_err());
}

#[test]
fn test_activate_cert_nonexist() {
    // This should not pass because the cert is not added
    let cert_data = r#"
-----BEGIN CERTIFICATE-----
MIICEjCCAXsCAg36MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
ODIyMDUyNjU0WhcNMTcwODIxMDUyNjU0WjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
ZS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAm/xmkHmEQrurE/0re/jeFRLl
8ZPjBop7uLHhnia7lQG/5zDtZIUC3RVpqDSwBuw/NTweGyuP+o8AG98HxqxTBwID
AQABMA0GCSqGSIb3DQEBBQUAA4GBABS2TLuBeTPmcaTaUW/LCB2NYOy8GMdzR1mx
8iBIu2H6/E2tiY3RIevV2OW61qY2/XRQg7YPxx3ffeUugX9F4J/iPnnu1zAxxyBy
2VguKv4SWjRFoRkIfIlHX0qVviMhSlNy2ioFLy7JcPZb+v3ftDGywUqcBiVDoea0
Hn+GmxZA
-----END CERTIFICATE-----
    "#;
    let cert = X509::from_pem(cert_data.as_bytes()).expect("Parse pem cert error");
    assert!(activate_cert(&cert.to_der().unwrap(), CertStatus::BeforeUnlock, CertType::Other).is_err());
}

#[cfg(test)]
mod enterprise_resign_cert_tests {
    use super::*;
    use key_enable::profile_utils::test_utils::validate_enterprise_resign_cert_for_test;
    use key_enable::cert_path_utils::EnterpriseCertError;
    use std::fs;

    const CERT_PATH_2: &str = "/data/test/tmp/cert_chain_2.pem";
    const CERT_PATH_3_NO_EXT: &str = "/data/test/tmp/cert_chain_3_no_extension.pem";

    fn read_cert_file(path: &str) -> Vec<u8> {
        fs::read(path).unwrap_or_else(|_| {
            panic!("Failed to read certificate file: {}. Please ensure the file exists.", path);
        })
    }

    #[test]
    fn test_enterprise_resign_cert_chain_length_2_should_fail() {
        let cert_data = read_cert_file(CERT_PATH_2);
        let result = validate_enterprise_resign_cert_for_test(&cert_data);
        assert!(result.is_err(), "Expected error for cert chain with 2 certificates");
        match result {
            Err(EnterpriseCertError::InvalidCert) => {},
            _ => panic!("Expected InvalidCert error for cert chain with 2 certificates"),
        }
    }

    #[test]
    fn test_enterprise_resign_cert_missing_extension_should_fail() {
        let cert_data = read_cert_file(CERT_PATH_3_NO_EXT);
        let result = validate_enterprise_resign_cert_for_test(&cert_data);
        assert!(result.is_err(), "Expected error for cert chain without enterprise resign extension");
        match result {
            Err(EnterpriseCertError::InvalidCert) => {},
            _ => panic!("Expected InvalidCert error for missing enterprise resign extension"),
        }
    }
}