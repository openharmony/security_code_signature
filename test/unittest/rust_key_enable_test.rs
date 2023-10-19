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
extern crate key_enable;
use key_enable::cert_chain_utils::{load_cert_path_from_json_file, load_pem_cert_from_json_file};

#[test]
fn test_load_pem_cert_from_valid_json_file() {
    // test is_debuggable true
    let result = load_pem_cert_from_json_file(VALID_PEM_CERT, ALLOWED_ROOT_CERT_MEMBER_NAMES);
    let expected_cert = [
        "-----BEGIN CERTIFICATE-----\nMIICGjCCAaGgAwIBAgIIShhpn519jNAwCgYIKoZIzj0EAwMwUzELMAkGA1UEBhMC\n\
        Q04xDzANBgNVBAoMBkh1YXdlaTETMBEGA1UECwwKSHVhd2VpIENCRzEeMBwGA1UE\nAwwVSHVhd2VpIENCRyBSb290IENBIEcyMB4XDTIwMDMxNjAzMDQzOVoXDTQ5MDMx\n\
        NjAzMDQzOVowUzELMAkGA1UEBhMCQ04xDzANBgNVBAoMBkh1YXdlaTETMBEGA1UE\nCwwKSHVhd2VpIENCRzEeMBwGA1UEAwwVSHVhd2VpIENCRyBSb290IENBIEcyMHYw\n\
        EAYHKoZIzj0CAQYFK4EEACIDYgAEWidkGnDSOw3/HE2y2GHl+fpWBIa5S+IlnNrs\nGUvwC1I2QWvtqCHWmwFlFK95zKXiM8s9yV3VVXh7ivN8ZJO3SC5N1TCrvB2lpHMB\n\
        wcz4DA0kgHCMm/wDec6kOHx1xvCRo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T\nAQH/BAUwAwEB/zAdBgNVHQ4EFgQUo45a9Vq8cYwqaiVyfkiS4pLcIAAwCgYIKoZI\n\
        zj0EAwMDZwAwZAIwMypeB7P0IbY7c6gpWcClhRznOJFj8uavrNu2PIoz9KIqr3jn\nBlBHJs0myI7ntYpEAjBbm8eDMZY5zq5iMZUC6H7UzYSix4Uy1YlsLVV738PtKP9h\n\
        FTjgDHctXJlC5L7+ZDY=\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nMIICRDCCAcmgAwIBAgIED+E4izAMBggqhkjOPQQDAwUAMGgxCzAJBgNVBAYTAkNO\n\
        MRQwEgYDVQQKEwtPcGVuSGFybW9ueTEZMBcGA1UECxMQT3Blbkhhcm1vbnkgVGVh\nbTEoMCYGA1UEAxMfT3Blbkhhcm1vbnkgQXBwbGljYXRpb24gUm9vdCBDQTAeFw0y\n\
        MTAyMDIxMjE0MThaFw00OTEyMzExMjE0MThaMGgxCzAJBgNVBAYTAkNOMRQwEgYD\nVQQKEwtPcGVuSGFybW9ueTEZMBcGA1UECxMQT3Blbkhhcm1vbnkgVGVhbTEoMCYG\n\
        A1UEAxMfT3Blbkhhcm1vbnkgQXBwbGljYXRpb24gUm9vdCBDQTB2MBAGByqGSM49\nAgEGBSuBBAAiA2IABE023XmRaw2DnO8NSsb+KG/uY0FtS3u5LQucdr3qWVnRW5ui\n\
        QIL6ttNZBEeLTUeYcJZCpayg9Llf+1SmDA7dY4iP2EcRo4UN3rilovtfFfsmH4ty\n3SApHVFzWUl+NwdH8KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n\
        AQYwHQYDVR0OBBYEFBc6EKGrGXzlAE+s0Zgnsphadw7NMAwGCCqGSM49BAMDBQAD\nZwAwZAIwd1p3JzHN93eoPped1li0j64npgqNzwy4OrkehYAqNXpcpaEcLZ7UxW8E\n\
        I2lZJ3SbAjAkqySHb12sIwdSFKSN9KCMMEo/eUT5dUXlcKR2nZz0MJdxT5F51qcX\n1CumzkcYhgU=\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nMIICRDCCAcmgAwIBAgIED+E4izAMBggqhkjOPQQDAwUAMGgxCzAJBgNVBAYTAkNO\n\
        MRQwEgYDVQQKEwtPcGVuSGFybW9ueTEZMBcGA1UECxMQT3Blbkhhcm1vbnkgVGVh\nbTEoMCYGA1UEAxMfT3Blbkhhcm1vbnkgQXBwbGljYXRpb24gUm9vdCBDQTAeFw0y\n\
        MTAyMDIxMjE0MThaFw00OTEyMzExMjE0MThaMGgxCzAJBgNVBAYTAkNOMRQwEgYD\nVQQKEwtPcGVuSGFybW9ueTEZMBcGA1UECxMQT3Blbkhhcm1vbnkgVGVhbTEoMCYG\n\
        A1UEAxMfT3Blbkhhcm1vbnkgQXBwbGljYXRpb24gUm9vdCBDQTB2MBAGByqGSM49\nAgEGBSuBBAAiA2IABE023XmRaw2DnO8NSsb+KG/uY0FtS3u5LQucdr3qWVnRW5ui\n\
        QIL6ttNZBEeLTUeYcJZCpayg9Llf+1SmDA7dY4iP2EcRo4UN3rilovtfFfsmH4ty\n3SApHVFzWUl+NwdH8KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n\
        AQYwHQYDVR0OBBYEFBc6EKGrGXzlAE+s0Zgnsphadw7NMAwGCCqGSM49BAMDBQAD\nZwAwZAIwd1p3JzHN93eoPped1li0j64npgqNzwy4OrkehYAqNXpcpaEcLZ7UxW8E\n\
        I2lZJ3SbAjAkqySHb12sIwdSFKSN9KCMMEo/eUT5dUXlcKR2nZz0MJdxT5F51qcX\n1CumzkcYhgU=\n-----END CERTIFICATE-----\n"
    ].join("\n").into_bytes();
    assert_eq!(result, expected_cert);
}

#[test]
fn test_invalid_pem_cert_file_path() {
    let result =
        load_pem_cert_from_json_file(NON_EXISTEND_PEM_CERT, ALLOWED_ROOT_CERT_MEMBER_NAMES);
    assert!(result.is_empty());
}

#[test]
fn test_invalid_pem_cert_json_structure() {
    let result =
        load_pem_cert_from_json_file(INVALID_STRUCTURE_PEM_CERT, ALLOWED_ROOT_CERT_MEMBER_NAMES);
    assert!(result.is_empty());
}

#[test]
fn test_empty_pem_cert_json_file() {
    let result = load_pem_cert_from_json_file(EMPTY_PEM_CERT, ALLOWED_ROOT_CERT_MEMBER_NAMES);
    assert!(result.is_empty());
}

#[test]
fn test_successful_load_cert_path() {
    let mut cert_paths = Vec::new();
    load_cert_path_from_json_file(&mut cert_paths, VALID_CERT_PATH);

    assert_eq!(
        cert_paths.len(),
        3,
        "Expected three entries to be populated"
    );

    assert_eq!(
        cert_paths[0].path_len, 3,
        "Expected the path of the first entry to be 3"
    );
    assert_eq!(
        cert_paths[0].signing.to_str().unwrap(),
        "Huawei: HOS AppGallery Application Release",
        "Unexpected app-signing-cert for the first entry"
    );
    assert_eq!(
        cert_paths[0].issuer.to_str().unwrap(),
        "Huawei CBG Software Signing Service CA Test",
        "Unexpected issuer-ca for the first entry"
    );

    assert_eq!(
        cert_paths[1].path_len, 3,
        "Expected the path of the second entry to be 3"
    );
    assert_eq!(
        cert_paths[1].signing.to_str().unwrap(),
        "Huawei CBG: HOS Application Provision Dev",
        "Unexpected app-signing-cert for the second entry"
    );
    assert_eq!(
        cert_paths[1].issuer.to_str().unwrap(),
        "Huawei CBG Software Signing Service CA Test",
        "Unexpected issuer-ca for the second entry"
    );

    assert_eq!(
        cert_paths[2].path_len, 3,
        "Expected the path of the third entry to be 3"
    );
    assert_eq!(
        cert_paths[2].signing.to_str().unwrap(),
        "Huawei: HOS Preload Service",
        "Unexpected app-signing-cert for the third entry"
    );
    assert_eq!(
        cert_paths[2].issuer.to_str().unwrap(),
        "Huawei CBG Software Signing Service CA Test",
        "Unexpected issuer-ca for the third entry"
    );
}
#[test]
fn test_invalid_cert_path_file_path() {
    let mut cert_paths = Vec::new();
    load_cert_path_from_json_file(&mut cert_paths, NON_EXISTEND_CERT_PATH);
    assert!(
        cert_paths.is_empty(),
        "Expected cert_paths to be empty for a non-existent file"
    );
}

#[test]
fn test_invalid_cert_path_json_structure() {
    let mut cert_paths = Vec::new();
    load_cert_path_from_json_file(&mut cert_paths, INVALID_STRUCTURE_CERT_PATH);

    assert_eq!(
        cert_paths.len(),
        3,
        "Expected 3 valid TrustAppSource instances for given JSON"
    );

    assert_eq!(
        cert_paths[0].signing.to_str().unwrap(),
        "Huawei: HOS AppGallery Application Release"
    );
    assert_eq!(
        cert_paths[0].issuer.to_str().unwrap(),
        "Huawei CBG Software Signing Service CA Test"
    );
    assert_eq!(cert_paths[0].path_len, 3);

    assert_eq!(
        cert_paths[1].signing.to_str().unwrap(),
        "Huawei CBG: HOS Application Provision Dev"
    );
    assert_eq!(
        cert_paths[1].issuer.to_str().unwrap(),
        "Huawei CBG Software Signing Service CA Test"
    );
    assert_eq!(cert_paths[1].path_len, 3);

    assert_eq!(
        cert_paths[2].signing.to_str().unwrap(),
        "Huawei: HOS Preload Service"
    );
    assert_eq!(
        cert_paths[2].issuer.to_str().unwrap(),
        "Huawei CBG Software Signing Service CA Test"
    );
    assert_eq!(cert_paths[2].path_len, 3);
}

#[test]
fn test_empty_cert_path_json_file() {
    let mut cert_paths = Vec::new();
    load_cert_path_from_json_file(&mut cert_paths, EMPTY_CERT_PATH);
    assert!(
        cert_paths.is_empty(),
        "Expected cert_paths to be empty for an empty JSON file"
    );
}
