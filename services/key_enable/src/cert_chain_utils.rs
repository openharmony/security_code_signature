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

use hilog_rust::{error, hilog, HiLogLabel, LogType};
use openssl::error::ErrorStack;
use openssl::x509::X509;
use std::ffi::{c_char, CString};
use ylong_json::JsonValue;

const ALLOWED_APP_SOURCE_MEMBERNAMES: &[&str] = &[
    "huawei app gallery",
    "huawei system apps",
    "third_party app preload",
];
const TRUST_APP_SOURCE_KEY: &str = "trust-app-source";
const CERT_NAME_KEY: &str = "name";
const APP_SIGNING_CERT_KEY: &str = "app-signing-cert";
const ISSUER_CA_KEY: &str = "issuer-ca";
const MAX_CERT_PATH: &str = "max-certs-path";

const LOG_LABEL: HiLogLabel = HiLogLabel {
    log_type: LogType::LogCore,
    domain: 0xd002f00, // security domain
    tag: "CODE_SIGN",
};

/// data of trust app source
pub struct TrustAppSource {
    /// signing
    pub signing: CString,
    /// issuer
    pub issuer: CString,
    /// path
    pub path_len: i32,
}

fn print_openssl_error_stack(error_stack: ErrorStack) {
    for error in error_stack.errors() {
        error!(LOG_LABEL, "{}", @public(error.to_string()));
    }
}

fn load_certs_from_json_file(file_path: &str, member_names: &[&str]) -> Option<Vec<X509>> {
    let pem: Vec<u8> = load_pem_cert_from_json_file(file_path, member_names);
    match X509::stack_from_pem(&pem) {
        Ok(certs) => Some(certs),
        Err(e) => {
            print_openssl_error_stack(e);
            None
        }
    }
}

fn dump_cert_in_der(cert: X509) -> Option<Vec<u8>> {
    match cert.to_der() {
        Ok(der) => Some(der),
        Err(e) => {
            print_openssl_error_stack(e);
            None
        }
    }
}

/// get root cert from json file
pub fn get_root_cert_from_json_file(certs: &mut Vec<Vec<u8>>, path: &str, member_names: &[&str]) {
    let pem_certs: Vec<X509> = load_certs_from_json_file(path, member_names).unwrap();
    for pem_cert in pem_certs {
        let der_cert = dump_cert_in_der(pem_cert).unwrap();
        certs.push(der_cert);
    }
}

/// load pem certs from json file
pub fn load_pem_cert_from_json_file(file_path: &str, member_names: &[&str]) -> Vec<u8> {
    let value = match JsonValue::from_file(file_path) {
        Ok(v) => v,
        Err(e) => {
            error!(
                LOG_LABEL,
                "Error loading JSON from file {}: {}", file_path, e
            );
            return Vec::new();
        }
    };

    let cert_vec: Vec<String> = member_names
        .iter()
        .filter_map(|subject| {
            let cert_value = &value[subject];
            match cert_value.try_as_string() {
                Ok(s) => Some(s.to_string()),
                Err(_) => None,
            }
        })
        .collect();
    cert_vec.join("\n").into_bytes()
}

/// load cert path from json file
pub fn load_cert_path_from_json_file(cert_paths: &mut Vec<TrustAppSource>, file_path: &str) {
    let value = match JsonValue::from_file(file_path) {
        Ok(v) => v,
        Err(e) => {
            error!(
                LOG_LABEL,
                "Error loading JSON from file {}: {}", file_path, e
            );
            return;
        }
    };

    let cert_path_array = match value[TRUST_APP_SOURCE_KEY].try_as_array() {
        Ok(array) => array,
        Err(_) => {
            error!(
                LOG_LABEL,
                "Cannot get preset key TRUST_APP_SOURCE_KEY from file {}", file_path
            );
            return;
        }
    };

    for cert_path in cert_path_array.iter() {
        let cert_name = match cert_path[CERT_NAME_KEY].try_as_string() {
            Ok(name) => name,
            Err(e) => {
                error!(
                    LOG_LABEL,
                    "Error trying to interpret CERT_NAME_KEY as string: {:?}", e
                );
                return;
            }
        };
        if !ALLOWED_APP_SOURCE_MEMBERNAMES.contains(&cert_name.as_str()) {
            continue;
        }

        let signing = match cert_path[APP_SIGNING_CERT_KEY].try_as_string() {
            Ok(s) => s,
            Err(_) => continue,
        };

        let issuer = match cert_path[ISSUER_CA_KEY].try_as_string() {
            Ok(s) => s,
            Err(_) => continue,
        };

        let path_len = match cert_path[MAX_CERT_PATH]
            .try_as_number()
            .and_then(|n| n.try_as_i64())
        {
            Ok(num) => num,
            Err(_) => continue,
        };

        let signing_cstring = CString::new(signing.as_str()).expect("app-signing-cert is invalid");
        let issuer_cstring = CString::new(issuer.as_str()).expect("issuer-ca is invalid");
        cert_paths.push(TrustAppSource {
            signing: signing_cstring,
            issuer: issuer_cstring,
            path_len: path_len as i32,
        });
    }
}
