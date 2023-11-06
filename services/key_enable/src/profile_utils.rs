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
use super::cert_path_utils::{
    add_cert_path_info, remove_cert_path_info, DebugCertPathType, ReleaseCertPathType,
    TrustCertPath,
};
use super::cs_hisysevent::report_parse_profile_err;
use super::file_utils::{
    create_file_path, delete_file_path, file_exists, load_bytes_from_file, write_bytes_to_file,
};
use hilog_rust::{error, hilog, HiLogLabel, LogType};
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::{X509NameRef, X509};
use std::error::Error;
use std::ffi::{c_char, CStr, CString};
use std::fs::read_dir;
use ylong_json::JsonValue;

const ERROR_CODE: i32 = -1;
const SUCCESS_CODE: i32 = 0;
const LOG_LABEL: HiLogLabel = HiLogLabel {
    log_type: LogType::LogCore,
    domain: 0xd002f00, // security domain
    tag: "CODE_SIGN",
};
const PROFILE_STORE_PREFIX: &str = "/data/service/el0/profiles/developer";
const DEBUG_PROFILE_STORE_PREFIX: &str = "/data/service/el0/profiles/debug";
const PROFILE_STORE_TAIL: &str = "profile.p7b";
const PROFILE_TYPE_KEY: &str = "type";
const PROFILE_BUNDLE_INFO_KEY: &str = "bundle-info";
const PROFILE_BUNDLE_INFO_RELEASE_KEY: &str = "distribution-certificate";
const PROFILE_BUNDLE_INFO_DEBUG_KEY: &str = "development-certificate";
const DEFAULT_MAX_CERT_PATH_LEN: u32 = 3;
const PROFILE_RELEASE_TYPE: &str = "release";
const PROFILE_DEBUG_TYPE: &str = "debug";

/// profile error
pub enum ProfileError {
    /// add cert path error
    AddCertPathError,
}

extern "C" {
    /// if developer state on return true
    pub fn IsDeveloperModeOn() -> bool;
}

#[no_mangle]
/// the interface to enable key in profile
pub extern "C" fn EnableKeyInProfileByRust(
    bundle_name: *const c_char,
    profile: *const u8,
    profile_size: u32,
) -> i32 {
    match enable_key_in_profile_internal(bundle_name, profile, profile_size) {
        Ok(_) => SUCCESS_CODE,
        Err(_) => ERROR_CODE,
    }
}

#[no_mangle]
/// the interface remove key in profile
pub extern "C" fn RemoveKeyInProfileByRust(bundle_name: *const c_char) -> i32 {
    match remove_key_in_profile_internal(bundle_name) {
        Ok(_) => SUCCESS_CODE,
        Err(_) => ERROR_CODE,
    }
}

fn parse_pkcs7_data(
    profile_data: &[u8],
    root_store: &X509Store,
    profile_signer: &[(&String, &String)],
    verify: bool,
) -> Result<(String, String, u32), Box<dyn Error>> {
    let pkcs7 = Pkcs7::from_der(profile_data)?;
    let stack_of_certs = Stack::<X509>::new()?;

    let flags = if verify {
        let signers_result = pkcs7.signers(&stack_of_certs, Pkcs7Flags::empty())?;
        for signer in signers_result {
            let subject_name = format_x509name_to_string(signer.subject_name());
            let issuer_name = format_x509name_to_string(signer.issuer_name());
            if !profile_signer.contains(&(&subject_name, &issuer_name)) {
                return Err("Verification failed.".into());
            }
        }
        Pkcs7Flags::empty()
    } else {
        Pkcs7Flags::NOVERIFY
    };

    let mut profile = Vec::new();
    if pkcs7.verify(&stack_of_certs, root_store, None, Some(&mut profile), flags).is_err() {
        error!(LOG_LABEL, "pkcs7 verify failed.");
        return Err("pkcs7 verify failed.".into());
    }

    let profile_json = JsonValue::from_text(profile)?;
    let bundle_type = profile_json[PROFILE_TYPE_KEY].try_as_string()?.as_str();
    let profile_type = match bundle_type {
        PROFILE_DEBUG_TYPE => DebugCertPathType::Developer as u32,
        PROFILE_RELEASE_TYPE => ReleaseCertPathType::Developer as u32,
        _ => {
            error!(LOG_LABEL, "pkcs7 verify failed.");
            return Err("Invalid bundle type.".into());
        }
    };
    let signed_cert = match bundle_type {
        PROFILE_DEBUG_TYPE => {
            profile_json[PROFILE_BUNDLE_INFO_KEY][PROFILE_BUNDLE_INFO_DEBUG_KEY].try_as_string()?
        }
        PROFILE_RELEASE_TYPE => profile_json[PROFILE_BUNDLE_INFO_KEY][PROFILE_BUNDLE_INFO_RELEASE_KEY]
            .try_as_string()?,
        _ => {
            error!(LOG_LABEL, "pkcs7 verify failed.");
            return Err("Invalid bundle type.".into());
        }
    };
    let signed_pem = X509::from_pem(signed_cert.as_bytes())?;
    let subject = format_x509name_to_string(signed_pem.subject_name());
    let issuer = format_x509name_to_string(signed_pem.issuer_name());

    Ok((subject, issuer, profile_type))
}

fn format_x509name_to_string(name: &X509NameRef) -> String {
    let mut parts = Vec::new();

    for entry in name.entries() {
        let tag = match entry.object().nid() {
            openssl::nid::Nid::COMMONNAME => "CN",
            openssl::nid::Nid::COUNTRYNAME => "C",
            openssl::nid::Nid::ORGANIZATIONNAME => "O",
            openssl::nid::Nid::ORGANIZATIONALUNITNAME => "OU",
            _ => continue,
        };
        let value = entry.data().as_utf8().unwrap();
        parts.push(format!("{}={}", tag, value));
    }
    parts.join(", ")
}

fn get_profile_paths(is_debug: bool) -> Vec<String> {
    let mut paths = Vec::new();
    let profile_paths = match is_debug {
        false => PROFILE_STORE_PREFIX,
        true => DEBUG_PROFILE_STORE_PREFIX,
    };
    if let Ok(entries) = read_dir(profile_paths) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let filename = format!("{}/{}", path.to_string_lossy(), PROFILE_STORE_TAIL);
            if file_exists(&filename) {
                paths.push(filename);
            }
        }
    }
    paths
}

/// add profile cert path data
pub fn add_profile_cert_path(
    root_cert: &PemCollection,
    cert_paths: &TrustCertPath,
) -> Result<(), ProfileError> {
    let x509_store = root_cert.to_x509_store().unwrap();
    if process_profile_paths(false, &x509_store, cert_paths.get_profile_info().as_slice()).is_err() {
        return Err(ProfileError::AddCertPathError);
    }
    if unsafe { IsDeveloperModeOn() }
        && process_profile_paths(
            true,
            &x509_store,
            cert_paths.get_debug_profile_info().as_slice(),
        ).is_err() {
        return Err(ProfileError::AddCertPathError);
    }
    Ok(())
}

fn process_profile_paths(
    is_debug: bool,
    x509_store: &X509Store,
    profile_info: &[(&String, &String)],
) -> Result<(), ProfileError> {
    let profiles_paths = get_profile_paths(is_debug);
    for path in profiles_paths {
        let mut pkcs7_data = Vec::new();
        if load_bytes_from_file(&path, &mut pkcs7_data).is_err() {
            continue;
        }
        let (subject, issuer, profile_type) =
            match parse_pkcs7_data(&pkcs7_data, x509_store, profile_info, true) {
                Ok(tuple) => tuple,
                Err(_) => {
                    error!(LOG_LABEL, "Failed to parse profile file {}", path);
                    report_parse_profile_err(&path);
                    continue;
                }
            };
        if add_cert_path_info(&subject, &issuer, profile_type, DEFAULT_MAX_CERT_PATH_LEN).is_err() {
            error!(
                LOG_LABEL,
                "Failed to add profile cert path info into ioctl for {}", path
            );
            report_parse_profile_err(&path);
            continue;
        }
    }
    Ok(())
}

fn enable_key_in_profile_internal(
    bundle_name: *const c_char,
    profile: *const u8,
    profile_size: u32,
) -> Result<(), ()> {
    let _bundle_name = c_char_to_string(bundle_name);
    if _bundle_name.is_empty() {
        error!(LOG_LABEL, "invalid profile bundle name!");
        return Err(());
    }
    let profile_data = cbyte_buffer_to_vec(profile, profile_size);
    let signer_info: &[(&String, &String)] = &[];
    let store = match X509StoreBuilder::new() {
        Ok(store) => store.build(),
        Err(_) => {
            error!(LOG_LABEL, "Failed to build X509 store");
            return Err(());
        }
    };
    let (subject, issuer, profile_type) =
        match parse_pkcs7_data(&profile_data, &store, signer_info, false) {
            Ok(tuple) => tuple,
            Err(_) => {
                error!(LOG_LABEL, "parse pkcs7 data error");
                return Err(());
            }
        };
    let bundle_path = match profile_type {
        value if value == DebugCertPathType::Developer as u32 => {
            format!("{}/{}", DEBUG_PROFILE_STORE_PREFIX, _bundle_name)
        }
        value if value == ReleaseCertPathType::Developer as u32 => {
            format!("{}/{}", PROFILE_STORE_PREFIX, _bundle_name)
        }
        _ => {
            error!(LOG_LABEL, "invalid profile type");
            return Err(());
        }
    };
    if !file_exists(&bundle_path) && create_file_path(&bundle_path).is_err() {
        error!(LOG_LABEL, "create bundle_path path {} failed!", bundle_path);
        return Err(());
    }

    let filename = format!("{}/{}", bundle_path, PROFILE_STORE_TAIL);
    if write_bytes_to_file(&filename, &profile_data).is_err() {
        error!(LOG_LABEL, "dump profile data error!");
        return Err(());
    }

    if add_cert_path_info(&subject, &issuer, profile_type, DEFAULT_MAX_CERT_PATH_LEN).is_err() {
        error!(LOG_LABEL, "add profile data error!");
        return Err(());
    }
    Ok(())
}

fn remove_key_in_profile_internal(bundle_name: *const c_char) -> Result<(), ()> {
    let _bundle_name = c_char_to_string(bundle_name);
    if _bundle_name.is_empty() {
        error!(LOG_LABEL, "Invalid bundle name");
        return Err(());
    }

    let debug_bundle_path = format!("{}/{}", DEBUG_PROFILE_STORE_PREFIX, _bundle_name);
    let release_bundle_path = format!("{}/{}", PROFILE_STORE_PREFIX, _bundle_name);

    let bundle_path = if file_exists(&debug_bundle_path) {
        debug_bundle_path
    } else if file_exists(&release_bundle_path) {
        release_bundle_path
    } else {
        error!(LOG_LABEL, "bundle path does not exists!");
        return Err(());
    };
    let filename = format!("{}/{}", bundle_path, PROFILE_STORE_TAIL);
    let mut profile_data = Vec::new();
    if load_bytes_from_file(&filename, &mut profile_data).is_err() {
        error!(LOG_LABEL, "load profile data error!");
        return Err(());
    }

    let signer_info: &[(&String, &String)] = &[];
    let store = match X509StoreBuilder::new() {
        Ok(store) => store.build(),
        Err(_) => {
            error!(LOG_LABEL, "Failed to build X509 store");
            return Err(());
        }
    };

    let (subject, issuer, profile_type) =
        match parse_pkcs7_data(&profile_data, &store, signer_info, false) {
            Ok(tuple) => tuple,
            Err(_) => {
                error!(LOG_LABEL, "parse pkcs7 data error");
                return Err(());
            }
        };
    if delete_file_path(&bundle_path).is_err() {
        error!(LOG_LABEL, "remove profile data error!");
        return Err(());
    }
    if unsafe { IsDeveloperModeOn() }
        && profile_type != DebugCertPathType::Developer as u32
        && remove_cert_path_info(&subject, &issuer, profile_type, DEFAULT_MAX_CERT_PATH_LEN).is_err() {
        error!(LOG_LABEL, "remove profile data error!");
        return Err(());
    }
    Ok(())
}

fn c_char_to_string(c_str: *const c_char) -> String {
    unsafe {
        if c_str.is_null() {
            return String::new();
        }
        let c_str = CStr::from_ptr(c_str);
        c_str.to_string_lossy().to_string()
    }
}

fn cbyte_buffer_to_vec(data: *const u8, size: u32) -> Vec<u8> {
    unsafe {
        if data.is_null() {
            return Vec::new();
        }
        let data_slice = std::slice::from_raw_parts(data, size as usize);
        let mut result = Vec::with_capacity(size as usize);
        result.extend_from_slice(data_slice);
        result
    }
}
