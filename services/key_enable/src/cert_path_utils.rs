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
use super::cs_hisysevent;
use super::profile_utils::IsDeveloperModeOn;
use hilog_rust::{error, hilog, info, HiLogLabel, LogType};
use std::ffi::{c_char, CString};
use ylong_json::JsonValue;

extern "C" {
    fn IsRdDevice() -> bool;
}

const LOG_LABEL: HiLogLabel = HiLogLabel {
    log_type: LogType::LogCore,
    domain: 0xd005a06, // security domain
    tag: "CODE_SIGN",
};
const TRUST_PROFILE_PATH_KEY: &str = "trust-profile-path";
const TRUST_CERT_PATH_KEY: &str = "trust-cert-path";
const MODE_KEY: &str = "mode";
const TYPE_KEY: &str = "type";
const SUBJECT_KEY: &str = "subject";
const ISSUER_KEY: &str = "issuer";
const MAX_CERT_PATH: &str = "max-certs-path";
const EMPTY_APP_ID: &str = "";
const COMMON_NAME_CHAR_LIMIT: usize = 7;
/// profile cert path error
pub enum CertPathError {
    /// cert path add remove error
    CertPathOperationError,
    /// activate cert error
    ActivateCertError,
}
/// release cert path type
pub enum ReleaseCertPathType {
    /// release platform code
    Platform = 0x1,
    /// release authed code
    Authed = 0x2,
    /// release developer code
    Developer = 0x3,
    /// release block code
    Block = 0x4,
    /// restrict code
    Restricted = 0xff,
}

impl ReleaseCertPathType {
    fn from_str(s: &str) -> Result<u32, ()> {
        match s {
            "Platform" => Ok(ReleaseCertPathType::Platform as u32),
            "Authed" => Ok(ReleaseCertPathType::Authed as u32),
            "Developer" => Ok(ReleaseCertPathType::Developer as u32),
            "Block" => Ok(ReleaseCertPathType::Block as u32),
            "Restricted" => Ok(ReleaseCertPathType::Restricted as u32),
            _ => Err(()),
        }
    }
}
/// debug cert path type
pub enum DebugCertPathType {
    /// debug platform code
    Platform = 0x101,
    /// debug authed code
    Authed = 0x102,
    /// debug developer code
    Developer = 0x103,
    /// debug block code
    Block = 0x104,
    /// debug debug code
    Debug = 0x105,
    /// restrict code
    Restricted = 0x1ff,
}

/// enterprise cert type
#[allow(dead_code)]
pub enum EnterpriseCertPathType {
    /// enterprise platform code
    Platform = 0x201,
    /// enterprise authed code
    Authed = 0x202,
    /// enterprise developer code
    Developer = 0x203,
    /// enterprise block code
    Block = 0x204,
    /// enterprise debug code
    Debug = 0x205,
    /// restrict code
    Restricted = 0x2ff,
}

impl DebugCertPathType {
    fn from_str(s: &str) -> Result<u32, ()> {
        match s {
            "Platform" => Ok(DebugCertPathType::Platform as u32),
            "Authed" => Ok(DebugCertPathType::Authed as u32),
            "Developer" => Ok(DebugCertPathType::Developer as u32),
            "Block" => Ok(DebugCertPathType::Block as u32),
            "Debug" => Ok(DebugCertPathType::Debug as u32),
            "Restricted" => Ok(DebugCertPathType::Restricted as u32),
            _ => Err(()),
        }
    }
}
/// profile cert path type
pub enum ProfileCertPathType {
    /// profile developer code
    Developer = 0x01,
    /// profile debug code
    Debug = 0x02,
}

extern "C" {
    fn AddCertPath(info: *const CertPathInfo) -> i32;
    fn RemoveCertPath(info: *const CertPathInfo) -> i32;
}
/// structure of trust-app-source from json file
pub struct TrustCertPath {
    /// vec to contains valid profile_signers
    pub profile_signers: Vec<CertPath>,
    /// vec to contains app source data
    pub app_sources: Vec<CertPath>,
}
/// inner data of trust-app-source
pub struct CertPath {
    ///mode
    pub mode: String,
    /// subject
    pub subject: String,
    /// issuer
    pub issuer_ca: String,
    /// max certs path
    pub max_certs_path: u32,
    /// cert path type
    pub cert_path_type: u32,
}
impl Default for TrustCertPath {
    fn default() -> Self {
        Self::new()
    }
}
impl TrustCertPath {
    /// init object
    pub fn new() -> Self {
        TrustCertPath {
            profile_signers: Vec::new(),
            app_sources: Vec::new(),
        }
    }
    /// get source.profile_signing_cert from json array to check developer profiles
    pub fn get_profile_info(&self) -> Vec<(&String, &String)> {
        self.profile_signers
            .iter()
            .filter(|source| source.cert_path_type == ProfileCertPathType::Developer as u32)
            .map(|source| (&source.subject, &source.issuer_ca))
            .collect()
    }
    /// get source.profile_signing_cert from json array to check debug profiles
    pub fn get_debug_profile_info(&self) -> Vec<(&String, &String)> {
        self.profile_signers
            .iter()
            .filter(|source| source.cert_path_type == ProfileCertPathType::Debug as u32)
            .map(|source| (&source.subject, &source.issuer_ca))
            .collect()
    }
    /// add signing cert paths to kernel
    pub fn add_cert_paths(&self) -> Result<(), CertPathError> {
        for cert_path in &self.app_sources {
            if !unsafe { IsDeveloperModeOn() } && &cert_path.mode == "Dev" {
                continue;
            }
            if !cert_path.subject.is_empty()
            && !cert_path.issuer_ca.is_empty()
            && cert_path.add_subject_cert_path().is_err() {
                    error!(
                        LOG_LABEL,
                        "add signing cert path into ioctl error {} : {} : {}",
                        cert_path.subject,
                        cert_path.issuer_ca,
                        cert_path.cert_path_type
                    );
                    continue;
            }
        }
        Ok(())
    }

    fn parse_cert_profile<F>(
        cert_profile: &JsonValue,
        path_type_resolver: F,
    ) -> Result<CertPath, ()>
    where
        F: Fn(&str, &str) -> Result<u32, ()> {
        let cert_mode = match cert_profile[MODE_KEY].try_as_string() {
            Ok(v) => v,
            Err(e) => {
                error!(LOG_LABEL, "Error JSON MODE_KEY from file {:?}", e);
                return Err(());
            }
        };

        let cert_type = match cert_profile[TYPE_KEY].try_as_string() {
            Ok(v) => v,
            Err(e) => {
                error!(LOG_LABEL, "Error JSON TYPE_KEY from file {:?}", e);
                return Err(());
            }
        };

        let path_type = match path_type_resolver(cert_mode, cert_type) {
            Ok(v) => v,
            Err(e) => {
                error!(LOG_LABEL, "Error JSON Path Type from file {:?}", e);
                return Err(());
            }
        };

        let signing_cert = match cert_profile[SUBJECT_KEY].try_as_string() {
            Ok(v) => v,
            Err(e) => {
                error!(LOG_LABEL, "Error JSON SUBJECT_KEY from file {:?}", e);
                return Err(());
            }
        };

        let issuer = match cert_profile[ISSUER_KEY].try_as_string() {
            Ok(v) => v,
            Err(e) => {
                error!(LOG_LABEL, "Error JSON ISSUER_KEY from file {:?}", e);
                return Err(());
            }
        };

        let path_len = match cert_profile[MAX_CERT_PATH].try_as_number().and_then(|n| n.try_as_i64()) {
            Ok(v) => v,
            Err(e) => {
                error!(LOG_LABEL, "Error JSON MAX_CERT_PATH from file {:?}", e);
                return Err(());
            }
        };

        Ok(CertPath {
            mode: cert_mode.to_string(),
            subject: signing_cert.to_string(),
            issuer_ca: issuer.to_string(),
            cert_path_type: path_type,
            max_certs_path: path_len as u32,
        })
    }

    fn issuer_resolver(cert_mode: &str, _cert_type: &str) -> Result<u32, ()> {
        match cert_mode {
            "developer" => Ok(ProfileCertPathType::Developer as u32),
            "debug" => Ok(ProfileCertPathType::Debug as u32),
            _ => Err(()),
        }
    }

    fn path_resolver(cert_mode: &str, cert_type: &str) -> Result<u32, ()> {
        match cert_mode {
            "Release" => ReleaseCertPathType::from_str(cert_type),
            "Dev" => DebugCertPathType::from_str(cert_type),
            _ => Err(()),
        }
    }

    /// load cert path from json file
    pub fn load_cert_path_from_json_file(&mut self, file_path: &str) {
        let value = match JsonValue::from_file(file_path) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    LOG_LABEL,
                    "Error loading JSON from file {}: {:?}", file_path, e
                );
                return;
            }
        };

        let certs_profile_issuer = match value[TRUST_PROFILE_PATH_KEY].try_as_array() {
            Ok(array) => array,
            Err(_) => {
                error!(
                    LOG_LABEL,
                    "Cannot get preset key TRUST_PROFILE_PATH_KEY from file "
                );
                return;
            }
        };

        let cert_path_array = match value[TRUST_CERT_PATH_KEY].try_as_array() {
            Ok(array) => array,
            Err(_) => {
                error!(
                    LOG_LABEL,
                    "Cannot get preset key TRUST_CERT_PATH_KEY from file "
                );
                return;
            }
        };

        for cert_profile in certs_profile_issuer.iter() {
            match Self::parse_cert_profile(cert_profile, Self::issuer_resolver) {
                Ok(app_source) => self.profile_signers.push(app_source),
                Err(e) => {
                    error!(LOG_LABEL, "Error parsing cert profile issuer : {:?}", e);
                    continue;
                }
            }
        }

        for cert_path in cert_path_array.iter() {
            match Self::parse_cert_profile(cert_path, Self::path_resolver) {
                Ok(app_source) => self.app_sources.push(app_source),
                Err(e) => {
                    error!(LOG_LABEL, "Error parsing cert path: {:?}", e);
                    continue;
                }
            }
        }
    }
}

impl CertPath {
    /// add single app cert path
    pub fn add_subject_cert_path(&self) -> Result<(), CertPathError> {
        let subject = fabricate_name(&self.subject);
        let issuer = fabricate_name(&self.issuer_ca);
        add_cert_path_info(
            subject,
            issuer,
            self.cert_path_type,
            EMPTY_APP_ID.to_string(),
            self.max_certs_path,
        )?;
        Ok(())
    }
}

#[repr(C)]
/// cert path info reflect to C
pub struct CertPathInfo {
    /// signing_length
    pub signing_length: u32,
    /// issuer_length
    pub issuer_length: u32,
    /// signing
    pub signing: u64,
    /// issuer
    pub issuer: u64,
    /// path length
    pub path_len: u32,
    /// path type
    pub path_type: u32,
    /// app id
    pub app_id: u64,
    /// app id length
    pub app_id_length: u32,
    __reserved: [u8; 20],
}

fn fabricate_name(subject: &str) -> String {
    if subject == "ALL" {
        return "ALL".to_string();
    }
    let mut common_name = String::new();
    let mut organization = String::new();
    let mut email = String::new();
    let parts: Vec<&str> = subject.split(',').collect();
    for part in parts {
        let inner: Vec<&str> = part.split('=').collect();
        if inner.len() < 2 {
            continue;
        }
        let inner_trimmed: Vec<&str> = inner.iter().map(|s| s.trim()).collect();
        if inner_trimmed[0] == "CN" {
            common_name = inner_trimmed[1].into();
        } else if inner_trimmed[0] == "O" {
            organization = inner_trimmed[1].into();
        } else if inner_trimmed[0] == "E" {
            email = inner_trimmed[1].into();
        }
    }
    let ret = common_format_fabricate_name(&common_name, &organization, &email);
    ret
}
/// common rule to fabricate name
pub fn common_format_fabricate_name(common_name: &str, organization: &str, email: &str) -> String {
    let mut ret = String::new();
    if !common_name.is_empty() && !organization.is_empty() {
        if common_name.len() >= organization.len() && common_name.starts_with(organization) {
            return common_name.to_string();
        }
        if common_name.len() >= COMMON_NAME_CHAR_LIMIT && organization.len() >= COMMON_NAME_CHAR_LIMIT {
            let common_name_prefix = &common_name.as_bytes()[..COMMON_NAME_CHAR_LIMIT];
            let organization_prefix = &organization.as_bytes()[..COMMON_NAME_CHAR_LIMIT];
            if common_name_prefix == organization_prefix {
                ret = common_name.to_string();
                return ret;
            }
        }
        ret = format!("{}: {}", organization, common_name);
    } else if !common_name.is_empty() {
        ret = common_name.to_string();
    } else if !organization.is_empty() {
        ret = organization.to_string();
    } else if !email.is_empty() {
        ret = email.to_string();
    }
    ret
}

fn convert_cert_type(cert_path_type: u32) -> u32 {
    if cert_path_type == ReleaseCertPathType::Restricted as u32 {
        if env!("support_openharmony_ca") == "on" || unsafe { IsRdDevice() } {
            return ReleaseCertPathType::Authed as u32;
        } else {
            return 0;   // return invalid type
        }
    } else if cert_path_type == DebugCertPathType::Restricted as u32 {
        if env!("support_openharmony_ca") == "on" || unsafe { IsRdDevice() } {
            return DebugCertPathType::Authed as u32;
        } else {
            return 0;   // return invalid type
        }
    }
    cert_path_type
}

fn cert_path_operation<F>(
    subject: String,
    issuer: String,
    cert_path_type: u32,
    app_id: String,
    path_length: u32,
    operation: F,
    op_name: &str,
) -> Result<(), CertPathError>
where
    F: Fn(&CertPathInfo) -> i32 {
    if subject.is_empty() || issuer.is_empty() {
        return Err(CertPathError::CertPathOperationError);
    }

    if !app_id.is_empty() {
        info!(LOG_LABEL, "sending APP_ID '{}' through ioctl", @public(app_id));
    }
    let subject_cstring = CString::new(subject).expect("convert to subject_cstring error!");
    let issuer_cstring = CString::new(issuer).expect("convert to issuer_cstring error!");
    let converted_cert_type = convert_cert_type(cert_path_type);
    let app_id_cstring = CString::new(app_id).expect("convert to app_id_cstring error!");

    // invalid cert type, skip adding
    if converted_cert_type == 0u32 {
        return Ok(());
    }

    let cert_path_info = CertPathInfo {
        signing_length: subject_cstring.as_bytes().len() as u32,
        issuer_length: issuer_cstring.as_bytes().len() as u32,
        signing: subject_cstring.as_ptr() as u64,
        issuer: issuer_cstring.as_ptr() as u64,
        path_len: path_length,
        path_type: converted_cert_type,
        app_id: app_id_cstring.as_ptr() as u64,
        app_id_length: app_id_cstring.as_bytes().len() as u32,
        __reserved: [0; 20],
    };
    let ret = operation(&cert_path_info);
    info!(LOG_LABEL, "ioctl return:{}", @public(ret));
    if ret < 0 {
        cs_hisysevent::report_add_key_err(op_name, ret);
        return Err(CertPathError::CertPathOperationError);
    }
    Ok(())
}
/// add cert path info in kernel
pub fn add_cert_path_info(
    subject: String,
    issuer: String,
    cert_path_type: u32,
    app_id: String,
    path_length: u32,
) -> Result<(), CertPathError> {
    cert_path_operation(
        subject,
        issuer,
        cert_path_type,
        app_id,
        path_length,
        |info| unsafe { AddCertPath(info) },
        "add cert_path",
    )?;
    Ok(())
}
/// remove cert path info in kernel
pub fn remove_cert_path_info(
    subject: String,
    issuer: String,
    cert_path_type: u32,
    app_id: String,
    path_length: u32,
) -> Result<(), CertPathError> {
    cert_path_operation(
        subject,
        issuer,
        cert_path_type,
        app_id,
        path_length,
        |info| unsafe { RemoveCertPath(info) },
        "remove cert_path",
    )?;
    Ok(())
}

extern "C" {
    fn ActivateCert(info: *const CertActivationInfo) -> i32;
}

/// cert type
#[derive(Clone, Copy)]
pub enum CertType {
    /// other cert (root, enterprise, etc.)
    Other = 0,
    
    /// local cert
    Local = 1,
}

/// cert status
#[derive(Clone, Copy)]
pub enum CertStatus {
    /// activated before first unlock
    BeforeUnlock = 0,

    /// activated after first unlock
    AfterUnlock = 1,
}

#[repr(C)]
/// cert activation info reflect to C
struct CertActivationInfo {
    /// cert
    pub cert: u64,
    /// cert length
    pub cert_length: u32,
    /// status,     before unlock: 0 after unlock: 1
    pub status: u8,
    /// cert_type   other: 0 local:1 
    pub cert_type: u8,
}

/// activate the given cert in kernel
pub fn activate_cert(cert_data: &Vec<u8>, cert_status: CertStatus, cert_type: CertType) -> Result<(), CertPathError> {
    let cert_activation_info = CertActivationInfo {
        cert: cert_data.as_ptr() as u64,
        cert_length: cert_data.len() as u32,
        status: cert_status as u8,
        cert_type: cert_type as u8,
    };
    info!(LOG_LABEL, "Activating cert");
    let ret = unsafe { ActivateCert(&cert_activation_info) };
    info!(LOG_LABEL, "ioctl return:{}", @public(ret));
    if ret < 0 {
        cs_hisysevent::report_add_key_err("activate_cert", ret);
        return Err(CertPathError::ActivateCertError);
    }
    Ok(())
}

#[repr(C)]
/// cert path info reflect to C
pub struct EnterpriseResignCertInfo {
    /// signing_length
    pub signing_length: u32,
    /// issuer_length
    pub issuer_length: u32,
    /// signing
    pub signing: u64,
    /// issuer
    pub issuer: u64,
    /// path length
    pub path_len: u32,
    /// path type
    pub path_type: u32,
    /// app id
    pub app_id: u64,
    /// app id length
    pub app_id_length: u32,
    /// cert length
    pub cert_length: u32,
    /// cert
    pub cert: u64,
    _reserved: [u8; 8],
}

extern "C" {
    fn AddEnterpriseResignCert(info: *const EnterpriseResignCertInfo) -> i32;
    fn RemoveEnterpriseResignCert(info: *const EnterpriseResignCertInfo) -> i32;
}

/// Params for adding enterprise resign cert
#[derive(Debug)]
pub struct EnterpriseResignCertParam<'a> {
    /// subject (signing)
    pub subject: String,
    /// issuer
    pub issuer: String,
    /// path_type
    pub cert_path_type: u32,
    /// app_id
    pub app_id: String,
    /// max_path_length
    pub path_length: u32,
    /// pem encoded cert data
    pub cert_data: &'a Vec<u8>,
}

fn handle_enterprise_resign_cert<F>(
    cert: EnterpriseResignCertParam,
    operation: F,
    op_name: &str
) -> Result<(), CertPathError>
where
    F: Fn(&EnterpriseResignCertInfo) -> i32 {
    info!(LOG_LABEL, "start {}", @public(op_name));
    if cert.subject.is_empty() || cert.issuer.is_empty() {
        error!(LOG_LABEL, "Empty subject or issuer");
        return Err(CertPathError::CertPathOperationError);
    }

    let subject_cstring = CString::new(cert.subject).expect("convert to subject_cstring error!");
    let issuer_cstring = CString::new(cert.issuer).expect("convert to issuer_cstring error!");
    let app_id_cstring = CString::new(cert.app_id).expect("convert to app_id_cstring error!");

    let info = EnterpriseResignCertInfo {
        signing_length: subject_cstring.as_bytes().len() as u32,
        issuer_length: issuer_cstring.as_bytes().len() as u32,
        signing: subject_cstring.as_ptr() as u64,
        issuer: issuer_cstring.as_ptr() as u64,
        path_len: cert.path_length,
        path_type: cert.cert_path_type,
        app_id: app_id_cstring.as_ptr() as u64,
        app_id_length: app_id_cstring.as_bytes().len() as u32,
        cert_length: cert.cert_data.len() as u32,
        cert: cert.cert_data.as_ptr() as u64,
        _reserved: [0; 8],
    };
    let ret = operation(&info);
    if ret < 0 {
        error!(LOG_LABEL, "{} failed, ret = {}", @public(op_name), @public(ret));
        cs_hisysevent::report_add_key_err(op_name, ret);
        return Err(CertPathError::CertPathOperationError);
    }
    Ok(())
}

/// add enterprise resign cert
pub fn add_enterprise_resign_cert(cert: EnterpriseResignCertParam) -> Result<(), CertPathError> {
    handle_enterprise_resign_cert(
        cert,
        |info| unsafe { AddEnterpriseResignCert(info) },
        "add enterprise resign cert"
    )
}

/// remove enterprise resign cert
pub fn remove_enterprise_resign_cert(cert: EnterpriseResignCertParam) -> Result<(), CertPathError> {
    handle_enterprise_resign_cert(
        cert,
        |info| unsafe { RemoveEnterpriseResignCert(info) },
        "remove enterprise resign cert"
    )
}
