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
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::X509PurposeId;
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::X509;
use std::ffi::{c_char, CString};
use ylong_json::JsonValue;

const LOG_LABEL: HiLogLabel = HiLogLabel {
    log_type: LogType::LogCore,
    domain: 0xd005a06, // security domain
    tag: "CODE_SIGN",
};
/// collection to contain pem data
pub struct PemCollection {
    /// vector to store pem data
    pub pem_data: Vec<String>,
}
impl Default for PemCollection {
    fn default() -> Self {
        Self::new()
    }
}
impl PemCollection {
    /// init object
    pub fn new() -> Self {
        PemCollection {
            pem_data: Vec::new(),
        }
    }
    /// add pem string into self.pem_data
    pub fn add(&mut self, data: String) {
        self.pem_data.push(data);
    }
    fn pem_to_x509(&self, pem: &str) -> Result<X509, openssl::error::ErrorStack> {
        X509::from_pem(pem.as_bytes())
    }
    /// convert pem data to X509 object
    pub fn to_x509(&self) -> Result<Vec<X509>, openssl::error::ErrorStack> {
        self.pem_data
            .iter()
            .map(|pem| self.pem_to_x509(pem))
            .collect()
    }
    /// convert pem data to X509 store
    pub fn to_x509_store(&self) -> Result<X509Store, openssl::error::ErrorStack> {
        let x509_certs = self.to_x509()?;
        let mut store_builder = X509StoreBuilder::new()?;
        for cert in x509_certs {
            store_builder.add_cert(cert).unwrap();
        }
        store_builder.set_flags(X509VerifyFlags::NO_CHECK_TIME)?;
        store_builder.set_purpose(X509PurposeId::ANY)?;
        Ok(store_builder.build())
    }
    /// convert pem data to der data
    pub fn to_der(&self) -> Result<Vec<Vec<u8>>, openssl::error::ErrorStack> {
        let x509_certs = self.to_x509()?;
        x509_certs.iter().map(|cert| cert.to_der()).collect()
    }
    /// load pem certs from json file
    pub fn load_pem_certs_from_json_file(
        &mut self,
        file_path: &str,
        member_names: &[&str]
    ) {
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
        for &subject in member_names.iter() {
            if let Ok(cert_str) = value[subject].try_as_string() {
                self.add(cert_str.to_string());
            }
        }
    }
}

