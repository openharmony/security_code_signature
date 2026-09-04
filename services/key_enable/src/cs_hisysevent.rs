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

use hisysevent::EventType;

/// profile error report to hisysevent
pub enum HisyseventProfileError {
    /// verify signer code
    VerifySigner = 1,
    /// parse pkcs7 code
    ParsePkcs7 = 2,
    /// add cert path code
    AddCertPath = 3,
    /// add enterprise code
    AddEnterpriseCert = 4,
    /// remove enterprise code
    RemoveEnterpriseCert = 5,
    /// remove cert path code
    RemoveCertPath = 6,
    /// parse cert path json (field/load) failed
    ParseCertPathJson = 7,
    /// missing preset key in cert path json
    MissingPresetKey = 8,
    /// empty subject or issuer for enterprise resign cert
    EmptySubjectIssuer = 9,
    /// load profile file failed
    LoadProfileFailed = 10,
    /// load pkcs7 from profile failed
    LoadPkcs7Profile = 11,
    /// build trusted root store failed
    BuildRootStoreFailed = 12,
    /// convert cert to der failed
    ConvertCertToDer = 13,
    /// enterprise resign extension missing
    EnterpriseResignExtMissing = 14,
    /// parse pem cert stack failed
    ParsePemStack = 15,
    /// enterprise cert structure invalid (empty/length/leaf)
    EnterpriseCertInvalid = 16,
    /// not enterprise device
    NotEnterpriseDevice = 17,
}

/// key error report to hisysevent
pub enum HisyseventKeyError {
    /// local key empty
    LocalKeyEmpty = 1,
    /// local key timeout
    LocalKeyTimeout = 2,
    /// restrict_keys failed
    RestrictKeys = 3,
    /// get keyring id failed
    GetKeyringId = 4,
    /// load trusted certs from json file failed
    LoadTrustedCerts = 5,
    /// init local certificate failed
    InitLocalCert = 6,
    /// parse key serial failed
    ParseKeySerial = 7,
    /// open /proc/keys failed
    OpenProcKeys = 8,
    /// fs-verity keyring not found
    KeyringNotFound = 9,
    /// openssl to_der failed
    OpensslToDer = 10,
    /// trusted certs empty
    EmptyTrustedCerts = 11,
    /// wait for boot completion timeout
    BootCompletionTimeout = 12,
    /// cert path thread panicked
    CertPathThreadPanic = 13,
    /// certificate chain verification failed
    ChainVerifyFailed = 14,
}

/// report add key err by hisysevent
pub fn report_add_key_err(cert_type: &str, errcode: i32) {
    hisysevent::write(
        "CODE_SIGN",
        "CS_ADD_KEY",
        EventType::Fault,
        &[
            hisysevent::build_str_param!("STRING_SINGLE", cert_type),
            hisysevent::build_number_param!("INT32_SINGLE", errcode),
        ],
    );
}

/// report parse local profile err by hisysevent
pub fn report_parse_profile_err(profile_path: &str, errcode: i32) {
    hisysevent::write(
        "CODE_SIGN",
        "CS_ERR_PROFILE",
        EventType::Security,
        &[
            hisysevent::build_str_param!("STRING_SINGLE", profile_path),
            hisysevent::build_number_param!("INT32_SINGLE", errcode),
        ],
    );
}