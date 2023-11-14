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