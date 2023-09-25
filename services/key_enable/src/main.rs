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

//! enable keys for code signature
use hilog_rust::{error, hilog, info, HiLogLabel, LogType};
use std::ffi::{c_char, CString};

mod cert_chain_utils;
mod cert_utils;
mod cs_hisysevent;
mod key_enable;

const LOG_LABEL: HiLogLabel = HiLogLabel {
    log_type: LogType::LogCore,
    domain: 0xd002f00, // security domain
    tag: "CODE_SIGN",
};

fn main() {
    match key_enable::enable_all_keys() {
        Ok(()) => {
            info!(LOG_LABEL, "Succeed to enable all keys.");
        }
        Err(()) => {
            error!(LOG_LABEL, "Enable keys failed.");
        }
    };
}
