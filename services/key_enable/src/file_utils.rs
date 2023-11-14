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
use std::fs::{create_dir_all, remove_dir_all, File};
use std::io::{Read, Write};
use std::path::Path;
use cxx::let_cxx_string;
use utils_rust::directory_ex;
// rw-r--r--
const PROFILE_FILE_MODE: u32 = 0o644; 
// rw-r-xr-x
const PROFILE_PATH_MODE: u32 = 0o655; 
/// code sign file error
pub enum CodeSignFileError {
        /// change file mode error
        ChangeFileModError,
        /// change path mode error
        ChangePathModError,
    }
/// change default mode of file
pub fn change_default_mode_file(path_file: &str) -> Result<(), CodeSignFileError> {
    let_cxx_string!(dirpath = path_file);
    let mode = PROFILE_FILE_MODE;
    let ret = directory_ex::ffi::ChangeModeFile(&dirpath, &mode);
    if !ret {
        return Err(CodeSignFileError::ChangeFileModError);
    }
    Ok(())
}
/// change default mode of directory
pub fn change_default_mode_directory(path_file: &str) -> Result<(), CodeSignFileError> {
    let_cxx_string!(dirpath = path_file);
    let mode = PROFILE_PATH_MODE;
    let ret = directory_ex::ffi::ChangeModeDirectory(&dirpath, &mode);
    if !ret {
        return Err(CodeSignFileError::ChangePathModError);
    }
    Ok(())
}
/// format storage file path
pub fn fmt_store_path(prefix: &str, tail: &str) -> String {
    format!("{}/{}", prefix, tail)
}
/// create file path with path name
pub fn create_file_path(path_name: &str) -> Result<(), std::io::Error> {
    let path = Path::new(path_name);
    create_dir_all(path)?;
    Ok(())
}
/// write file buffer to disk
pub fn write_bytes_to_file(filename: &str, data: &[u8]) -> Result<(), std::io::Error> {
    let mut file = File::create(filename)?;
    file.write_all(data)?;
    Ok(())
}
/// loads file buffer from disk
pub fn load_bytes_from_file(filename: &str, buffer: &mut Vec<u8>) -> Result<(), std::io::Error> {
    let mut file = File::open(filename)?;
    file.read_to_end(buffer)?;
    Ok(())
}
/// find file
pub fn file_exists(file_path: &str) -> bool {
    Path::new(file_path).exists()
}
/// delete file path
pub fn delete_file_path(file_path: &str) -> Result<(), std::io::Error> {
    remove_dir_all(file_path)?;
    Ok(())
}
