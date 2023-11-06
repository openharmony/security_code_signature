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
use std::fs::{remove_dir_all , create_dir_all, File};
use std::io::{Read, Write};
use std::path::Path;
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
