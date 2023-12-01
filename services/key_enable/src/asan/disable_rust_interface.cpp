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
#include "rust_interface.h"
#include "errcode.h"

/// two mocked function beacause of at asan mode, c_utils:utils_rust cannot compile
int32_t EnableKeyInProfileByRust(const char* bundleName, const uint8_t* profile, uint32_t profileSize)
{
    return CS_SUCCESS;
}

int32_t RemoveKeyInProfileByRust(const char* bundleName)
{
    return CS_SUCCESS;
}