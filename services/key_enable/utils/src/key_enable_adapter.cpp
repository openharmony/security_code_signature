/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "key_enable_adapter.h"

#include "byte_buffer.h"
#include "common_event_data.h"
#include "local_code_sign_kit.h"
#include "unlock_event_helper.h"

using namespace OHOS::Security::CodeSign;

constexpr int32_t SLEEP_TIME_FOR_LOCAL_KEY = 100 * 1000; // 100 ms
constexpr int32_t MAX_RETRY_FOR_LOCAL_KEY = 120; // about 1 min

int32_t InitLocalCertificate(uint8_t *certData, uint32_t *certSize)
{
    ByteBuffer cert;
    int32_t ret = LocalCodeSignKit::InitLocalCertificate(cert);
    int32_t retryCount = MAX_RETRY_FOR_LOCAL_KEY;
    while ((ret == CS_ERR_SA_GET_PROXY || ret == CS_ERR_HUKS_INIT_KEY) && retryCount--) {
        ret = LocalCodeSignKit::InitLocalCertificate(cert);
        usleep(SLEEP_TIME_FOR_LOCAL_KEY);
    }
    if (ret != CS_SUCCESS) {
        return ret;
    }
    if (memcpy_s(certData, *certSize, cert.GetBuffer(), cert.GetSize()) != EOK) {
        return CS_ERR_MEMORY;
    }
    *certSize = cert.GetSize();
    return CS_SUCCESS;
}

bool CheckUserUnlock()
{
    // check whether unlocked at current
    if (UnlockEventHelper::GetInstance().CheckUserUnlockByScreenLockManager()) {
        return true;
    }

    // waiting for user unlock
    if (UnlockEventHelper::GetInstance(). StartWaitingUnlock()) {
        return true;
    }

    // if some error occours, check again at current
    if (UnlockEventHelper::GetInstance().CheckUserUnlockByScreenLockManager()) {
        return true;
    }
    return false;
}