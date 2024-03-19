/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "local_code_sign_utils.h"

#include <securec.h>
#include <unistd.h>

#include "byte_buffer.h"
#include "local_code_sign_kit.h"
#include "log.h"
#include "thread_ex.h"

using namespace OHOS::Security::CodeSign;

namespace OHOS {
namespace Security {
namespace CodeSign {
constexpr uint32_t INIT_LOCAL_CERT_TIMEOUT_MS = 300 * 1000; // 5min
constexpr uint32_t INIT_LOCAL_CERT_SLEEP_US = 1000 * 1000;  // 1s
const std::string INIT_LOCAL_CERT_THREAD_NAME = "init_local_cert";

static std::condition_variable g_condition;

class InitLocalCertThread : public OHOS::Thread {
public:
    InitLocalCertThread() {}
    ~InitLocalCertThread() {}

    int GetRet()
    {
        return initResult_;
    }

    ByteBuffer& GetCert()
    {
        return cert_;
    }

protected:
    bool Run()
    {
        initResult_ = LocalCodeSignKit::InitLocalCertificate(cert_);
        if (initResult_ == CS_ERR_SA_GET_PROXY) {
            usleep(INIT_LOCAL_CERT_SLEEP_US);
            return true;
        } else {
            g_condition.notify_one();
            return false;
        }
    }

private:
    int32_t initResult_ = -1;
    ByteBuffer cert_;
};
}
}
}

int32_t InitLocalCertificate(uint8_t *certData, uint32_t *certSize)
{
    std::unique_ptr<InitLocalCertThread> thread = std::make_unique<InitLocalCertThread>();
    OHOS::ThreadStatus status = thread->Start(INIT_LOCAL_CERT_THREAD_NAME);
    if (status != OHOS::ThreadStatus::OK) {
        LOG_ERROR(LABEL, "initing local cert thread not start.");
        return CS_ERR_INIT_LOCAL_CERT;
    }

    std::mutex mtx;
    std::unique_lock<std::mutex> lock(mtx);
    g_condition.wait_for(lock, std::chrono::milliseconds(INIT_LOCAL_CERT_TIMEOUT_MS));
    thread->NotifyExitSync();

    int ret = thread->GetRet();
    if (ret != CS_SUCCESS) {
        LOG_ERROR(LABEL, "init local cert timeout or error, ret = %{public}d", ret);
        return ret;
    }

    ByteBuffer &cert = thread->GetCert();
    if (memcpy_s(certData, *certSize, cert.GetBuffer(), cert.GetSize()) != EOK) {
        return CS_ERR_MEMORY;
    }
    *certSize = cert.GetSize();
    return ret;
}