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

#ifndef CODE_SIGN_UNLOCK_EVENT_HELPER_H
#define CODE_SIGN_UNLOCK_EVENT_HELPER_H

#include <cstdint>
#include <memory>
#include <mutex>

#include "common_event_manager.h"
#include "common_event_support.h"
#include "iservice_registry.h"

#ifndef LOG_RUST
#define LOG_RUST
#endif

namespace OHOS {
namespace Security {
namespace CodeSign {
class UnlockEventHelper {
public:
    static UnlockEventHelper &GetInstance();

    bool StartWaitingUnlock();
    void FinishWaiting();
    bool CheckUserUnlockByScreenLockManager();

private:
    class UnlockEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
    public:
        UnlockEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo& info) : CommonEventSubscriber(info) {}
        ~UnlockEventSubscriber() override = default;
        void OnReceiveEvent(const OHOS::EventFwk::CommonEventData& event) override;
    };

    UnlockEventHelper() {};
    ~UnlockEventHelper() = default;
    void InitUnlockEventSubscriber();
    bool RegisterEvent();
    void UnregisterEvent();
    bool WaitForCommonEventManager();

    bool hasRegistered_ = false;
    bool hasInited_ = false;
    bool hasUnLocked_ = false;
    std::mutex unlockMutex_;
    std::condition_variable unlockConVar_;
    std::shared_ptr<UnlockEventSubscriber> unlockEventSubscriber_;
};
}
}
}
#endif