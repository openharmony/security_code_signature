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

#include "unlock_event_helper.h"

#include <unistd.h>

#include "datetime_ex.h"
#include "log.h"

#ifdef SCREENLOCK_MANAGER_ENABLED
#include "screenlock_manager.h"
#endif

namespace OHOS {
namespace Security {
namespace CodeSign {
constexpr int32_t SEELP_TIME_FOR_COMMON_EVENT_MGR = 500 * 1000; // 500 ms
constexpr int32_t SEELP_TIME_FOR_COMMON_EVENT_MGR_TIME_OUT = 10 * 60; // 10 min
constexpr int32_t COMMON_EVENT_MANAGER_ID = 3299;

void UnlockEventHelper::UnlockEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData& event)
{
    const auto want = event.GetWant();
    const auto action = want.GetAction();
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED) {
        LOG_INFO(LABEL, "receive unlocked event");
        UnlockEventHelper::GetInstance().FinishWaiting();
        return;
    }
}

UnlockEventHelper &UnlockEventHelper::GetInstance()
{
    static UnlockEventHelper singleUnlockEventHelper;
    return singleUnlockEventHelper;
}

bool UnlockEventHelper::CheckUserUnlockByScreenLockManager()
{
    std::lock_guard<std::mutex> lock(unlockMutex_);
#ifdef SCREENLOCK_MANAGER_ENABLED
    if (hasUnLocked_) {
        return true;
    }
    bool lockStatus = false;
    if (ScreenLock::ScreenLockManager::GetInstance()->IsLocked(lockStatus) == ScreenLock::E_SCREENLOCK_OK) {
        LOG_INFO(LABEL, "screen locked status = %{private}d", lockStatus);
        hasUnLocked_ = !lockStatus;
    } else {
        LOG_ERROR(LABEL, "unable get lock screen status");
    }
#endif
    return hasUnLocked_;
}

void UnlockEventHelper::InitUnlockEventSubscriber()
{
    if (hasInited_) {
        return;
    }
    EventFwk::MatchingSkills matchingSkill;
    // use COMMON_EVENT_USER_UNLOCKED if only for device with PIN
    matchingSkill.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
    EventFwk::CommonEventSubscribeInfo eventInfo(matchingSkill);
    unlockEventSubscriber_ = std::make_shared<UnlockEventSubscriber>(eventInfo);
    hasInited_ = true;
    LOG_INFO(LABEL, "Init subscriber success.");
}

bool UnlockEventHelper::RegisterEvent()
{
    LOG_INFO(LABEL, "RegisterEvent start");
    if (hasRegistered_) {
        LOG_DEBUG(LABEL, "status observer already registered");
        return false;
    }
    InitUnlockEventSubscriber();
    const auto result = EventFwk::CommonEventManager::SubscribeCommonEvent(
        unlockEventSubscriber_);
    if (!result) {
        LOG_ERROR(LABEL, "RegisterEvent result is err");
        return false;
    }
    hasRegistered_ = true;
    return true;
}

void UnlockEventHelper::UnregisterEvent()
{
    LOG_INFO(LABEL, "UnregisterEvent start");
    const auto result = EventFwk::CommonEventManager::UnSubscribeCommonEvent(
        unlockEventSubscriber_);
    if (!result) {
        LOG_ERROR(LABEL, "UnregisterEvent result is err");
        return;
    }
    hasRegistered_ = false;
}

bool UnlockEventHelper::WaitForCommonEventManager()
{
    struct tm doingTime = {0};
    struct tm startTime = {0};
    int64_t seconds = 0;
    bool ret = false;
    if (!OHOS::GetSystemCurrentTime(&startTime)) {
        return false;
    }
    while (seconds <= SEELP_TIME_FOR_COMMON_EVENT_MGR_TIME_OUT) {
        sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgr != nullptr &&
            samgr->CheckSystemAbility(COMMON_EVENT_MANAGER_ID) != nullptr) {
            ret = true;
            LOG_INFO(LABEL, "Common event manager is loaded.");
            break;
        }
        LOG_DEBUG(LABEL, "Get common event manager failed.");
        usleep(SEELP_TIME_FOR_COMMON_EVENT_MGR);
        if (OHOS::GetSystemCurrentTime(&doingTime)) {
            seconds = OHOS::GetSecondsBetween(startTime, doingTime);
        }
    }
    return ret;
}

bool UnlockEventHelper::StartWaitingUnlock()
{
    std::unique_lock<std::mutex> lock(unlockMutex_);
    if (hasUnLocked_) {
        return true;
    }
    if (!WaitForCommonEventManager()) {
        return false;
    }
    if (!RegisterEvent()) {
        return false;
    }
    unlockConVar_.wait(lock, [this]() { return this->hasUnLocked_; });
    LOG_INFO(LABEL, "thread is wake up");
    // only listening the first unlock event
    UnregisterEvent();
    return true;
}

void UnlockEventHelper::FinishWaiting()
{
    std::lock_guard<std::mutex> lock(unlockMutex_);
    hasUnLocked_ = true;
    unlockConVar_.notify_one();
}
}
}
}