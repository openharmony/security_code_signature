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

#include "local_code_sign_client.h"
#include <iservice_registry.h>

#include "cert_utils.h"
#include "cs_hisysevent.h"
#include "huks_attest_verifier.h"
#include "local_code_sign_proxy.h"
#include "local_code_sign_load_callback.h"
#include "log.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
constexpr int32_t LOAD_SA_TIMEOUT_MS = 5000;

LocalCodeSignClient::LocalCodeSignClient()
{
    localCodeSignSvrRecipient_ = new (std::nothrow) LocalCodeSignSvrRecipient();
    if (localCodeSignSvrRecipient_ == nullptr) {
        LOG_ERROR("Create LocalCodeSignSvrRecipient failed.");
    }
}

void LocalCodeSignClient::LocalCodeSignSvrRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        LOG_ERROR("OnRemoteDied remote is nullptr.");
        return;
    }
    LOG_INFO("LocalCodeSignSvrRecipient OnRemoteDied.");
    LocalCodeSignClient::GetInstance().OnRemoteLocalCodeSignSvrDied(remote);
}

int32_t LocalCodeSignClient::StartSA()
{
    std::unique_lock<std::mutex> lock(proxyMutex_);
    LOG_DEBUG("Start LocalCodeSignService");
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        LOG_ERROR("Get system ability mgr failed.");
        return CS_ERR_SA_GET_SAMGR;
    }
    sptr<LocalCodeSignLoadCallback> loadCallback = new (std::nothrow) LocalCodeSignLoadCallback();
    if (loadCallback == nullptr) {
        return CS_ERR_MEMORY;
    }
    int32_t ret = samgr->LoadSystemAbility(LOCAL_CODE_SIGN_SA_ID, loadCallback);
    if (ret != ERR_OK) {
        LOG_ERROR("Load systemAbility failed, systemAbilityId:%{public}d ret code:%{public}d",
            LOCAL_CODE_SIGN_SA_ID, ret);
        return CS_ERR_SA_LOAD_FAILED;
    }
    LOG_INFO("To load system ability.");
    auto waitStatus = proxyConVar_.wait_for(lock, std::chrono::milliseconds(LOAD_SA_TIMEOUT_MS),
        [this]() { return localCodeSignProxy_ != nullptr; });
    if (!waitStatus) {
        LOG_ERROR("code sign load SA timeout");
        return CS_ERR_SA_LOAD_TIMEOUT;
    }
    LOG_INFO("code sign load SA successfully");
    return CS_SUCCESS;
}

void LocalCodeSignClient::FinishStartSA(const sptr<IRemoteObject> &remoteObject)
{
    LOG_DEBUG("LocalCodeSignClient FinishStartSA");
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (localCodeSignSvrRecipient_ == nullptr) {
        LOG_ERROR("localCodeSignSvrRecipient_ is nullptr.");
        return;
    }
    if (!remoteObject->AddDeathRecipient(localCodeSignSvrRecipient_)) {
        LOG_ERROR("AddDeathRecipient failed");
    }
    localCodeSignProxy_ = iface_cast<LocalCodeSignInterface>(remoteObject);
    if ((localCodeSignProxy_ == nullptr) || (localCodeSignProxy_->AsObject() == nullptr)) {
        LOG_ERROR("Get code sign proxy failed.");
        return;
    }
    proxyConVar_.notify_one();
}

void LocalCodeSignClient::FailStartSA()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    localCodeSignProxy_ = nullptr;
    proxyConVar_.notify_one();
}

void LocalCodeSignClient::CheckLocalCodeSignProxy()
{
    {
        std::lock_guard<std::mutex> lock(proxyMutex_);
        if (localCodeSignProxy_ != nullptr) {
            return;
        }
        sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgr == nullptr) {
            LOG_ERROR("Get system ability mgr failed.");
            return;
        }
        auto remoteObject = samgr->CheckSystemAbility(LOCAL_CODE_SIGN_SA_ID);
        if (remoteObject != nullptr) {
            localCodeSignProxy_ = iface_cast<LocalCodeSignInterface>(remoteObject);
            return;
        }
    }
    int32_t ret = StartSA();
    if (ret != CS_SUCCESS) {
        ReportLoadSAError(ret);
    }
}

int32_t LocalCodeSignClient::InitLocalCertificate(ByteBuffer &cert)
{
    LOG_DEBUG("InitLocalCertificate called");
    CheckLocalCodeSignProxy();
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (localCodeSignProxy_ == nullptr) {
        return CS_ERR_SA_GET_PROXY;
    }
    ByteBuffer certChainBuffer;
    std::unique_ptr<ByteBuffer> challenge = GetRandomChallenge();
    int32_t ret = localCodeSignProxy_->InitLocalCertificate(*challenge, certChainBuffer);
    if (ret != CS_SUCCESS) {
        LOG_ERROR("InitLocalCertificate err, error code = %{public}d", ret);
        return ret;
    }

    if (!GetVerifiedCert(certChainBuffer, *challenge, cert)) {
        ret = CS_ERR_VERIFY_CERT;
    }
    return ret;
}

int32_t LocalCodeSignClient::SignLocalCode(const std::string &ownerID, const std::string &path, ByteBuffer &signature)
{
    LOG_DEBUG("SignLocalCode called");
    CheckLocalCodeSignProxy();
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (localCodeSignProxy_ == nullptr) {
        return CS_ERR_SA_GET_PROXY;
    }
    int32_t ret = localCodeSignProxy_->SignLocalCode(ownerID, path, signature);
    if (ret != CS_SUCCESS) {
        LOG_ERROR("SignLocalCode err, error code = %{public}d", ret);
        return ret;
    }
    LOG_INFO("SignLocalCode successfully");
    return CS_SUCCESS;
}

void LocalCodeSignClient::OnRemoteLocalCodeSignSvrDied(const wptr<IRemoteObject> &remote)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (localCodeSignProxy_ == nullptr) {
        LOG_ERROR("localCodeSignProxy_ is nullptr.");
        return;
    }
    sptr<IRemoteObject> remoteObject = remote.promote();
    if (remoteObject == nullptr) {
        LOG_ERROR("OnRemoteDied remote promoted failed");
        return;
    }

    if (localCodeSignProxy_->AsObject() != remoteObject) {
        LOG_ERROR("OnRemoteLocalCodeSignSvrDied not found remote object.");
        return;
    }
    localCodeSignProxy_->AsObject()->RemoveDeathRecipient(localCodeSignSvrRecipient_);
    localCodeSignProxy_ = nullptr;
}

LocalCodeSignClient &LocalCodeSignClient::GetInstance()
{
    static LocalCodeSignClient singleLocalCodeSignClient;
    return singleLocalCodeSignClient;
}

LocalCodeSignClient *GetLocalCodeSignClient()
{
    return &LocalCodeSignClient::GetInstance();
}
}
}
}