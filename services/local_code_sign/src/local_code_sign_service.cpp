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

#include "local_code_sign_service.h"

#include "directory_ex.h"
#include "fsverity_utils_helper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "local_sign_key.h"
#include "log.h"
#include "pkcs7_generator.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
const std::string DEFAULT_HASH_ALGORITHM = "sha256";
const std::string TASK_ID = "unload";
constexpr int32_t DELAY_TIME = 180000;
constexpr uint32_t MAX_OWNER_ID_LEN = 32; // owner id in signature should not exceed 32 bytes

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<LocalCodeSignService>::GetInstance().get());

LocalCodeSignService::LocalCodeSignService()
    : SystemAbility(LOCAL_CODE_SIGN_SA_ID, false), state_(ServiceRunningState::STATE_NOT_START)
{
}

LocalCodeSignService::~LocalCodeSignService()
{
}

void LocalCodeSignService::OnStart()
{
    LOG_INFO("LocalCodeSignService OnStart");
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        LOG_INFO("LocalCodeSignService has already started.");
        return;
    }
    if (!Init()) {
        LOG_ERROR("Init LocalCodeSignService failed.");
        return;
    }
    bool ret = Publish(DelayedSingleton<LocalCodeSignService>::GetInstance().get());
    if (!ret) {
        LOG_ERROR("Publish service failed.");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    DelayUnloadTask();
}

bool LocalCodeSignService::Init()
{
    auto runner = AppExecFwk::EventRunner::Create(TASK_ID);
    if (unloadHandler_ == nullptr) {
        unloadHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
    return true;
}

void LocalCodeSignService::DelayUnloadTask()
{
    auto task = [this]() {
        sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgr == nullptr) {
            LOG_ERROR("Get system ability mgr failed.");
            return;
        }
        int32_t ret = samgr->UnloadSystemAbility(LOCAL_CODE_SIGN_SA_ID);
        if (ret != ERR_OK) {
            LOG_ERROR("Remove system ability failed.");
            return;
        }
    };
    unloadHandler_->RemoveTask(TASK_ID);
    unloadHandler_->PostTask(task, TASK_ID, DELAY_TIME);
}

void LocalCodeSignService::OnStop()
{
    LOG_INFO("LocalCodeSignService OnStop");
    state_ = ServiceRunningState::STATE_NOT_START;
}

int32_t LocalCodeSignService::InitLocalCertificate(const ByteBuffer &challenge, ByteBuffer &certChainData)
{
    LocalSignKey &key = LocalSignKey::GetInstance();
    key.SetChallenge(challenge);
    if (!key.InitKey()) {
        LOG_ERROR("Init key failed.");
        return CS_ERR_HUKS_INIT_KEY;
    }
    return key.GetFormattedCertChain(certChainData);
}

int32_t LocalCodeSignService::SignLocalCode(const std::string &ownerID, const std::string &filePath,
                                            ByteBuffer &signature)
{
    if (ownerID.length() > MAX_OWNER_ID_LEN) {
        LOG_ERROR("ownerID len %{public}zu should not exceed %{public}u", ownerID.length(), MAX_OWNER_ID_LEN);
        return CS_ERR_INVALID_OWNER_ID;
    }
    ByteBuffer digest;
    std::string realPath;
    if (!OHOS::PathToRealPath(filePath, realPath)) {
        LOG_INFO("Get real path failed, path = %{public}s", filePath.c_str());
        return CS_ERR_FILE_PATH;
    }
    if (!FsverityUtilsHelper::GetInstance().GenerateFormattedDigest(realPath.c_str(), digest)) {
        LOG_ERROR("Generate formatted fsverity digest failed.");
        return CS_ERR_COMPUTE_DIGEST;
    }
    return PKCS7Generator::GenerateSignature(ownerID, LocalSignKey::GetInstance(), DEFAULT_HASH_ALGORITHM.c_str(),
        digest, signature);
}
}
}
}
