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

#include "local_code_sign_stub.h"

#include "cert_utils.h"
#include "cs_hisysevent.h"
#include "cs_hitrace.h"
#include "errcode.h"
#include "ipc_skeleton.h"
#include "log.h"
#include "message_parcel.h"
#include "permission_utils.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
using namespace std;

LocalCodeSignStub::LocalCodeSignStub()
{
}

LocalCodeSignStub::~LocalCodeSignStub()
{
}

int32_t LocalCodeSignStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DelayUnloadTask();
    std::u16string descriptor = LocalCodeSignStub::GetDescriptor();
    std::u16string token = data.ReadInterfaceToken();
    if (token != descriptor) {
        return CS_ERR_IPC_MSG_INVALID;
    }
    switch (code) {
        case static_cast<uint32_t>(LocalCodeSignInterfaceCode::INIT_LOCAL_CERTIFICATE):
            return InitLocalCertificateInner(data, reply);
        case static_cast<uint32_t>(LocalCodeSignInterfaceCode::SIGN_LOCAL_CODE):
            return SignLocalCodeInner(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t LocalCodeSignStub::InitLocalCertificateInner(MessageParcel &data, MessageParcel &reply)
{
    if (!PermissionUtils::IsValidCallerOfCert()) {
        reply.WriteInt32(CS_ERR_NO_PERMISSION);
        return CS_ERR_NO_PERMISSION;
    }

    uint32_t challengeLen;
    if (!data.ReadUint32(challengeLen) || !CheckChallengeSize(challengeLen)) {
        LOG_ERROR("Get challenge size failed.");
        return CS_ERR_IPC_READ_DATA;
    }
    ByteBuffer challenge;
    const uint8_t *challengeBuffer = data.ReadBuffer(challengeLen);
    if (!challenge.CopyFrom(challengeBuffer, challengeLen)) {
        return CS_ERR_MEMORY;
    }

    ByteBuffer cert;
    int32_t result = InitLocalCertificate(challenge, cert);
    if (!reply.WriteInt32(result)) {
        return CS_ERR_IPC_WRITE_DATA;
    }
    if (result != CS_SUCCESS) {
        return result;
    }
    if (!reply.WriteUint32(cert.GetSize())) {
        return CS_ERR_IPC_WRITE_DATA;
    }
    if (!reply.WriteBuffer(cert.GetBuffer(), cert.GetSize())) {
        return CS_ERR_IPC_WRITE_DATA;
    }
    return CS_SUCCESS;
}

int32_t LocalCodeSignStub::SignLocalCodeInner(MessageParcel &data, MessageParcel &reply)
{
    if (!PermissionUtils::IsValidCallerOfLocalCodeSign()) {
        (void)reply.WriteInt32(CS_ERR_NO_PERMISSION);
        return CS_ERR_NO_PERMISSION;
    }
    std::string filePath = data.ReadString();
    std::string ownerID;
    if (data.GetReadableBytes() > 0) {
        ownerID = data.ReadString();
    }
    StartTrace(HITRACE_TAG_ACCESS_CONTROL, CODE_SIGN_ENABLE_START);
    ByteBuffer signature;
    int32_t result = SignLocalCode(ownerID, filePath, signature);
    FinishTrace(HITRACE_TAG_ACCESS_CONTROL);
    if (!reply.WriteInt32(result)) {
        return CS_ERR_IPC_WRITE_DATA;
    }
    if (result != CS_SUCCESS) {
        return result;
    }
    if (!reply.WriteUint32(signature.GetSize())) {
        return CS_ERR_IPC_WRITE_DATA;
    }
    if (!reply.WriteBuffer(signature.GetBuffer(), signature.GetSize())) {
        return CS_ERR_IPC_WRITE_DATA;
    }
    return CS_SUCCESS;
}
}
}
}