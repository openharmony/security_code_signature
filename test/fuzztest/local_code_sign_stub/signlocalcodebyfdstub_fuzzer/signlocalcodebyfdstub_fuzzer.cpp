/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include "signlocalcodebyfdstub_fuzzer.h"

#include <cstdint>
#include <fcntl.h>
#include <string>
#include <unistd.h>

#include "accesstoken_kit.h"
#include "access_token.h"
#include "local_code_sign_interface.h"
#define private public
#include "local_code_sign_service.h"
#undef private
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "fuzz_common.h"

using namespace OHOS::Security::CodeSign;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    static uint64_t NativeTokenSet(const char *caller)
    {
        uint64_t tokenId = GetSelfTokenID();
        uint64_t mockTokenId = AccessTokenKit::GetNativeTokenId(caller);
        SetSelfTokenID(mockTokenId);
        return tokenId;
    }
    static void NativeTokenReset(uint64_t tokenId)
    {
        SetSelfTokenID(tokenId);
    }

    bool SignLocalCodeByFdStubFuzzTest(const uint8_t *data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        SignInfoRandomGenerator fuzzData(data, size);
        std::string ownerID;
        fuzzData.GenerateString(ownerID);

        bool writeValidFd = (size % 2) == 0;

        MessageParcel datas;
        datas.WriteInterfaceToken(LocalCodeSignInterface::GetDescriptor());
        int fd = -1;
        if (writeValidFd) {
            const char *tmpFile = "/data/local/tmp/localsignfile";
            size_t fileSize = size % (1024 * 1024 + 1);
            uint8_t fileData[fileSize];
            remove(tmpFile);
            fd = open(tmpFile, O_CREAT | O_RDWR, 0600);
            if (fd < 0) {
                return false;
            }
            if (write(fd, fileData, fileSize) != static_cast<ssize_t>(fileSize)) {
                close(fd);
                return false;
            }
            if (!datas.WriteFileDescriptor(fd)) {
                close(fd);
                return false;
            }
        }
        if (!datas.WriteString(ownerID)) {
            if (fd >= 0) {
                close(fd);
            }
            return false;
        }

        uint32_t code = static_cast<uint32_t>(LocalCodeSignInterfaceCode::SIGN_LOCAL_CODE_BY_FD);
        MessageParcel reply;
        MessageOption option;
        uint64_t selfTokenId = NativeTokenSet("compiler_service");
        DelayedSingleton<LocalCodeSignService>::GetInstance()->Init();
        DelayedSingleton<LocalCodeSignService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        DelayedSingleton<LocalCodeSignService>::GetInstance()->OnStop();
        if (fd >= 0) {
            close(fd);
        }
        NativeTokenReset(selfTokenId);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::SignLocalCodeByFdStubFuzzTest(data, size);
    return 0;
}
