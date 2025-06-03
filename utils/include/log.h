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

#ifndef CODE_SIGN_LOG_H
#define CODE_SIGN_LOG_H

#include "hilog/log.h"

#ifndef LOG_RUST
#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "CODE_SIGN"

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD005A06

#define LOG_DEBUG(fmt, ...) HILOG_DEBUG(LOG_CORE, "[%{public}s]:" fmt, __func__, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) HILOG_INFO(LOG_CORE, "[%{public}s]:" fmt, __func__, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) HILOG_WARN(LOG_CORE, "[%{public}s]:" fmt, __func__, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) HILOG_ERROR(LOG_CORE, "[%{public}s]:" fmt, __func__, ##__VA_ARGS__)
#define LOG_FATAL(fmt, ...) HILOG_FATAL(LOG_CORE, "[%{public}s]:" fmt, __func__, ##__VA_ARGS__)

#else // LOG_RUST
namespace OHOS {
namespace Security {
namespace CodeSign {
static constexpr unsigned int SECURITY_DOMAIN = 0xD005A06;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN, "CODE_SIGN"};

#define LOG_DEBUG(label, fmt, ...) \
    OHOS::HiviewDFX::HiLog::Debug(label, "%{public}s: " fmt, __func__, ##__VA_ARGS__)
#define LOG_INFO(label, fmt, ...) \
    OHOS::HiviewDFX::HiLog::Info(label, "%{public}s: " fmt, __func__, ##__VA_ARGS__)
#define LOG_WARN(label, fmt, ...) \
    OHOS::HiviewDFX::HiLog::Warn(label, "%{public}s: " fmt, __func__, ##__VA_ARGS__)
#define LOG_ERROR(label, fmt, ...) \
    OHOS::HiviewDFX::HiLog::Error(label, "%{public}s: " fmt, __func__, ##__VA_ARGS__)
#define LOG_FATAL(label, fmt, ...) \
    OHOS::HiviewDFX::HiLog::Fatal(label, "%{public}s: " fmt, __func__, ##__VA_ARGS__)
}
}
}
#endif
#endif // CODE_SIGN_LOG_H
