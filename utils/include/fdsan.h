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

#ifndef CODE_SIGN_FDASAN_H
#define CODE_SIGN_FDASAN_H

#ifndef LOG_DOMAIN
#define LOG_DOMAIN 0xD005A06
#endif
#define FDSAN_MARK(fd) fdsan_exchange_owner_tag(fd, 0, LOG_DOMAIN)
#define FDSAN_CLOSE(fd) fdsan_close_with_tag(fd, LOG_DOMAIN)

#endif // CODE_SIGN_FDASAN_H
