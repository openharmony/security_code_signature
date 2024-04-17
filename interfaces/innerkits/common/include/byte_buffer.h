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

#ifndef CODE_SIGN_BYTE_BUFFER_H
#define CODE_SIGN_BYTE_BUFFER_H

#include <memory>
#include <climits>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <securec.h>

namespace OHOS {
namespace Security {
namespace CodeSign {
class ByteBuffer {
public:
    ByteBuffer(): data(nullptr), size(0)
    {
    }

    ByteBuffer(uint32_t bufferSize): data(nullptr), size(0)
    {
        Init(bufferSize);
    }

    ByteBuffer(const ByteBuffer &other): data(nullptr), size(0)
    {
        CopyFrom(other.GetBuffer(), other.GetSize());
    }

    ~ByteBuffer()
    {
        if (data != nullptr) {
            data.reset(nullptr);
            data = nullptr;
        }
        size = 0;
    }
    bool CopyFrom(const uint8_t *srcData, uint32_t srcSize)
    {
        if (srcData == nullptr) {
            return false;
        }
        if (!Resize(srcSize)) {
            return false;
        }
        if (memcpy_s(data.get(), size, srcData, srcSize) != EOK) {
            return false;
        }
        return true;
    }

    bool PutData(uint32_t pos, const uint8_t *srcData, uint32_t srcSize)
    {
        if (pos >= size) {
            return false;
        }
        if (memcpy_s(data.get() + pos, size - pos, srcData, srcSize) != EOK) {
            return false;
        }
        return true;
    }

    bool Resize(uint32_t newSize)
    {
        if (data != nullptr) {
            data.reset(nullptr);
        }
        return Init(newSize);
    }

    uint8_t *GetBuffer() const
    {
        return data.get();
    }

    uint32_t GetSize() const
    {
        return size;
    }

    bool Empty() const
    {
        return (size == 0) || (data == nullptr);
    }
private:
    bool Init(uint32_t bufferSize)
    {
        if (bufferSize == 0) {
            return false;
        }
        data = std::make_unique<uint8_t[]>(bufferSize);
        if (data == nullptr) {
            return false;
        }
        size = bufferSize;
        return true;
    }

    std::unique_ptr<uint8_t[]> data;
    uint32_t size;
};
}
}
}
#endif