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

#ifndef CODE_SIGN_BYTE_BUFFER_MOCK_HELPER_H
#define CODE_SIGN_BYTE_BUFFER_MOCK_HELPER_H

#include "byte_buffer.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
enum Byte_Buffer {
    COPYFORM = 1,
    PUTDATA = 2,
    RESIZE = 3,
    GETBUFFER = 4,
    GETSIZE = 5,
    EMPTY = 6,
};
int byte_type = 0;
class ByteBufferMockHelper : public ByteBuffer {
public:
    ByteBufferMockHelper(): data(nullptr), size(0)
    {
    }

    ByteBufferMockHelper(uint32_t bufferSize): data(nullptr), size(0)
    {
        Init(bufferSize);
    }

    ByteBufferMockHelper(const ByteBufferMockHelper &other): data(nullptr), size(0)
    {
        CopyFrom(other.GetBuffer(), other.GetSize());
    }

    ~ByteBufferMockHelper()
    {
        if (data != nullptr) {
            data.reset(nullptr);
            data = nullptr;
        }
        size = 0;
    }
    bool CopyFrom(const uint8_t *srcData, uint32_t srcSize)
    {
        if (byte_type == COPYFORM) {
            return false;
        }
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
        if (byte_type == PUTDATA) {
            return false;
        }
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
        if (byte_type == RESIZE) {
            return false;
        }
        if (data != nullptr) {
            data.reset(nullptr);
        }
        return Init(newSize);
    }

    uint8_t *GetBuffer() const
    {
        if (byte_type == GETBUFFER) {
            return 0;
        }
        return data.get();
    }

    uint32_t GetSize() const
    {
        if (byte_type == GETSIZE) {
            return false;
        }
        return size;
    }

    bool Empty() const
    {
        if (byte_type == EMPTY) {
            return false;
        }
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