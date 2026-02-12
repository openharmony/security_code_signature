# JIT Code Sign - AI Knowledge Base

## Module Overview

JIT Code Sign provides ARMv8.3-A Pointer Authentication (PAC) for protecting JIT-generated code integrity. This module enables compile-time signing of instructions, patching support, and verification before copying to JIT executable memory.

**Location**: `interfaces/inner_api/jit_code_sign/`

**Key Features**:
- PAC-based instruction signing (ARMv8.3-A+ only)
- Instruction-level patching with signature updates
- Queue-based byte handling for unaligned data
- JIT-FORT integration for memory protection
- Context-based signing with salt randomization

---

## Build and Test Commands

### Feature Flag

The jit_code_sign module is conditionally compiled based on:
```bash
# Auto-enabled on arm64 when code_signature_support_oh_code_sign=true
jit_code_sign_enable = false  # default
```

In `code_signature.gni`:
```gni
jit_code_sign_enable = false
if (defined(target_cpu) && target_cpu == "arm64" &&
    code_signature_support_oh_code_sign && !is_emulator) {
  jit_code_sign_enable = true
}
```

### Build Commands

```bash
# Build the entire code_signature component
./build.sh --product-name rk3568 --build-target base/security/code_signature:code_signature

# Or using hb tool
hb build code_signature -i
```

### Test Commands

```bash
# Build all unit tests
./build.sh --product-name rk3568 --build-target base/security/code_signature/test:testgroup --no-indep

# Build only jit_code_sign tests
./build.sh --product-name rk3568 --build-target base/security/code_signature/test/unittest:jit_code_sign_unittest --no-indep
```

**Note**: To run tests, ensure `jit_code_sign_enable=true` and target is arm64 with PAC support.

### Running Tests on Device

```bash
# Build test binary
./build.sh --product-name rk3568 --build-target base/security/code_signature/test/unittest:jit_code_sign_unittest --no-indep

# Push to device
hdc shell mkdir -p /data/test
hdc file send out/rk3568/tests/unittest/code_signature/code_signature/jit_code_sign_unittest /data/test/

# Run test
hdc shell /data/test/jit_code_sign_unittest

# Run specific test case (gtest filter)
hdc shell /data/test/jit_code_sign_unittest --gtest_filter=JitCodeSignTest.JitCodeSignTest_0001
```

---

## Code Style Guidelines

### File Headers

All files use Apache 2.0 license with Huawei copyright:
```cpp
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
```

### Include Statement Ordering

In `.cpp` files:
1. System includes (C/C++ standard library)
2. External library includes (third_party)
3. Internal module headers (same module)
4. Other internal headers (code_signature component)

Example from `jit_code_signer.cpp`:
```cpp
#include <sstream>                 // system
#include "securec.h"               // external (bounds_checking_function)
#include "errcode.h"               // internal (common)
#include "log.h"                   // internal (common)
```

In `.h` files:
1. Standard library headers first
2. Type aliases/using statements
3. Constants/constexprs
4. Forward declarations
5. Class/struct definitions

### Naming Conventions

**Classes**: PascalCase
```cpp
class JitCodeSigner {};
class PACSignCtx {};
```

**Functions**: PascalCase for public members, mixed for static helpers
```cpp
void SignInstruction(Instr insn);          // public method
static inline int GetIndexFromOffset(...)  // static helper
```

**Variables**:
- Member variables: camelCase with trailing underscore
```cpp
Byte *tmpBuffer_;
int offset_;
std::queue<Byte> willSign_;
```
- Local variables: camelCase
```cpp
int i = 0;
uint32_t cur = 0;
```
- Constants: UPPER_SNAKE_CASE
```cpp
constexpr int32_t INSTRUCTION_SIZE = 4;
constexpr uint32_t UNALIGNMENT_MASK = 0x3;
```

**Type Aliases**: PascalCase
```cpp
using Instr = uint32_t;
using Byte = uint8_t;
```

**Macros**: UPPER_SNAKE_CASE
```cpp
#define CAST_TO_CONST_BYTES(buffer) (reinterpret_cast<const Byte *const>(buffer))
#define CHECK_NULL_AND_RETURN_CODE(ptr) do { ... } while (0)
```

### Error Handling

**Return Codes**: All functions return `int32_t` using error codes from `errcode.h`:
```cpp
int32_t SignData(const Byte *const data, uint32_t size) {
    if (data == nullptr) {
        return CS_ERR_INVALID_DATA;
    }
    // ...
    return CS_SUCCESS;
}
```

**Error Code Pattern**: Use negative integers, `CS_SUCCESS = 0`

JIT-specific error codes (`JitCodeSignErrCode` enum):
```cpp
CS_ERR_NO_SIGNER = -0x700,
CS_ERR_PATCH_INVALID = -0x701,
CS_ERR_JIT_SIGN_SIZE = -0x702,
CS_ERR_TMP_BUFFER = -0x703,
CS_ERR_VALIDATE_CODE = -0x704,
CS_ERR_JITFORT_IN = -0x705,
CS_ERR_JITFORT_OUT = -0x706,
// ... more in errcode.h
```

**Validation Pattern**: Always validate inputs first
```cpp
int32_t PatchInstruction(Byte *buffer, Instr insn) {
    if ((buffer == nullptr) || (tmpBuffer_ == nullptr)) {
        return CS_ERR_PATCH_INVALID;
    }
    return PatchInstruction(static_cast<int>(buffer - tmpBuffer_), insn);
}
```

### Constants and Macros

**constexpr**: Use for compile-time constants
```cpp
constexpr int32_t INSTRUCTION_SIZE = 4;
constexpr int32_t LOG_2_INSTRUCTION_SIZE = 2;
```

**Macros**: Use for code reduction only (type casting, validation)
```cpp
#define CAST_TO_CONST_BYTES(buffer) (reinterpret_cast<const Byte *const>(buffer))
#define CHECK_NULL_AND_RETURN_CODE(ptr) do { \
    if ((ptr) == nullptr) { \
        return JitCodeSignErrCode::CS_ERR_NO_SIGNER; \
    } \
} while (0)
```

**Defines**: Use for conditional compilation
```cpp
#ifndef JIT_FORT_DISABLE  // Disable JIT-FORT protection
#ifndef ARCH_PAC_SUPPORT    // PAC instruction availability
#ifdef JIT_CODE_SIGN_DEBUGGABLE  // Debug logging
```

### Memory Management

**Heap Allocation**: Use `new/delete` for objects
```cpp
JitCodeSigner *signer = new JitCodeSigner();
// ...
delete signer;
```

**Stack Allocation**: Prefer stack for small buffers
```cpp
Byte tmpBuffer[INSTRUCTIONS_SET_SIZE_BYTES] = {0};
```

**Manual Memory**: Use `malloc/free` with FDSAN for file descriptors
```cpp
char *buffer = reinterpret_cast<char *>(malloc(MAX_DEFERRED_LOG_LENGTH));
if (buffer == nullptr) {
    return CS_ERR_OOM;
}
// ...
free(buffer);
```

**String Operations**: Use `securec` (bounds checking functions)
```cpp
memcpy_s(dest, destSize, src, srcSize);
sprintf_s(buffer, MAX_DEFERRED_LOG_LENGTH, format, ...);
__builtin_memset(ptr, 0, size);  // built-in for simple memset
```

### Inline and Assembly

**Inline Functions**: Use `static inline` for helpers
```cpp
static inline int GetIndexFromOffset(int offset) {
    return static_cast<int>(static_cast<uint32_t>(offset) >> LOG_2_INSTRUCTION_SIZE);
}
```

**Assembly**: Wrap PAC instructions in inline functions with guards
```cpp
static inline uint64_t PACDB(uint64_t value, uint64_t modifier) {
#ifdef ARCH_PAC_SUPPORT
    asm volatile("pacdb %0, %1" : "+r"(value) : "r"(modifier) :);
#endif
    return value;
}
```

### Threading

**Thread Safety**: Use `std::atomic` for shared state
```cpp
std::atomic<uint32_t> curStat_ = 0;
```

**Mutex**: Protect shared resources
```cpp
std::mutex g_jitMemory_mutex;
{
    std::lock_guard<std::mutex> lock(g_jitMemory_mutex);
    // critical section
}
```

### Documentation

**Doxygen Style**: For public APIs in `jit_buffer_integrity.h`
```cpp
/**
 * @brief Sign an intruction when appending it to tmp buffer
 * @param signer jit code signer
 * @param instr an instruction to be signed
 * @return error code, see errcode.h
 */
static inline int32_t AppendInstruction(JitCodeSigner *signer, Instr instr);
```

**Test Documentation**: Use XTS format
```cpp
/**
 * @tc.name: JitCodeSignTest_0001
 * @tc.desc: sign instructions and verify succuss
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0001, TestSize.Level0) {
    // test body
}
```

---

## Testing Patterns

### Test Framework

Uses OpenHarmony's extended gtest:
```cpp
#include <gtest/gtest.h>
#include <gtest/hwext/gtest-multithread.h>
```

**Test Macros**:
- `HWTEST_F`: Single-threaded test
- `HWMTEST_F`: Multi-threaded test (specify thread count as last parameter)

Example:
```cpp
HWMTEST_F(JitCodeSignTest, JitCodeSignTest_00015, TestSize.Level1, 10);
```

### Test Structure

```cpp
class JitCodeSignTest : public testing::Test {
public:
    static void SetUpTestCase() {
        // Per-test-class setup
        AllocJitMemory();
        JitFortPrepare();
    }

    static void TearDownTestCase() {
        // Per-test-class cleanup
        FreeJitMemory();
    }

    void SetUp() {};  // Per-test-case setup
    void TearDown() {};  // Per-test-case cleanup
};
```

### Common Test Patterns

1. **Sign and Verify**: Sign data, copy to JIT memory, verify match
```cpp
signer = CreateJitCodeSigner();
AppendInstruction(signer, g_testInstructionSet[i]);
EXPECT_EQ(CopyToJitCode(signer, g_jitMemory, g_testInstructionSet, size), CS_SUCCESS);
EXPECT_EQ(memcmp(g_jitMemory, g_testInstructionSet, size), 0);
```

2. **Patch and Verify**: Patch at offset, verify updated value
```cpp
WillFixUp(signer, 1);
AppendInstruction(signer, instruction);
PatchInstruction(signer, offset, newInstruction);
```

3. **Error Cases**: Test null pointers, invalid sizes, out-of-range offsets
```cpp
EXPECT_EQ(PatchInstruction(signer, nullptr, 0), CS_ERR_PATCH_INVALID);
EXPECT_EQ(PatchData(signer, 0, nullptr, 0), CS_ERR_INVALID_DATA);
```

---

## Architecture Notes

### Module Structure

```
jit_code_sign/
├── include/
│   ├── jit_code_signer.h      # Main signing class
│   ├── jit_buffer_integrity.h # Static API wrappers
│   ├── pac_sign_ctx.h        # PAC context management
│   ├── random_helper.h        # Random salt generation
│   └── jit_fort_helper.h    # JIT-FORT integration
├── src/
│   ├── jit_code_signer.cpp    # Implementation
│   └── pac_sign_ctx.cpp      # PAC context implementation
└── BUILD.gn                  # Build configuration
```

### Dependencies

**External**:
- `bounds_checking_function:libsec_shared` - Secure string functions
- `hilog:libhilog` - Logging

**Internal**:
- `errcode.h` - Error code definitions
- `log.h` - Logging utilities
- `code_sign_attr_utils` - XPM initialization (for JIT-FORT)

### Key Classes

1. **JitCodeSigner**: Main API for signing/verifying JIT code
   - Maintains signing state and salt
   - Handles instruction/data queuing
   - Supports patching at runtime

2. **PACSignCtx**: Low-level PAC signing context
   - Manages signing context (AUTH_CONTEXT, SIGN_WITH_CONTEXT, SIGN_WITHOUT_CONTEXT)
   - Uses salt for randomization
   - Wraps ARMv8.3-A PAC instructions (`pacga`, `pacdb`, `autdb`)

### Instruction Signing Flow

1. **Signing Phase**:
   - Call `SignInstruction()` for each 4-byte instruction
   - Context updates with each signature
   - Signatures stored in `signTable_`

2. **Patching Phase**:
   - Call `WillFixUp()` to reserve space
   - Call `PatchInstruction()` or `PatchData()` to update
   - Signature in table updated to match new instruction

3. **Verification Phase**:
   - Call `CopyToJitCode()` with signer, JIT memory, and temp buffer
   - Creates verification context with same salt
   - Validates each instruction matches expected signature
   - Copies to JIT memory only if all valid

### 4-Byte Alignment

All instructions must be 4-byte aligned:
```cpp
constexpr int32_t INSTRUCTION_SIZE = 4;

// Unaligned data handling via queue
std::queue<Byte> willSign_;  // Holds pending bytes
```

Offset calculations shift by 2 (log2(4)):
```cpp
static inline int GetIndexFromOffset(int offset) {
    return static_cast<int>(static_cast<uint32_t>(offset) >> 2);
}
```
