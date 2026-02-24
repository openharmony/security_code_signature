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
