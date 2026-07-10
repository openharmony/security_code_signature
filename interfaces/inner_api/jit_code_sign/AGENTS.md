# JIT Code Sign — AI Knowledge Base

## Basic Information

| Attribute | Value |
|-----------|-------|
| Module Name | jit_code_sign |
| Subsystem | base/security |
| Parent Guide | [AGENTS.md](../../../AGENTS.md) |
| Primary Language | C++ |
| Architecture | ARMv8.3-A+ (PAC) |
| Last Updated | 2026-07-10 |

---

## Before Editing

Before making changes, write a 3-line declaration referencing both this guide and the parent guide:

1. **Task category**: Change PAC signing logic / Change JIT-FORT integration / Change test / Change build / Change documentation.
2. **Documents read**: Sections from this guide + parent [AGENTS.md](../../../AGENTS.md) relevant sections + `errcode.h` + header paths of files being changed.
3. **Constraints identified**: Which items from the "Do Not / Ask Before / Module Invariants" sections below are triggered.

## Where to Look

| Task type | Read these first |
| --- | --- |
| Modify PAC signing or verification logic | `src/jit_code_signer.cpp` + `src/pac_sign_ctx.cpp` + this guide's "Instruction Signing Flow" |
| Modify PAC context or salt management | `include/pac_sign_ctx.h` + `src/pac_sign_ctx.cpp` + this guide's "Key Classes" |
| Modify JIT-FORT integration | `include/jit_fort_helper.h` + parent AGENTS.md's "code_sign_attr_utils Module" |
| Modify random salt generation | `include/random_helper.h` |
| Add or modify tests | This guide's "Test Commands" + "Testing Patterns" |
| Modify feature flag or build config | `code_signature.gni` (parent) + `BUILD.gn` (module-local) + this guide's "Feature Flag" |

## Routing by Vocabulary

| Term / Abbreviation | Meaning / Location | Knowledge to load |
| --- | --- | --- |
| PAC / pacga / pacdb / autdb | ARMv8.3-A Pointer Authentication instructions | This guide's "Key Classes" + "Instruction Signing Flow" |
| `JitCodeSigner` / `signTable_` | Main signing class with instruction signature table | `include/jit_code_signer.h` + this guide's "Key Classes" |
| `PACSignCtx` / AUTH_CONTEXT / SIGN_WITH_CONTEXT / SIGN_WITHOUT_CONTEXT | PAC context management with signing modes | `include/pac_sign_ctx.h` + this guide's "Key Classes" |
| JIT-FORT | Memory protection for JIT regions | `include/jit_fort_helper.h` + parent AGENTS.md's "code_sign_attr_utils Module" |
| `jit_code_sign_enable` | Feature flag (auto-enabled on arm64) | This guide's "Feature Flag" + parent `code_signature.gni` |
| `INSTRUCTION_SIZE` / 4-byte alignment | Instruction alignment requirement | This guide's "4-Byte Alignment" |
| `WillFixUp` / `PatchInstruction` / `PatchData` | Runtime instruction patching | This guide's "Instruction Signing Flow — Patching Phase" |

---

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
- `bounds_checking_function:libsec_shared` — Secure string functions
- `hilog:libhilog` — Logging

**Internal**:
- `errcode.h` — Error code definitions
- `log.h` — Logging utilities
- `code_sign_attr_utils` — XPM initialization (for JIT-FORT)

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

---

## Build and Test

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

### Lint

```bash
# Format C++ source files according to the project's code style
```

> If the formatter is not available, note "lint skipped" in the Final Response.

---

## Verification Loop

### Done Definition

A task is considered complete only when all of the following are satisfied:

- [ ] Items triggered from "Do Not / Ask Before / Module Invariants" have been confirmed with a human.
- [ ] The minimum build command has been run and passes (verify `jit_code_sign_enable=true` in the build config).
- [ ] Unit tests (`jit_code_sign_unittest`) pass on arm64 with PAC support.
- [ ] Lint has been run, or explicitly noted as skipped.
- [ ] Feature flag changes (if any) are documented in `code_signature.gni` and the parent [AGENTS.md](../../../AGENTS.md).

### Final Response

When reporting back, the response must include:

1. **Changed file list** + diff summary per file.
2. **Constraint check conclusion**: Which "Do Not / Ask Before / Module Invariants" items were hit and the outcome.
3. **Validation commands run** and their results (build / tests / lint / on-device).
4. **Impact scope**: PAC signing algorithm, JIT-FORT integration, feature flag, ABI (4-byte alignment contract).
5. **Risk points** and **items not run** with explicit reasons.

### When Validation Cannot Run

- **No arm64/PAC hardware available**: Build only, mark on-device PAC verification as "not validated — no PAC hardware available".
- **On-device tests unreachable**: Run local build + lint, note "device test not run".
- **jit_code_sign_enable=false in build config**: Build with `code_signature_support_oh_code_sign=true` and arm64 target to enable the module, or note "test skipped — flag disabled".

---

## Constraints and Boundaries

### Do Not

The following must not be changed without escalation to the module owner.

- **PAC instruction selection**: Do not replace `pacga` / `pacdb` / `autdb` with software-based alternatives. The module relies on ARMv8.3-A hardware instructions for security guarantees.
- **Salt reuse across processes**: Do not reuse `PacSignContext` salt across processes — each signing context must have independent salt randomization.
- **arm64 guard bypass**: Do not call PAC instructions or JIT code signing logic on non-arm64 targets. All PAC code must be guarded by `jit_code_sign_enable` (which is false on x86 / emulators).
- **4-byte alignment violation**: Do not change `INSTRUCTION_SIZE` (4) or the offset-to-index shift (`>> 2`). These are hardware-level constraints.
- **Verification bypass**: Do not skip the verification phase in `CopyToJitCode()`. Code must be verified before copying to JIT executable memory.

### Ask Before

The following require human confirmation before changes.

- Adding new PAC instruction modes or changing the signing algorithm — requires ARM architecture review.
- Changing the salt generation strategy (in `random_helper.h`) — affects security guarantees of the entire signing system.
- Modifying JIT-FORT integration (in `jit_fort_helper.h`) — requires coordination with the runtime / kernel team (see parent [AGENTS.md `Ask Before — XPM InitXpm*`](../../../AGENTS.md#ask-before)).
- Changing the multi-threaded test pattern (`HWMTEST_F` thread count) — if tests pass with fewer threads, the change is safe; if they only pass with specific thread counts, it may indicate a race condition in the implementation.

### Module Invariants

- **`pacga` must only be called on arm64 when `jit_code_sign_enable` is true**.
- **`PacSignContext` salt must not be reused across processes**.
- **Every `SignInstruction` must have a corresponding signature entry in `signTable_`**.
- **Verification must validate every instruction before any are copied to JIT memory**.
- **`CopyToJitCode()` must atomically validate all signatures before copying any data**.

### Known Pitfalls

- **PAC is arm64-only**: The `pacga` instruction does not exist on x86 or emulators. JIT code signing code must be guarded by `jit_code_sign_enable`.
- **4-byte alignment is a hardware constraint**: ARM instructions are fixed at 4 bytes. Changing `INSTRUCTION_SIZE` or the offset shift will break instruction alignment with hardware expectations.
- **Salt uniqueness**: Reusing salt across processes enables signature forgery. Each `PacSignContext` must receive independent salt.
- **Feature flag interaction**: `jit_code_sign_enable` is auto-enabled based on `code_signature_support_oh_code_sign` + arm64 + non-emulator. A change to any of these in `code_signature.gni` may unexpectedly enable or disable JIT signing.
- **Test hardware requirement**: JIT code sign tests require real arm64 hardware with PAC support. They cannot be fully validated on emulators or x86 build machines.

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
