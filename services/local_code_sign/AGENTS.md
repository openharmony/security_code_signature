# Local Code Sign Service — AI Knowledge Base

## Basic Information

| Attribute | Value |
|-----------|-------|
| Module Name | local_code_sign |
| Subsystem | base/security |
| Parent Guide | [AGENTS.md](../../AGENTS.md) |
| Primary Language | C++ |
| SystemAbility | SA ID: 3507 |
| Last Updated | 2026-07-10 |

---

## Before Editing

Before making changes, write a 3-line declaration referencing both this guide and the parent guide:

1. **Task category**: Change SA implementation / Change IPC stub / Change HUKS integration / Change permission check / Change build / Change test / Change documentation.
2. **Documents read**: Sections from this guide + parent [AGENTS.md](../../AGENTS.md) relevant sections + `errcode.h` + header paths of files being changed.
3. **Constraints identified**: Which items from the "Do Not / Ask Before / Module Invariants" sections below are triggered.

## Where to Look

| Task type | Read these first |
| --- | --- |
| Modify SA 3507 IPC interface (stub) | `src/local_code_sign_stub.cpp` + `include/local_code_sign_stub.h` + this guide's "IPC Pattern" section + parent AGENTS.md's "Do Not — SA 3507 IPC" |
| Modify signing logic or HUKS integration | `src/local_sign_key.cpp` + `include/local_sign_key.h` + this guide's "HUKS Integration" section |
| Modify permission verification | `src/permission_utils.cpp` + `include/permission_utils.h` + this guide's "Permission Verification" section |
| Modify service lifecycle | `src/local_code_sign_service.cpp` + `include/local_code_sign_service.h` + `sa_profile/3507.json` |
| Modify build configuration | `BUILD.gn` (module-local) + `code_signature.gni` (parent) |
| Add new IPC method | This guide's "IPC Pattern" + `errcode.h` for new error codes + parent AGENTS.md's "Ask Before — public API" |

## Routing by Vocabulary

| Term / Abbreviation | Meaning / Location | Knowledge to load |
| --- | --- | --- |
| `LocalCodeSignStub` / IPC code / `MessageParcel` | IPC stub implementation | `local_code_sign_stub.cpp` + this guide's "IPC Pattern" |
| `LocalSignKey` / HUKS / ECDSA256 | HUKS key management and signing | `local_sign_key.cpp` + this guide's "HUKS Integration" |
| SA 3507 / `LocalCodeSignService` | SystemAbility registration and lifecycle | `local_code_sign_service.cpp` + `sa_profile/3507.json` + parent AGENTS.md's "Ask Before — SA 3507" |
| `IsValidCallerOf*` / SELinux / AccessToken | Permission verification | `permission_utils.cpp` + this guide's "Permission Verification" |
| `DECLARE_DELAYED_SINGLETON` / `SystemAbility::MakeAndRegisterAbility` | Service registration pattern | This guide's "SystemAbility Lifecycle" and "Singleton Pattern" |

---

## Module Structure

```
local_code_sign/
├── src/
│   ├── local_code_sign_service.cpp    # Main service implementation
│   ├── local_code_sign_stub.cpp       # IPC request handling
│   ├── local_sign_key.cpp            # HUKS key management & signing
│   └── permission_utils.cpp          # SELinux/AccessToken verification
├── include/
│   ├── local_code_sign_service.h      # Service header
│   ├── local_code_sign_stub.h         # IPC stub header
│   ├── local_sign_key.h              # Key management header
│   └── permission_utils.h            # Permission utilities
├── BUILD.gn                         # Build configuration
├── local_code_sign.cfg               # Init service config
├── sa_profile/3507.json             # SystemAbility profile
└── config/                          # Certificate configs
```

## Key Dependencies

- HUKS: Certificate storage and signing
- SAMGR: SystemAbility management
- OpenSSL: PKCS7 signature generation
- AccessToken: Permission verification
- HiSysEvent: Security event logging
- HiTrace: Performance tracing

---

## Build and Test

### Build Commands

```bash
# Build only local_code_sign service
./build.sh --product-name rk3568 --build-target base/security/code_signature/services/local_code_sign:liblocal_code_sign

# Using hb (independent compilation)
cd services/local_code_sign && hb build . -i

# Build all code_signature tests
./build.sh --product-name rk3568 --build-target base/security/code_signature/test:testgroup --no-indep
```

### Test Commands

```bash
# Build specific local_code_sign unit test
./build.sh --product-name rk3568 --build-target base/security/code_signature/test/unittest:local_code_sign_unittest

# Run test on device (after pushing)
hdc file send out/rk3568/tests/unittest/code_signature/code_signature/local_code_sign_unittest /data/test/
hdc shell /data/test/local_code_sign_unittest

# Run specific test case
hdc shell "/data/test/local_code_sign_unittest --gtest_filter=LocalCodeSignTest.LocalCodeSignTest_0001"
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
- [ ] The minimum build command has been run and passes.
- [ ] Unit tests (`local_code_sign_unittest`) pass.
- [ ] Lint has been run, or explicitly noted as skipped.
- [ ] SA ID / IPC code changes (if any) are recorded in the commit message and cross-referenced in the parent [AGENTS.md](../../AGENTS.md).

### Final Response

When reporting back, the response must include:

1. **Changed file list** + diff summary per file.
2. **Constraint check conclusion**: Which "Do Not / Ask Before / Module Invariants" items were hit and the outcome.
3. **Validation commands run** and their results.
4. **Impact scope**: SA ID 3507, IPC methods, permission model, HUKS operations affected.
5. **Risk points** and **items not run** with explicit reasons.

### When Validation Cannot Run

- **On-device tests unreachable**: At minimum run local build + lint, note "device test not run".
- **Only docs / build config changed**: "No code changes, unit tests not required", but still run one build to confirm no breakage.

---

## Constraints and Boundaries

### Do Not

The following must not be changed without escalation to the module owner.

- **SA 3507 IPC interface**: Do not modify `LocalCodeSignStub` IPC fields, SA ID, or IPC codes. These are cross-process contracts — changes break all callers (see parent [AGENTS.md `Do Not — SA 3507 IPC`](../../AGENTS.md#do-not) for rationale).
- **HUKS certificate lifecycle**: Do not bypass HUKS for certificate operations. Key generation, initialization, and signing must follow the three-stage flow (`HksInit` → `HksUpdate` → `HksFinish`).
- **Permission check bypass**: Do not remove or bypass the SELinux / AccessToken check (`PermissionUtils::IsValidCallerOfXXX()`) in any IPC method. This is a mandatory security control.
- **SELinux check ordering**: Do not move the permission check to after data reading — it must be the **first** operation in every IPC `Inner()` method.
- **Error code meanings**: Do not invent new error codes outside `errcode.h`. Return only codes defined in `interfaces/inner_api/common/include/errcode.h`.
- **Local certificate generation**: If HUKS certificate retrieval fails, do not generate or substitute a local certificate.

### Ask Before

The following require human confirmation before changes.

- Adding a new IPC method to `LocalCodeSignStub` — requires SA ID 3507 contract review and coordination with all IPC callers.
- Changing the signature or semantics of existing IPC methods — requires cross-team coordination (installer, compiler service, etc.).
- Changing the key algorithm from ECDSA256 or modifying the three-stage HUKS flow — requires security review.
- Adding new permission roles or modifying `IsValidCallerOf*` logic — requires security review.
- Modifying `sa_profile/3507.json` — this file may be generated by the packaging system; confirm the source of truth first.

### Module Invariants

- **Every IPC `Inner()` method** must: check permission first, read input, call service implementation, write output/reply.
- **Every signing operation** must use a valid HUKS key handle. Do not fall back to software signing.
- **Owner ID validation** must enforce `MAX_OWNER_ID_LEN` (32 bytes). Empty owner ID is valid but produces `CS_ERR_NO_OWNER_ID`.
- **Error logging** must use `LOG_ERROR` before returning, with `%{public}` specifier for security (never log raw certificate data).

### Known Pitfalls

- **IPC ordering**: The permission check is the **first** line of every `Inner()` method. Inserting code before it can create security bypasses.
- **HUKS three-stage flow**: `HksInit()` → `HksUpdate()` → `HksFinish()` must be completed in order. Skipping stages or reordering causes signing failures.
- **Challenge-response**: `SetChallenge()` must be called before `InitLocalCertificate()`. Forgetting this breaks the handshake protocol.
- **fs-verity integration**: Use `FsverityUtilsHelper::GetInstance().GenerateFormattedDigest()` for file digests. The default hash algorithm is SHA256.

---

## Coding Patterns

### Naming

- Classes: `PascalCase` (`LocalCodeSignService`, `LocalSignKey`)
- Methods: `PascalCase` for public, `camelCase` for private
- Constants: `kPascalCase` or `UPPER_CASE` (`LOCAL_SIGN_KEY_ALIAS`, `MAX_OWNER_ID_LEN`)
- File names: `snake_case.cpp` (`local_code_sign_service.cpp`)
- Headers: `snake_case.h` with `#ifndef OHOS_SNAKE_CASE_H` guards

### Imports Order

1. Project headers with paths: `#include "local_code_sign_service.h"`
2. System headers: `#include <cstdint>`, `#include <mutex>`

### Formatting (OpenHarmony C++ Style)

- Use `std::lock_guard<std::mutex>` for mutex locking
- Use `constexpr` for compile-time constants
- Use `std::make_unique` instead of `new` for single ownership
- Use `delete` and set to `nullptr` for cleanup
- Use `memcpy_s` instead of `memcpy` for secure copying

### Error Handling

```cpp
// Return error codes from errcode.h (defined in interfaces/inner_api/common/include/errcode.h)
// All error codes are negative integers (CS_SUCCESS = 0)

// Common patterns:
if (!condition) {
    LOG_ERROR("Description with details: %{public}d", value);
    return CS_ERR_CODE;
}

// Always log errors before returning
// Use %{public} specifier in LOG_* macros for security (avoids leaking sensitive data)
```

### IPC Pattern (LocalCodeSignStub)

```cpp
// Each IPC method has an Inner() function that handles MessageParcel
int32_t LocalCodeSignStub::MethodNameInner(MessageParcel &data, MessageParcel &reply) {
    // 1. Permission check (always first)
    if (!PermissionUtils::IsValidCallerOfXXX()) {
        reply.WriteInt32(CS_ERR_NO_PERMISSION);
        return CS_ERR_NO_PERMISSION;
    }

    // 2. Read input from data parcel
    Type param;
    if (!data.ReadType(param)) {
        LOG_ERROR("Read failed.");
        return CS_ERR_IPC_READ_DATA;
    }

    // 3. Call service implementation
    Type output;
    int32_t result = MethodName(param, output);

    // 4. Write result and output to reply
    if (!reply.WriteInt32(result) || !reply.WriteType(output)) {
        return CS_ERR_IPC_WRITE_DATA;
    }
    return CS_SUCCESS;
}
```

### SystemAbility Lifecycle

```cpp
// Service registration (in .cpp)
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(
    DelayedSingleton<LocalCodeSignService>::GetInstance().get());

// OnStart: Initialize, Publish, set state, schedule unload task
// OnStop: Clear state, remove tasks, set state to NOT_START
```

### Singleton Pattern

```cpp
// Use DECLARE_DELAYED_SINGLETON(Class) in class declaration
// Use DelayedSingleton<Class>::GetInstance() to access
class LocalCodeSignService {
    DECLARE_DELAYED_SINGLETON(LocalCodeSignService);
    DECLARE_SYSTEM_ABILITY(LocalCodeSignService);
};
```

### HUKS Integration (LocalSignKey)

```cpp
// Key lifecycle: GenerateKey() → InitKey() → Sign()
// Use ECC 256-bit keys for signing (ECDSA256)
// Challenge-Response: SetChallenge() before InitLocalCertificate()
// Three-stage signing: HksInit() → HksUpdate() → HksFinish()
```

### Permission Verification

```cpp
// Valid callers defined in permission_utils.cpp:
// - InitLocalCertificate: "key_enable"
// - SignLocalCode: "compiler_service"

// Check via PermissionUtils::IsValidCallerOfXXX()
```

## Owner ID Constraints

- Maximum length: 32 bytes (`MAX_OWNER_ID_LEN`)
- Must be validated before signing: `if (ownerID.length() > MAX_OWNER_ID_LEN)`
- Empty owner ID is valid (results in `CS_ERR_NO_OWNER_ID` when parsing)

## fs-verity Integration

- Use `FsverityUtilsHelper::GetInstance().GenerateFormattedDigest()` to get file digest
- Default hash algorithm: SHA256
