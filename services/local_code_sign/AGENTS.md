# Local Code Sign Service - AI Knowledge Base

## Build Commands

```bash
# Build only local_code_sign service
./build.sh --product-name rk3568 --build-target base/security/code_signature/services/local_code_sign:liblocal_code_sign

# Using hb (independent compilation)
cd services/local_code_sign && hb build . -i

# Build all code_signature tests
./build.sh --product-name rk3568 --build-target base/security/code_signature/test:testgroup --no-indep
```

## Test Commands

```bash
# Build specific local_code_sign unit test
./build.sh --product-name rk3568 --build-target base/security/code_signature/test/unittest:local_code_sign_unittest

# Run test on device (after pushing)
hdc file send out/rk3568/tests/unittest/code_signature/code_signature/local_code_sign_unittest /data/test/
hdc shell /data/test/local_code_sign_unittest

# Run specific test case
hdc shell "/data/test/local_code_sign_unittest --gtest_filter=LocalCodeSignTest.LocalCodeSignTest_0001"
```

## Code Style & Conventions

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

## Owner ID Constraints
- Maximum length: 32 bytes (`MAX_OWNER_ID_LEN`)
- Must be validated before signing: `if (ownerID.length() > MAX_OWNER_ID_LEN)`
- Empty owner ID is valid (results in `CS_ERR_NO_OWNER_ID` when parsing)

## fs-verity Integration
- Use `FsverityUtilsHelper::GetInstance().GenerateFormattedDigest()` to get file digest
- Default hash algorithm: SHA256
