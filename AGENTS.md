# Code Signature - AI Knowledge Base

## Basic Information

| Attribute | Value |
|-----------|-------|
| Repository Name | code_signature |
| Subsystem | base/security |
| Primary Language | C++ / Rust |
| Last Updated | 2026-01-31 |

## Directory Structure

```
code_signature/
├── interfaces/                    # Interface layer (API definitions)
│   └── inner_api/
│       ├── code_sign_utils/      # Core code signing enforcement APIs (EnforceCodeSignForApp, EnableKeyInProfile)
│       │                          # See [API Reference](#api-reference), [code_sign_utils Module](#code_sign_utils-module)
│       ├── code_sign_attr_utils/ # Code attribute setting APIs (InitXpm, SetXpmOwnerId)
│       │                          # See [API Reference](#api-reference), [code_sign_attr_utils Module](#code_sign_attr_utils-module)
│       ├── local_code_sign/      # Local signing APIs (InitLocalCertificate, SignLocalCode)
│       │                          # See [API Reference](#api-reference), [local_code_sign_service Module](#local_code_sign_service-module)
│       ├── jit_code_sign/        # JIT code signing for ARMv8.3-A+ Pointer Authentication
│       │                          # See [API Reference](#api-reference), [jit_code_sign Module](#jit_code_sign-module)
│       └── common/               # Shared types and error codes (errcode.h)
│                                  # See [Error Code Reference](#error-code-reference)
├── services/                     # Service layer (implementations)
│   ├── local_code_sign/          # SystemAbility (SA ID: 3507) for local signing service
│   │                              # See [local_code_sign_service Module](#local_code_sign_service-module)
│   └── key_enable/               # Certificate trust management (Rust + C++ FFI)
│                                  # See [key_enable Module](#key_enable-module-rust)
├── utils/                        # Common utilities (ELF parsing, fs-verity, OpenSSL wrappers)
│                                  # See [Architecture Design](#architecture-design)
├── test/                         # Test cases
│   ├── unittest/                 # Unit tests
│   └── fuzztest/                 # Fuzz tests
├── BUILD.gn                      # Main build configuration
├── code_signature.gni            # Build arguments and feature flags
├── bundle.json                   # Component metadata
└── README.md                     # Component documentation
```

---

## Repository Overview

### Introduction

The code signature component implements the code signing mechanism of OpenHarmony. It provides validity check and integrity protection for apps at runtime, preventing execution of malicious code on devices and malicious tampering of app code by attackers.

### Technology Stack

- **C++17**: Primary implementation language for services and interfaces
- **Rust**: Key enable service (certificate trust management)
- **C**: FFI layer between Rust and C++

### Main Dependencies

| Dependency | Purpose |
|------------|---------|
| HUKS | Universal key storage for certificates |
| SAMGR | System ability manager |
| OpenSSL | PKCS7 certificate parsing, signature verification |
| fs-verity-utils | File integrity verification |
| SELinux | Mandatory access control |
| elfio | ELF file parsing |
| HISYSEVENT | System event logging |
| HITRACE | Performance tracing |

## Architecture Design

### Component Layers

```
┌─────────────────────────────────────────────────────────┐
│                   Application Layer                      │
│              (HAP Installation, AOT Compiler)            │
└─────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────┐
│                    Interface Layer                       │
│  code_sign_utils | local_code_sign | code_sign_attr_utils │
└─────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────┐
│                     Service Layer                        │
│        LocalCodeSignService | KeyEnableService           │
└─────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────┐
│                    Utility Layer                         │
│  ELF Parser | fs-verity | OpenSSL | Certificate Utils    │
└─────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────┐
│                   Kernel Layer                           │
│              fs-verity | XPM | PAC                       │
└─────────────────────────────────────────────────────────┘
```

### IPC Communication

- LocalCodeSignService registered as SystemAbility (SA ID: 3507)
- IPC stub: LocalCodeSignStub
- Configuration: [sa_profile/3507.json](services/local_code_sign/sa_profile/3507.json)

### Module Descriptions

#### code_sign_utils Module

**Location**: [interfaces/inner_api/code_sign_utils/src/](interfaces/inner_api/code_sign_utils/src/)

**Purpose**: Enforce code signing on HAP packages and individual files during installation.

**Key Functions**:
- `EnforceCodeSignForApp()` - Parse signature file, extract owner ID, enable fs-verity for all files in HAP
- `EnforceCodeSignForFile()` - Enable fs-verity on individual files using signature data
- `EnableKeyInProfile()` / `RemoveKeyInProfile()` - Trust/revoke developer certificates via key_enable service
- `EnableKeyForEnterpriseResign()` / `RemoveKeyForEnterpriseResign()` - Manage enterprise resigning certificates
- Parses ELF Code Signature Block v1 (and v2 when `SUPPORT_BINARY_ENABLE` defined)
- Verifies fs-verity kernel support before enabling

**Dependencies**: OpenSSL (PKCS7), fs-verity-utils, key_enable service (Rust FFI)

#### local_code_sign_service Module

**Location**: [services/local_code_sign/src/](services/local_code_sign/src/)

**Purpose**: SystemAbility (SA ID: 3507) for on-device local code signing (e.g., AOT-generated code).

**Key Functions**:
- `InitLocalCertificate()` - Load local signing certificate from HUKS
- `SignLocalCode()` - Sign ELF files or data buffers using device certificate
- Permission verification via SELinux before signing operations
- IPC stub (`LocalCodeSignStub`) handles cross-process calls

**Dependencies**: HUKS (certificate storage), SAMGR, OpenSSL

#### key_enable Module (Rust)

**Location**: [services/key_enable/src/](services/key_enable/src/)

**Purpose**: Certificate trust management - load device certs, manage kernel keyring, handle developer certs.

**Key Functions**:
- Load trusted device certificates from `/data/service/el1/public/certificate/`
- Manage `.fs-verity` kernel keyring via `keyctl` syscalls
- Certificate path validation and chain verification (OpenSSL)
- Profile certificate management for developer/enterprise certs
- FFI layer (`rust_interface.h`) for C++ integration

**Dependencies**: OpenSSL (rust-openssl), kernel keyring APIs, HUKS

#### jit_code_sign Module

**Location**: [interfaces/inner_api/jit_code_sign/src/](interfaces/inner_api/jit_code_sign/src/)

**Purpose**: ARMv8.3-A Pointer Authentication (PAC) for JIT-generated code integrity.

**Key Functions**:
- `SignJitCode()` - Sign JIT-generated code buffer using PAC instruction
- `VerifyJitCode()` - Verify PAC signature on code buffer
- Instruction-level signing (4-byte aligned instructions)
- `PacSignContext` manages signing state and salt
- Supports JIT-FORT integration for memory protection

**Dependencies**: ARMv8.3-A PAC instructions (pacga), JIT-FORT

#### code_sign_attr_utils Module

**Location**: [interfaces/inner_api/code_sign_attr_utils/src/](interfaces/inner_api/code_sign_attr_utils/src/)

**Purpose**: Configure code attributes (XPM region, owner ID) for memory access control.

**Key Functions**:
- `InitXpm()` - Initialize XPM (eXtended Permission Model) region with owner ID and JIT-FORT settings
- `SetXpmOwnerId()` - Set owner ID for XPM memory access control
- Owner ID types: SYSTEM, APP, DEBUG, PLUGIN

**Dependencies**: XPM kernel module

---

## Build and Test

### Build Configuration

Feature flags in [code_signature.gni](code_signature.gni):

| Flag | Default | Description |
|------|---------|-------------|
| code_signature_support_openharmony_ca | true | Support OpenHarmony CA certificates |
| code_signature_support_oh_code_sign | false | Enable OH code signing |
| code_signature_enable_xpm_mode | 0 | XPM mode enablement (0=disabled) |
| code_signature_support_oh_release_app | false | Support release app signing |
| code_signature_support_app_allow_list | false | Enable app allow list |
| code_signature_screenlock_mgr_enable | auto | Enable screenlock manager integration (auto-detected) |
| code_signature_support_binary_enable | false | Enable ELF Code Signature Block v2 support |
| jit_code_sign_enable | auto | JIT signing (auto-enabled on arm64 when code_signature_support_oh_code_sign=true) |

### Build Commands

```bash
# Build component only
./build.sh --product-name rk3568 --build-target base/security/code_signature:code_signature

# Build tests
./build.sh --product-name rk3568 --build-target base/security/code_signature/test:testgroup --no-indep
```

Or use independent compilation

```bash
# Build component only
hb build code_signature -i

# Build tests
hb build code_signature -t
```

### Test Commands

```bash
# Build all tests
./build.sh --product-name rk3568 --build-target base/security/code_signature/test:testgroup  --no-indep

# Test binaries location: out/{product}/tests/{unittest,fuzztest}/code_signature/code_signature/
# Available unit tests:
#   - code_sign_utils_unittest
#   - local_code_sign_unittest
#   - code_sign_attr_utils_unittest
#   - jit_code_sign_unittest
#   - cert_chain_verifier_unittest
#   - local_code_sign_utils_unittest
#   - local_code_sign_utils_mock_unittest
#   - code_sign_utils_in_c_unittest
#   - enable_verity_ioctl_unittest
#   - sign_and_enforce_unittest
#   - multi_thread_local_sign_unittest
#   - key_enable_utils_unittest (when code_signature_support_oh_code_sign=true)
#   - rust_key_enable_unittest (when not using clang coverage)

# Run fuzz tests (requires HKP tool)
# Available fuzzers:
#   - InitLocalCertificateStubFuzzTest
#   - SignLocalCodeStubFuzzTest
#   - InitLocalCertificateFuzzTest
#   - SignLocalCodeFuzzTest
```

### Running Tests on Device

```bash
# Push tests to device
hdc shell mkdir -p /data/test
hdc file send out/rk3568/tests/unittest/code_signature/code_signature/* /data/test/

# Run specific test on device
hdc shell /data/test/code_sign_utils_unittest

# Run all tests on device
hdc shell "cd /data/test && for test in *_unittest; do ./\$test; done"
```

### Build Artifacts

| Artifact Type | Location |
|---------------|----------|
| Libraries and Binaries | out/{product}/security/code_signature/ |
| Test binaries | out/{product}/tests/unittest/code_signature/ |

### Coding Style

- [OpenHarmony C++ Coding Style Guide](../../../docs/en/contribute/OpenHarmony-cpp-coding-style-guide.md)
- [License and Copyright Specifications](../../../docs/en/contribute/license-and-copyright-specifications.md)

---

## API Reference

### Core Code Signing APIs

| API | Description | Header |
|-----|-------------|--------|
| `int32_t EnforceCodeSignForApp(const EntryMap &entryPath, const std::string &signatureFile)` | Enforce code signing for HAP packages | [code_sign_utils.h](interfaces/inner_api/code_sign_utils/include/code_sign_utils.h) |
| `int32_t EnforceCodeSignForFile(const std::string &path, const ByteBuffer &signature)` | Enforce code signing for files | [code_sign_utils.h](interfaces/inner_api/code_sign_utils/include/code_sign_utils.h) |
| `int ParseOwnerIdFromSignature(const ByteBuffer &sigbuffer, std::string &ownerID)` | Parse owner ID from signature | [code_sign_utils.h](interfaces/inner_api/code_sign_utils/include/code_sign_utils.h) |
| `int32_t EnableKeyInProfile(const std::string &bundleName, const ByteBuffer &profileBuffer)` | Trust developer certificate | [code_sign_utils.h](interfaces/inner_api/code_sign_utils/include/code_sign_utils.h) |
| `int32_t RemoveKeyInProfile(const std::string &bundleName)` | Revoke trusted certificate | [code_sign_utils.h](interfaces/inner_api/code_sign_utils/include/code_sign_utils.h) |
| `int32_t EnableKeyForEnterpriseResign(const ByteBuffer &certBuffer)` | Add enterprise resigning cert | [code_sign_utils.h](interfaces/inner_api/code_sign_utils/include/code_sign_utils.h) |
| `int32_t RemoveKeyForEnterpriseResign(const ByteBuffer &certBuffer)` | Remove enterprise resigning cert | [code_sign_utils.h](interfaces/inner_api/code_sign_utils/include/code_sign_utils.h) |

### Local Code Signing APIs

| API | Description | Header |
|-----|-------------|--------|
| `int32_t InitLocalCertificate(ByteBuffer &cert)` | Initialize local code signing certificate | [local_code_sign_kit.h](interfaces/inner_api/local_code_sign/include/local_code_sign_kit.h) |
| `int32_t SignLocalCode(const std::string &filePath, ByteBuffer &signature)` | Sign local code file | [local_code_sign_kit.h](interfaces/inner_api/local_code_sign/include/local_code_sign_kit.h) |
| `int32_t SignLocalCode(const std::string &ownerID, const std::string &filePath, ByteBuffer &signature)` | Sign with owner ID | [local_code_sign_kit.h](interfaces/inner_api/local_code_sign/include/local_code_sign_kit.h) |

### Code Attribute APIs

| API | Description | Header |
|-----|-------------|--------|
| `int InitXpm(int enableJitFort, uint32_t idType, const char *ownerId, const char *apiTargetVersionStr, const char *appSignType)` | Initialize XPM resources | [code_sign_attr_utils.h](interfaces/inner_api/code_sign_attr_utils/include/code_sign_attr_utils.h) |
| `int SetXpmOwnerId(uint32_t idType, const char *ownerId)` | Set owner ID for XPM | [code_sign_attr_utils.h](interfaces/inner_api/code_sign_attr_utils/include/code_sign_attr_utils.h) |

### JIT Code Signing APIs

| API | Description | Header |
|-----|-------------|--------|
| `int32_t SignJitCode(uint64_t codeAddr, size_t codeSize, ByteBuffer &signature)` | Sign JIT-generated code buffer | [jit_code_signer.h](interfaces/inner_api/jit_code_sign/include/jit_code_signer.h) |
| `bool VerifyJitCode(uint64_t codeAddr, size_t codeSize, const ByteBuffer &signature)` | Verify JIT code signature | [jit_code_signer.h](interfaces/inner_api/jit_code_sign/include/jit_code_signer.h) |

---

## Error Code Reference

Error codes are defined in [interfaces/inner_api/common/include/errcode.h](interfaces/inner_api/common/include/errcode.h). All error codes are negative integers (except `CS_SUCCESS = 0` and `CS_SUCCESS_END = 1`).

### Error Code Categories

| Category | Range | Description |
|----------|-------|-------------|
| Common | `-0x1` to `-0x4` | General errors (memory, permission, signature) |
| File Operation | `-0x100` to `-0x104` | File access and extraction errors |
| Signing | `-0x200` to `-0x208` | HUKS and signing operation errors |
| OpenSSL | `-0x210` to `-0x214` | Certificate and PKCS7 parsing errors |
| Verification | `-0x300` to `-0x311` | fs-verity and profile verification errors |
| IPC | `-0x500` to `-0x507` | Inter-process communication errors |
| Sign Block | `-0x600` to `-0x630` | Code signature block parsing errors |
| JIT Code Sign | `-0x700` to `-0x7ff` | JIT signing and PAC errors |

### Common Error Codes

| Error Code | Hex Value | Description |
|------------|-----------|-------------|
| `CS_SUCCESS` | `0x0` | Operation successful |
| `CS_ERR_NO_PERMISSION` | `-0x2` | Permission denied |
| `CS_ERR_NO_SIGNATURE` | `-0x3` | Signature not found |
| `CS_ERR_INVALID_SIGNATURE` | `-0x4` | Invalid signature |
| `CS_ERR_FILE_INVALID` | `-0x100` | Invalid file |
| `CS_ERR_HUKS_OBTAIN_CERT` | `-0x201` | Failed to obtain certificate from HUKS |
| `CS_ERR_NO_OWNER_ID` | `-0x205` | Owner ID not found |
| `CS_ERR_FSVERITY_NOT_ENABLED` | `-0x302` | fs-verity not enabled on file |
| `CS_ERR_IPC_MSG_INVALID` | `-0x500` | Invalid IPC message |