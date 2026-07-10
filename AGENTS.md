# Code Signature — AI Knowledge Base

## Basic Information

| Attribute | Value |
|-----------|-------|
| Repository Name | code_signature |
| Subsystem | base/security |
| Primary Language | C++ / Rust |
| Last Updated | 2026-07-10 |

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

## Before Editing

Before making changes, write a 3-line declaration:

1. **Task category**: Change public API / Change service implementation / Change tests / Change build / Change documentation.
2. **Documents read**: Section headers from this guide + corresponding nested `AGENTS.md` (if any) + relevant header file paths.
3. **Constraints identified**: Which items from the "Do Not / Ask Before / Module Invariants" sections below are triggered.

## Where to Look

| Task type | Read these first |
| --- | --- |
| Modify public API or error codes | `interfaces/inner_api/common/include/errcode.h` + corresponding module's nested `AGENTS.md` |
| Modify HAP installation signing enforcement | `interfaces/inner_api/code_sign_utils/` implementation + this guide's "code_sign_utils Module" |
| Modify JIT code signing / PAC | `interfaces/inner_api/jit_code_sign/AGENTS.md` (nested guide) |
| Modify local signing service / SA 3507 | `services/local_code_sign/AGENTS.md` (nested guide) + `sa_profile/3507.json` |
| Modify certificate trust / keyring (Rust) | `services/key_enable/AGENTS.md` (nested guide) |
| Modify XPM / owner ID | `interfaces/inner_api/code_sign_attr_utils/include/code_sign_attr_utils.h` |
| Modify build flags / dependencies | `code_signature.gni`, `BUILD.gn` |
| Modify device commands / on-device testing | This guide's "Running Tests on Device" + confirm the target is a test device |

## Routing by Vocabulary

When task descriptions, logs, or code contain the following terms, load the corresponding knowledge before editing:

| Term / Abbreviation | Meaning / Location | Knowledge to load |
| --- | --- | --- |
| XPM / owner ID / JIT-FORT | `code_sign_attr_utils` module, memory access control | `code_sign_attr_utils.h` + this guide's "code_sign_attr_utils Module" |
| PAC / pacga / ARMv8.3-A | `jit_code_sign` module, JIT code integrity | `interfaces/inner_api/jit_code_sign/AGENTS.md` |
| fs-verity / keyctl / `.fs-verity` keyring | `key_enable` service, kernel integrity | `services/key_enable/AGENTS.md` |
| ELF Code Signature Block v1/v2 / `SUPPORT_BINARY_ENABLE` | `code_sign_utils` ELF parsing | `code_sign_utils/src/` implementation + `errcode.h` |
| SA 3507 / `LocalCodeSignStub` | `local_code_sign_service` module | `services/local_code_sign/AGENTS.md` + `sa_profile/3507.json` |
| HUKS | Universal key storage for certificates | `//base/security/huks/` — HUKS developer guide |
| SAMGR | System ability manager | `//base/system-samgr/` — SAMGR developer guide |
| HISYSEVENT | System event logging | `//base/hiviewdfx/hisysevent/` — HISYSEVENT reference |
| HITRACE | Performance tracing | `//base/hiviewdfx/hitrace/` — HITRACE reference |

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
- `EnforceCodeSignForApp()` — Parse signature file, extract owner ID, enable fs-verity for all files in HAP
- `EnforceCodeSignForFile()` — Enable fs-verity on individual files using signature data
- `EnableKeyInProfile()` / `RemoveKeyInProfile()` — Trust/revoke developer certificates via key_enable service
- `EnableKeyForEnterpriseResign()` / `RemoveKeyForEnterpriseResign()` — Manage enterprise resigning certificates
- Parses ELF Code Signature Block v1 (and v2 when `SUPPORT_BINARY_ENABLE` defined)
- Verifies fs-verity kernel support before enabling

**Dependencies**: OpenSSL (PKCS7), fs-verity-utils, key_enable service (Rust FFI)

#### local_code_sign_service Module

**Location**: [services/local_code_sign/src/](services/local_code_sign/src/)

**Purpose**: SystemAbility (SA ID: 3507) for on-device local code signing (e.g., AOT-generated code).

**Key Functions**:
- `InitLocalCertificate()` — Load local signing certificate from HUKS
- `SignLocalCode()` — Sign ELF files or data buffers using device certificate
- Permission verification via SELinux before signing operations
- IPC stub (`LocalCodeSignStub`) handles cross-process calls

**Dependencies**: HUKS (certificate storage), SAMGR, OpenSSL

**For finer-grained agent guidance, see**: [`services/local_code_sign/AGENTS.md`](services/local_code_sign/AGENTS.md)

#### key_enable Module (Rust)

**Location**: [services/key_enable/src/](services/key_enable/src/)

**Purpose**: Certificate trust management — load device certs, manage kernel keyring, handle developer certs.

**Key Functions**:
- Load trusted device certificates from `/data/service/el1/public/certificate/`
- Manage `.fs-verity` kernel keyring via `keyctl` syscalls
- Certificate path validation and chain verification (OpenSSL)
- Profile certificate management for developer/enterprise certs
- FFI layer (`rust_interface.h`) for C++ integration

**Dependencies**: OpenSSL (rust-openssl), kernel keyring APIs, HUKS

**For finer-grained agent guidance, see**: [`services/key_enable/AGENTS.md`](services/key_enable/AGENTS.md)

#### jit_code_sign Module

**Location**: [interfaces/inner_api/jit_code_sign/src/](interfaces/inner_api/jit_code_sign/src/)

**Purpose**: ARMv8.3-A Pointer Authentication (PAC) for JIT-generated code integrity.

**Key Functions**:
- `SignJitCode()` — Sign JIT-generated code buffer using PAC instruction
- `VerifyJitCode()` — Verify PAC signature on code buffer
- Instruction-level signing (4-byte aligned instructions)
- `PacSignContext` manages signing state and salt
- Supports JIT-FORT integration for memory protection

**Dependencies**: ARMv8.3-A PAC instructions (pacga), JIT-FORT

**For finer-grained agent guidance, see**: [`interfaces/inner_api/jit_code_sign/AGENTS.md`](interfaces/inner_api/jit_code_sign/AGENTS.md)

#### code_sign_attr_utils Module

**Location**: [interfaces/inner_api/code_sign_attr_utils/src/](interfaces/inner_api/code_sign_attr_utils/src/)

**Purpose**: Configure code attributes (XPM region, owner ID) for memory access control.

**Key Functions**:
- `InitXpm()` — Initialize XPM (eXtended Permission Model) region with owner ID and JIT-FORT settings
- `SetXpmOwnerId()` — Set owner ID for XPM memory access control
- Owner ID types: SYSTEM, APP, DEBUG, PLUGIN

**Dependencies**: XPM kernel module

---

## Constraints and Boundaries

### Do Not

The following must not be changed without escalation to the module owner.

- **SA 3507 IPC interface**: Do not modify `LocalCodeSignStub` IPC fields, SA ID, or IPC codes — these are cross-process contracts; changes break all callers.
- **Error code contract**: Do not add, delete, or rename error codes already defined in `errcode.h`; do not change the numeric value or semantics of existing error codes — public API contract.
- **ELF Code Signature Block format**: Do not modify the magic number, version, or field offsets of Block v1; v2 parsing must go through the `code_signature_support_binary_enable` flag.
- **fs-verity enablement flow**: Do not bypass the fs-verity enablement checks in `EnforceCodeSignForApp` / `EnforceCodeSignForFile`; fs-verity is irreversible once enabled.
- **Trust root**: Do not silently write certificates to `/data/service/el1/public/certificate/` or revoke device certificates in HUKS.
- **Keyring identity**: Do not change the `.fs-verity` kernel keyring keyid or description in `key_enable` — they must remain stable for fd reuse.
- **Generated artifacts**: `bundle.json`, `sa_profile/3507.json` are typically generated by the build/packaging system — confirm the source of truth before editing.
- **DFX / observability**: Do not delete or rename event IDs defined in `hisysevent.yaml`; do not remove HITRACE trace points without notifying the DFX module owner.

### Ask Before

The following require human confirmation before changes.

- Adding or deleting owner ID types (SYSTEM / APP / DEBUG / PLUGIN) — must align with the XPM kernel side.
- Changing public API function signatures, parameter semantics, or return value contracts — must coordinate with all callers.
- Changing PKCS7 / OpenSSL certificate chain verification policy — requires security review.
- Changing the Rust ↔ C++ FFI boundary (new FFI functions, modifying `rust_interface.h`) — requires ABI review.
- Running `hdc file send` / `hdc shell /data/test/...` on a physical device — confirm the target is a test device.
- Adjusting XPM `InitXpm*` behavior or JIT-FORT flags — requires coordination with the runtime / kernel team.

### Module Invariants

Each module must maintain the following invariants:

- **code_sign_utils**: fs-verity must verify kernel support before enabling; signature parsing failures must not silently fall through; all error codes must be centrally defined in `errcode.h`.
- **local_code_sign_service**: SELinux permission check is required before every signing operation; if HUKS certificate retrieval fails, do not generate a substitute certificate locally.
- **key_enable (Rust)**: Only trust certificate chains from HUKS or `/data/service/el1/public/certificate/`; `.fs-verity` keyring keyid must remain persistent and stable.
- **jit_code_sign**: `pacga` must only be called on arm64 when `jit_code_sign_enable` is true; `PacSignContext` salt must not be reused across processes.
- **code_sign_attr_utils**: `InitXpm*` may be called only once per process; owner ID must be one of the registered types (SYSTEM / APP / DEBUG / PLUGIN).

### Known Pitfalls

- **fs-verity is irreversible**: Once enabled, a file cannot be modified. Test the flow against temporary files first, then apply to real targets.
- **PAC is arm64-only**: The `pacga` instruction is not available on x86 or emulators. JIT code signing code must be guarded by the `jit_code_sign_enable` flag.
- **ELF Block v1 vs v2**: v2 is only compiled when `code_signature_support_binary_enable=true`. When modifying parsing logic, verify both flag combinations.
- **FFI repr(C) layout**: Struct layout across the Rust ↔ C++ FFI boundary must use `repr(C)`. Adding new fields must not break existing offsets.
- **Feature flag interactions**: Several feature flags (especially `code_signature_support_oh_code_sign`, `jit_code_sign_enable`) have auto-detection defaults. Verify the resolved value on the target build, not just the source default.

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

Or use independent compilation:

```bash
# Build component only
hb build code_signature -i

# Build tests
hb build code_signature -t
```

### Test Commands

```bash
# Build all tests
./build.sh --product-name rk3568 --build-target base/security/code_signature/test:testgroup --no-indep

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
#   - rust_key_enable_unittest (when not using code coverage instrumentation)

# Run fuzz tests (requires HKP tool)
# Available fuzzers:
#   - InitLocalCertificateStubFuzzTest
#   - SignLocalCodeStubFuzzTest
#   - InitLocalCertificateFuzzTest
#   - SignLocalCodeFuzzTest
```

### Lint

```bash
# Format C++ source files according to the project's code style

# Rust (key_enable submodule)
cd services/key_enable && cargo fmt --check
cd services/key_enable && cargo clippy --all-targets -- -D warnings
```

> If the formatter or `cargo` toolchains are unavailable, explicitly note "lint skipped" in the Final Response.

### API Compatibility

When modifying public headers under `interfaces/inner_api/`, consider checking ABI compatibility:

```bash
# After installing abi-dumper / abi-compliance-checker:
abi-dumper old.so -o old.dump
abi-dumper new.so -o new.dump
abi-compliance-checker -l code_signature -old old.dump -new new.dump
```

If the toolchain is not installed, note "ABI check skipped" in the Final Response.

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

## Verification Loop

### Done Definition

A task is considered complete only when all of the following are satisfied:

- [ ] Items triggered from "Do Not / Ask Before / Module Invariants" have been confirmed with a human.
- [ ] The minimum build command (see "Build Commands") corresponding to the task has been run and passes.
- [ ] The unit tests corresponding to the task (see "Test Commands") have been run and pass. (When modifying Rust code, `rust_key_enable_unittest` must be run.) For security-critical paths, fuzz testing is strongly recommended.
- [ ] The relevant lint commands (see "Lint") have been run, or explicitly noted as skipped in the Final Response.
- [ ] Public API / error code / SA IPC field changes (if any) are recorded in the commit message.
- [ ] Affected nested `AGENTS.md` files have been updated to stay in sync.

### Final Response

When reporting back to the user, the response must include:

1. **Changed file list** + a diff summary for each file.
2. **Constraint check conclusion**: Which items in "Do Not / Ask Before / Module Invariants" were triggered and the outcome of human confirmation.
3. **Validation commands run** and their results (build / unit tests / lint / on-device tests).
4. **Impact scope**: Modules, SA, API, error codes, feature flags affected.
5. **Risk points** and **items not run** — each skipped item must include an explicit reason.

### When Validation Cannot Run

Degrade gracefully based on the situation:

- **On-device tests unreachable**: At minimum run local unit tests + lint, and note "device test not run" in the Final Response.
- **Rust toolchain not installed**: Skip `cargo clippy` / `cargo fmt --check`, fall back to `hb build code_signature` for indirect Rust verification.
- **Docs / build config only**: Explicitly state "no code changes, unit tests not required", but still run a minimal build to confirm no syntax breakage.
- **Dependent SA / kernel unavailable**: Complete intra-component validation only; explicitly mark cross-process and kernel behavior as "not validated".

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
| `int InitXpmWithParam(const struct XpmInitParam *initParam)` | Initialize XPM resources with grouped parameters (preferred) | [code_sign_attr_utils.h](interfaces/inner_api/code_sign_attr_utils/include/code_sign_attr_utils.h) |
| `int InitXpm(int enableJitFort, uint32_t idType, const char *ownerId, const char *apiTargetVersionStr, const char *appSignType)` | Compatibility wrapper for legacy callers | [code_sign_attr_utils.h](interfaces/inner_api/code_sign_attr_utils/include/code_sign_attr_utils.h) |
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
