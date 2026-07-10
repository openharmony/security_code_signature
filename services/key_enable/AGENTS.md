# Key Enable Service — AI Knowledge Base

## Basic Information

| Attribute | Value |
|-----------|-------|
| Module Name | key_enable |
| Subsystem | base/security |
| Parent Guide | [AGENTS.md](../../AGENTS.md) |
| Primary Language | Rust / C++ |
| Last Updated | 2026-07-10 |

---

## Before Editing

Before making changes, write a 3-line declaration referencing both this guide and the parent guide:

1. **Task category**: Change Rust implementation / Change C++ FFI / Change build / Change test / Change certificate management / Change hisysevent / Change documentation.
2. **Documents read**: Sections from this guide + parent [AGENTS.md](../../AGENTS.md) relevant sections + `errcode.h` + `rust_interface.h` + file paths being changed.
3. **Constraints identified**: Which items from the "Do Not / Ask Before / Module Invariants" sections below are triggered.

## Where to Look

| Task type | Read these first |
| --- | --- |
| Modify core key lifecycle (enable_all_keys, keyring) | `src/key_enable.rs` + this guide's "Initialization Lifecycle" |
| Modify certificate parsing / validation | `src/cert_utils.rs` + `src/cert_chain_utils.rs` + `src/cert_path_utils.rs` |
| Modify profile processing | `src/profile_utils.rs` + this guide's "Common Issues — Error Handling" |
| Modify Rust ↔ C++ FFI boundary | `include/rust_interface.h` + `utils/src/` (C++ implementation) + this guide's "C++/FFI for Missing Rust OpenSSL Bindings" |
| Add new hisysevent | `src/cs_hisysevent.rs` + parent AGENTS.md's "Do Not — DFX / observability" |
| Modify ASAN mock | `src/asan/disable_rust_interface.cpp` + this guide's "ASAN Build Support" |
| Modify certificate path config | `config/` directory files |
| Modify build flags / dependencies | `BUILD.gn` + parent `code_signature.gni` |

## Routing by Vocabulary

| Term / Abbreviation | Meaning / Location | Knowledge to load |
| --- | --- | --- |
| `.fs-verity` keyring / `keyctl` / `KeyctlRestrictKeyring` | Kernel keyring management | `src/key_enable.rs` + this guide's "Keyring Restriction Timing" |
| `WaitForBootCompletion` / boot sequence | Boot synchronization (max 20s wait) | `src/key_enable.rs` + this guide's "Initialization Lifecycle" |
| `BeforeUnlock` / `AfterUnlock` | Certificate state lifecycle | This guide's "Key States" |
| EL1 path / `/data/service/el1/public/certificate/` | Trusted certificate directory | `src/cert_path_utils.rs` + parent AGENTS.md's "Do Not — Trust root" |
| `CheckCertHasEnterpriseResignExtension` / enterprise resign / OID | Enterprise resign certificate extension | This guide's "C++/FFI for Missing Rust OpenSSL Bindings" |
| ASAN / AddressSanitizer | ASAN build with Rust disabled | `src/asan/disable_rust_interface.cpp` + this guide's "ASAN Build Support" |
| `CS_ADD_KEY` / `CS_ERR_PROFILE` / `CODE_SIGN` domain | Hisysevent events | `src/cs_hisysevent.rs` + this guide's "Hisysevent Error Reporting" |

---

## Directory Structure

```
key_enable/
├── src/                       # Rust source code
│   ├── main.rs               # Binary entry point
│   ├── lib.rs                # FFI library exports
│   ├── key_enable.rs         # Core key lifecycle management
│   ├── cert_utils.rs         # Certificate parsing and validation
│   ├── cert_chain_utils.rs   # Certificate chain operations
│   ├── cert_path_utils.rs    # Certificate path management
│   ├── profile_utils.rs      # Profile handling and validation
│   ├── file_utils.rs         # File operations
│   ├── cs_hisysevent.rs      # System event logging
│   └── asan/                 # ASAN build support (mock FFI)
│       └── disable_rust_interface.cpp  # Mock FFI for ASAN builds (Rust disabled)
├── utils/                     # C++ utilities and FFI bridge
│   ├── include/              # C++ header files
│   └── src/                  # C++ source files
├── include/                   # C FFI interface definitions
│   └── rust_interface.h      # FFI exports for C++
├── config/                    # Certificate path configurations
├── cfg/                       # Init service configurations
└── BUILD.gn                   # Rust build configuration
```

---

## Repository Overview

### Introduction

The **key_enable** component is responsible for initializing and managing cryptographic keys for code signing verification in OpenHarmony. The component includes a binary `key_enable` that manages the kernel's `.fs-verity` keyring, handles trusted certificates, local keys, and enterprise certificates through a phased initialization lifecycle. Other than the binary, the component provides Rust implementation to some interfaces defined in `code_sign_utils`.

Key responsibilities:
- Load trusted certificates into kernel fs-verity keyring
- Initialize and manage local code signing certificates
- Handle enterprise certificate management for app resigning
- Process developer profile certificates
- Restrict keyring after initialization to prevent tampering

### Technology Stack

- **Languages**: Rust (primary), C++ (system integration)
- **Build System**: GN
- **FFI**: rust_cxx for Rust-C++ interop
- **Crypto**: OpenSSL (via rust_rust-openssl)
- **Logging**: hilog, hisysevent
- **Configuration**: JSON (ylong_json)
- **Build Variants**: Supports ASAN builds with C++-only mock FFI (Rust disabled)

### Main Dependencies

**Rust Dependencies:**
- `hilog_rust` — Logging framework
- `hisysevent_rust` — System event reporting
- `ylong_json` — JSON parsing
- `rust_rust-openssl` — Cryptographic operations
- `rust_cxx` — C++ FFI support
- `c_utils_rust` — C utility bindings
- `lazy-static` — Static initialization

**C++ Dependencies:**
- `local_code_sign` SDK — Local code signing interfaces
- `hilog:libhilog` — C++ logging
- `init:libbegetutil` — Init utilities (For system parameters)
- `ipc:ipc_single` — IPC framework
- `samgr:samgr_proxy` — System capability manager
- `eventhandler:libeventhandler` — Event handling
- `screenlock_mgr` — Screen lock manager

---

## Workflow

### Initialization Lifecycle

```
                                    System Boot
                                         │
                                         ▼
                          ┌─────────────────────────┐
                          │ key_enable service starts │
                          └──────────┬──────────────┘
                                     │
                                     ▼
                  ┌────────────────────────────────────────┐
                  │ Load trusted certificates              │
                  │ - Root certificates on disk            │
                  └──────────────┬─────────────────────────┘
                                 │
                  ┌──────────────┴──────────────┐
                  ▼                             ▼
    ┌───────────────────────────┐   ┌─────────────────────────────┐
    │  Start profile&enterprise │   │    Main thread continues    │
    │  resign cert thread       │   │                             │
    │  (background)             │   └──────────┬──────────────────┘
    └──────────┬────────────────┘              │
               │                               ▼
               │                  ┌─────────────────────────────┐
               │                  │ Wait for boot completion    │
               ▼                  │ (max 20 seconds)            │
    ┌───────────────────────────┐ └──────────┬──────────────────┘
    │ Poll /data/service/el1    │            │
    │ (200ms interval,          │            ▼
    │  600s timeout)            │ ┌─────────────────────────────┐
    └──────────┬────────────────┘ │ Add local key (inactive)    │
               │                  └──────────┬──────────────────┘
               ▼                             │
    ┌───────────────────────────┐            ▼
    │ Parse profiles for:       │ ┌─────────────────────────────┐
    │ - Developer cert paths    │ │ Restrict fs-verity keyring  │
    │ - Enterprise certs        │ │ (prevent further changes)   │
    └──────────┬────────────────┘ └──────────┬──────────────────┘
               │                             │
               ▼                             ▼
    ┌───────────────────────────┐ ┌─────────────────────────────┐
    │ Add certs to kernel       │ │ Wait for user unlock        │
    └───────────────────────────┘ └──────────┬──────────────────┘
                                             │
                                             ▼
                              ┌─────────────────────────────┐
                              │ Activate local certificate  │
                              └─────────────────────────────┘
```

**Note:** The profile & enterprise resign cert thread runs in parallel (background). It polls for el1 path since it may be temporarily unavailable right after boot.

### Key States

| State | Description |
|-------|-------------|
| `BeforeUnlock` | Certificate loaded but not active (pre-user unlock) |
| `AfterUnlock` | Certificate activated and usable for AOT (ahead of time) signing |

---

## Build and Test

### Build Commands

For full build commands, see the [parent AGENTS.md](../../AGENTS.md).

```bash
# Build key_enable component
./build.sh --product-name rk3568 --build-target base/security/code_signature/services/key_enable:key_enable

# Build tests
./build.sh --product-name rk3568 --build-target base/security/code_signature/test:testgroup --no-indep
```

### Test Commands

```bash
# Build specific unit test (when code_signature_support_oh_code_sign=true)
./build.sh --product-name rk3568 --build-target base/security/code_signature/test/unittest:key_enable_utils_unittest

# Rust unit tests (requires Rust toolchain)
cd services/key_enable && cargo test
```

### Lint

```bash
# Rust (key_enable submodule)
cd services/key_enable && cargo fmt --check
cd services/key_enable && cargo clippy --all-targets -- -D warnings
```

> If Rust toolchain is not installed, skip cargo lint commands and note "Rust lint skipped" in the Final Response. Fall back to `hb build code_signature` for indirect Rust verification.

### Build Artifacts

| Artifact | Type |
|----------|------|
| `key_enable` | Executable |
| `libkey_enable.so` | Shared library |

---

## Verification Loop

### Done Definition

A task is considered complete only when all of the following are satisfied:

- [ ] Items triggered from "Do Not / Ask Before / Module Invariants" have been confirmed with a human.
- [ ] The minimum build command has been run and passes.
- [ ] Unit tests pass. When modifying Rust code, `cargo test` and `key_enable_utils_unittest` must be run.
- [ ] Lint (`cargo fmt --check` + `cargo clippy`) has been run, or explicitly noted as skipped.
- [ ] FFI changes (if any) are cross-referenced in both `include/rust_interface.h` and `src/asan/disable_rust_interface.cpp`.
- [ ] HISYSEVENT event changes (if any) are documented and the parent [AGENTS.md](../../AGENTS.md) DFX constraint is checked.

### Final Response

When reporting back, the response must include:

1. **Changed file list** + diff summary per file.
2. **Constraint check conclusion**: Which "Do Not / Ask Before / Module Invariants" items were hit and the outcome.
3. **Validation commands run** and their results (build / tests / lint).
4. **Impact scope**: Keyring, certificate trust store, FFI boundary, hisysevent events affected.
5. **Risk points** and **items not run** with explicit reasons.

### When Validation Cannot Run

- **Rust toolchain not installed**: Skip `cargo clippy` / `cargo fmt --check`, verify via `hb build code_signature` instead. Note "Rust lint skipped" in Final Response.
- **On-device tests unreachable**: Run local Rust unit tests + lint, note "device test not run".
- **Dependent SA / kernel unavailable**: Complete intra-module validation only; mark keyring and kernel behavior as "not validated".

---

## Constraints and Boundaries

### Do Not

The following must not be changed without escalation to the module owner.

- **Keyring restriction timing**: Do not insert time-consuming operations between key addition and `KeyctlRestrictKeyring()`. The window after key addition must be minimized to prevent attack injection.
- **fs-verity keyring identity**: Do not change the `.fs-verity` kernel keyring keyid or description — they must remain stable for fd reuse (see parent [AGENTS.md `Do Not — keyring identity`](../../AGENTS.md#do-not)).
- **Trust root**: Do not silently write certificates to `/data/service/el1/public/certificate/` or revoke device certificates in HUKS (see parent [AGENTS.md `Do Not — trust root`](../../AGENTS.md#do-not)).
- **Certificate verification bypass**: Do not add certificates to the kernel keyring without verifying the signer against trusted root certificates.
- **Error abort on recoverable errors**: Do not `panic!`, `return` fatal, or `abort` when a single profile or certificate fails — log the error and `continue` to process remaining items.
- **Mock FFI parity (ASAN)**: Every Rust FFI function exported from `libkey_enable.so` must have a corresponding mock implementation in `src/asan/disable_rust_interface.cpp`. Adding an FFI function without updating the mock breaks ASAN builds.
- **HISYSEVENT compatibility**: Do not delete or rename event IDs (`CS_ADD_KEY`, `CS_ERR_PROFILE`) defined in the module. New parameters may be added, but existing event definitions must be preserved.

### Ask Before

The following require human confirmation before changes.

- Changing the initialization lifecycle (boot wait timeout, polling interval, key state transitions) — affects boot reliability and security.
- Adding new certificate sources or trust anchors — requires security review.
- Modifying FFI function signatures in `rust_interface.h` — requires ABI review.
- Adding or removing UDID checks — affects production device security.
- Changing `KeyctlRestrictKeyring()` behavior or timing — affects the kernel-level keyring security window.
- Modifying the profile polling timeout (`PROFILE_SEARCH_SLEEP_OUT_TIME`, currently 600s) — affects boot completion on devices with slow storage.

### Module Invariants

- **Error handling**: Recoverable errors (per-profile, per-certificate) must log + `continue`. Only abort on fatal errors (e.g., unable to get keyring ID).
- **Keyring restriction**: `KeyctlRestrictKeyring()` must follow immediately after the last key addition in `enable_local_keys_after_user_unlock()`, with no other operations in between.
- **Certificate verification**: Always verify signer against trusted roots before adding to keyring. Validate PKCS7 structure before extracting certificates. Check UDID on non-RD devices.
- **FFI boundary**: All Rust FFI exports must use `extern "C"` and have matching declarations in `include/rust_interface.h`. C++ implementations must use `extern "C"` linkage to prevent name mangling.
- **ASAN mock parity**: Adding a new Rust FFI function requires a matching mock in `src/asan/disable_rust_interface.cpp`.

### Known Pitfalls

- **Keyring restriction timing**: Time-consuming tasks before `KeyctlRestrictKeyring()` create a window for attackers to inject malicious keys. The `enable_local_keys_after_user_unlock()` flow must keep the window minimal.
- **`WaitForBootCompletion()` does NOT block on timeout** — it logs an error and continues with key addition. This is intentional; do not change it to a blocking wait.
- **C++/FFI for missing Rust OpenSSL bindings**: When Rust's `openssl` crate does not expose a needed function (e.g., X509 extension lookup by OID), implement it in C++ (`utils/src/`) and expose via FFI. Check `utils/include/*.h` for existing declarations before creating new ones.
- **Profile polling timeout**: The profile store (`/data/service/el1/public/profiles`) may not be available immediately after boot. The background thread polls at 200ms intervals with a 600s timeout. Do not reduce the timeout without verifying worst-case boot times.
- **ASAN builds disable Rust**: ASAN builds use a mock C++ implementation (`src/asan/disable_rust_interface.cpp`) instead of Rust FFI. Adding a new FFI function without updating the mock breaks ASAN builds silently.

---

## Error Code Reference

See the [parent AGENTS.md Error Code Reference](../../AGENTS.md#error-code-reference). Error codes returned to the interface layers match the definitions in `interfaces/inner_api/common/include/errcode.h`.

### Hisysevent Error Reporting

The component reports errors to hisysevent for debugging and monitoring. All events use domain `CODE_SIGN`. Create new parameters if needed, but use existing events only.

| Event Name | Event Type | Parameter | Description |
|------------|------------|-----------|-------------|
| `CS_ADD_KEY` | Fault | String | Reported when adding a key to kernel keyring fails |
| `CS_ERR_PROFILE` | Security | String | Reported when profile parsing or processing fails |

---

## Common Issues (Detailed Patterns)

### 1. Error Handling — Do Not Abort on Recoverable Errors

**Problem**: Aborting certificate adding due to small errors leaves the device without trusted certificates, causing app installation failures and security issues.

**Correct Pattern** (from `profile_utils.rs:439-462`):
```rust
if verify_signers(&pkcs7, profile_info).is_err() {
    error!(LOG_LABEL, "Invalid signer profile file {}", @public(path));
    report_parse_profile_err(&path, HisyseventProfileError::VerifySigner as i32);
    continue; // Skip this profile, continue with next
}
```

**Key Points**:
- Log the error with `error!` macro
- Report to hisysevent for monitoring
- Use `continue` in loops to skip failed items, not `return` or panic
- Only abort for fatal errors (e.g., unable to get keyring ID)

### 2. Keyring Restriction Timing

This is covered under [Known Pitfalls](#known-pitfalls). The key constraint is: no time-consuming operations between key addition and `KeyctlRestrictKeyring()`.

**Current Flow** (from `key_enable.rs:276-294`):
```rust
fn enable_local_keys_after_user_unlock(key_id: KeySerial) {
    // Wait for boot completion (non-blocking on timeout)
    if !unsafe { WaitForBootCompletion() } {
        error!(LOG_LABEL, "WaitForBootCompletion timed out, proceeding with local key");
    } else {
        info!(LOG_LABEL, "Boot completed, adding local key");
    }
    // Add local key (quick operation)
    add_local_key(key_id);
    // Immediately restrict - no other operations here!
    restrict_keys(key_id);  // KeyctlRestrictKeyring()
    // After restriction: user unlock and activation
    CheckUserUnlock();
    activate_local_cert(cert_data);
}
```

### 3. C++/FFI for Missing Rust OpenSSL Bindings

**Problem**: Rust's `openssl` crate may not expose all needed OpenSSL functions (e.g., X509 extension lookup by OID).
**Solution**: Implement in C++ (`utils/`) using full OpenSSL API and expose via FFI.

**Example**: Checking for enterprise resign extension in a certificate (from `utils/src/key_utils.cpp:68-104`):
```cpp
// C++ implementation using OpenSSL X509 API
#define ENTERPRISE_RESIGN_OID "1.3.6.1.4.1.2011.2.376.1.9"
int32_t CheckCertHasEnterpriseResignExtension(const uint8_t *certDer, uint32_t certSize)
{
    if (certDer == nullptr || certSize == 0) {
        return CS_ERR_PARAM_INVALID;
    }
    const unsigned char *certPtr = certDer;
    X509 *cert = d2i_X509(nullptr, &certPtr, certSize);
    if (cert == nullptr) {
        return CS_ERR_PARAM_INVALID;
    }
    int nid = OBJ_txt2nid(ENTERPRISE_RESIGN_OID);
    if (nid == NID_undef) {
        nid = OBJ_create(ENTERPRISE_RESIGN_OID, "EnterpriseAppResignCertID",
                         "Enterprise App Resign Cert ID");
    }
    int loc = X509_get_ext_by_NID(cert, nid, -1);
    X509_free(cert);
    return (loc >= 0) ? CS_SUCCESS : CS_ERR_PARAM_INVALID;
}
```

**Declared in** (`utils/include/key_utils.h:51`):
```c
extern "C" {
    int32_t CheckCertHasEnterpriseResignExtension(const uint8_t *certDer, uint32_t certSize);
}
```

**Called from Rust** (from `src/profile_utils.rs:795-801`):
```rust
extern "C" {
    fn CheckCertHasEnterpriseResignExtension(cert_der: *const u8, cert_size: u32) -> i32;
}

let ret = unsafe {
    CheckCertHasEnterpriseResignExtension(der.as_ptr(), der.len() as u32)
};

if ret == 0 {  // CS_SUCCESS
    info!(LOG_LABEL, "Found enterprise resign extension");
}
```

**Key Points**:
- Check `utils/include/*.h` for existing FFI declarations before adding new ones
- Always use `extern "C"` in C++ headers to prevent name mangling
- Return standard error codes (`CS_SUCCESS`, `CS_ERR_PARAM_INVALID`, etc.) for consistency

### 4. Certificate Verification Before Adding

**Problem**: Adding unverified certificates compromises the entire trust chain.

**Required Verifications** (from `profile_utils.rs:439-462`):
```rust
// 1. Verify signer certificate chain
if verify_signers(&pkcs7, profile_info).is_err() {
    report_parse_profile_err(&path, HisyseventProfileError::VerifySigner as i32);
    continue;
}

// 2. Parse and validate PKCS7 structure
let (subject, issuer, profile_type, app_id) = match parse_pkcs7_data(...) {
    Ok(tuple) => tuple,
    Err(e) => {
        report_parse_profile_err(&path, HisyseventProfileError::ParsePkcs7 as i32);
        continue;
    }
};

// 3. Verify UDID on non-RD devices
let check_udid = unsafe { !IsRdDevice() };
```

**Key Points**:
- Always verify signer against trusted root certificates
- Validate PKCS7 structure before extracting certificates
- Check UDID on production (non-RD) devices
- Enterprise certificates must be verified against the root store

### 5. Background Thread for Profile Polling

**Problem**: The profile store (`/data/service/el1/public/profiles`) may not be available immediately after boot.

**Solution**: Background thread with timeout (from `key_enable.rs:220-238`):
```rust
fn add_profile_cert_path_thread(...) -> JoinHandle<()> {
    thread::spawn(move || {
        loop {
            if check_and_add_cert_path(&root_cert, &cert_paths) {
                break;
            } else if start_time.elapsed() >= Duration::from_secs(PROFILE_SEARCH_SLEEP_OUT_TIME) {
                error!(LOG_LABEL, "Timeout while waiting for PROFILE_STORE_EL1.");
                break;
            } else {
                thread::sleep(Duration::from_millis(PROFILE_SEARCH_SLEEP_TIME)); // 200ms
            }
        }
    })
}
```

**Key Points**:
- Does not block the main thread
- Thread is joined at the end of `enable_all_keys()`

### 6. ASAN Build Support — Mock FFI Implementation

**Problem**: ASAN (AddressSanitizer) builds do not support Rust, but `key_enable` interfaces require Rust to work.

**Solution**: Provide mock FFI implementation in `src/asan/disable_rust_interface.cpp` that replaces Rust FFI with C++ equivalents when ASAN is enabled.

**Key Points**:
- All Rust-exported interfaces must have a mock in `src/asan/disable_rust_interface.cpp`
- Adding a new FFI export without updating the mock breaks ASAN builds
