# Key enable

## Basic Information

| Attribute | Value |
|-----------|-------|
| Module Name | key_enable |
| Subsystem | base/security |
| Primary Language | Rust/C++ |
| Last Updated | 2026-02-09 |

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
- `hilog_rust` - Logging framework
- `hisysevent_rust` - System event reporting
- `ylong_json` - JSON parsing
- `rust_rust-openssl` - Cryptographic operations
- `rust_cxx` - C++ FFI support
- `c_utils_rust` - C utility bindings
- `lazy-static` - Static initialization

**C++ Dependencies:**
- `local_code_sign` SDK - Local code signing interfaces
- `hilog:libhilog` - C++ logging
- `init:libbegetutil` - Init utilities (For system parameters)
- `ipc:ipc_single` - IPC framework
- `samgr:samgr_proxy` - System capability manager
- `eventhandler:libeventhandler` - Event handling
- `screenlock_mgr` - Screen lock manager

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

**Note:** The profile&enterprise resign cert thread runs in parallel (background). It polls for el1 path since it may be temporarily unavailable right after boot.

### Key States

| State | Description |
|-------|-------------|
| `BeforeUnlock` | Certificate loaded but not active (pre-user unlock) |
| `AfterUnlock` | Certificate activated and usable for AOT(ahead of time) signing |

## Build and Test

For building and testing commands, see the main AGENTS.md @../../AGENTS.md

### Build Artifacts

| Artifact | Type |
|----------|------|
| `key_enable` | Executable |
| `libkey_enable.so` | Shared library |

---

## Error Code Reference

See this part in the main AGENTS.md @../../AGENTS.md. Error code returned to the interface layers are in match with the definition in errcode.h.

### Hisysevent Error Reporting

The component reports errors to hisysevent for debugging and monitoring. All events use domain `CODE_SIGN`. Create new parameter if needed, but use existing event only.

| Event Name | Event Type | Parameter | Description |
|------------|------------|------------|-------------|
| `CS_ADD_KEY` | Fault | String | Reported when adding a key to kernel keyring fails |
| `CS_ERR_PROFILE` | Security | String | Reported when profile parsing or processing fails |

## Common Issues

The `key_enable` process is critical to the boot procedure. Mistakes here can cause device security vulnerabilities or boot failures. Follow these guidelines:

### 1. Error Handling - Do Not Abort on Recoverable Errors

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

**Problem**: Time-consuming tasks before `KeyctlRestrictKeyring()` create a window for attackers to inject malicious keys.

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

- **Important**: `WaitForBootCompletion()` does NOT block on timeout - it logs an error but continues with key addition

### 3. Use C++/FFI for Missing Rust OpenSSL Bindings
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
    // Parse DER certificate using OpenSSL
    const unsigned char *certPtr = certDer;
    X509 *cert = d2i_X509(nullptr, &certPtr, certSize);
    if (cert == nullptr) {
        return CS_ERR_PARAM_INVALID;
    }
    // Convert OID string to NID (create if not exists)
    int nid = OBJ_txt2nid(ENTERPRISE_RESIGN_OID);
    if (nid == NID_undef) {
        nid = OBJ_create(ENTERPRISE_RESIGN_OID, "EnterpriseAppResignCertID",
                         "Enterprise App Resign Cert ID");
    }
    // Find extension by NID
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
// Declare FFI function
extern "C" {
    fn CheckCertHasEnterpriseResignExtension(cert_der: *const u8, cert_size: u32) -> i32;
}

// Use in Rust code
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
- Return standard error codes (CS_SUCCESS, CS_ERR_PARAM_INVALID, etc.) for consistency

### 4. Certificate Verification Before Adding

**Problem**: Adding unverified certificates compromises the entire trust chain.

**Required Verifications** (from `profile_utils.rs:439-462`):
```rust
// 1. Verify signer certificate chain
if verify_signers(&pkcs7, profile_info).is_err() {
    // Reject
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
// ... UDID validation logic
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
                break; // Success
            } else if start_time.elapsed() >= Duration::from_secs(PROFILE_SEARCH_SLEEP_OUT_TIME) {
                error!(LOG_LABEL, "Timeout while waiting for PROFILE_STORE_EL1.");
                break; // Timeout after 600s
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

### 6. ASAN Build Support - Mock FFI Implementation

**Problem**: ASAN (AddressSanitizer) builds do not support Rust, but code_signature interfaces requires Rust to work.

**Solution**: Provide mock FFI implementation that replaces Rust FFI with C++ equivalents when ASAN is enabled.

**Mock Implementation** (from `src/asan/disable_rust_interface.cpp`):

The ASAN build path uses a separate C++ implementation that provides the same FFI functions normally exposed by Rust via `libkey_enable.so`:

**Key Points**:
- All Rust-exported interface must have a mock in `src/asan/disable_rust_interface.cpp`
