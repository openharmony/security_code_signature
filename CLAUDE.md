# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **Code Signature** component of OpenHarmony (`base/security/code_signature`), part of the security subsystem. It provides runtime code signing verification and integrity protection for applications, preventing execution of malicious code and tampering.

## Build System

Uses the **GN build system** (Generate Ninja). Build configuration files:
- `BUILD.gn` - Main build definition
- `code_signature.gni` - Build arguments and feature flags
- `bundle.json` - Component metadata and dependencies

### Build Commands

```bash
# Build the component
./build.sh --product-name <product> --build-target code_signature

# Build with specific feature flags (set via args.gn or command line)
# Available feature flags (see code_signature.gni):
#   code_signature_support_oh_code_sign      - OH code signing support
#   code_signature_enable_xpm_mode           - XPM mode (0=disabled, 1=enabled)
#   code_signature_support_oh_release_app    - Release app support
#   code_signature_support_app_allow_list    - App allowlist support
#   code_signature_support_binary_enable     - Binary enable support
#   jit_code_sign_enable                    - JIT code signing (auto-enabled on arm64)
```

## Testing

Tests are defined in `test/` directory:

```bash
# Run all tests
./build.sh --product-name <product> --build-target make_test_code_signature

# Run specific unit test (output in /data/test/code_signature/code_signature/)
# Unit test binaries:
#   - add_cert_path_unittest
#   - cert_chain_verifier_unittest
#   - code_sign_attr_utils_unittest
#   - code_sign_utils_unittest
#   - code_sign_utils_in_c_unittest
#   - local_code_sign_unittest
#   - local_code_sign_utils_unittest
#   - local_code_sign_utils_mock_unittest
#   - multi_thread_local_sign_unittest
#   - sign_and_enforce_unittest
#   - enable_verity_ioctl_unittest
#   - jit_code_sign_unittest
#   - rust_key_enable_unittest (Rust)
#   - key_enable_utils_unittest

# Fuzz tests (requires HKP tool)
# Fuzzers in test/fuzztest/local_code_sign_stub/
```

## Architecture

Layered architecture:

### 1. Interface Layer (`interfaces/inner_api/`)
- `code_sign_utils/` - Core code signing APIs (`EnforceCodeSignForApp`, `EnforceCodeSignForFile`)
- `code_sign_attr_utils/` - Attribute setting APIs (`InitXpm`, `SetXpmOwnerId`)
- `local_code_sign/` - Local signing APIs (`InitLocalCertificate`, `SignLocalCode`)
- `jit_code_sign/` - JIT code signing (ARMv8.3-A+ only)
- `common/` - Shared types and utilities

### 2. Service Layer (`services/`)
- `key_enable/` - Certificate initialization and trust management (Rust + C++)
- `local_code_sign/` - On-device signing service with IPC communication

### 3. Utility Layer (`utils/`)
- Certificate utilities, ELF handling, fs-verity integration
- HISYSEVENT and HITRACE integration for logging/tracing

## Key Technologies

- **fs-verity**: File integrity verification (kernel fs-verity keyring)
- **XPM** (eXecutable Page Monitor): Memory protection for code integrity
- **SELinux**: Security policies and context management
- **HUKS**: Universal key storage
- **JIT code signing**: ARMv8.3-A Pointer Authentication (PAC) based protection

## Dependencies

Key internal dependencies (from bundle.json):
- `hilog`, `hitrace`, `hisysevent` - Logging and tracing
- `ipc`, `samgr`, `safwk` - System service framework
- `huks` - Universal key storage
- `openssl`, `fsverity-utils` - Crypto and file integrity
- `access_token`, `bundle_framework` - App framework integration
- `rust_rust-openssl`, `rust_cxx` - Rust FFI support

## Important Notes

- The component is primarily C++ with some Rust code in `services/key_enable/`
- Certificate management integrates with kernel's `.fs-verity` keyring
- Owner ID is used for multi-tenant code attribution
- XPM mode provides hardware-assisted memory protection
- JIT code signing is only available on ARMv8.3-A+ and requires `code_signature_support_oh_code_sign=true`