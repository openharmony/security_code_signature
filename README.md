# Code Signature

## Introduction

Code signature is a security mechanism on OpenHarmony to protect integrity of the application and verify the validity of the application source on runtime.

The code signature component provides the following features:

- Writing trusted code signing certificates into the kernel
- Enabling code signing for applicaitons
- Signing local code

## Directory Structure

```
/base/security/code_signature
├── interfaces                   # APIs
│   └── innerkits                #
│       ├── code_sign_utils      # APIs for enabling code signing
│       ├── common               # Common basic capacities
│       └── local_code_sign      # APIs for local signing
├── services                     # Service layer
│    ├── key_enable              # Certificate initialization
│    └── local_code_sign         # Local signing service
├── test                         # Test cases
│    ├── fuzztest                # Fuzz test cases
│    └── unittest                # Unit test cases
└── utils                        # Common basic capacities
```

## Usage
### Available APIs

| **API** | **Description** |
| --- | --- |
| int32_t EnforceCodeSignForApp(const EntryMap &entryPath, const std::string &signatureFile); | Enforces code signing for an hap |
| int32_t EnforceCodeSignForFile(const std::string &path, const ByteBuffer &signature); | Enforces code signing for an file |
| int32_t SignLocalCode(const std::string &filePath, ByteBuffer &signature); | Signs the local code |

### Signing Tool User Guide

**[User Guide](https://gitee.com/openharmony/developtools_hapsigner/blob/master/codesigntool/README.md)**

## 相关仓

## Repositories Involved

**[developtools\_hapsigner](https://gitee.com/openharmony/developtools_hapsigner/blob/master/codesigntool/README.md)**

**[third\_party\_fsverity-utils](https://gitee.com/openharmony/third_party_fsverity-utils/blob/master/README.md)**
