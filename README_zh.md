# 代码签名

## 简介

代码签名部件用于支持OpenHarmony的代码签名机制。OpenHarmony使用代码签名提供运行时应用程序的完整性保护，校验应用来源的合法性。
代码签名部件主要提供如下功能：

- 提供可信代码签名证书写入内核能力
- 提供代码签名使能能力
- 提供本地代码签名能力

## 目录

```
/base/security/code_signature
├── interfaces                   # 接口层
│   └── innerkits                #
│       ├── code_sign_utils      # 使能接口
│       ├── common               # 公共基础能力
│       └── local_code_sign      # 本地签名接口
├── services                     # 服务层
│    ├── key_enable              # 证书初始化
│    └── local_code_sign         # 本地签名服务
├── test                         # 测试用例
│    ├── fuzztest                # fuzz测试用例
│    └── unittest                # 单元测试用例
└── utils                        # 公共基础能力
```

## 使用
### 接口说明

| **接口声明** | **接口描述** |
| --- | --- |
| int32_t EnforceCodeSignForApp(const EntryMap &entryPath, const std::string &signatureFile); | 对hap使能代码签名 |
| int32_t EnforceCodeSignForFile(const std::string &path, const ByteBuffer &signature); | 对文件使能代码签名 |
| int32_t SignLocalCode(const std::string &filePath, ByteBuffer &signature); | 本地代码签名 |

### 签名工具使用指南

**[使用指南](https://gitee.com/openharmony/developtools_hapsigner/blob/master/codesigntool/README_zh.md)**

## 相关仓

**[developtools\_hapsigner](https://gitee.com/openharmony/developtools_hapsigner/blob/master/codesigntool/README_zh.md)**

**[third\_party\_fsverity-utils](https://gitee.com/openharmony/third_party_fsverity-utils/blob/master/README_zh.md)**
