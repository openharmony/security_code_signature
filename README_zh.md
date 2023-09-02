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

### 构建指导

#### 构建环境

- 拉取主干最新代码。

- 构建环境: [RK3568默认环境](https://gitee.com/openharmony/docs/blob/master/zh-cn/device-dev/quick-start/Readme-CN.md)

#### 修改代码

1.拉取代码签名部件

```
cd base/security

git clone https://gitee.com/openharmony-sig/security_code_signature.git

mv security_code_signature code_signature
```

2.修改代码签名部件依赖的相关仓

代码签名仓下的 [patches.json](patches/patches.json) 中详细描述了代码签名部件依赖的仓以及patch，根据文件中描述依次在对应仓打上对应的patch即可。

#### 编译

```
./build.sh --product-name rk3568 --ccache
```

### 签名工具使用指南

**[使用指南](https://gitee.com/openharmony/developtools_hapsigner/blob/master/codesigntool/README_zh.md)**

## 相关仓

**[developtools\_hapsigner](https://gitee.com/openharmony/developtools_hapsigner/blob/master/codesigntool/README_zh.md)**

**[third\_party\_fsverity-utils](https://gitee.com/openharmony/third_party_fsverity-utils/blob/master/README_zh.md)**
