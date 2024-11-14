/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <gtest/hwext/gtest-multithread.h>
#include <random>
#include <securec.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "errcode.h"
#include "jit_code_signer_factory.h"
#include "jit_buffer_integrity.h"
#include "code_sign_attr_utils.h"
#include "pac_sign_ctx.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
using namespace std;
using namespace testing::ext;
using namespace testing::mt;

#define CAST_VOID_PTR(buffer) (reinterpret_cast<void *>(buffer))

static Instr g_testInstructionSet[] = {
    0x11111111,
    0x22222222,
    0x33333333, // patched -> 0x66666666
    0x44444444, // patched -> 0x77777777
    0x55555555
};

static Instr g_afterPatchInstructionSet[] = {
    0x11111111,
    0x22222222,
    0x66666666,
    0x77777777,
    0x55555555
};

static Instr g_testPatchInstructionSet[] = {
    0x66666666,
    0x77777777
};

static constexpr uint32_t MULTI_THREAD_NUM = 10;
static constexpr int INSTRUCTIONS_SET_SIZE =
    sizeof(g_testInstructionSet) / sizeof(g_testInstructionSet[0]);
static constexpr int INSTRUCTIONS_SET_SIZE_BYTES = sizeof(g_testInstructionSet);
static constexpr int TEST_PATCH_INDEX = 2;

static constexpr int PATCH_INSTRUCTIONS_SET_SIZE =
    sizeof(g_testPatchInstructionSet) / sizeof(g_testPatchInstructionSet[0]);

static void *g_testInstructionBuf = CAST_VOID_PTR(g_testInstructionSet);
static void *g_afterPatchInstructionBuf = CAST_VOID_PTR(g_afterPatchInstructionSet);
static void *g_testPatchInstructionBuf = CAST_VOID_PTR(g_testPatchInstructionSet);
static void *g_jitMemory = nullptr;

void *g_mapJitBase = CAST_VOID_PTR(0x800000000);
void *g_mapJitBase2 = CAST_VOID_PTR(0x800001000);
constexpr size_t PAGE_SIZE = 4096;
constexpr int BUFFER_SIZE = 4096;

#define JITFORT_PRCTL_OPTION 0x6a6974
#define JITFORT_CREATE_COPGTABLE    5
#define MAP_JIT 0x1000

const JitBufferIntegrityLevel MIN_LEVEL = JitBufferIntegrityLevel::Level0;
const JitBufferIntegrityLevel MAX_LEVEL = JitBufferIntegrityLevel::Level1;

std::mutex g_jitMemory_mutex;

static inline void AllocJitMemory()
{
    g_jitMemory = mmap(g_mapJitBase, PAGE_SIZE + PAGE_SIZE,
        PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
#ifndef JIT_FORT_DISABLE
    int cookie = std::random_device{}();
    g_jitMemory = mmap(g_mapJitBase2, PAGE_SIZE,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_JIT, cookie, 0);
#endif
    EXPECT_NE(g_jitMemory, MAP_FAILED);
}

static inline void JitFortPrepare()
{
#ifndef JIT_FORT_DISABLE
    EXPECT_EQ(InitXpm(1, PROCESS_OWNERID_UNINIT, NULL), CS_SUCCESS);
    PrctlWrapper(JITFORT_PRCTL_OPTION, JITFORT_CREATE_COPGTABLE);
#endif
}

static inline void FreeJitMemory()
{
#ifndef JIT_FORT_DISABLE
    munmap(g_mapJitBase, PAGE_SIZE);
    munmap(g_mapJitBase2, PAGE_SIZE);
#endif
}

class JitCodeSignTest : public testing::Test {
public:
    JitCodeSignTest() {};
    virtual ~JitCodeSignTest() {};

    static void SetUpTestCase()
    {
        EXPECT_EQ(IsSupportJitCodeSigner(), true);
        JitFortPrepare();
        AllocJitMemory();
    };

    static void TearDownTestCase()
    {
        FreeJitMemory();
    };

    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: JitCodeSignTest_0001
 * @tc.desc: sign instructions and verify succuss
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0001, TestSize.Level0)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL; level = static_cast<JitBufferIntegrityLevel>(static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        int i = 0;
        while (i < INSTRUCTIONS_SET_SIZE) {
            AppendInstruction(signer, g_testInstructionSet[i]);
            i++;
        }

        EXPECT_EQ(CopyToJitCode(signer, g_jitMemory, g_testInstructionSet,
            INSTRUCTIONS_SET_SIZE_BYTES), CS_SUCCESS);
        EXPECT_EQ(memcmp(g_jitMemory, g_testInstructionSet, INSTRUCTIONS_SET_SIZE_BYTES), 0);

        delete signer;
        signer = nullptr;
    }
}


/**
 * @tc.name: JitCodeSignTest_0002
 * @tc.desc: sign data and verify succuss
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0002, TestSize.Level0)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL; level = static_cast<JitBufferIntegrityLevel>(static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        AppendData(signer, g_testInstructionBuf, INSTRUCTIONS_SET_SIZE_BYTES);

        EXPECT_EQ(CopyToJitCode(signer, g_jitMemory, g_testInstructionBuf,
            INSTRUCTIONS_SET_SIZE_BYTES), CS_SUCCESS);
        EXPECT_EQ(memcmp(g_jitMemory, g_testInstructionBuf, INSTRUCTIONS_SET_SIZE_BYTES), 0);

        delete signer;
        signer = nullptr;
    }
}

/**
 * @tc.name: JitCodeSignTest_0003
 * @tc.desc: sign and patch instructions succuss
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0003, TestSize.Level0)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL;
        level = static_cast<JitBufferIntegrityLevel>(static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        int i = 0, offset = 0;
        while (i < TEST_PATCH_INDEX) {
            AppendInstruction(signer, g_testInstructionSet[i]);
            i++;
        }
        for (int j = 0; j < PATCH_INSTRUCTIONS_SET_SIZE; j++) {
            WillFixUp(signer, 1);
            AppendInstruction(signer, g_testInstructionSet[i]);
            i++;
        }
        while (i < INSTRUCTIONS_SET_SIZE) {
            AppendInstruction(signer, g_testInstructionSet[i]);
            i++;
        }
        offset = TEST_PATCH_INDEX * INSTRUCTION_SIZE;
        for (int j = 0; j < PATCH_INSTRUCTIONS_SET_SIZE; j++) {
            PatchInstruction(signer, offset, g_testPatchInstructionSet[j]);
            offset += INSTRUCTION_SIZE;
        }

        EXPECT_EQ(CopyToJitCode(signer, g_jitMemory, g_afterPatchInstructionBuf,
            INSTRUCTIONS_SET_SIZE_BYTES), CS_SUCCESS);
        EXPECT_EQ(memcmp(g_jitMemory, g_afterPatchInstructionBuf, INSTRUCTIONS_SET_SIZE_BYTES), 0);

        delete signer;
        signer = nullptr;
    }
}

/**
 * @tc.name: JitCodeSignTest_0004
 * @tc.desc: sign and patch data succuss
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0004, TestSize.Level0)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL;
        level = static_cast<JitBufferIntegrityLevel>(static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        int i = 0, offset = 0;
        while (i < TEST_PATCH_INDEX) {
            AppendInstruction(signer, g_testInstructionSet[i]);
            offset += INSTRUCTION_SIZE;
            i++;
        }

        int patchSize = sizeof(g_testPatchInstructionSet);
        WillFixUp(signer, PATCH_INSTRUCTIONS_SET_SIZE);
        AppendData(signer, CAST_VOID_PTR(&g_testInstructionSet[i]), patchSize);
        i += PATCH_INSTRUCTIONS_SET_SIZE;
        offset += patchSize;

        while (i < INSTRUCTIONS_SET_SIZE) {
            AppendInstruction(signer, g_testInstructionSet[i]);
            i++;
        }

        offset = TEST_PATCH_INDEX * INSTRUCTION_SIZE;
        PatchData(signer, offset, g_testPatchInstructionBuf, INSTRUCTION_SIZE);
        
        RegisterTmpBuffer(signer, g_afterPatchInstructionBuf);
        PatchData(signer, CAST_VOID_PTR(reinterpret_cast<uintptr_t>(
            g_afterPatchInstructionBuf) + offset + INSTRUCTION_SIZE),
            CAST_VOID_PTR(&g_testPatchInstructionSet[1]),
            INSTRUCTION_SIZE);

        EXPECT_EQ(CopyToJitCode(signer, g_jitMemory, g_afterPatchInstructionBuf,
            INSTRUCTIONS_SET_SIZE_BYTES), CS_SUCCESS);
        EXPECT_EQ(memcmp(g_jitMemory, g_afterPatchInstructionBuf, INSTRUCTIONS_SET_SIZE_BYTES), 0);

        delete signer;
        signer = nullptr;
    }
}

/**
 * @tc.name: JitCodeSignTest_0005
 * @tc.desc: sign and copy wrong data failed
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0005, TestSize.Level0)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL;
        level = static_cast<JitBufferIntegrityLevel>(static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        AppendData(signer, g_testInstructionBuf, INSTRUCTIONS_SET_SIZE_BYTES);
        int sizeInByte = sizeof(g_testInstructionSet);
        EXPECT_EQ(CopyToJitCode(signer, g_jitMemory, g_afterPatchInstructionBuf,
            sizeInByte), CS_ERR_VALIDATE_CODE);

        delete signer;
        signer = nullptr;
    }
}

/**
 * @tc.name: JitCodeSignTest_0006
 * @tc.desc: sign and copy with wrong size failed
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0006, TestSize.Level0)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL;
        level = static_cast<JitBufferIntegrityLevel>(static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        RegisterTmpBuffer(signer, g_testInstructionBuf);
        AppendData(signer, g_testInstructionBuf, INSTRUCTIONS_SET_SIZE_BYTES);

        EXPECT_EQ(CopyToJitCode(signer, g_jitMemory, g_testInstructionBuf,
            INSTRUCTIONS_SET_SIZE_BYTES - 1), CS_ERR_JIT_SIGN_SIZE);

        delete signer;
        signer = nullptr;
    }
}

/**
 * @tc.name: JitCodeSignTest_0007
 * @tc.desc: sign and copy with buffer failed
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0007, TestSize.Level0)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL;
        level = static_cast<JitBufferIntegrityLevel>(static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        RegisterTmpBuffer(signer, g_testInstructionBuf);
        AppendData(signer, g_testInstructionBuf, INSTRUCTIONS_SET_SIZE_BYTES - 1);

        EXPECT_EQ(CopyToJitCode(signer, g_jitMemory, g_afterPatchInstructionBuf,
            INSTRUCTIONS_SET_SIZE_BYTES), CS_ERR_JIT_SIGN_SIZE);

        delete signer;
        signer = nullptr;
    }
}

/**
 * @tc.name: JitCodeSignTest_0008
 * @tc.desc: sign data without 4 byte-alignment and copy success
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0008, TestSize.Level0)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL;
        level = static_cast<JitBufferIntegrityLevel>(static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        Byte *ptr = reinterpret_cast<Byte *>(g_testInstructionBuf) + 1;
        AppendData(signer, g_testInstructionBuf, 1);
        AppendData(signer, CAST_VOID_PTR(ptr), INSTRUCTIONS_SET_SIZE_BYTES - 1);

        EXPECT_EQ(CopyToJitCode(signer, g_jitMemory, g_testInstructionBuf,
            INSTRUCTIONS_SET_SIZE_BYTES), CS_SUCCESS);

        delete signer;
        signer = nullptr;
    }
}

/**
 * @tc.name: JitCodeSignTest_0009
 * @tc.desc: sign data and patch without 4 byte-alignment failed
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0009, TestSize.Level0)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL;
        level = static_cast<JitBufferIntegrityLevel>(static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        int i = 0, offset = 0;
        while (i < TEST_PATCH_INDEX) {
            AppendInstruction(signer, g_testInstructionSet[i]);
            offset += INSTRUCTION_SIZE;
            i++;
        }

        int patchSize = sizeof(g_testPatchInstructionSet);
        WillFixUp(signer, PATCH_INSTRUCTIONS_SET_SIZE);
        AppendData(signer, CAST_VOID_PTR(&g_testInstructionSet[i]), patchSize);
        i += PATCH_INSTRUCTIONS_SET_SIZE;
        offset += patchSize;

        while (i < INSTRUCTIONS_SET_SIZE) {
            AppendInstruction(signer, g_testInstructionSet[i]);
            i++;
        }

        offset = TEST_PATCH_INDEX * INSTRUCTION_SIZE;
        EXPECT_EQ(PatchData(signer, offset, g_testPatchInstructionBuf,
            patchSize - 1), CS_ERR_JIT_SIGN_SIZE);

        delete signer;
        signer = nullptr;
    }
}

/**
 * @tc.name: JitCodeSignTest_0010
 * @tc.desc: patch with buffer address successfully
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0010, TestSize.Level0)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL;
        level = static_cast<JitBufferIntegrityLevel>(static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        int i = 0, offset = 0;
        while (i < TEST_PATCH_INDEX) {
            AppendInstruction(signer, g_testInstructionSet[i]);
            i++;
        }
        for (int j = 0; j < PATCH_INSTRUCTIONS_SET_SIZE; j++) {
            WillFixUp(signer, 1);
            AppendInstruction(signer, g_testInstructionSet[i]);
            i++;
        }
        while (i < INSTRUCTIONS_SET_SIZE) {
            AppendInstruction(signer, g_testInstructionSet[i]);
            i++;
        }
        offset = TEST_PATCH_INDEX * INSTRUCTION_SIZE;
        RegisterTmpBuffer(signer, g_afterPatchInstructionBuf);
        for (int j = 0; j < PATCH_INSTRUCTIONS_SET_SIZE; j++) {
            PatchInstruction(signer, CAST_VOID_PTR(
                &g_afterPatchInstructionSet[TEST_PATCH_INDEX + j]), g_testPatchInstructionSet[j]);
            offset += INSTRUCTION_SIZE;
        }

        EXPECT_EQ(CopyToJitCode(signer, g_jitMemory, g_afterPatchInstructionBuf,
            INSTRUCTIONS_SET_SIZE_BYTES), CS_SUCCESS);
        EXPECT_EQ(memcmp(g_jitMemory, g_afterPatchInstructionBuf, INSTRUCTIONS_SET_SIZE_BYTES), 0);

        delete signer;
        signer = nullptr;
    }
}

/**
 * @tc.name: JitCodeSignTest_0011
 * @tc.desc: patch faied with invalid buffer
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0011, TestSize.Level0)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL;
        level = static_cast<JitBufferIntegrityLevel>(static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);

        RegisterTmpBuffer(signer, g_afterPatchInstructionBuf);
        EXPECT_EQ(PatchInstruction(signer, nullptr, INSTRUCTION_SIZE), CS_ERR_PATCH_INVALID);
        
        RegisterTmpBuffer(signer, nullptr);
        EXPECT_EQ(PatchInstruction(signer, reinterpret_cast<Byte *>(g_afterPatchInstructionBuf),
            INSTRUCTION_SIZE), CS_ERR_PATCH_INVALID);

        delete signer;
        signer = nullptr;
    }
}

/**
 * @tc.name: JitCodeSignTest_00012
 * @tc.desc: reset jit memory success
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_00012, TestSize.Level0)
{
    Byte tmpBuffer[INSTRUCTIONS_SET_SIZE_BYTES] = {0};
    ResetJitCode(g_jitMemory, INSTRUCTIONS_SET_SIZE_BYTES);
    EXPECT_EQ(memcmp(g_jitMemory, tmpBuffer, INSTRUCTIONS_SET_SIZE_BYTES), 0);
}

/**
 * @tc.name: JitCodeSignTest_00013
 * @tc.desc: copy failed with wrong size
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_00013, TestSize.Level0)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL;
        level = static_cast<JitBufferIntegrityLevel>(static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        AppendData(signer, g_testInstructionBuf, INSTRUCTIONS_SET_SIZE_BYTES);
        EXPECT_EQ(CopyToJitCode(signer, g_jitMemory, g_testInstructionBuf,
            INSTRUCTIONS_SET_SIZE_BYTES - 1), CS_ERR_JIT_SIGN_SIZE);

        signer->Reset();
        EXPECT_EQ(CopyToJitCode(signer, g_jitMemory, g_testInstructionBuf,
            INSTRUCTIONS_SET_SIZE_BYTES), CS_ERR_JIT_SIGN_SIZE);

        delete signer;
        signer = nullptr;
    }
}

/**
 * @tc.name: JitCodeSignTest_00014
 * @tc.desc: copy data with different size
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_00014, TestSize.Level0)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL;
        level = static_cast<JitBufferIntegrityLevel>(static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        Byte *data = reinterpret_cast<Byte *>(g_testInstructionSet);
        uint32_t dataSize[] = {1, 2, 1, 4, 2, 8, 2, 1, 3};
        int pos = 0;
        for (auto size : dataSize) {
            AppendData(signer, CAST_VOID_PTR(data + pos), size);
            pos += size;
        }

        EXPECT_EQ(CopyToJitCode(signer, g_jitMemory, g_testInstructionBuf,
            INSTRUCTIONS_SET_SIZE_BYTES), CS_SUCCESS);
        EXPECT_EQ(memcmp(g_jitMemory, g_testInstructionBuf, INSTRUCTIONS_SET_SIZE_BYTES), 0);

        delete signer;
        signer = nullptr;
    }
}

/**
 * @tc.name: JitCodeSignTest_00015
 * @tc.desc: validate and copy code to same buffer in parallel
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWMTEST_F(JitCodeSignTest, JitCodeSignTest_00015, TestSize.Level1, MULTI_THREAD_NUM)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL;
        level = static_cast<JitBufferIntegrityLevel>(static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        int i = 0;
        while (i < INSTRUCTIONS_SET_SIZE) {
            AppendInstruction(signer, g_testInstructionSet[i]);
            i++;
        }
        size_t size = INSTRUCTIONS_SET_SIZE_BYTES;
        {
            std::lock_guard<std::mutex> lock(g_jitMemory_mutex);
#ifndef JIT_FORT_DISABLE
            PrctlWrapper(JITFORT_PRCTL_OPTION, JITFORT_SWITCH_IN, 0);
#endif
            EXPECT_EQ(signer->ValidateCodeCopy(reinterpret_cast<Instr *>(g_jitMemory),
                reinterpret_cast<Byte *>(g_testInstructionSet), size), CS_SUCCESS);
#ifndef JIT_FORT_DISABLE
            PrctlWrapper(JITFORT_PRCTL_OPTION, JITFORT_SWITCH_OUT, 0);
#endif
            EXPECT_EQ(memcmp(g_jitMemory, g_testInstructionSet, size), 0);
        }

        delete signer;
        signer = nullptr;
    }
}

/**
 * @tc.name: JitCodeSignTest_0016
 * @tc.desc: validate and copy code to different buffer in parallel
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_00016, TestSize.Level0)
{
    void *tmpMemory = nullptr;
#ifndef JIT_FORT_DISABLE
    int cookie = std::random_device{}();
    tmpMemory = mmap(nullptr, PAGE_SIZE,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_JIT, cookie, 0);
#else
    tmpMemory = mmap(nullptr, PAGE_SIZE,
        PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
#endif
    EXPECT_NE(tmpMemory, MAP_FAILED);
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL;
        level = static_cast<JitBufferIntegrityLevel>(static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        int i = 0;
        while (i < INSTRUCTIONS_SET_SIZE) {
            AppendInstruction(signer, g_testInstructionSet[i]);
            i++;
        }
        size_t size = INSTRUCTIONS_SET_SIZE_BYTES;
        {
#ifndef JIT_FORT_DISABLE
            PrctlWrapper(JITFORT_PRCTL_OPTION, JITFORT_SWITCH_IN, 0);
#endif
            EXPECT_EQ(signer->ValidateCodeCopy(reinterpret_cast<Instr *>(tmpMemory),
                reinterpret_cast<Byte *>(g_testInstructionSet), size), CS_SUCCESS);
#ifndef JIT_FORT_DISABLE
            PrctlWrapper(JITFORT_PRCTL_OPTION, JITFORT_SWITCH_OUT, 0);
#endif
            EXPECT_EQ(memcmp(tmpMemory, g_testInstructionSet, size), 0);
        }

        delete signer;
        signer = nullptr;
    }
    munmap(tmpMemory, PAGE_SIZE);
}

/**
 * @tc.name: JitCodeSignTest_0017
 * @tc.desc: validate and copy code to same buffer in parallel
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWMTEST_F(JitCodeSignTest, JitCodeSignTest_0017, TestSize.Level1, MULTI_THREAD_NUM)
{
    int instructionNum = BUFFER_SIZE / sizeof(uint32_t);
    uint32_t *tmpBuffer = reinterpret_cast<uint32_t *>(malloc(BUFFER_SIZE));
    for (int i = 0; i < instructionNum; i++) {
        tmpBuffer[i] = i;
    }

    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL;
        level = static_cast<JitBufferIntegrityLevel>(static_cast<int>(level) + 1)) {
        JitCodeSignerBase *signer = CreateJitCodeSigner(level);
        int i = 0;
        while (i < instructionNum) {
            AppendInstruction(signer, tmpBuffer[i]);
            i++;
        }
        int cookie = std::random_device{}();
        void *tmpJitMemory = mmap(nullptr, PAGE_SIZE,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_ANONYMOUS | MAP_PRIVATE | MAP_JIT, cookie, 0);
        
        EXPECT_EQ(CopyToJitCode(signer, tmpJitMemory, tmpBuffer, BUFFER_SIZE), CS_SUCCESS);
        EXPECT_EQ(memcmp(tmpJitMemory, tmpBuffer, BUFFER_SIZE), 0);

        delete signer;
        signer = nullptr;
    }
    free(tmpBuffer);
    tmpBuffer = nullptr;
}

/**
 * @tc.name: JitCodeSignTest_0018
 * @tc.desc: no signer
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0018, TestSize.Level0)
{
    EXPECT_EQ(RegisterTmpBuffer(nullptr, nullptr), CS_ERR_NO_SIGNER);
    EXPECT_EQ(AppendInstruction(nullptr, 0), CS_ERR_NO_SIGNER);
    EXPECT_EQ(AppendData(nullptr, nullptr, 0), CS_ERR_NO_SIGNER);
    EXPECT_EQ(WillFixUp(nullptr, 1), CS_ERR_NO_SIGNER);
    EXPECT_EQ(PatchInstruction(nullptr, 0, 0), CS_ERR_NO_SIGNER);
    EXPECT_EQ(PatchInstruction(nullptr, nullptr, 1), CS_ERR_NO_SIGNER);
    EXPECT_EQ(PatchData(nullptr, 0, nullptr, 0), CS_ERR_NO_SIGNER);
    EXPECT_EQ(PatchData(nullptr, nullptr, nullptr, 0), CS_ERR_NO_SIGNER);
    EXPECT_EQ(CopyToJitCode(nullptr, nullptr, nullptr, 0), CS_ERR_JIT_MEMORY);
}

/**
 * @tc.name: JitCodeSignTest_0019
 * @tc.desc: create failed
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0019, TestSize.Level0)
{
    EXPECT_EQ(CreateJitCodeSigner(
        static_cast<JitBufferIntegrityLevel>(static_cast<int>(MAX_LEVEL) + 1)),
        nullptr);
}

/**
 * @tc.name: JitCodeSignTest_0020
 * @tc.desc: patch instruction failed for wrong offset or address
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0020, TestSize.Level0)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL; level = static_cast<JitBufferIntegrityLevel>(static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        AppendData(signer, g_testInstructionBuf, INSTRUCTIONS_SET_SIZE_BYTES);

        // offset is greater than signed size
        EXPECT_EQ(PatchInstruction(signer, INSTRUCTIONS_SET_SIZE_BYTES + 4, 1), CS_ERR_PATCH_INVALID);
        // offset < 0
        EXPECT_EQ(PatchInstruction(signer, -INSTRUCTION_SIZE, 1), CS_ERR_PATCH_INVALID);
        
        // offset is greater than signed size
        EXPECT_EQ(PatchInstruction(signer, CAST_VOID_PTR(reinterpret_cast<uintptr_t>(
            g_testInstructionBuf) + INSTRUCTIONS_SET_SIZE_BYTES), 1), CS_ERR_PATCH_INVALID);
        // offset < 0
        EXPECT_EQ(PatchInstruction(signer, CAST_VOID_PTR(reinterpret_cast<uintptr_t>(
            g_testInstructionBuf) - INSTRUCTION_SIZE), 1), CS_ERR_PATCH_INVALID);

        delete signer;
        signer = nullptr;
    }
}

/**
 * @tc.name: JitCodeSignTest_0021
 * @tc.desc: append or patch data with nullptr failed
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0021, TestSize.Level0)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL; level = static_cast<JitBufferIntegrityLevel>(
        static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        AppendData(signer, nullptr, INSTRUCTIONS_SET_SIZE_BYTES);

        AppendData(signer, g_testInstructionBuf, INSTRUCTIONS_SET_SIZE_BYTES);
        EXPECT_EQ(PatchInstruction(signer, nullptr, 0), CS_ERR_PATCH_INVALID);
        EXPECT_EQ(PatchData(signer, 0, nullptr, 0), CS_ERR_INVALID_DATA);

        RegisterTmpBuffer(signer, g_testInstructionBuf);
        EXPECT_EQ(PatchData(signer, reinterpret_cast<Byte *>(g_testInstructionBuf),
            nullptr, 0), CS_ERR_INVALID_DATA);

        delete signer;
        signer = nullptr;
    }
}

/**
 * @tc.name: JitCodeSignTest_0022
 * @tc.desc: jit memory == nullptr
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0022, TestSize.Level0)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL; level = static_cast<JitBufferIntegrityLevel>(
        static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        EXPECT_EQ(ResetJitCode(nullptr, 0), CS_ERR_JIT_MEMORY);
        EXPECT_EQ(CopyToJitCode(signer, nullptr, g_testInstructionBuf, 0), CS_ERR_JIT_MEMORY);

        delete signer;
        signer = nullptr;
    }
}

/**
 * @tc.name: JitCodeSignTest_0023
 * @tc.desc: sign instructions and verify succuss
 * @tc.type: Func
 * @tc.require: I9O6PK
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0023, TestSize.Level0)
{
    JitCodeSignerBase *signer = nullptr;
    for (JitBufferIntegrityLevel level = MIN_LEVEL;
        level <= MAX_LEVEL; level = static_cast<JitBufferIntegrityLevel>(
        static_cast<int>(level) + 1)) {
        signer = CreateJitCodeSigner(level);
        for (int i = 0; i < INSTRUCTIONS_SET_SIZE_BYTES; i++) {
            uint32_t tmpBuffer[INSTRUCTIONS_SET_SIZE];
            (void) memcpy_s(tmpBuffer, INSTRUCTIONS_SET_SIZE_BYTES, g_testInstructionBuf, INSTRUCTIONS_SET_SIZE_BYTES);

            for (int j = 0; j < INSTRUCTIONS_SET_SIZE; j++) {
                AppendInstruction(signer, tmpBuffer[j]);
            }
            *(reinterpret_cast<Byte *>(tmpBuffer) + i) = 0;

            EXPECT_EQ(CopyToJitCode(signer, g_jitMemory, tmpBuffer,
                INSTRUCTIONS_SET_SIZE_BYTES), CS_ERR_VALIDATE_CODE);
        }

        delete signer;
        signer = nullptr;
    }
}

/**
 * @tc.name: JitCodeSignTest_0024
 * @tc.desc: pac sign with auth
 * @tc.type: Func
 * @tc.require: IAKH9D
 */
HWTEST_F(JitCodeSignTest, JitCodeSignTest_0024, TestSize.Level0)
{
    PACSignCtx signCtx(CTXPurpose::SIGN);
    signCtx.InitSalt();
    signCtx.Init(0);
    uint32_t signature[INSTRUCTIONS_SET_SIZE];
    int i;
    for (i = 0; i < INSTRUCTIONS_SET_SIZE; i++) {
        signature[i] = signCtx.Update(g_testInstructionSet[i]);
    }
    PACSignCtx verifyCtx(CTXPurpose::VERIFY, signCtx.GetSalt());
    verifyCtx.Init(0);
    for (i = 0; i < INSTRUCTIONS_SET_SIZE; i++) {
        EXPECT_EQ(signature[i], verifyCtx.Update(g_testInstructionSet[i]));
    }
}
}
}
}
