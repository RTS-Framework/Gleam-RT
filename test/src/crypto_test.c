#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "random.h"
#include "crypto.h"
#include "test.h"

static bool TestEncryptBuffer();
static bool TestDecryptBuffer();
static bool TestObfuscateBuffer();
static bool TestIlluminateBuffer();
static bool TestFillInstruction();
static bool TestXORBuffer();
static bool TestSubstituteBuffer();
static bool TestShuffleBuffer();
static bool TestEraseBuffer();
static bool TestEraseInstruction();

static void printHexBytes(byte* buf, uint size);

bool TestCrypto()
{
    test_t tests[] = 
    {
        { TestEncryptBuffer    },
        { TestDecryptBuffer    },
        { TestObfuscateBuffer  },
        { TestIlluminateBuffer },
        { TestFillInstruction  },
        { TestXORBuffer        },
        { TestSubstituteBuffer },
        { TestShuffleBuffer    },
        { TestEraseBuffer      },
        { TestEraseInstruction },
    };
    for (int i = 0; i < arrlen(tests); i++)
    {
        if (!tests[i]())
        {
            return false;
        }
    }
    return true;
}

static bool TestEncryptBuffer()
{
    printf_s("=======TestEncryptBuffer begin========\n");

    // generate key and iv
    byte key[CRYPTO_KEY_SIZE];
    byte iv1[CRYPTO_IV_SIZE];
    byte iv2[CRYPTO_IV_SIZE];
    RandBuffer(key, sizeof(key));
    RandBuffer(iv1, sizeof(iv1));
    RandBuffer(iv2, sizeof(iv2));

    // write repetitive and orderly data
    byte testdata[128];
    mem_init(testdata, sizeof(testdata));
    for (byte i = 0; i < 16; i++)
    {
        testdata[i+0]  = i;
        testdata[i+16] = i;
    }

    // copy test data
    byte data1[128];
    byte data2[128];
    mem_init(data1, sizeof(data1));
    mem_init(data2, sizeof(data2));
    mem_copy(data1, testdata, sizeof(data1));
    mem_copy(data2, testdata, sizeof(data2));
    data2[0]++;

    printf_s("plain data:\n");
    printHexBytes(data1, sizeof(data1));
    printHexBytes(data2, sizeof(data2));

    printf_s("cipher data with the different iv:\n");
    EncryptBuffer(data1, sizeof(data1), key, iv1);
    EncryptBuffer(data2, sizeof(data2), key, iv2);
    printHexBytes(data1, sizeof(data1));
    printHexBytes(data2, sizeof(data2));

    printf_s("cipher data with the same iv:\n");
    mem_init(data1, sizeof(data1));
    mem_init(data2, sizeof(data2));
    mem_copy(data1, testdata, sizeof(data1));
    mem_copy(data2, testdata, sizeof(data2));
    data2[0]++;

    EncryptBuffer(data1, sizeof(data1), key, iv1);
    EncryptBuffer(data2, sizeof(data2), key, iv1);
    printHexBytes(data1, sizeof(data1));
    printHexBytes(data2, sizeof(data2));

    printf_s("=======TestEncryptBuffer passed=======\n\n");
    return true;
}

static bool TestDecryptBuffer()
{
    printf_s("=======TestDecryptBuffer begin========\n");

    byte key[CRYPTO_KEY_SIZE];
    RandBuffer(key, sizeof(key));

    byte data1[64+4];
    byte data2[64+4];
    RandBuffer(data1, sizeof(data1));
    mem_copy(data2, data1, sizeof(data1));

    byte iv[CRYPTO_IV_SIZE];
    RandBuffer(iv, sizeof(iv));

    printf_s("plain data:\n");
    printHexBytes(data2, sizeof(data2));

    EncryptBuffer(data2, sizeof(data2), key, iv);

    printf_s("cipher data:\n");
    printHexBytes(data2, sizeof(data2));

    DecryptBuffer(data2, sizeof(data2), key, iv);

    // compare the decrypted data
    if (!mem_equal(data1, data2, sizeof(data1)))
    {
        printf_s("[error] plain data is incorrect\n");
        return false;
    }

    printf_s("=======TestDecryptBuffer passed=======\n\n");
    return true;
}

static bool TestObfuscateBuffer()
{
    printf_s("=======TestObfuscateBuffer begin========\n");

    byte data[256];
    mem_init(data, sizeof(data));
    for (int i = 0; i < 128; i++)
    {
        data[i] = (byte)i;
    }
    for (int i = 128; i < 256; i++)
    {
        data[i] = 0;
    }
    printHexBytes(data, sizeof(data));

    uint64 key = RandUint64(0);
    ObfuscateBuffer(data, sizeof(data), key);
    printHexBytes(data, sizeof(data));

    printf_s("=======TestObfuscateBuffer passed=======\n\n");
    return true;
}

static bool TestIlluminateBuffer()
{
    printf_s("=======TestIlluminateBuffer begin========\n");

    byte data[256];
    mem_init(data, sizeof(data));
    for (int i = 0; i < 128; i++)
    {
        data[i] = (byte)i;
    }
    for (int i = 128; i < 256; i++)
    {
        data[i] = 0;
    }

    byte buf[256];
    mem_copy(buf, data, sizeof(data));

    uint64 key = RandUint64(0);
    ObfuscateBuffer(buf, sizeof(buf), key);
    IlluminateBuffer(buf, sizeof(buf), key);
    if (!mem_equal(buf, data, sizeof(data)))
    {
        printf_s("[error] recover incorrect data\n");
        return false;
    }

    printf_s("=======TestIlluminateBuffer passed=======\n\n");
    return true;
}

static bool TestFillInstruction()
{
    printf_s("======TestFillInstruction begin=======\n");

    byte inst[256];
    mem_init(inst, sizeof(inst));

    uint64 seed = 123;
    FillInstruction(inst, sizeof(inst), seed);
    printHexBytes(inst, sizeof(inst));

    byte copy[256];
    mem_copy(copy, inst, sizeof(inst));
    FillInstruction(inst, sizeof(inst), seed);
    if (!mem_equal(copy, inst, sizeof(inst)))
    {
        printf_s("[error] different instruction\n");
        return false;
    }

    printf_s("======TestFillInstruction passed======\n\n");
    return true;
}

static bool TestXORBuffer()
{
    printf_s("=========TestXORBuffer begin==========\n");

    // generate random data and key
    byte data[64];
    byte key[4];
    RandBuffer(data, sizeof(data));
    RandBuffer(key, sizeof(key));
    printf_s("plain data:\n");
    printHexBytes(data, sizeof(data));

    // encrypt and decrypt
    byte cipher[sizeof(data)];
    mem_copy(cipher, data, sizeof(data));
    XORBuffer(cipher, sizeof(data), key, sizeof(key));
    XORBuffer(cipher, sizeof(data), key, sizeof(key));

    if (!mem_equal(data, cipher, sizeof(data)))
    {
        printf_s("[error] plain data is incorrect\n");
        return false;
    }

    printf_s("=========TestXORBuffer passed=========\n\n");
    return true;
}

static bool TestSubstituteBuffer()
{
    printf_s("=======TestSubstituteBuffer begin=======\n");

    byte data[256];
    mem_init(data, sizeof(data));
    for (int i = 0; i < 256; i++)
    {
        data[i] = (byte)i;
    }

    SubstituteBuffer(data, sizeof(data));
    printHexBytes(data, sizeof(data));

    printf_s("=======TestSubstituteBuffer passed======\n\n");
    return true;
}

static bool TestShuffleBuffer()
{
    printf_s("=======TestShuffleBuffer begin=======\n");

    byte data[256];
    mem_init(data, sizeof(data));
    for (int i = 0; i < 256; i++)
    {
        data[i] = (byte)i;
    }

    ShuffleBuffer(data, sizeof(data));
    printHexBytes(data, sizeof(data));

    printf_s("=======TestShuffleBuffer passed======\n\n");
    return true;
}

static bool TestEraseBuffer()
{
    printf_s("========TestEraseBuffer begin=========\n");

    byte data[32];
    EraseBuffer(data, sizeof(data));

    if (!mem_is_zero(data, sizeof(data)))
    {
        printf_s("[error] data is not erased\n");
        return false;
    }

    printf_s("========TestEraseBuffer passed========\n\n");
    return true;
}

static bool TestEraseInstruction()
{
    printf_s("======TestEraseInstruction begin======\n");

    byte inst[256];
    EraseInstruction(inst, sizeof(inst));
    printHexBytes(inst, sizeof(inst));

    printf_s("======TestEraseInstruction passed=====\n\n");
    return true;
}

static void printHexBytes(byte* buf, uint size)
{
    int counter = 0;
    for (uint i = 0; i < size; i++)
    {
        printf_s("%02X ", *buf);

        buf++;
        counter++;
        if (counter >= 16)
        {
            counter = 0;
            printf_s("\n");
        }
    }
    printf_s("\n");
}
