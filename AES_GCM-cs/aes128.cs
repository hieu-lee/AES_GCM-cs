﻿namespace AES_GCM_cs;

// My own implementation of AES128 after reading stuffs
unsafe class aes128
{

    static readonly byte[] SBox = new byte[256]
    {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    };

    static readonly byte[] InvSBox = new byte[256]
    {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    };

    static readonly byte[] RCon = new byte[10]
    {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    static byte XTime(byte a)
    {
        return (byte)(((a & 0x80) != 0) ? ((a << 1) ^ 0x1b) : (a << 1));
    }

    static void U128Copy(byte* src, byte* dst)
    {
        var srcLong = (ulong*)src;
        var dstLong = (ulong*)dst;
        *dstLong = *srcLong;
        dstLong++;
        srcLong++;
        *dstLong = *srcLong;
    }

    static void SubAndShiftRows(byte* state)
    {
        var temp = stackalloc byte[16]
        {
            SBox[state[0]],
            SBox[state[5]],
            SBox[state[10]],
            SBox[state[15]],
            SBox[state[4]],
            SBox[state[9]],
            SBox[state[14]],
            SBox[state[3]],
            SBox[state[8]],
            SBox[state[13]],
            SBox[state[2]],
            SBox[state[7]],
            SBox[state[12]],
            SBox[state[1]],
            SBox[state[6]],
            SBox[state[11]]
        };
        U128Copy(temp, state);
    }

    static void InvSubAndShiftRows(byte* state)
    {
        var temp = stackalloc byte[16]
        {
            InvSBox[state[0]],
            InvSBox[state[13]],
            InvSBox[state[10]],
            InvSBox[state[7]],
            InvSBox[state[4]],
            InvSBox[state[1]],
            InvSBox[state[14]],
            InvSBox[state[11]],
            InvSBox[state[8]],
            InvSBox[state[5]],
            InvSBox[state[2]],
            InvSBox[state[15]],
            InvSBox[state[12]],
            InvSBox[state[9]],
            InvSBox[state[6]],
            InvSBox[state[3]]
        };
        U128Copy(temp, state);
    }

    static void MixColumns(byte* state)
    {
        byte t, u;
        int i;
        int c;
        for (i = 0; i < 4; i++)
        {
            c = i << 2;
            int d = c + 1, e = c + 2, f = c + 3;
            t = (byte)(state[c] ^ state[d] ^ state[e] ^ state[f]);
            u = state[c];
            state[c] ^= (byte)(t ^ XTime((byte)(state[c] ^ state[d])));
            state[d] ^= (byte)(t ^ XTime((byte)(state[d] ^ state[e])));
            state[e] ^= (byte)(t ^ XTime((byte)(state[e] ^ state[f])));
            state[f] ^= (byte)(t ^ XTime((byte)(state[f] ^ u)));
        }
    }

    static void InvMixColumns(byte* state)
    {
        byte i, c;
        uint u;
        byte* ptrByte;
        uint* ptrInt = (uint*)state;
        for (i = 0; i < 4; i++)
        {
            ptrByte = (byte*)ptrInt;
            u = XTime(XTime((byte)(*(ptrByte + 1) ^ *(ptrByte + 3))));
            u <<= 8;
            u ^= XTime(XTime((byte)(*ptrByte ^ *(ptrByte + 2))));
            u = (u << 16) ^ u;
            *ptrInt ^= u;
            ptrInt++;
        }
        MixColumns(state);
    }

    static void AddRoundKey(byte* state, byte* RoundKey)
    {
        var stateLong = (ulong*)state;
        var RoundKeyLong = (ulong*)RoundKey;
        *stateLong ^= *RoundKeyLong;
        stateLong++;
        RoundKeyLong++;
        *stateLong ^= *RoundKeyLong;
    }

    static void KeyExpansion(byte* RoundKey, int round)
    {
        byte i;
        byte* res = stackalloc byte[16];
        uint* RoundKey32 = (uint*)RoundKey;
        byte* temp = stackalloc byte[4] {
            SBox[RoundKey[13]],
            SBox[RoundKey[14]],
            SBox[RoundKey[15]],
            SBox[RoundKey[12]]
        };
        *(uint*)res = *(uint*)temp ^ *RoundKey32;
        uint* ptr = (uint*)(res + 4);
        RoundKey32++;
        *res ^= RCon[round - 1];
        for (i = 1; i < 4; i++)
        {
            *ptr = *(ptr - 1) ^ *RoundKey32;
            ptr++;
            RoundKey32++;
        }
        U128Copy(res, RoundKey);
    }

    static void InvKeyExpansion(byte* RoundKey, int round)
    {
        byte* res = stackalloc byte[16];
        uint* ptr = (uint*)(res + 4);
        uint* RoundKey32 = (uint*)RoundKey;
        byte i;
        for (i = 1; i < 4; i++)
        {
            *ptr = *RoundKey32 ^ *(RoundKey32 + 1);
            ptr++;
            RoundKey32++;
        }
        byte* temp = stackalloc byte[4] {
            SBox[res[13]],
            SBox[res[14]],
            SBox[res[15]],
            SBox[res[12]]
        };
        *(uint*)res = *(uint*)temp ^ *(uint*)RoundKey;
        res[0] ^= RCon[10 - round];
        U128Copy(res, RoundKey);
    }

    // AES128 encryption function 
    public static void AES128EncryptPointer(byte *input, byte *key, byte *output)
    {
        var state = stackalloc byte[16];
        var RoundKey = stackalloc byte[16];
        U128Copy(input, state);
        U128Copy(key, RoundKey);
        AddRoundKey(state, RoundKey);

        for (var round = 1; round < 10; round++)
        {
            KeyExpansion(RoundKey, round);
            SubAndShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, RoundKey);
        }
        KeyExpansion(RoundKey, 10);
        SubAndShiftRows(state);
        AddRoundKey(state, RoundKey);
        U128Copy(state, output);
    }

    // AES128 encryption function 
    public static TupleU128 AES128E(byte[] input, byte[] key)
    {
        var state = stackalloc byte[16];
        var RoundKey = stackalloc byte[16];
        for (int i = 0; i < 16; i++)
        {
            RoundKey[i] = key[i];
            state[i] = input[i];
        }
        AddRoundKey(state, RoundKey);

        for (var round = 1; round < 10; round++)
        {
            KeyExpansion(RoundKey, round);
            SubAndShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, RoundKey);
        }
        KeyExpansion(RoundKey, 10);
        SubAndShiftRows(state);
        AddRoundKey(state, RoundKey);
        return new(state, RoundKey);
    }

    // AES128 decryption function
    public static TupleU128 AES128D(byte[] CipherText, byte[] key)
    {
        var state = stackalloc byte[16];
        var RoundKey = stackalloc byte[16];
        for (int i = 0; i < 16; i++)
        {
            RoundKey[i] = key[i];
            state[i] = CipherText[i];
        }
        AddRoundKey(state, RoundKey);
        InvSubAndShiftRows(state);
        InvKeyExpansion(RoundKey, 1);
        for (var round = 2; round < 11; round++)
        {
            AddRoundKey(state, RoundKey);
            InvMixColumns(state);
            InvSubAndShiftRows(state);
            InvKeyExpansion(RoundKey, round);
        }
        AddRoundKey(state, RoundKey);
        return new(state, RoundKey);
    }

    static void PrintArray(byte[] array)
    {
        var s = "[";
        for (int i = 0; i < array.Length; i++)
        {
            s += $"{array[i]}, ";
        }
        s += "]";
        Console.WriteLine(s);
    }

    // Run this function to see the test result
    public static void Test()
    {
        var Key = new byte[16]
        {
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f
        };

        var Input = new byte[16]
        {
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff
        };

        Console.WriteLine("Initial given datas:\nText:");
        PrintArray(Input);
        Console.WriteLine("Key:");
        PrintArray(Key);

        Console.WriteLine("\nAfter encryption:\nCipher Text:");

        var dataE = AES128E(Input, Key);

        var CipherText = dataE.Item1;
        var LastRoundKey = dataE.Item2;
        PrintArray(CipherText);
        Console.WriteLine("Last Round Key:");
        PrintArray(LastRoundKey);

        Console.WriteLine("\nAfter decryption:\nPlain Text:");

        var dataD = AES128D(CipherText, LastRoundKey);

        var PlainText = dataD.Item1;
        var FirstRoundKey = dataD.Item2;
        PrintArray(PlainText);
        Console.WriteLine("First Round Key:");
        PrintArray(FirstRoundKey);
        Console.WriteLine("END");
    }
}
