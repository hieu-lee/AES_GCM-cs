namespace AES_GCM_cs;

// My own AES128GCM implementation after reading stuffs
unsafe class aes128gcm
{

    const int twoP32 = 4294967;
    const ulong getLastBits = 0x101010101010101;
    const ulong setFirstBits = 0x7F7F7F7F7F7F7F7F;

    static void CopyToPtr128(byte[] src, byte* dst)
    {
        ulong* dstLong = (ulong*)dst;
        fixed (byte* src_ptr = src)
        {
            var scan = (ulong*)src_ptr;
            *dstLong = *scan;
            scan++;
            dstLong++;
            *dstLong = *scan;
        }
    }

    static void U128Copy(byte *src, byte *dst)
    {
        var srcLong = (ulong*)src;
        var dstLong = (ulong*)dst;
        *dstLong = *srcLong;
        dstLong++;
        srcLong++;
        *dstLong = *srcLong;
    }

    static void inc32(byte *x)
    {
        int lsb = 0;
        lsb |= x[12] << 24;
        lsb |= x[13] << 16;
        lsb |= x[14] << 8;
        lsb |= x[15];

        lsb++;

        int after_mod = lsb % twoP32;

        x[15] = (byte)after_mod;

        after_mod >>= 8;
        x[14] = (byte)after_mod;

        after_mod >>= 8;
        x[13] = (byte)after_mod;

        after_mod >>= 8;
        x[12] = (byte)after_mod;
    }

    static void right_shift(byte *v)
    {
        ulong temp;
        ulong* vLong = (ulong*)v;
        temp = getLastBits & *vLong;
        temp <<= 15;
        int highestBit = v[7] & 1;
        *vLong >>= 1;
        *vLong &= setFirstBits;
        *vLong |= temp;

        vLong++;

        temp = getLastBits & *vLong;
        temp <<= 15;
        *vLong >>= 1;
        *vLong &= setFirstBits;
        *vLong |= temp;
        v = (byte*)vLong;
        if (highestBit == 1)
        {
            v[0] |= 0x80;
        }
    }

    static void xor_block_128(byte *dst, byte *src)
    {
        var dst_long = (ulong*)dst;
        var src_long = (ulong*)src;
        *dst_long ^= *src_long;
        dst_long++;
        src_long++;
        *dst_long ^= *src_long;
    }

    static void concate_block(ulong LengthA, ulong LengthB, byte *output)
    {
        var pOutput = (ulong*)output;
        *pOutput = (LengthA << 3);
        pOutput++;
        *pOutput = (LengthB << 3);
        for (int i = 0; i < 4; i++)
        {
            int a = 7 - i, b = 8 + i, c = 15 - i;
            (output[i], output[a]) = (output[a], output[i]);
            (output[b], output[c]) = (output[c], output[b]);
        }
    }

    static void g_mult(byte *X, byte *Y, byte *output)
    {
        var V = stackalloc byte[16];

        int i, j, lsb;

        var Z = stackalloc byte[16];

        U128Copy(Y, V);

        for (i = 0; i < 16; i++)
        {
            for (j = 0; j < 8; j++)
            {
                if (((*X >> (7 - j)) & 1) == 1)
                {
                    xor_block_128(Z, V);
                }
                lsb = V[15] & 0x01;
                right_shift(V);
                
                if (lsb == 1)
                {
                    *V ^= 0xe1;
                }

            }
            X++;
        }

        U128Copy(Z, output);
    }

    static void Ghash(byte *H, byte[] X, int len_X, byte *output)
    {
        int c;
        var temp = stackalloc byte[16];
        CopyToPtr128(X, temp);
        var Y = stackalloc byte[16];

        g_mult(H, temp, Y);
        for (int i = 1; i < len_X; i++)
        {
            c = i << 4;
            for (int j = 0; j < 16; j++)
            {
                temp[j] = X[c + j];
            }
            xor_block_128(Y, temp);
            g_mult(Y, H, Y);
        }
        
        U128Copy(Y, output);
    }

    static void Gctr128(byte *K, byte* ICB, byte *X, byte *Tag)
    {
        var tmp = stackalloc byte[16];
        var CB = stackalloc byte[16];
        U128Copy(ICB, CB);

        aes128.AES128EncryptPointer(CB, K, tmp);
        *(ulong*)Tag = *(ulong*)tmp ^ *(ulong*)X;
        *(ulong*)(Tag + 8) = *(ulong*)(tmp + 8) ^ *(ulong*)(X + 8);
    }

    static void Gctr(byte *K, byte *ICB, byte[] X, int len_X, int last_len_X, byte[] Cipher)
    {
        var CB = stackalloc byte[16];
        if (X.Length == 0)
        {
            return;
        }
        int i, j, c;
        var tmp = stackalloc byte[16];
        U128Copy(ICB, CB);

        for (i = 0; i < len_X - 1; i++)
        {
            c = i << 4;
            aes128.AES128EncryptPointer(CB, K, tmp);
            for (j = 0; j < 16; j++)
            {
                Cipher[c + j] = (byte)(tmp[j] ^ X[c + j]);
            }
            inc32(CB);
        }

        aes128.AES128EncryptPointer(CB, K, tmp);
        c = (len_X - 1) << 4;
        for (i = 0; i < last_len_X; i++)
        {
            Cipher[c + i] = (byte)(tmp[i] ^ X[c + i]);
        }
    }

    // Run this function to see a test result
    public static void Test()
    {
        byte[] K = new byte[16]
        {
            0x98,0xff,0xf6,0x7e,0x64,0xe4,0x6b,0xe5,0xee,0x2e,0x05,0xcc,0x9a,0xf6,0xd0,0x12
        };

        byte[] IV = new byte[12]
        {
            0x2d, 0xfb, 0x42, 0x9a, 0x48, 0x69, 0x7c, 0x34, 0x00, 0x6d, 0xa8, 0x86
        };

        byte[] P = new byte[48]
        {
            0x29,0xb9,0x1b,0x4a,0x68,0xa9,0x9f,0x97,0xc4,0x1c,0x75,0x08,0xf1,0x7a,0x5c,0x7a,
            0x7a,0xfc,0x9e,0x1a,0xca,0x83,0xe1,0x29,0xb0,0x85,0xbd,0x63,0x7f,0xf6,0x7c,0x01,
            0x29,0xb9,0x1b,0x4a,0x68,0xa9,0x9f,0x97,0xc4,0x1c,0x75,0x08,0xf1,0x7a,0x5c,0x7a
        };

        byte[] A = new byte[48]
        {
            0xa0,0xca,0x58,0x61,0xc0,0x22,0x6c,0x5b,0x5a,0x65,0x14,0xc8,0x2b,0x77,0x81,0x5a,
            0x9e,0x0e,0xb3,0x59,0xd0,0xd4,0x6d,0x03,0x33,0xc3,0xf2,0xba,0xe1,0x4d,0xa0,0xc4,
            0x03,0x30,0xc0,0x02,0x16,0xb4,0xaa,0x64,0xb7,0xc1,0xed,0xb8,0x71,0xc3,0x28,0xf6
        };

        byte[] ciphertext_ref = new byte[48]
        {
            0xc2,0x2f,0xee,0xb3,0xe2,0x7d,0xc3,0x29,0x93,0x45,0x03,0x01,0x39,0xee,0x81,0x67,
            0x19,0xa8,0xa8,0x99,0x39,0x03,0x78,0x95,0xd7,0x49,0x65,0xfa,0x02,0x40,0xaf,0x5b,
            0xe3,0x19,0x26,0x59,0xd5,0x66,0x39,0x8a,0x5d,0x95,0xf3,0xe0,0x4b,0xcd,0x53,0x57
        };

        var resE = AES128GCMe(IV, P, A, K);

        var C = resE.CipherText;
        var T = resE.Tag;

        var resD = AES128GCMd(IV, C, K, A, T);

        Console.WriteLine("Ciphertext result:");
        PrintArray(C);

        Console.WriteLine("\nCiphertext reference:");
        PrintArray(ciphertext_ref);

        Console.WriteLine("\nPlaintext reference:");
        PrintArray(P);

        Console.WriteLine("\nPlaintext result:");
        PrintArray(resD);

    }

    // This function is for debugging
    static void PrintArray<T>(T[] arr)
    {
        var s = "[";
        for (int i = 0; i < arr.Length; i++)
        {
            s += $"{arr[i]}, ";
        }
        s += "]";
        Console.WriteLine(s);
    }

    // Encryption function
    public static GcmOutput AES128GCMe(byte[] IV, byte[] _P, byte[] _A, byte[] K)
    {
        var key = stackalloc byte[16];
        var last_len_a = ((_A.Length & 15) == 0) ? 16 : (_A.Length & 15);
        var last_len_p = ((_P.Length & 15) == 0) ? 16 : (_P.Length & 15);
        var len_a = (last_len_a == 16) ? (_A.Length >> 4) : ((_A.Length >> 4) + 1);
        var len_p = (last_len_p == 16) ? (_P.Length >> 4) : ((_P.Length >> 4) + 1);
        var C = new byte[_P.Length];
        var T = stackalloc byte[16];
        var H = stackalloc byte[16];
        var ZeroU128 = stackalloc byte[16];
        *(ulong*)ZeroU128 = 0;
        *(ulong*)(ZeroU128 + 8) = 0;
        CopyToPtr128(K, key);
        aes128.AES128EncryptPointer(ZeroU128, key, H);
        var Y0 = stackalloc byte[16];
        *(uint*)(Y0 + 12) = 16777216;
        fixed (byte* IVptr = IV)
        {
            var scan = IVptr;
            *(ulong*)Y0 = *(ulong*)scan;
            scan += 8;
            *(uint*)(Y0 + 8) = *(uint*)scan;
        }
        inc32(Y0);
        Gctr(key, Y0, _P, len_p, last_len_p, C);
        var temp = stackalloc byte[16];
        concate_block((ulong)_A.Length, (ulong)C.Length, temp);
        len_a <<= 4;
        len_p <<= 4;
        var l = len_a + len_p + 16;
        var tmp = new byte[l];
        for (int i = 0; i < _A.Length; i++)
        {
            tmp[i] = _A[i];
        }
        for (int i = len_a; i < len_a + C.Length; i++)
        {
            tmp[i] = C[i - len_a];
        }
        var c = l - 16;
        for (int i = c; i < l; i++)
        {
            tmp[i] = temp[i - c];
        }
        var S = stackalloc byte[16];
        Ghash(H, tmp, l >> 4, S);
        *(uint*)(Y0 + 12) = 16777216;
        fixed (byte* IVptr = IV)
        {
            var scan = IVptr;
            *(ulong*)Y0 = *(ulong*)scan;
            scan += 8;
            *(uint*)(Y0 + 8) = *(uint*)scan;
        }
        Gctr128(key, Y0, S, T);
        return new(C, T);
    }

    // Decryption function
    public static byte[] AES128GCMd(byte[] IV, byte[] _C, byte[] K, byte[] _A, byte[] _T)
    {
        var key = stackalloc byte[16];
        var last_len_a = ((_A.Length & 15) == 0) ? 16 : (_A.Length & 15);
        var last_len_c = ((_C.Length & 15) == 0) ? 16 : (_C.Length & 15);
        var len_a = (last_len_a == 16) ? (_A.Length >> 4) : ((_A.Length >> 4) + 1);
        var len_c = (last_len_c == 16) ? (_C.Length >> 4) : ((_C.Length >> 4) + 1);
        var P = new byte[_C.Length];
        var T = stackalloc byte[16];
        var H = stackalloc byte[16];
        var ZeroU128 = stackalloc byte[16];
        *(ulong*)ZeroU128 = 0;
        *(ulong*)(ZeroU128 + 8) = 0;
        CopyToPtr128(K, key);
        aes128.AES128EncryptPointer(ZeroU128, key, H);
        var Y0 = stackalloc byte[16];
        *(uint*)(Y0 + 12) = 16777216;
        fixed (byte* IVptr = IV)
        {
            var scan = IVptr;
            *(ulong*)Y0 = *(ulong*)scan;
            scan += 8;
            *(uint*)(Y0 + 8) = *(uint*)scan;
        }
        inc32(Y0);

        Gctr(key, Y0, _C, len_c, last_len_c, P);

        var temp = stackalloc byte[16];
        concate_block((ulong)_A.Length, (ulong)_C.Length, temp);
        len_a <<= 4;
        len_c <<= 4;
        var l = len_a + len_c + 16;
        var tmp = new byte[l];
        for (int i = 0; i < _A.Length; i++)
        {
            tmp[i] = _A[i];
        }
        for (int i = len_a; i < len_a + _C.Length; i++)
        {
            tmp[i] = _C[i - len_a];
        }
        var c = l - 16;
        for (int i = c; i < l; i++)
        {
            tmp[i] = temp[i - c];
        }
        var S = stackalloc byte[16];
        Ghash(H, tmp, l >> 4, S);
        *(uint*)(Y0 + 12) = 16777216;
        fixed (byte* IVptr = IV)
        {
            var scan = IVptr;
            *(ulong*)Y0 = *(ulong*)scan;
            scan += 8;
            *(uint*)(Y0 + 8) = *(uint*)scan;
        }
        Gctr128(key, Y0, S, T);

        fixed(byte* _Tptr = _T)
        {
            var scan = _Tptr;
            if ((*(ulong*)T != *(ulong*)scan) || (*(ulong*)(T + 8) != *(ulong*)(scan + 8)))
            {
                Console.WriteLine("FAIL");
                return new byte[1] { 0 };
            }
        }
        return P;
    }

    private static Exception UnauthorizedAccessException()
    {
        return new("FAIL");
    }
}

