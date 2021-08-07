using System;

namespace AES_GCM_cs
{
    // My own AES128GCM implementation after reading stuffs
    class aes128gcm
    {

        const int twoP32 = 4294967;

        public static void inc32(byte[] x)
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

        public static void right_shift(byte[] v)
        {
            int i;
            int lowestBit, highestBit;
            lowestBit = v[0] & 1;
            v[0] >>= 1;
            highestBit = lowestBit;
            for (i = 1; i < 16; i++)
            {
                lowestBit = v[i] & 1;
                v[i] >>= 1;
                if (highestBit == 1)
                {
                    v[i] |= (1 << 7);
                }
                highestBit = lowestBit;
            }
        }

        public static void xor_block(byte[] dst, byte[] src, int length = 16)
        {
            int i;
            for (i = 0; i < length; i++)
            {
                dst[i] ^= src[i];
            }
        }

        // Return the concatenation of two array
        static T[] concate_block<T>(T[] a, T[] b)
        {
            int u = a.Length;
            int v = b.Length;
            var res = new T[u + v];
            for (int i = 0; i < u; i++)
            {
                res[i] = a[i];
            }
            for (int i = u; i < u + v; i++)
            {
                res[i] = b[i - u];
            }
            return res;
        }

        static byte[] len(byte[] A)
        {
            byte[] res = new byte[8];
            int c = A.Length << 3;
            for (int i = 0; i < 8; i++)
            {
                res[i] = (byte)((c >> ((7 - i) << 3)) & 0xff);
            }
            return res;
        }

        static byte[] g_mult(byte[] X, byte[] Y)
        {
            byte[] V = new byte[16];

            int i, j, lsb;

            byte[] Z = new byte[16] 
            {
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0
            };

            for (i = 0; i < 16; i++)
            {
                V[i] = X[i];
            }

            for (i = 0; i < 16; i++)
            {
                for (j = 0; j < 8; j++)
                {
                    if ((Y[i] >> (7 - j)) == 1)
                    {
                        xor_block(Z, V);
                    }

                    lsb = V[15] & 0x01;
                    right_shift(V);
                    if (lsb == 1)
                    {
                        V[0] ^= 0xe1;
                    }
                }
            }

            return Z;
        }

        static byte[] Ghash(byte[] H, byte[] X, int len_X)
        {
            int c;
            var temp = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                temp[i] = X[i];
            }
            var Y = g_mult(H, temp);

            for (int i = 1; i < len_X; i++)
            {
                c = i << 4;
                for (int j = 0; j < 16; j++)
                {
                    temp[j] = X[c + j];
                }
                xor_block(Y, temp);
                Y = g_mult(Y, H);
            }
            return Y;
        }

        static void Gctr(byte[] K, byte[] ICB, byte[] X, int len_X, int last_len_X, byte[] Cipher)
        {
            if (X.Length == 0)
            {
                return;
            }
            int i, j, c;
            byte[] tmp;
            var CB = ICB;

            for (i = 0; i < len_X - 1; i++)
            {
                c = i << 4;
                tmp = aes128.AES128E(CB, K).Item1;
                for (j = 0; j < 16; j++)
                {
                    Cipher[c + j] = (byte)(tmp[j] ^ X[c + j]);
                }
                inc32(CB);
            }

            tmp = aes128.AES128E(CB, K).Item1;
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
            var last_len_a = (_A.Length % 16 == 0) ? 16 : _A.Length % 16;
            var last_len_p = (_P.Length % 16 == 0) ? 16 : _P.Length % 16;
            var len_a = (last_len_a == 16) ? (_A.Length / 16) : (_A.Length / 16 + 1);
            var len_p = (last_len_p == 16) ? (_P.Length / 16) : (_P.Length / 16 + 1);
            var C = new byte[_P.Length];
            var T = new byte[16];
            var H = aes128.AES128E(new byte[16]
            {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            }, K).Item1;
            var Y0 = new byte[16];
            Y0[12] = 0;
            Y0[13] = 0;
            Y0[14] = 0;
            Y0[15] = 1;
            for (int i = 0; i < 12; i++)
            {
                Y0[i] = IV[i];
            }
            inc32(Y0);
            Gctr(K, Y0, _P, len_p, last_len_p, C);

            byte[] temp = concate_block(len(_A), len(C));
            len_a <<= 4;
            len_p <<= 4;
            var l = len_a + len_p + 16;
            var tmp = new byte[l];
            for (int i = 0; i < len_a; i++)
            {
                tmp[i] = _A[i];
            }
            for (int i = len_a; i < l - 16; i++)
            {
                tmp[i] = C[i - len_a];
            }
            for (int i = l - 16; i < l; i++)
            {
                tmp[i] = temp[i + 16 - l];
            }
            var S = Ghash(H, tmp, l >> 4);
            Y0[12] = 0;
            Y0[13] = 0;
            Y0[14] = 0;
            Y0[15] = 1;
            for (int i = 0; i < 12; i++)
            {
                Y0[i] = IV[i];
            }
            Gctr(K, Y0, S,1, 16, T);
            return new(C, T);
        }

        // Decryption function
        public static byte[] AES128GCMd(byte[] IV, byte[] _C, byte[] K, byte[] _A, byte[] _T)
        {
            var last_len_a = (_A.Length % 16 == 0) ? 16 : _A.Length % 16;
            var last_len_c = (_C.Length % 16 == 0) ? 16 : _C.Length % 16;
            var len_a = (last_len_a == 16) ? (_A.Length / 16) : (_A.Length / 16 + 1);
            var len_c = (last_len_c == 16) ? (_C.Length / 16) : (_C.Length / 16 + 1);
            var P = new byte[_C.Length];
            var T = new byte[16];
            var H = aes128.AES128E(new byte[16]
            {
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            }, K).Item1;
            var Y0 = new byte[16];
            Y0[12] = 0;
            Y0[13] = 0;
            Y0[14] = 0;
            Y0[15] = 1;
            for (int i = 0; i < 12; i++)
            {
                Y0[i] = IV[i];
            }
            inc32(Y0);

            Gctr(K, Y0, _C, len_c, last_len_c, P);

            byte[] temp = concate_block(len(_A), len(_C));
            len_a <<= 4;
            len_c <<= 4;
            var l = len_a + len_c + 16;
            var tmp = new byte[l];
            for (int i = 0; i < len_a; i++)
            {
                tmp[i] = _A[i];
            }
            for (int i = len_a; i < l - 16; i++)
            {
                tmp[i] = _C[i - len_a];
            }
            for (int i = l - 16; i < l; i++)
            {
                tmp[i] = temp[i + 16 - l];
            }
            var S = Ghash(H, tmp, l >> 4);
            Y0[12] = 0;
            Y0[13] = 0;
            Y0[14] = 0;
            Y0[15] = 1;
            for (int i = 0; i < 12; i++)
            {
                Y0[i] = IV[i];
            }
            Gctr(K, Y0, S, 1, 16, T);

            for (int i = 0; i < 16; i++)
            {
                if (T[i] != _T[i])
                {
                    Console.WriteLine("FAIL");
                    return new byte[1] { 0 };
                }
            }
            return P;
        }

        // Return the t most significant bits of X
        static byte[] MSB(byte[] X, int t)
        {
            var c = t / 8;
            if (t % 8 != 0)
            {
                c++;
            }
            var res = new byte[c];
            for (int i = 0; i < c; i++)
            {
                res[i] = X[i];
            }
            return res;
        }
    }
}
