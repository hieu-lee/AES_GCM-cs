using System;

namespace AES_GCM_cs
{
    // My own AES128GCM implementation after reading stuffs
    class aes128gcm
    {
        static readonly byte[] ZeroU128 = new byte[16]
        {
           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        };

        const uint twoP32 = 4294967;

        public static void inc32(byte[] x)
        {
            uint lsb = 0;
            lsb |= (uint)(x[12] << 24);
            lsb |= (uint)(x[13] << 16);
            lsb |= (uint)(x[14] << 8);
            lsb |= x[15];

            lsb++;

            uint after_mod = lsb % twoP32;

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

        public static byte[] xor_block(byte[] a, byte[] b, int length = 16)
        {
            int i;
            byte[] res = new byte[length];
            for (i = 0; i < length; i++)
            {
                res[i] = (byte)(a[i] ^ b[i]);
            }
            return res;
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

        static byte[] len(BitString[] A)
        {
            byte[] res = new byte[8];
            ulong l = (ulong)A.Length;
            ulong c = ((l - 1) * 128) + A[l - 1].BitLength;
            for (int i = 0; i < 8; i++)
            {
                res[i] = (byte)((c >> ((7 - i) * 8)) & 0xff);
            }
            return res;
        }

        static byte[] g_mult(byte[] X, byte[] Y)
        {
            byte[] V = new byte[16];

            int i, j, lsb;

            byte[] Z = ZeroU128;

            for (i = 0; i < 16; i++)
            {
                V[i] = X[i];
            }

            for (i = 0; i < 16; i++)
            {
                for (j = 0; j < 8; j++)
                {
                    int Ybit = Y[i] >> (7 - j) & 1;

                    if ((Ybit & 0x01) == 1)
                    {
                        Z = xor_block(Z, V);
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

        static BitString Ghash(byte[] H, BitString[] X)
        {
            var m = X.Length;
            var Y = g_mult(H, X[0].Bytes);

            for (int i = 1; i < m; i++)
            {
                var Xi = X[i].Bytes;
                Y = xor_block(Y, Xi);
                Y = g_mult(Y, H);
            }
            return new(Y);
        }

        static BitString[] Gctr(byte[] K, byte[] ICB, BitString[] X)
        {
            if (X.Length == 0)
            {
                return X;
            }
            var n = X.Length;
            var Y = new BitString[n];
            var CB = ICB;
            for (int i = 0; i < n - 1; i++)
            {
                var tmp = aes128.AES128E(CB, K).Item1;
                Y[i] = new(xor_block(X[i].Bytes, tmp));
                inc32(CB);
            }

            var temp = aes128.AES128E(CB, K).Item1;
            temp = xor_block(temp, X[n - 1].Bytes);
            temp = MSB(temp, X[n - 1].BitLength);
            Y[n - 1] = new(temp);
            return Y;

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

            uint t = 128;

            var resE = AES128GCMe(IV, P, A, K, t);

            var C = resE.CipherText;
            var T = resE.Tag;

            var resD = AES128GCMd(IV, C, K, A, T, t);

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
        public static GcmOutput AES128GCMe(byte[] IV, byte[] _P, byte[] _A, byte[] K, uint t)
        {
            var P = BitString.BytesToBitStrings(_P);
            var A = BitString.BytesToBitStrings(_A);
            var H = aes128.AES128E(ZeroU128, K).Item1;
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
            var C = Gctr(K, Y0, P);
            BitString temp = new(concate_block(len(A), len(C)));
            var lenA = A.Length;
            var lenC = C.Length;
            var l = lenA + lenC + 1;
            var tmp = new BitString[l];
            for (int i = 0; i < lenA; i++)
            {
                tmp[i] = A[i];
            }
            for (int i = lenA; i < l - 1; i++)
            {
                tmp[i] = C[i - lenA];
            }
            tmp[l - 1] = temp;
            var S = new BitString[1] { Ghash(H, tmp) };
            Y0[12] = 0;
            Y0[13] = 0;
            Y0[14] = 0;
            Y0[15] = 1;
            for (int i = 0; i < 12; i++)
            {
                Y0[i] = IV[i];
            }
            var T = Gctr(K, Y0, S)[0].Bytes;
            T = MSB(T, t);
            return new(C, T);
        }

        // Decryption function
        public static byte[] AES128GCMd(byte[] IV, byte[] _C, byte[] K, byte[] _A, byte[] _T, uint t)
        {
            if (_T.Length * 8 - t >= 8 || _T.Length * 8 - t < 0)
            {
                Console.WriteLine("FAIL");
                return ZeroU128;
            }
            else
            {
                var C = BitString.BytesToBitStrings(_C);
                var A = BitString.BytesToBitStrings(_A);
                var H = aes128.AES128E(ZeroU128, K).Item1;
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
                var P = Gctr(K, Y0, C);
                BitString temp = new(concate_block(len(A), len(C)));
                var lenA = A.Length;
                var lenC = C.Length;
                var l = lenA + lenC + 1;
                var tmp = new BitString[l];
                for (int i = 0; i < lenA; i++)
                {
                    tmp[i] = A[i];
                }
                for (int i = lenA; i < l - 1; i++)
                {
                    tmp[i] = C[i - lenA];
                }
                tmp[l - 1] = temp;
                var S = new BitString[1] { Ghash(H, tmp) };
                Y0[12] = 0;
                Y0[13] = 0;
                Y0[14] = 0;
                Y0[15] = 1;
                for (int i = 0; i < 12; i++)
                {
                    Y0[i] = IV[i];
                }
                var T = Gctr(K, Y0, S)[0].Bytes;
                T = MSB(T, t);
                for (int i = 0; i < T.Length; i++)
                {
                    if (T[i] != _T[i])
                    {
                        Console.WriteLine("FAIL");
                        return ZeroU128;
                    }
                }
                return BitString.BitStringsToBytes(P);
            }
        }

        // Return the t most significant bits of X
        static byte[] MSB(byte[] X, uint t)
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
