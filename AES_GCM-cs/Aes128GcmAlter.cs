namespace AES_GCM_cs;

public class Aes128GcmAlter
{
    const int AES_SIZE = 16;

    public static void inc32(byte[] x)
    {
        uint lsb = 0;
        lsb |= (uint)(x[12] << 24);
        lsb |= (uint)(x[13] << 16);
        lsb |= (uint)(x[14] << 8);
        lsb |= x[15];

        lsb++;

        uint twoP32 = 4294967;

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
        int lowestBit, highestBit = 0;
        for (i = 0; i < 16; i++)
        {
            lowestBit = v[i] & 0x01;
            v[i] >>= 1;
            if (i != 0)
            {
                v[i] |= (byte)((highestBit == 0) ? (0) : (0x80));
            }
            highestBit = lowestBit;
        }
    }

    public static void xor_block(byte[] dst, byte[] src)
    {
        int i;
        for (i = 0; i < 16; i++)
        {
            dst[i] ^= src[i];
        }
    }

    public static void g_mult(byte[] x, byte[] H, byte[] z)
    {
        byte[] v = new byte[AES_SIZE];

        int i, j;

        MemSet<byte>(z, 0, AES_SIZE);
        MemCpy(v, H, AES_SIZE);

        for (i = 0; i < 16; i++)
        {
            for (j = 0; j < 8; j++)
            {
                int x_bit = x[i] >> (7 - j) & 1;

                if ((x_bit & 0x01) == 1)
                {
                    xor_block(z, v);
                }

                if ((v[15] & 0x01) == 1)
                {
                    right_shift(v);
                    v[0] ^= 0xe1;
                }
                else
                {
                    right_shift(v);
                }
            }
        }
    }

    public static void g_hash(byte[] H, byte[] s_block, ulong len_s_block, byte[] y_output)
    {
        MemSet<byte>(y_output, 0, AES_SIZE);

        byte[] out_s_block = new byte[AES_SIZE * len_s_block];
        byte[] tmp_s = new byte[AES_SIZE];
        byte[] tmp_out_block = new byte[AES_SIZE];

        MemSet<byte>(out_s_block, 0, AES_SIZE * len_s_block);
        MemSet<byte>(tmp_s, 0, AES_SIZE);
        MemSet<byte>(tmp_out_block, 0, AES_SIZE);

        ulong i;

        for (i = 1; i <= len_s_block; i++)
        {
            MemCpy(tmp_s, s_block, AES_SIZE, SrcStart: AES_SIZE * (i - 1));
            if (i == 1)
            {
                g_mult(tmp_s, H, y_output);
            }
            else
            {
                MemCpy(tmp_out_block, out_s_block, AES_SIZE, SrcStart: AES_SIZE * (i - 2));
                xor_block(tmp_out_block, tmp_s);
                g_mult(tmp_out_block, H, y_output);
            }

            MemCpy(out_s_block, y_output, AES_SIZE, DesStart: AES_SIZE * (i - 1));
            MemSet<byte>(tmp_s, 0, AES_SIZE);
            MemSet<byte>(tmp_out_block, 0, AES_SIZE);

            if (i != len_s_block)
            {
                MemSet<byte>(y_output, 0, AES_SIZE);
            }
        }
    }

    static void MemSet<T>(T[] array, T value, ulong count)
    {
        for (ulong i = 0; i < count; i++)
        {
            array[i] = value;
        }
    }

    static void MemCpy<T>(T[] destination, T[] source, ulong count, ulong SrcStart = 0, ulong DesStart = 0)
    {
        for (ulong i = 0; i < count; i++)
        {
            destination[i + DesStart] = source[i + SrcStart];
        }
        return;
    }

    public static void g_ctrk(byte[] ICB, byte[] X, ulong len_p, byte[] K, byte[] Cipher)
    {
        if (len_p == 0)
        {
            return;
        }
        ulong i;
        byte[] cb = new byte[AES_SIZE * len_p];
        byte[] tmp = new byte[AES_SIZE];
        byte[] cipher = new byte[AES_SIZE];

        MemSet<byte>(Cipher, 0, AES_SIZE * len_p);
        MemSet<byte>(cb, 0, AES_SIZE * len_p);
        MemSet<byte>(tmp, 0, 16);
        MemSet<byte>(cipher, 0, 16);

        MemCpy(cb, ICB, 16);
        MemCpy(tmp, ICB, 16);

        for (i = 2; i <= len_p; i++)
        {
            inc32(tmp);
            MemCpy(cb, tmp, 16, DesStart: 16 * (i - 1));
        }

        MemSet<byte>(tmp, 0, 16);

        for (i = 1; i <= len_p; i++)
        {
            var c = 16 * (i - 1);
            MemCpy(tmp, cb, 16, SrcStart: c);

            aes128e.AES128E(cipher, tmp, K);

            MemSet<byte>(tmp, 0, 16);
            MemCpy(tmp, X, 16, SrcStart: c);

            xor_block(tmp, cipher);

            MemCpy(Cipher, tmp, 16, DesStart: c);

            MemSet<byte>(tmp, 0, 16);
            MemSet<byte>(cipher, 0, 16);
        }
    }

    public static void AES128GCM(byte[] ciphertext, byte[] tag,
        byte[] k, byte[] IV, byte[] plaintext,
        byte[] add_data)
    {
        ulong len_ad, len_p;
        byte[] H, J0;
        H = new byte[AES_SIZE];
        J0 = new byte[AES_SIZE];

        len_ad = (add_data.Length % 16 == 0) ? (ulong) (add_data.Length / 16) : (ulong) (add_data.Length / 16 + 1);
        len_p = (plaintext.Length % 16 == 0) ? (ulong)(plaintext.Length / 16) : (ulong)(plaintext.Length / 16 + 1);

        MemSet<byte>(H, 0, AES_SIZE);
        aes128e.AES128E(H, H, k);

        MemSet<byte>(J0, 0, AES_SIZE);

        MemCpy(J0, IV, 12);
        J0[AES_SIZE - 1] = 0x01;

        inc32(J0);

        g_ctrk(J0, plaintext, len_p, k, ciphertext);

        ulong s_size = len_ad + len_p + 1;
        byte[] S_Block = new byte[AES_SIZE * s_size];
        MemSet<byte>(S_Block, 0, AES_SIZE * s_size);

        MemCpy(S_Block, add_data, AES_SIZE * len_ad);
        MemCpy(S_Block, ciphertext, AES_SIZE * len_p, DesStart: AES_SIZE * len_ad);

        ulong rem_size = (s_size - 1) * AES_SIZE;
        ulong inBits_1 = 128 * len_ad;

        for (ulong i = rem_size + 7; i >= rem_size; i--)
        {
            var x = S_Block[i] | inBits_1;
            S_Block[i] = (byte)x;
            inBits_1 >>= 8;
            if (i == 0)
            {
                break;
            }
        }

        ulong inBits_2 = 128 * len_p;
        for (ulong i = rem_size + 15; i >= rem_size + 8; i--)
        {
            S_Block[i] = (byte)(S_Block[i] | inBits_2);
            inBits_2 >>= 8;
        }

        byte[] s_hashed = new byte[AES_SIZE];
        g_hash(H, S_Block, len_ad + len_p + 1, s_hashed);



        MemSet<byte>(J0, 0, AES_SIZE);
        MemCpy(J0, IV, 12);
        J0[AES_SIZE - 1] = 0x01;

        g_ctrk(J0, s_hashed, 1, k, tag);


    }
}

