namespace AES_GCM_cs;
struct BitString
{
    public byte[] Bytes { get; set; }
    public uint BitLength;

    public static BitString Zero = new BitString(new byte[16]
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        });

    public static byte[] BitStringsToBytes(BitString[] bitStrings)
    {
        var l = bitStrings.Length;
        var c = 16 * (l - 1) + (bitStrings[l - 1].BitLength / 8);
        var res = new byte[c];
        for (int i = 0; i < c; i++)
        {
            res[i] = bitStrings[i / 16].Bytes[i % 16];
        }
        return res;
    }

    public static BitString[] BytesToBitStrings(byte[] Bytes)
    {
        var q = Bytes.Length / 16;
        var r = Bytes.Length % 16;
        if (r != 0)
        {
            var res = new BitString[q + 1];
            for (var i = 0; i < q; i++)
            {
                var bytes = new byte[16];
                for (var j = 0; j < 16; j++)
                {
                    bytes[j] = Bytes[16 * i + j];
                }
                res[i] = new(bytes);
            }
            var tmp = new byte[r];
            for (var i = 0; i < r; i++)
            {
                tmp[i] = Bytes[16 * q + i];
            }
            res[q] = new(tmp);
            return res;
        }
        else
        {
            var res = new BitString[q];
            for (var i = 0; i < q; i++)
            {
                var bytes = new byte[16];
                for (var j = 0; j < 16; j++)
                {
                    bytes[j] = Bytes[16 * i + j];
                }
                res[i] = new(bytes);
            }
            return res;
        }
    }

    public BitString(byte[] _Bytes)
    {
        var c = _Bytes.Length;
        if (c < 16)
        {
            BitLength = (uint)(8 * c);
            Bytes = new byte[16]
            {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            for (int i = 0; i < c; i++)
            {
                Bytes[i] = _Bytes[i];
            }
        }
        else
        {
            BitLength = 128;
            Bytes = _Bytes;
        }
    }
}