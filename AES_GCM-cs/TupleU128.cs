namespace AES_GCM_cs;

public unsafe struct TupleU128
{
    public byte[] Item1 { get; }
    public byte[] Item2 { get; }

    public TupleU128(byte *_Item1, byte *_Item2)
    {
        Item1 = new byte[16];
        Item2 = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            Item1[i] = *_Item1;
            Item2[i] = *_Item2;
            _Item1++;
            _Item2++;
        }
    }
}

