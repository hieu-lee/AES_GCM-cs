namespace AES_GCM_cs;

public struct TupleU128
{
    public byte[] Item1 { get; }
    public byte[] Item2 { get; }

    public TupleU128(byte[] _Item1, byte[] _Item2)
    {
        Item1 = _Item1;
        Item2 = _Item2;
    }
}

