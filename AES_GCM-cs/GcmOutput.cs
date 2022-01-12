namespace AES_GCM_cs;

unsafe struct GcmOutput
{
    public byte[] CipherText;
    public byte[] Tag;

    public GcmOutput(byte[] _CipherText, byte *_Tag)
    {
        CipherText = _CipherText;
        Tag = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            Tag[i] = *_Tag;
            _Tag++;
        }
    }
}
