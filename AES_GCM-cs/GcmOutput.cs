namespace AES_GCM_cs
{
    struct GcmOutput
    {
        public byte[] CipherText;
        public byte[] Tag;

        public GcmOutput(BitString[] _CipherText, byte[] _Tag)
        {
            CipherText = BitString.BitStringsToBytes(_CipherText);
            Tag = _Tag;
        }
    }
}