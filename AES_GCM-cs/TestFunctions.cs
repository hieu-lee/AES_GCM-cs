namespace AES_GCM_cs;

[MemoryDiagnoser]
public class TestFunctions
{
    Random rng = new Random();
    byte[] K = new byte[16];
    byte[] IV = new byte[12];
    byte[] P = new byte[1000000];
    byte[] A = new byte[24];

    //public TestFunctions()
    //{
    //    rng.NextBytes(K);
    //    rng.NextBytes(IV);
    //    var p = rng.Next(5000000, 10000000);
    //    P = new byte[p];
    //    rng.NextBytes(P);
    //    var a = rng.Next(5000, 10000);
    //    A = new byte[a];
    //    rng.NextBytes(A);
    //}

    [Benchmark]
    public void MyAES()
    {
        var Key = new byte[16];

        rng.NextBytes(Key);

        var Input = new byte[16];

        rng.NextBytes(Input);

        aes128.AES128E(Input, Key);
    }

    [Benchmark]
    public void MyGCM()
    {
        rng.NextBytes(K);
        rng.NextBytes(IV);
        rng.NextBytes(P);
        rng.NextBytes(A);
        _ = aes128gcm.AES128GCMe(IV, P, A, K);
    }

    public static void RunTest()
    {
        Console.WriteLine("Please choose one of the 3 following choices.");
        Console.WriteLine("What do you want to see?");
        Console.WriteLine("1. Test result of AES128");
        Console.WriteLine("2. Test result of AES128GCM");
        Console.WriteLine("3. Performance of my AES128GCM implementation (encrypt 1mb of data)");
        Console.Write("Choose a number from 1 to 3: ");
        var s = Console.ReadLine();
        s = s.Trim();
        switch (s)
        {
            case "1":
                aes128.Test();
                break;
            case "2":
                aes128gcm.Test();
                break;
            case "3":
                var _ = BenchmarkRunner.Run<TestFunctions>();
                break;
            default:
                Console.WriteLine("Unidentified choice, the program is shutting down...");
                Console.WriteLine("Press any key to close this window...");
                Console.ReadLine();
                return;
        }
        Console.WriteLine("Press any key to close this window...");
        Console.ReadLine();
        return;
    }

    public static void LastCheckToBeSure()
    {
        byte[] P = { 0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39 };
        byte[] K = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08 };
        byte[] IV = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
        byte[] A = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2 };
        byte[] Tag = { 0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47 };
        byte[] C = { 0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91 };
        var res = aes128gcm.AES128GCMe(IV, P, A, K);
        if (C.Length != res.CipherText.Length)
        {
            Console.WriteLine("FAIL CIPHER LENGTH");
            return;
        }
        for (int i = 0; i < C.Length; i++)
        {
            if (C[i] != res.CipherText[i])
            {
                Console.WriteLine("FAIL CIPHER");
                return;
            }
        }
        if (Tag.Length != res.Tag.Length)
        {
            Console.WriteLine("FAIL TAG LENGTH");
            return;
        }
        for (int i = 0; i < Tag.Length; i++)
        {
            if (Tag[i] != res.Tag[i])
            {
                Console.WriteLine("FAIL TAG");
                return;
            }
        }
        Console.WriteLine("OK");
    }

    public static void RunTestAlternative()
    {
        Console.WriteLine("Enter the plaintext");
        var p = Console.ReadLine();
        var P = Encoding.UTF8.GetBytes(p);
        Console.WriteLine("Enter the additional data");
        var a = Console.ReadLine();
        var A = Encoding.UTF8.GetBytes(a);
        byte[] K = new byte[16]
        {
            0x98,0xff,0xf6,0x7e,0x64,0xe4,0x6b,0xe5,0xee,0x2e,0x05,0xcc,0x9a,0xf6,0xd0,0x12
        };

        byte[] IV = new byte[12]
        {
            0x2d, 0xfb, 0x42, 0x9a, 0x48, 0x69, 0x7c, 0x34, 0x00, 0x6d, 0xa8, 0x86
        };

        var res = aes128gcm.AES128GCMe(IV, P, A, K);
        var C = res.CipherText;
        var T = res.Tag;

        var _p = aes128gcm.AES128GCMd(IV, C, K, A, T);
        Console.WriteLine("\nText after decryption:");
        Console.WriteLine(Encoding.UTF8.GetString(_p));
    }

    public static void PrintArray(byte[] arr)
    {
        string[] Arr = new string[arr.Length];
        for (int i = 0; i < arr.Length; i++)
        {
            Arr[i] = arr[i].ToString();
        }
        Console.WriteLine(string.Join(' ', Arr));
    }
}

