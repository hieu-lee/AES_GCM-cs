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

