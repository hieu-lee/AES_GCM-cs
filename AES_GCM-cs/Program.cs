using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using System;
using System.Threading.Tasks;

namespace AES_GCM_cs
{
    [MemoryDiagnoser]
    public class Program
    {
        [Benchmark]
        public void TestAES1()
        {
            var Key = new byte[16]
            {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b,
                0x0c, 0x0d, 0x0e, 0x0f
            };

            var Input = new byte[16]
            {
                0x00, 0x11, 0x22, 0x33,
                0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb,
                0xcc, 0xdd, 0xee, 0xff
            };

            aes128.AES128E(Input, Key);
        }

        [Benchmark]
        public void TestAES2()
        {
            var Key = new byte[16]
            {
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b,
                0x0c, 0x0d, 0x0e, 0x0f
            };

            var Input = new byte[16]
            {
                0x00, 0x11, 0x22, 0x33,
                0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb,
                0xcc, 0xdd, 0xee, 0xff
            };

            var C = new byte[16];
            aes128e.AES128E(Input, Key, C);
        }

        static void RunTest()
        {
            Console.WriteLine("Please choose one of the 3 following choices.");
            Console.WriteLine("What do you want to see?");
            Console.WriteLine("1. Test result of AES128");
            Console.WriteLine("2. Test result of AES128GCM");
            Console.WriteLine("3. Performance comparision between my AES128 implementation and the given implementation online");
            Console.Write("Choose a number from 1 to 3: ");
            var s = Console.ReadLine();
            s = s.Trim();
            switch(s)
            {
                case "1":
                    aes128.Test();
                    break;
                case "2":
                    aes128gcm.Test();
                    break;
                case "3":
                    var summary = BenchmarkRunner.Run<Program>();
                    break;
                default:
                    Console.WriteLine("Unidentified choice, the program is shutting down...");
                    Console.WriteLine("Press any key to close this window...");
                    Console.ReadLine();
                    return;
            }
        }

        // Uncomment the line RunTest() to see some test results
        static void Main(string[] args)
        {
            // RunTest();
        }
    }
}
