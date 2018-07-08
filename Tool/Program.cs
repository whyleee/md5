// C# port of md5main.c https://sourceforge.net/projects/libmd5-rfc/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
namespace Tool
{
    class Program
    {
        private static readonly string usage =
@"Usage:
    md5main --test		# run the self-test (A.5 of RFC 1321)
    md5main --t-values		# print the T values for the library
    md5main --version		# print the version of the package
";
        private static readonly string version = "2002-04-13";
        private static IList<TestCase> testCases = new List<TestCase>
        {
            new TestCase { Input = "", Hash = "d41d8cd98f00b204e9800998ecf8427e" },
            new TestCase { Input = "a", Hash = "0cc175b9c0f1b6a831c399e269772661" },
            new TestCase { Input = "abc", Hash = "900150983cd24fb0d6963f7d28e17f72" },
            new TestCase { Input = "message digest", Hash = "f96b697d7cb7938d525a2f31aaf161d0" },
            new TestCase { Input = "abcdefghijklmnopqrstuvwxyz", Hash = "c3fcd3d76192e4007dfb496cca67e13b" },
            new TestCase { Input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", Hash = "d174ab98d277d9f5a5611c2c9f419d9f" },
            new TestCase { Input = "12345678901234567890123456789012345678901234567890123456789012345678901234567890", Hash = "57edf4a22be3c955ac49da2e2107b67a" }
        };

        static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine(usage);
                return;
            }

            var command = args.First();

            if (command == "--test")
            {
                var status = Test();
                Environment.Exit(status);
            }
            if (command == "--t-values")
            {
                PrintValues();
                return;
            }
            if (command == "--version")
            {
                Console.WriteLine(version);
                return;
            }
        }

        private static int Test()
        {
            var status = 0;

            foreach (var testCase in testCases)
            {
                var inputBytes = Encoding.ASCII.GetBytes(testCase.Input);
                var hashBytes = libmd5.Md5.ComputeHash(inputBytes);
                var hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

                if (hash != testCase.Hash)
                {
                    Console.WriteLine($"MD5 (\"{testCase.Input}\") = {hash}");
                    Console.WriteLine($"**** ERROR, should be: {testCase.Hash}");
                    status = 1;
                }
            }

            if (status == 0)
            {
                Console.WriteLine("md5 self-test completed successfully.");
            }

            return status;
        }

        private static void PrintValues()
        {
            for (var i = 0; i <= 64; ++i)
            {
                var v = (ulong) (4294967296.0 * Math.Abs(Math.Sin(i)));

                if (v >> 31 != 0)
                {
                    Console.WriteLine($"#define T{i} /* 0x{v:x8} */ (T_MASK ^ 0x{(ulong)(uint)~v:x8})");
                } else {
                    Console.WriteLine($"#define T{i}    0x{v:x8}");
                }
            }
        }
    }

    class TestCase
    {
        public string Input { get; set; }
        public string Hash { get; set; }
    }
}
