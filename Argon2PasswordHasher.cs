//This code is for the Argon2 hashing algorithm with libsodium library.
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace Argon2Hasher
{
        public class Argon2
        {
        private const string Name = "libsodium";
        public const int crypto_pwhash_argon2id_ALG_ARGON2ID13 = 2;
        public const long crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE = 4;
        public const int crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE = 1073741824;

        static Argon2()
        {
            sodium_init();
        }

        [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_init();

        [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void randombytes_buf(byte[] buffer, int size);

        [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash(byte[] buffer, long bufferLen, byte[] password, long passwordLen, byte[] salt, long opsLimit, int memLimit, int alg);

            private byte[] CreateSalt()
        {
            var buffer = new byte[16];
            Argon2.randombytes_buf(buffer, buffer.Length);
            return buffer;
        }

        private byte[] HashPassword(string password, byte[] salt)
        {
            var hash = new byte[16];

            var result = Argon2.crypto_pwhash(
                hash,
                hash.Length,
                Encoding.UTF8.GetBytes(password),
                password.Length,
                salt,
                Argon2.crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE,
                Argon2.crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE,
                Argon2.crypto_pwhash_argon2id_ALG_ARGON2ID13
                );

            if (result != 0)
                throw new Exception("An unexpected error has occurred.");

            return hash;
        }

        private bool VerifyHash(string password, byte[] salt, byte[] hash)
        {
            var newHash = HashPassword(password, salt);
            return newHash.SequenceEqual(hash);
        }

        public void Run()
        {
            Console.Write("Enter password to hash: \n");
            var password = Console.ReadLine();
            var stopwatch = new Stopwatch();
            stopwatch.Start();
            var salt = CreateSalt();
            var hash = HashPassword(password, salt);
            Console.WriteLine($"Hash: {Convert.ToBase64String(hash)}");
            Console.WriteLine($"Salt: {Convert.ToBase64String(salt)}");
            stopwatch.Stop();
            Console.WriteLine($"Time taken: {stopwatch.ElapsedMilliseconds}ms");
            stopwatch.Start();
            Console.Write("Enter password to verify: \n");
            var passwordToVerify = Console.ReadLine();
            var result = VerifyHash(passwordToVerify, salt, hash);
            Console.WriteLine($"Password is {(result ? "valid" : "invalid")}");            
            stopwatch.Stop();
            Console.WriteLine($"Time taken: {stopwatch.ElapsedMilliseconds}ms");
        }
    }
    
    class Program
    {
        static void Main(string[] args)
        {
            var argon2 = new Argon2();
            argon2.Run();
        }
    }
}
