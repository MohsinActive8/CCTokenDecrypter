using CCTokenDecrypter.Helper;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace CCTokenDecrypter.Utility
{
    public class Security
    {
        private static readonly int _primeEven = 89989;
        private static readonly int _primeOdd = 89527;
        private static readonly int _primeStatic = 95273;

        /// <summary>
        /// Uses TripleDESCryptoServiceProvider to encrypt based upon the given key. Different
        /// keys provide different results for the same plaintext variable.
        /// </summary>
        /// <param name="plaintext"> Text to encrypt. </param>
        /// <param name="key"></param>
        /// <returns>
        /// An encrypted string (about 3x the length of the given string) or the error message:
        /// "Failed to encrypt."
        /// </returns>
        public static string Encrypt(string plaintext, string key)
        {
            if (string.IsNullOrEmpty(plaintext))
            {
                return "";
            }

            try
            {
                TripleDESCryptoServiceProvider tripleDes = new TripleDESCryptoServiceProvider();

                // Initialize the crypto provider.
                tripleDes.Key = TruncateHash(key, tripleDes.KeySize / 8);
                tripleDes.IV = TruncateHash("", tripleDes.BlockSize / 8);

                // Convert the plaintext string to a byte array.
                byte[] plaintextBytes = Encoding.Unicode.GetBytes(plaintext);

                // Create the stream
                MemoryStream ms = new MemoryStream();
                // Create the encoder to write to the stream.
                CryptoStream encStream = new CryptoStream(ms, tripleDes.CreateEncryptor(), CryptoStreamMode.Write);

                // Use the crypto stream to write the byte array to the stream.
                encStream.Write(plaintextBytes, 0, plaintextBytes.Length);
                encStream.FlushFinalBlock();

                // Convert the encrypted stream to a printable string.
                return Convert.ToBase64String(ms.ToArray());
            }
            catch (Exception ex)
            {
                return "Failed to encrypt.";
            }
        }

        /// <summary>
        /// Uses TripleDESCryptoServiceProvider to decrypt based upon the given key. If it
        /// fails, it assumes the key is off.
        /// </summary>
        /// <param name="ciphertext"> Encrypted text to decrypt. </param>
        /// <param name="key"> Key used during encryption. </param>
        /// <returns> Decrypted value or the error message: "Failed to decrypt." </returns>
        public static string Decrypt(string ciphertext, string key)
        {
            if (string.IsNullOrEmpty(ciphertext))
            {
                return "";
            }

            try
            {
                TripleDESCryptoServiceProvider tripleDes = new TripleDESCryptoServiceProvider();

                // Initialize the crypto provider.
                tripleDes.Key = TruncateHash(key, tripleDes.KeySize / 8);
                tripleDes.IV = TruncateHash("", tripleDes.BlockSize / 8);

                // Convert the encrypted text string to a byte array.
                byte[] encryptedBytes = Convert.FromBase64String(ciphertext);

                // Create the stream.
                MemoryStream ms = new MemoryStream();
                // Create the decoder to write to the stream.
                CryptoStream decStream = new CryptoStream(ms, tripleDes.CreateDecryptor(), CryptoStreamMode.Write);

                // Use the crypto stream to write the byte array to the stream.
                decStream.Write(encryptedBytes, 0, encryptedBytes.Length);
                decStream.FlushFinalBlock();

                // Convert the plaintext stream to a string.
                return Encoding.Unicode.GetString(ms.ToArray());
            }
            catch (Exception ex)
            {
                return "Failed to decrypt.";
            }
        }

        /// <summary>
        /// Decrypts an AES encrypted string.
        /// </summary>
        /// <param name="ciphertext"> Encrypted text to decrypt. </param>
        /// <param name="key"> Key used during encryption. </param>
        /// <returns> Decrypted value." </returns>
        public static string DecryptAES(string cipherText, string key = "57UETT8lqFbaODExoxmFD2pj5bAmYcFPI7l1BpCojV4=")
        {
            using (var riAlg = new RijndaelManaged())
            {
                riAlg.Mode = CipherMode.CBC;
                riAlg.Padding = PaddingMode.PKCS7;
                riAlg.FeedbackSize = 128;
                riAlg.Key = Convert.FromBase64String(key);
                riAlg.IV = Convert.FromBase64String("24Mhelw/4/l894u442RUjA==");

                var decryptor = riAlg.CreateDecryptor(riAlg.Key, riAlg.IV);

                string plainText;
                using (var memoryStream = new MemoryStream(Convert.FromBase64String(cipherText)))
                {
                    using (var cyrptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (var reader = new StreamReader(cyrptoStream))
                        {
                            plainText = reader.ReadToEnd();
                        }
                    }
                }

                return plainText;
            }
        }

        /// <summary>
        /// Uses a modern and fast AES encryption based upon the given key.
        /// </summary>
        /// <param name="plaintext"> Text to encrypt. </param>
        /// <param name="key"></param>
        /// <returns>
        /// An encrypted string 
        /// </returns>
        public static string EncryptAES(string plainText, string key = "57UETT8lqFbaODExoxmFD2pj5bAmYcFPI7l1BpCojV4=")
        {
            using (var riAlg = new RijndaelManaged())
            {
                riAlg.Mode = CipherMode.CBC;
                riAlg.Padding = PaddingMode.PKCS7;
                riAlg.FeedbackSize = 128;
                riAlg.Key = Convert.FromBase64String(key);
                riAlg.IV = Convert.FromBase64String("24Mhelw/4/l894u442RUjA==");

                var encryptor = riAlg.CreateEncryptor(riAlg.Key, riAlg.IV);

                byte[] encrypted;
                using (var memoryStream = new MemoryStream())
                {
                    using (var cyrptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (var reader = new StreamWriter(cyrptoStream))
                        {
                            reader.Write(plainText);
                        }
                        encrypted = memoryStream.ToArray();
                    }
                }

                return Convert.ToBase64String(encrypted);
            }
        }

        public static T DecryptObject<T>(string cipherText)
        {
            return JsonConvert.DeserializeObject<T>(DecryptAES(cipherText));
        }

        public static string EncryptObject(object plainObject)
        {
            return EncryptAES(JsonConvert.SerializeObject(plainObject));
        }

        public static string GetUriToken(object plainObject)
        {
            return Uri.EscapeDataString(EncryptObject(plainObject));
        }

        public static string HmacHash(string data, string key)
        {
            HMAC hmacSha256 = new HMACSHA256(Encoding.UTF8.GetBytes(key));
            byte[] hmacData = hmacSha256.ComputeHash(Encoding.UTF8.GetBytes(data));

            string hex = BitConverter.ToString(hmacData);
            hex = hex.Replace("-", "").ToLower();
            byte[] hexArray = Encoding.UTF8.GetBytes(hex);
            return Convert.ToBase64String(hexArray);
        }

        /// <summary>
        /// Hashes a strng with MD5 encryption.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string Md5Hash(string input)
        {
            MD5 md5Hasher = MD5.Create();
            byte[] data = md5Hasher.ComputeHash(Encoding.Default.GetBytes(input));
            StringBuilder sBuilder = new StringBuilder();

            foreach (byte b in data)
            {
                sBuilder.Append(b.ToString("x2"));
            }

            return sBuilder.ToString();
        }

        public static bool VerifyMd5Hash(string input, string hash)
        {
            Regex isMD5 = new Regex("[0-9a-fA-F]{32}");
            string hashOfInput = "";

            if (isMD5.IsMatch(input))
            {
                hashOfInput = input;
            }
            else
            {
                hashOfInput = Md5Hash(input);
            }

            return hashOfInput.Equals(hash, StringComparison.InvariantCultureIgnoreCase);
        }

        /// <summary>
        /// Hashes a string with via the Sha256 algorithm.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string Sha256Hash(string input)
        {
            SHA256 sha256Hasher = SHA256Managed.Create();
            byte[] data = sha256Hasher.ComputeHash(Encoding.UTF8.GetBytes(input));

            StringBuilder sBuilder = new StringBuilder();

            foreach (byte b in data)
            {
                sBuilder.Append(b.ToString("x2"));
            }

            return sBuilder.ToString();
        }

        private static byte[] TruncateHash(string key, int length)
        {
            // Create a SHA1 hash algorithm
            SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();

            // Hash the key.
            byte[] keyBytes = Encoding.Unicode.GetBytes(key);
            byte[] hash = sha1.ComputeHash(keyBytes);

            // Buffer or truncate the final hash size so it fits with the crypto class
            byte[] finalhash = new byte[length];
            Buffer.BlockCopy(hash, 0, finalhash, 0, hash.Length <= length ? hash.Length : length);

            return finalhash;
        }

        public static string Rfc2898(string toHash, int pk)
        {
            byte[] results = ComputeRfc2898Hash(toHash, pk);

            return results.ToNormalString();
        }

        private static byte[] ComputeRfc2898Hash(string toHash, int pk)
        {
            // get salt
            byte[] salt = GetSalt(pk);

            // determine iterations
            int iterations = pk;
            const int max = 70000;
            const int min = 50000;

            int magicNumber = Convert.ToInt32((max - min) * (Math.E * 523) / (Math.PI * 571));

            if (iterations >= max)
            {
                iterations = iterations % min;
            }

            while (iterations <= min)
            {
                iterations += magicNumber;
            }

            return ComputeRfc2898(Encoding.Default.GetBytes(toHash), salt, iterations);
        }

        private static byte[] GetSalt(int pk)
        {
            // if even
            if ((pk % 2) == 0)
            {
                // Prime Multipication
                byte[] innerPw = Encoding.Default.GetBytes((_primeOdd * pk).ToString());
                byte[] innerSalt = Encoding.Default.GetBytes((_primeEven * _primeStatic).ToString());

                // hash(pk * even, hash(odd * pk, even * static)) based on above
                return HashMD5(Encoding.Default.GetBytes((pk * _primeEven).ToString()), HashMD5(innerPw, innerSalt));
            }
            else // if odd
            {
                // Prime Multipication
                byte[] innerPw = Encoding.Default.GetBytes((_primeEven * pk).ToString());
                byte[] innerSalt = Encoding.Default.GetBytes((_primeOdd * _primeStatic).ToString());

                // hash(pk * odd, hash(even * pk, odd * static)) based on above
                return HashMD5(Encoding.Default.GetBytes((pk * _primeOdd).ToString()), HashMD5(innerPw, innerSalt));
            }
        }

        private static byte[] HashMD5(byte[] pw, byte[] salt)
        {
            HMACMD5 hmacMd5 = new HMACMD5(salt);
            return hmacMd5.ComputeHash(pw);
        }

        private static byte[] ComputeRfc2898(byte[] pw, byte[] salt, int rounds)
        {
            using (Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(pw, salt, rounds))
            {
                return rfc2898.GetBytes(128);
            }
        }
    }
}
