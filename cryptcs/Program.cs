using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace cryptcs
{
    internal class Program
    {
        [DllImport("crypt.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int mm_rsa_generate_pair_key_in_file([In] byte[] _filepath_private_key, [In] byte[] _filepath_public_key, int _bits);
        [DllImport("crypt.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int mm_rsa_encrypt_public_with_key_file([Out] byte[] _crypt, [In] byte[] _plain, [In] byte[] _filepath_key, int _bits);
        [DllImport("crypt.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int mm_rsa_decrypt_private_with_key_file([Out] byte[] _plain, [In] byte[] _crypt, [In] byte[] _filepath_key, int _bits);
        [DllImport("crypt.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int mm_rsa_encrypt_private_with_key_file([Out] byte[] _crypt, [In] byte[] _plain, [In] byte[] _filepath_key, int _bits);
        [DllImport("crypt.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int mm_rsa_decrypt_public_with_key_file([Out] byte[] _plain, [In] byte[] _crypt, [In] byte[] _filepath_key, int _bits);


        public static void print_usage()
        {
            Console.WriteLine("Usage) cryptcs.exe generate_key_pair 2048 private.pem public.pem");
            Console.WriteLine("       cryptcs.exe encrypt_public 2048 public.pem plain");
            Console.WriteLine("       cryptcs.exe decrypt_private 2048 private.pem crypt");
            Console.WriteLine("       cryptcs.exe encrypt_private 2048 private.pem plain");
            Console.WriteLine("       cryptcs.exe decrypt_public 2048 public.pem crypt");
        }


        public static byte[] convert_string_to_bytes(string _str)
        {
            byte[] bytes = Encoding.Default.GetBytes(_str);
            //byte[] bytes = Encoding.UTF8.GetBytes(_str);
            //byte[] bytes = Encoding.GetEncoding(949).GetBytes(_str);
            return bytes;
        }

        public static string convert_bytes_to_string(byte[] _bytes)
        {
            string str = Encoding.Default.GetString(_bytes);
            //string str = Encoding.UTF8.GetString(_bytes);
            //string str = Encoding.GetEncoding(949).GetString(_bytes);
            return str;
        }

        static void Main(string[] args)
        {
            if (args.Length != 4)
            {
                print_usage();
                return;
            }

            byte[] arg2 = convert_string_to_bytes(args[2]);
            byte[] arg3 = convert_string_to_bytes(args[3]);
            for (int ii = 0; ii < args.Length; ++ii)
            {
                Console.WriteLine("parameter[{0}]: [{1}]", ii, args[ii]);
            }

            int bits = int.Parse(args[1]);

            if (args[0] == "generate_key_pair")
            {
                mm_rsa_generate_pair_key_in_file(arg2, arg3, bits);
            }
            else if (args[0] == "encrypt_public")
            {
                byte[] crypt = new byte[bits];
                mm_rsa_encrypt_public_with_key_file(crypt, arg3, arg2, bits);
                Console.WriteLine("Output: [{0}]", convert_bytes_to_string(crypt));
            }
            else if (args[0] == "decrypt_private")
            {
                byte[] plain = new byte[bits];
                mm_rsa_decrypt_private_with_key_file(plain, arg3, arg2, bits);
                Console.WriteLine("Output: [{0}]", convert_bytes_to_string(plain));
            }
            else if (args[0] == "encrypt_private")
            {
                byte[] crypt = new byte[bits];
                mm_rsa_encrypt_private_with_key_file(crypt, arg3, arg2, bits);
                Console.WriteLine("Output: [{0}]", convert_bytes_to_string(crypt));
            }
            else if (args[0] == "decrypt_public")
            {
                byte[] plain = new byte[bits];
                mm_rsa_decrypt_public_with_key_file(plain, arg3, arg2, bits);
                Console.WriteLine("Output: [{0}]", convert_bytes_to_string(plain));
            }
            else
            {
                Console.WriteLine("Invalid command");
            }
        }
    }
}
