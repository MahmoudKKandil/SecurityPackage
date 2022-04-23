using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        private static readonly byte[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };

        readonly int[] FP = { 40, 8, 48, 16, 56, 24, 64,
            32, 39, 7, 47, 15, 55,
            23, 63, 31, 38, 6, 46,
            14, 54, 22, 62, 30, 37,
            5, 45, 13, 53, 21, 61,
            29, 36, 4, 44, 12, 52,
            20, 60, 28, 35, 3, 43,
            11, 51, 19, 59, 27, 34,
            2, 42, 10, 50, 18, 58,
            26, 33, 1, 41, 9, 49,
            17, 57, 25 };
        private static readonly byte[] NShiftBits = {
            1, 1, 2, 2, 2, 2, 2, 2,
            1, 2, 2, 2, 2, 2, 2, 1
        };

        readonly int[] EP = { 32, 1, 2, 3, 4, 5, 4,
            5, 6, 7, 8, 9, 8, 9, 10,
            11, 12, 13, 12, 13, 14, 15,
            16, 17, 16, 17, 18, 19, 20,
            21, 20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29, 28,
            29, 30, 31, 32, 1 };

        private static readonly byte[] SBoxPermutation = {
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25
        };
        private static readonly byte[] K1P = {
            57, 49, 41, 33, 25,
            17, 9, 1, 58, 50, 42, 34, 26,
            18, 10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36, 63,
            55, 47, 39, 31, 23, 15, 7, 62,
            54, 46, 38, 30, 22, 14, 6, 61,
            53, 45, 37, 29, 21, 13, 5, 28,
            20, 12, 4
        };

        private static readonly byte[] K2P = {
            14, 17, 11, 24, 1, 5, 3,
            28, 15, 6, 21, 10, 23, 19, 12,
            4, 26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56,
            34, 53, 46, 42, 50, 36, 29, 32
        };
        private static readonly byte[,,] SBox =
        {
            {
                {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
            },
            {
                {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
            },
            {
                {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
            },
            {
                {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
            },
            {
                {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
            },
            {
                {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
            },
            {
                {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
            },
            {
                {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
            }
        };
        public override string Decrypt(string cipherText, string key)
        {
            var permutatedBinary = "";

            var BinaryCipher = hex2binary(cipherText);
            for (int i = 0; i < IP.Length; i++)
                permutatedBinary += BinaryCipher[IP[i] - 1]; //do the initial permutation
            var leftPlain = permutatedBinary.Substring(0, 32);
            var rightPlain = permutatedBinary.Substring(32, 32);

            var BinaryKey = hex2binary(key);
            var NewBinaryKey = Perm(BinaryKey, K1P); //first key permutation

            var leftKey = NewBinaryKey.Substring(0, 28);
            var rightKey = NewBinaryKey.Substring(28, 28);
            List<string> ll=new List<string>();
            for (int nRound = 15; nRound >= 0; nRound--)
            {

                var fullkey = leftKey + rightKey;
                ll.Add(binary2hex(fullkey));
                var KeySecondPerm = Perm(fullkey, K2P);//second key permutation

                var expandedRight = Perm(rightPlain, EP);//do the expansion permutation

                var temp = XorString(KeySecondPerm, expandedRight);
                var sboxtemp = Sbox(temp);
                var permutationTemp = Perm(sboxtemp, SBoxPermutation);//do the expansion permutation

                leftPlain = XorString(leftPlain, permutationTemp);
               // swap(ref leftPlain,ref rightPlain);
               leftKey = ShiftRightString(leftKey, NShiftBits[nRound]);
               rightKey = ShiftRightString(rightKey, NShiftBits[nRound]);

            }
            //swap(ref leftPlain, ref rightPlain);            //last swap

            cipherText = leftPlain + rightPlain;
            string result = Perm(cipherText, FP);//inv initial permutation

            return binary2hex(result);
        }

        private static string Sbox(string temp)
        {
            string result = "";
            for (int i = 0; i < 8; i++)
            {
                var block = temp.Substring(i*6, 6);
                var row = Convert.ToInt32(new string(new[] { block[0], block[5] }), 2);
                var column = Convert.ToInt32(block.Substring(1, 4),2);
                result += Convert.ToString(SBox[i, row, column],2).PadLeft(4,'0');
            }

            return result;
        }
        public override string Encrypt(string plainText, string key)
        {
            var BinaryPlain = hex2binary(plainText);
            var permutatedBinary = "";
            for (int i = 0; i < IP.Length; i++)
                permutatedBinary += BinaryPlain[IP[i] - 1]; //do the initial permutation
            var leftPlain = permutatedBinary.Substring(0, 32);
            var rightPlain = permutatedBinary.Substring(32, 32);
            var BinaryKey = hex2binary(key);
            var NewBinaryKey = Perm(BinaryKey, K1P); //first key permutation
        
            var leftKey = NewBinaryKey.Substring(0, 28);
            var rightKey = NewBinaryKey.Substring(28, 28);
            List<string> ll = new List<string>();

            for (int nRound = 0; nRound < 16; nRound++)
            {
              
                leftKey = ShiftLeftString(leftKey, NShiftBits[nRound]);
                rightKey = ShiftLeftString(rightKey, NShiftBits[nRound]);
                var fullkey = leftKey + rightKey;
                var KeySecondPerm = Perm(fullkey, K2P);//second key permutation

                ll.Add(binary2hex(fullkey));
                var expandedRight = Perm(rightPlain,EP);//do the expansion permutation

                var temp = XorString(KeySecondPerm, expandedRight);
                var sboxtemp = Sbox(temp);
                var permutationTemp = Perm(sboxtemp,SBoxPermutation);//do the expansion permutation

                leftPlain = XorString(leftPlain, permutationTemp);

                swap(ref leftPlain,ref rightPlain);

            }

            swap(ref leftPlain, ref rightPlain);            //last swap
            plainText = leftPlain + rightPlain;
            string result = Perm(plainText,FP);//inv initial permutation

            return binary2hex(result);
        }

        private static string Perm(string orig,int[] arr)
        {
            var res = "";
            for (int i = 0; i < arr.Length; i++)
                res += orig[arr[i] - 1];
            return res;
        }
        private static string Perm(string orig, byte[] arr)
        {
            var res = "";
            for (int i = 0; i < arr.Length; i++)
                res += orig[arr[i] - 1];
            return res;
        }
        public void swap(ref string p, ref string q)
        {

            string temp;

            temp = p;

            p = q;

            q = temp;

        }
        public static string ShiftLeftString(string t, int n = 1)
        {
            var result = t;
            for (var i = 0; i < n; i++)
                result = result.Substring(1, t.Length - 1) + result.Substring(0, 1);
            return result;

        }
        public static string ShiftRightString(string t, int n = 1)
        {
            var result = t;
            for (var i = 0; i < n; i++)
                result = result.Substring(t.Length - 2, 1) + result.Substring(0, t.Length - 1);
            return result;

        }
        private static string XorString(string a, string b)
        {
            string ans = "";

            // Loop to iterate over the
            // Binary Strings
            for (int i = 0; i < a.Length; i++)
            {
                // If the Character matches
                if (a[i] == b[i])
                    ans += "0";
                else
                    ans += "1";
            }
            return ans;
        }
        private string hex2binary(string hexvalue)
        {
            string binarystring = String.Join(String.Empty,
                hexvalue.Replace("0x", "").Select(
                    c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')
                )
            );

            return binarystring;
        }
        private string binary2hex(string binaryvalue)
        {

            var hex = string.Join("",
                Enumerable.Range(0, binaryvalue.Length / 8)
                    .Select(i => Convert.ToByte(binaryvalue.Substring(i * 8, 8), 2).ToString("X2")));
            return "0x"+hex;
        }
    }
}
