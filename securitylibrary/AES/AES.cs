using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public static string generateNewKey(string key, string rcon)
        {
            string lastColShifted = key.Substring(28, 6);
            lastColShifted += key.Substring(26, 2);
            string lastColSub = "";
            key = key.Substring(2);
            lastColSub += subBytes("0x" + lastColShifted);
            lastColSub = lastColSub.Substring(2);



            string newKey = "0x";
            for (int i = 0; i < 4; i++)
            {
                string s = "";
                for (int j = 0; j < 4; j++)
                {
                    byte KeyCol = Convert.ToByte(key.Substring((i * 8) + (j * 2), 2), 16);
                    byte lastColByte = Convert.ToByte(lastColSub.Substring(j * 2, 2), 16);
                    byte res = (byte)(KeyCol ^ lastColByte);

                    if (i == 0)
                    {
                        byte rconbyte = Convert.ToByte(rcon.Substring(j * 2, 2), 16);
                        res = (byte)(res ^ rconbyte);
                    }
                    if (res.ToString("x").Length == 1) { s += '0'; }
                    s += res.ToString("x");

                }
                lastColSub = s;
                newKey += s;

            }
            return newKey;

        }

        public override string Encrypt(string plainText, string key)
        {
            string newPlain = "";

            newPlain += addRoundKey(plainText.Substring(2), key.Substring(2));
            Console.WriteLine(newPlain.Length);
            plainText = newPlain;

            string[] rcon = { "01000000" , "02000000", "04000000", "08000000", "10000000", "20000000", "40000000",
                "80000000","1b000000","36000000" };
            for (int i = 0; i < 10; i++)
            {

                newPlain = subBytes(plainText);

                plainText = shiftRows(newPlain.Substring(2));

                if (i != 9) newPlain = mixColumns(plainText.Substring(2));
                else newPlain = plainText;
                if (i == 8)
                    Console.WriteLine(plainText.Length);
                key = generateNewKey(key, rcon[i]);
                plainText = addRoundKey(newPlain.Substring(2), key.Substring(2));




            }


            return plainText;

        }
        static string hex2binary(string hexvalue)
        {

            string binarystring = String.Join(String.Empty,
                hexvalue.Select(
                    c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')
                )
            );

            return binarystring;
        }
        static public string addRoundKey(string plainText, string key)
        {
            string hexResult = "";
            for (int i = 0; i < 4; i++)
            {
                long dec1 = Convert.ToInt64(plainText.Substring(i * 8, 8), 16);
                long dec2 = Convert.ToInt64(key.Substring(i * 8, 8), 16);
                long result = dec1 ^ dec2;
                if (result.ToString("x").Length != 8) { hexResult += '0'; }
                hexResult += result.ToString("X");

            }
            return "0x" + hexResult;
        }
        static public string subBytes(string plainText)
        {
            string[,] sBox = new string[16, 16] {  // populate the Sbox matrix
    
      {"63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"},
      {"ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"},
      {"b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15"},
     {"04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"},
      {"09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84"},
      {"53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf"},
      {"d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8"},
      {"51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2"},
      {"cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73"},
     {"60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db"},
     {"e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79"},
     {"e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08"},
     {"ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a"},
      {"70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e"},
      {"e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df"},
      {"8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"} };
            string newPlain = "0x";
            for (int i = 2; i < plainText.Length; i += 2)
            {
                int x = int.Parse("0" + plainText[i], System.Globalization.NumberStyles.HexNumber);
                int y = int.Parse("0" + plainText[i + 1], System.Globalization.NumberStyles.HexNumber);
                newPlain += sBox[x, y];
            }
            return newPlain;

        }
        static public string shiftRows(string plainText)
        {
            string s = "";

            for (int i = 0; i < 4; i++)
            {//divide the matrix into cols

                for (int j = 0; j < 4; j++)
                {
                    s += plainText.Substring((j * 8) + (i * 2), 2);

                }



            }
            string newPlain = "";
            newPlain += s.Substring(0, 8);
            int start = 8;
            for (int i = 1; i < 4; i++)
            {
                string str = s.Substring(start, 8);
                newPlain += str.Substring(i * 2, 8 - (i * 2));
                newPlain += str.Substring(0, i * 2);
                start += 8;


            }
            string last = "0x";
            for (int i = 0; i < 4; i++)
            {

                for (int j = 0; j < 4; j++)
                {
                    last += newPlain.Substring((j * 8) + (i * 2), 2);

                }

            }
            return last;



        }
        static public string mixColumns(string plainText)
        {
            string[] oldcol = new string[4];
            int[][] arr = { new int[] { 2, 3, 1, 1 }, new int[] { 1, 2, 3, 1 }, new int[] { 1, 1, 2, 3 }, new int[] { 3, 1, 1, 2 } };
            for (int j = 0; j < 4; j++)
            {
                string s = "";
                s += plainText.Substring(j * 8, 8);
                oldcol[j] = s;
            }
            string newcol = "";
            for (int outer = 0; outer < 4; outer++)
            {

                for (int i = 0; i < 4; i++)
                {
                    byte res = 0;
                    for (int j = 0; j < 4; j++)
                    {
                        string byteText = oldcol[outer].Substring(j * 2, 2);
                        string binarybyte = hex2binary(byteText);
                        bool usexor = false;
                        if (binarybyte[0] == '1' && arr[i][j] != 1) { usexor = true; }
                        byte numinbyte = Convert.ToByte(byteText, 16);
                        byte holder = numinbyte;
                        if (arr[i][j] != 1)
                            numinbyte <<= 1;
                        if (usexor) numinbyte = (byte)
                               (numinbyte ^ Convert.ToByte("0x1b", 16));
                        if (arr[i][j] == 3)
                        { numinbyte = (byte)(numinbyte ^ holder); }
                        res = (byte)(res ^ numinbyte);
                    }
                    if (res.ToString("x").Length == 1) newcol += '0' + res.ToString("x");
                    else newcol += res.ToString("x");
                }

            }

            return "0x" + newcol;

        }



    }
}