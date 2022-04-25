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
            string[] keys = new string[11];
            keys[0] = key;
            string[] rcon = { "01000000" , "02000000", "04000000", "08000000", "10000000", "20000000", "40000000",
                "80000000","1b000000","36000000" };
            for (int i = 1; i < keys.Length; i++)
            { keys[i] = generateNewKey(keys[i - 1], rcon[i - 1]); }

            for (int i = keys.Length - 1; i > 0; i--)
            {
                cipherText = addRoundKey(cipherText.Substring(2), keys[i].Substring(2));
                if (i != 10) cipherText = inversemixColumns(cipherText.Substring(2));
                cipherText = inverseshiftRows(cipherText.Substring(2));
                cipherText = inversesubBytes(cipherText);
            }
            cipherText = addRoundKey(cipherText.Substring(2), keys[0].Substring(2));
            return cipherText;
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
        static public string inverseshiftRows(string plainText)
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
            for (int i = 3; i > 0; i--)
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
        static public string inversesubBytes(string plainText)
        {
            string[,] isBox = new string[16, 16] {  // populate the Sbox matrix
    
      {"52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb"},
      {"7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb"},
    {"54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e"},
     {"08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25"},
     {"72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92"},
      {"6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84"},
    {"90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06"},
      {"d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b"},
      {"3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73"},
      {"96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e"},
      {"47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b"},
    {"fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4"},
     {"1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f"},
     {"60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef"},
      {"a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61"},
      {"17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d"} };
            string newPlain = "0x";
            for (int i = 2; i < plainText.Length; i += 2)
            {
                int x = int.Parse("0" + plainText[i], System.Globalization.NumberStyles.HexNumber);
                int y = int.Parse("0" + plainText[i + 1], System.Globalization.NumberStyles.HexNumber);
                newPlain += isBox[x, y];
            }
            return newPlain;

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
                int len = result.ToString("x").Length;
                while (len != 8)
                { hexResult += '0'; ++len; }
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


        static public string inversemixColumns(string plainText)
        {
            string[] oldcol = new string[4];
            int[][] arr = { new int[] { 14, 11, 13, 9 }, new int[] { 9, 14, 11, 13 }, new int[] { 13, 9, 14, 11 }, new int[] { 11, 13, 9, 14 } };

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
                        byte numinbyte = 0;
                        byte holder = Convert.ToByte(byteText, 16);
                        if (arr[i][j] == 9)
                        {
                            numinbyte = checklastBitandshift(byteText);
                            numinbyte = checklastBitandshift(numinbyte.ToString("x"));
                            numinbyte = checklastBitandshift(numinbyte.ToString("x"));
                            numinbyte ^= holder;

                        }
                        else if (arr[i][j] == 11)
                        {
                            numinbyte = checklastBitandshift(byteText);
                            numinbyte = checklastBitandshift(numinbyte.ToString("x"));
                            numinbyte ^= holder;
                            numinbyte = checklastBitandshift(numinbyte.ToString("x"));
                            numinbyte ^= holder;

                        }
                        else if (arr[i][j] == 13)
                        {
                            numinbyte = checklastBitandshift(byteText);
                            numinbyte ^= holder;
                            numinbyte = checklastBitandshift(numinbyte.ToString("x"));
                            numinbyte = checklastBitandshift(numinbyte.ToString("x"));
                            numinbyte ^= holder;

                        }
                        else
                        {
                            numinbyte = checklastBitandshift(byteText);
                            numinbyte ^= holder;
                            numinbyte = checklastBitandshift(numinbyte.ToString("x"));
                            numinbyte ^= holder;
                            numinbyte = checklastBitandshift(numinbyte.ToString("x"));

                        }
                        res = (byte)(res ^ numinbyte);
                    }
                    if (res.ToString("x").Length == 1) newcol += '0' + res.ToString("x");
                    else newcol += res.ToString("x");
                }

            }

            return "0x" + newcol;

        }
        static public byte checklastBitandshift(string bytetext)
        {
            if (bytetext.Length == 1) bytetext = "0" + bytetext;
            bool usexor = false;
            byte holder = Convert.ToByte(bytetext, 16);
            string binarybyte = hex2binary(bytetext);
            if (binarybyte[0] == '1') usexor = true;


            byte numinbyte = Convert.ToByte(bytetext, 16);
            numinbyte <<= 1;
            if (usexor) numinbyte = (byte)(numinbyte ^ Convert.ToByte("0x1b", 16));
            return numinbyte;
        }


    }
}