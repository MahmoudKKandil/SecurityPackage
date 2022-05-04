using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {

            throw new NotImplementedException();
        }
        static public string ConvertHexToAsci(string s)

        {

            string res = String.Empty;

            for (int a = 0; a < s.Length; a = a + 2)

            {

                string Char2Convert = s.Substring(a, 2);

                int n = Convert.ToInt32(Char2Convert, 16);

                char c = (char)n;

                res += c.ToString();

            }

            return res;

        }
        public static string ASCIITOHex(string asciiString)
        {
            StringBuilder builder = new StringBuilder();
            foreach (char c in asciiString)
            {
                builder.Append(Convert.ToInt32(c).ToString("X"));
            }
            return builder.ToString();
        }
        public override  string Encrypt(string plainText, string key)
        {
            bool flag = false;
            if (plainText.Substring(0, 2)=="0x")
            {
                plainText = ConvertHexToAsci(plainText.Remove(0,2));
                key = ConvertHexToAsci(key.Remove(0, 2));
                flag = true;
            }
            int[] S = new int[256];
            for (int i = 0; i < 256; i++)
            { S[i] = i; }
            char[] T = new char[256];
            char[] kk = new char[plainText.Length];
            char[] output = new char[plainText.Length];
            int ind = 0; int size = key.Length;
            for (int i = 0; i < (256 - size); i++)
            {
                if (ind >= key.Length)
                {

                    ind = 0;

                }

                key += key[ind];
                ind++;

            }
            T = key.ToCharArray();
            int j = 0;
            int temp;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                temp = S[i];
                S[i] = S[j];
                S[j] = temp;

            }
            j = 0;
            int I = 0;
            int t;
            for (int k = 0; k < plainText.Length; k++)
            {
                I = (I + 1) % 256;
                j = (j + S[I]) % 256;
                temp = S[I];
                S[I] = S[j];
                S[j] = temp;
                t = (S[I] + S[j]) % 256;
                kk[k] = (char)S[t];
                output[k] = (char)(plainText[k] ^ kk[k]);
              
            }
          
            string res = new string(output);
            if (flag)
            {
                res = ASCIITOHex(res);
                res = "0x" + res;
            }
            return res;
        }
    }
}
