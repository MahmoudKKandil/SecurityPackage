using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = "";
            int nextIndex = (cipherText.Length + key - 1) / key;
            int count = 0;
            while(count<nextIndex)
            {
                int hold = count;
                for (int j = 0; j < key; j++)
                {
                    if (count >= cipherText.Length) { break; }

                    plainText += cipherText[count];
                    count += nextIndex;
                }
                count = hold + 1;
                

            }

            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            string cipher = "";
            int count = 0;
            int secCount = 0;
            for(int i = 0; i <plainText.Length; i++)
            {
                if (count >= plainText.Length) { secCount++;count = secCount; }
                    cipher+= plainText[count];
                    count += key;
                

            }
            return cipher;
        }
    }
}
