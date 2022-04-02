using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string res = "";

            char[] arr1 = new char[cipherText.Length];
            plainText = plainText.ToUpper();
            for (int i = 0; i < cipherText.Length; i++)
            {

                int c = ((cipherText[i] - 'A') - (plainText[i] - 'A')) % 26;
                while (c < 0)
                    c += 26;
                arr1[i] = (char)(c + 'A');

            }
            int ind = 0;
            bool found = false;
            for (int i = 0; i < arr1.Length ; i++)
            {
                if (arr1[i] == plainText[0])
                {
                    ind = i+1;
               
                    for (int j = 1; j < plainText.Length - 1; j++)
                    {
                        if (ind == arr1.Length||j== plainText.Length-1)
                        {
                            found = true;
                            ind = i;
                            break;
                        }
                        if (plainText[j] != arr1[ind])
                            break;
                        ind++;
                    }

                }
                if (found)
                    break;

            }
            if (found)
            {
                for (int i = 0; i < ind; i++)
                    res += arr1[i];
            }
            return res.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            string res = "";
            string keystream = key.ToUpper();
            char[] arr1 = new char[cipherText.Length];

            int index = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (i >= key.Length)
                {
                    
                    keystream += arr1[index];
                    index++;
                }

                int c = ((cipherText[i] - 'A') - (keystream[i] - 'A')) % 26;
                while (c < 0)
                    c += 26;
                arr1[i] = (char)(c + 'A');

            }
            res = new string(arr1);
            return res.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            string res = "";
            string keystream = key;
            char[] arr1 = new char[plainText.Length];
            if (key.Length < plainText.Length)
            {
                int diff = plainText.Length - key.Length;
                int ind = 0;
                for (int i = 0; i < diff; i++)
                {
                    if (ind >= plainText.Length)
                    {

                        ind = 0;

                    }

                    keystream += plainText[ind];
                    ind++;
                }
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] >= 'A' && plainText[i] <= 'Z')
                    arr1[i] = (char)(((plainText[i] - 'A') + (keystream[i] - 'A')) % 26 + 'A');


                if (plainText[i] >= 'a' && plainText[i] <= 'z')
                    arr1[i] = (char)(((plainText[i] - 'a') + (keystream[i] - 'a')) % 26 + 'a');



            }
            res = new string(arr1);
            return res.ToUpper();
        }
    }
}
