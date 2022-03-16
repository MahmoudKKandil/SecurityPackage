using System;
using System.Collections.Generic;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
       
        public string Encrypt(string plainText, int key)
        {
            plainText = plainText.ToUpper();
            string Result;
           char[] arr1 = new char[plainText.Length];
            int ind;
            for (int i = 0; i < plainText.Length; i++)
            {

              ind = plainText[i] - 'A';
                ind= (ind + key) % 26;
                arr1[i] = (char)(ind + 'A');

            }
            Result = new string(arr1);
            return Result;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToUpper();
            string Result;
            char[] arr1 = new char[cipherText.Length];
            int ind;
            for (int i = 0; i < cipherText.Length; i++)
            {

                ind = cipherText[i] - 'A';
                ind = modInverse(ind,key);
                arr1[i] = (char)(ind + 'A');

            }
            Result = new string(arr1);
            return Result;


        }


        static int modInverse(int a, int key)
        {

            a = (a - key) % 26;
            if (a < 0)
                a = a + 26;

            return a;
        }
        public int Analyse(string plainText, string cipherText)
        {
            int result;
            int ind1;
            int ind2;
            cipherText = cipherText.ToUpper();
            plainText = plainText.ToUpper();
            ind1 = cipherText[0] - 'A';
            ind2 = plainText[0] - 'A';
            result = (ind1 - ind2) % 26;
            if (result < 0)
                result = result + 26;
            return result;
        }
    }
}