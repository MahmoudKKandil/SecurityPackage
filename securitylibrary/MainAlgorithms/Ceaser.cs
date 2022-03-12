using System;
using System.Collections.Generic;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        Dictionary<Char, int> Dictionary1 =
    new Dictionary<Char, int>();
        Dictionary<Char, int> Dictionary2 =
   new Dictionary<Char, int>();
        int c;
        int c2;

        public Ceaser()
        {
            c = 65;//ascii of letter (A)
            c2 = 97;//ascii of letter (a)
            for (int i = 0; i < 26; i++)
            {

                Dictionary1.Add(Convert.ToChar(c), i);
                Dictionary2.Add(Convert.ToChar(c2), i);
                c += 1;
                c2 += 1;

            }
        }


        public string Encrypt(string plainText, int key)
        {
            string Result;
            bool found = false;
            int[] arr1 = new int[plainText.Length];
            char[] arr2 = new char[plainText.Length];
            for (int i = 0; i < plainText.Length; i++)
            {
                if (Dictionary1.ContainsKey(plainText[i]))
                {
                    arr1[i] = Dictionary1[plainText[i]];
                    found = true;
                }
                else
                    arr1[i] = Dictionary2[plainText[i]];
                arr1[i] = (arr1[i] + key) % 26;

                if (found)//Capital letter
                {
                    foreach (var pair in Dictionary1)
                    {
                        if (pair.Value == arr1[i])
                        {
                            arr2[i] = pair.Key;
                        }
                    }
                }
                else //small letter
                {
                    foreach (var pair in Dictionary2)
                    {
                        if (pair.Value == arr1[i])
                        {
                            arr2[i] = pair.Key;
                        }
                    }
                }


            }
            Result = new string(arr2);
            return Result;
        }

        public string Decrypt(string cipherText, int key)
        {

            string Result;
            bool found = false;
            int[] arr1 = new int[cipherText.Length];
            char[] arr2 = new char[cipherText.Length];
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (Dictionary1.ContainsKey(cipherText[i]))
                {
                    arr1[i] = Dictionary1[cipherText[i]];
                    found = true;
                }
                else
                    arr1[i] = Dictionary2[cipherText[i]];
                arr1[i] = modInverse(arr1[i], key);



                if (found)//Capital letter
                {
                    foreach (var pair in Dictionary1)
                    {
                        if (pair.Value == arr1[i])
                        {
                            arr2[i] = pair.Key;
                        }
                    }
                }
                else //small letter
                {
                    foreach (var pair in Dictionary2)
                    {
                        if (pair.Value == arr1[i])
                        {
                            arr2[i] = pair.Key;
                        }
                    }
                }


            }
            Result = new string(arr2);
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

            int a1, a2;

            if (Dictionary1.ContainsKey(plainText[0]))
                a1 = Dictionary1[plainText[0]];

            else
                a1 = Dictionary2[plainText[0]];

            if (Dictionary1.ContainsKey(cipherText[0]))
                a2 = Dictionary1[cipherText[0]];

            else
                a2 = Dictionary2[cipherText[0]];

            result = (a2- a1) % 26;
            if (result < 0)
                result = result + 26;

            return result;

        }
    }
}