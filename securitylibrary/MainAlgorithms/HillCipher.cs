using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
       
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }

        static int modInverse(int a, int n)
        {
            int i = n, v = 0, d = 1;
            while (a > 0)
            {
                int t = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if (v < 0) v = (v + n) % n;
            return v;
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int det;
            List<int> arr = new List<int>();
            List<int> arrInv = new List<int>();
            int m = (int)Math.Sqrt(key.Count);
            //calc det
            if (m == 2)
            {
                  det = key[0] * key[3] - key[1] * key[2];
                arrInv.Add((1 / det) * key[3]);
                arrInv.Add(((1 / det) * -1 * key[1])+26);
                arrInv.Add(((1 / det) * -1 * key[2]) + 26);
                arrInv.Add((1 / det) * key[0]);

            }
            else
            {
                det = key[0] * (key[4] * key[8] - key[5] * key[7]) -
                   key[1] * (key[8] * key[3] - key[5] * key[6])
                   + key[2] * (key[7] * key[3] - key[4] * key[6]);

                det = (det % 26);
                //Console.WriteLine(det);
                if (det < 0)
                    det = det + 26;
                if (det == 0 || gcd(det, 26) != 1)
                    throw new NotImplementedException();


                //inverse 3*3
                //calc b
                int b;
                float c;
                int l = 1;
                int index;
                //c = 1 / (26 - det);
                //if (1 % (26 - det) != 0)
                //{
                //    c = (26 * l + 1) / (26 - det);
                //    while (((26 * l + 1) % (26 - det)) != 0)
                //    {

                //        c = (26 * l + 1) / (26 - det);
                //        l++;

                //    }
                //    c = (26 * l + 1) / (26 - det);
                //}

                //b = (int)(26 - c);
                b = modInverse(det,26);
                //k inverse matrix 
                arr.Add(((b * (int)Math.Pow(-1, 0 + 0)*(key[4] * key[8] - key[5] * key[7]))%26) % 26);
                arr.Add(((b * (int)Math.Pow(-1, 0 + 1) * (key[8] * key[3] - key[5] * key[6])) % 26) % 26);
                arr.Add(((b * (int)Math.Pow(-1, 0 + 2) * (key[3] * key[7] - key[4] * key[6])) % 26) % 26);
                arr.Add(((b * (int)Math.Pow(-1, 1 + 0) * (key[1] * key[8] - key[2] * key[7])) % 26) % 26);
                arr.Add(((b * (int)Math.Pow(-1, 1 + 1) * (key[0] * key[8] - key[2] * key[6])) % 26) % 26);
                arr.Add(((b * (int)Math.Pow(-1, 1 + 2) * (key[0] * key[7] - key[1] * key[6])) % 26) % 26);
                arr.Add(((b * (int)Math.Pow(-1, 2 + 0) * (key[1] * key[5] - key[2] * key[4])) % 26) % 26);
                arr.Add(((b * (int)Math.Pow(-1, 2 + 1) * (key[0] * key[5] - key[2] * key[3])) % 26) % 26);
                arr.Add(((b * (int)Math.Pow(-1, 2 + 2) * (key[0] * key[4] - key[3] * key[1])) % 26) % 26);
                for (int i = 0; i <  m; i++)
                {
                    index = i;
                    for (int j = 0; j < m ; j++)
                    {
                        if (arr[index] < 0)
                            arr[index] = arr[index] + 26;
                        arrInv.Add(arr[index]);
                        index += m;

                    }
                   
                }

            }

           return Encrypt( cipherText, arrInv);
        }
        static int gcd(int a, int b)
        {

            // Everything divides 0
            if (a == 0)
                return b;
            if (b == 0)
                return a;

            // base case
            if (a == b)
                return a;

            // a is greater
            if (a > b)
                return gcd(a - b, b);

            return gcd(a, b - a);
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> arr = new List<int>();
            int m = (int)Math.Sqrt(key.Count);
            int res=0;
            int z;
            int ind;
            for (int i = 0; i < plainText.Count; i = i + m)
            {
                ind = i;
                z = 0;
                for (int j = 0; j < m; j++) {
                   
                    for (int k = 0; k < m; k++)
                    {
                        res += plainText[ind] * key[z];
                        z++;
                        ind++;
                       
                    }
                    arr.Add(res % 26);
                    res = 0;
                    ind = i;
            }
            }
            return arr;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }


        //bonus
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }


        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }



        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }



        public string Analyse3By3Key(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

    }
}
