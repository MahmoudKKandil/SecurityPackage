using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            Dictionary<int, int> d = new Dictionary<int, int>();
            for (int i = 0; i < key.Count; i++)
            {

                d.Add(i, key[i] - 1);
            }
            string plaintext = "";
            int noOfRows = (cipherText.Length + key.Count - 1) / key.Count;//it is round up the result

            for (int i = 0; i < noOfRows; i++)
            {
                int start = d[0];
                for (int j = 0; j < key.Count; j++)
                {

                     plaintext += cipherText[(start * noOfRows) + i];

                    start = j + 1;
                    start %= key.Count;
                    start = d[start];



                }

            }
            return plaintext;
        }
    

        public string Encrypt(string plainText, List<int> key)
        {

            string cipher = "";

            int noOfRows = (plainText.Length + key.Count - 1) / key.Count;
            int noOfCols = key.Count;
            int count = 0;
            Dictionary<int, int> d = new Dictionary<int, int>();
            for (int i = 0; i < key.Count; i++)
            {
                int index = key.FindIndex(a => a.Equals(i + 1));
                d.Add(i, index);
            }

            foreach (var col in d)
            {
                int n = col.Value;
                for (int j = 0; j < noOfRows; j++)
                {
                    if (n >= plainText.Length) { break; }
                    cipher += plainText[n];

                    n += noOfCols;

                }
                count++;
            }

            return cipher;

        
    }
    }
}
