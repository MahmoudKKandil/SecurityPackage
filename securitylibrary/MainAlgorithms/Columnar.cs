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
            throw new NotImplementedException();

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
