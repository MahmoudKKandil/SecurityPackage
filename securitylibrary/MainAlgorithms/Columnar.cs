using System.Collections.Generic;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            List<int> key=new List<int>();
            cipherText= cipherText.ToLower();
            int keyLength = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                string toFind = plainText[0].ToString() + plainText[i +0] + plainText[2*i+0];
                if (cipherText.Contains(toFind))
                {
                    string toFind2 = plainText[1].ToString() + plainText[i+1] + plainText[(i*2) +1];
                    if (cipherText.Contains(toFind2))
                    {
                        keyLength = i;
                        break;
                    }
                   
                }
            }
            int oWordLength = cipherText.Length / keyLength;
            for (int i = 0; i < keyLength; i++)
            {
                string toFind = plainText[i].ToString() + plainText[i + keyLength] + plainText[i +(2* keyLength)];
                key.Add((cipherText.IndexOf(toFind)/oWordLength)+1);
            }
            return key;
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
