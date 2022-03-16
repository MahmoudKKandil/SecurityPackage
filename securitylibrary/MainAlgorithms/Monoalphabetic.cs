using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText=cipherText.ToLower();
            plainText = plainText.ToLower();
            var key = new char[26];

            for (var i = 0; i < cipherText.Length; i++)
            {
                
                var hold1 = plainText[i]-'a';
                var hold2 = cipherText[i]-'a';
                key[hold1] = (char)('a' +hold2);
            }

            var cur = 'a';
            for (var i = 0; i < key.Length; i++)
                if (key [i]< 'a')
                {
                    while (key.Contains(cur)) 
                        cur++;
                    key[i]  = cur;
                }
            return new string(key);
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            var DecryptedWord = new char[cipherText.Length];

            for (var i = 0; i < cipherText.Length; i++)
                if (cipherText[i] == ' ')
                {
                    DecryptedWord[i] = ' ';
                }
                else
                {

                    var hold = key.IndexOf(cipherText[i]);
                    DecryptedWord[i] = (char)(hold + 'a');
                }

            var Decrypted_Word = new string(DecryptedWord);
            return Decrypted_Word;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();

            var EncryptedWord = new char[plainText.Length];

            for (var i = 0; i < plainText.Length; i++)
                if (plainText[i] == ' ')
                    EncryptedWord[i] = ' ';
                else

                    EncryptedWord[i] = key[plainText[i] - 'a'];

            var Encrypted_word = new string(EncryptedWord);
            return Encrypted_word;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher=cipher.ToLower();
            Dictionary<Char, Double> cipherFreq = new Dictionary<char, double>();
            Dictionary<Char, Double> engFreq = new Dictionary<char, double>();
            Double[] engVal = { 8.04, 1.54, 3.06, 3.99, 12.51, 2.30, 1.96, 5.49, 7.26, 0.16, 0.67, 4.14, 2.53, 7.09, 7.60, 2.00, 0.11, 6.12, 6.54, 9.25, 2.71, 0.99, 1.92, 0.19, 1.73, 0.09 };

            for (char i = 'a'; i <= 'z'; i++)
            {
                engFreq.Add(i, engVal[ (i - 'a')]);
                cipherFreq.Add(i, 0);
            }
            foreach (char a in cipher)
            {
                cipherFreq[a] += 1;
            }

            int cipherLen = cipher.Length;
            for (char i = 'a'; i <= 'z'; i++)
            {
                cipherFreq[i] /= cipherLen;
            }
            var frequenciesInEnglishList = engFreq.ToList();
            frequenciesInEnglishList.Sort((pair1, pair2) => pair1.Value.CompareTo(pair2.Value));

            var frequenciesInCipherList = cipherFreq.ToList();
            frequenciesInCipherList.Sort((pair1, pair2) => pair1.Value.CompareTo(pair2.Value));

            bool[] charReplaced = new bool[cipher.Length];
            StringBuilder plaintext = new StringBuilder(cipher);

            for (int i = 0; i < 26; i++)
            {
                char charInCipher = frequenciesInCipherList[i].Key;
                char charInEnglish = frequenciesInEnglishList[i].Key;
                for (int j = 0; j < cipher.Length; j++)
                {
                    if (plaintext[j] == charInCipher && charReplaced[j] != true)
                    {
                        plaintext[j] = charInEnglish;
                        charReplaced[j] = true;
                    }
                }
            }

            return plaintext.ToString();
        }
    }
}
