using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText=cipherText.ToLower();

            // Character array that hold the required to decrypt string with the same length of string
            char[] DecryptedWord = new char[cipherText.Length];

            // For loop that change each key alphabet with the real alphabet
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (cipherText[i] == ' ')
                    DecryptedWord[i] = ' ';
                else
                {

                    // Character = Index key characters array [(character)index + (ascii for letter a)] to get the assci of the character in alphabet
                    int hold = key.IndexOf(cipherText[i]);
                    DecryptedWord[i] = (char)(hold+'a');
                }
            }
            string Decrypted_Word = new string(DecryptedWord);
            return Decrypted_Word;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText.ToLower();

            // Character array that hold the required to encrypt string with the same length of string
            char[] EncryptedWord = new char[plainText.Length];

            // For loop that change each alphabet with the key alphabet
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == ' ')
                    EncryptedWord[i] = ' ';
                else

                    // Character = key characters array [(character)ascii - (ascii for letter a)] to get the index of the character in key
                    EncryptedWord[i] = key[plainText[i] - 'a'];
            }

            string Encrypted_word= new string(EncryptedWord);
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
            throw new NotImplementedException();
        }
    }
}
