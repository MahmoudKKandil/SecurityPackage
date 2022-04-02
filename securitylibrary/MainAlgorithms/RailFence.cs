namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int key=0;
            cipherText = cipherText.ToLower();
            for (int i = 1; i < plainText.Length; i++)
            {
                if (plainText[i]==cipherText[1])
                {
                    if (plainText[i*2]==cipherText[2])
                    {
                        return i;
                    }
                }
            }
            return key;
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
