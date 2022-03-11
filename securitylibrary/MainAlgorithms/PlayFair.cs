using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        static Dictionary<char, Coords> createDectionary(string key)
        {
            Dictionary<char, Coords> dictionary = new Dictionary<char, Coords>();
            int index = 0;
            char alpha = 'a';
            for (int y = 0; y < 5; y++)
            {
                for (int x = 0; x < 5; x++)
                {
                    while (index < key.Length && dictionary.ContainsKey(key[index])) { index++; }
                    if (index < key.Length && !dictionary.ContainsKey(key[index])) { dictionary.Add(key[index], new Coords(x, y)); index++; }

                    else
                    {
                        if (!dictionary.ContainsKey(alpha)) { dictionary.Add(alpha, new Coords(x, y)); alpha++; }

                        else
                        {
                            while (dictionary.ContainsKey(alpha))
                            {
                                alpha++;
                            }
                            dictionary.Add(alpha, new Coords(x, y));
                        }
                    }
                    if (key[index - 1] == 'i' || alpha == 'i') { dictionary.Add('j', new Coords(x, y)); }
                    if (key[index - 1] == 'j' || alpha == 'j') { dictionary.Add('i', new Coords(x, y)); }

                }
            }
            return dictionary;
        }
        public struct Coords
        {
            public Coords(int x, int y)
            {
                X = x;
                Y = y;
            }
            public int X { get; }
            public int Y { get; }


        }
        public string Encrypt(string plainText, string key)
        {
            Dictionary<char, Coords> dictionary = createDectionary(key);
            string newWord = "";
            int i = 0;
            while (i < plainText.Length)
            {
                bool firstIsUpper = false, secIsUpper = false;
                char firstChar = plainText[i];
                char secChar;
                if (i == plainText.Length - 1 || plainText[i + 1] == firstChar) secChar = 'x';
                else secChar = plainText[i + 1];
                if (char.IsUpper(firstChar)) { firstIsUpper = true; char.ToLower(firstChar); }
                if (char.IsUpper(secChar)) { secIsUpper = true; char.ToLower(secChar); }
                char c1, c2;
                Coords firstCoord = dictionary[firstChar];
                Coords secondCord = dictionary[secChar];
                if (firstCoord.Y == secondCord.Y)
                {
                    Coords nextCoords = new Coords((dictionary[firstChar].X + 1) % 5, dictionary[firstChar].Y);

                    c1 = dictionary.FirstOrDefault(x => x.Value.X == nextCoords.X && x.Value.Y == nextCoords.Y).Key;

                    nextCoords = new Coords((dictionary[secChar].X + 1) % 5, dictionary[secChar].Y);

                    c2 = dictionary.FirstOrDefault(x => x.Value.X == nextCoords.X && x.Value.Y == nextCoords.Y).Key;


                }
                else if (firstCoord.X == secondCord.X)
                {
                    Coords nextCoords = new Coords(dictionary[firstChar].X, (dictionary[firstChar].Y + 1) % 5);
                    c1 = dictionary.FirstOrDefault(x => x.Value.X == nextCoords.X && x.Value.Y == nextCoords.Y).Key;

                    nextCoords = new Coords(dictionary[secChar].X, (dictionary[secChar].Y + 1) % 5);
                    c2 = dictionary.FirstOrDefault(x => x.Value.X == nextCoords.X && x.Value.Y == nextCoords.Y).Key;


                }
                else
                {
                    Coords nextCoords = new Coords(dictionary[secChar].X, dictionary[firstChar].Y);
                    c1 = dictionary.FirstOrDefault(x => x.Value.X == nextCoords.X && x.Value.Y == nextCoords.Y).Key;

                    nextCoords = new Coords(dictionary[firstChar].X, dictionary[secChar].Y);
                    c2 = dictionary.FirstOrDefault(x => x.Value.X == nextCoords.X && x.Value.Y == nextCoords.Y).Key;

                }
                if (firstIsUpper) { newWord += char.ToUpper(c1); firstIsUpper = false; }
                else newWord += c1;
                if (secIsUpper) { newWord += char.ToUpper(c2); secIsUpper = true; }
                else newWord += c2;
                if (i != plainText.Length - 1 && plainText[i + 1] == firstChar) i++;
                else i += 2;

            }
            return newWord;

        }

        public string Decrypt(string cipherText, string key)

        {
            Dictionary<char, Coords> dictionary = createDectionary(key);
            string newWord = "";
            int i = 0;
            bool checkDuplicate = false;
            while (i < cipherText.Length)
            {
                bool firstIsUpper = false, secIsUpper = false;
                char firstChar = cipherText[i];
                char secChar;

                secChar = cipherText[i + 1];

                if (char.IsUpper(firstChar)) { firstIsUpper = true; char.ToLower(firstChar); }
                if (char.IsUpper(secChar)) { secIsUpper = true; char.ToLower(secChar); }
                char c1, c2;
                Coords firstCoord = dictionary[firstChar];
                Coords secondCord = dictionary[secChar];
                if (firstCoord.Y == secondCord.Y)
                {
                    int num1 = dictionary[firstChar].X - 1;
                    int num2 = dictionary[secChar].X - 1;
                    if (num1 == -1) num1 = 4;
                    if (num2 == -1) num2 = 4;

                    Coords nextCoords = new Coords(num1, dictionary[firstChar].Y);

                    c1 = dictionary.FirstOrDefault(x => x.Value.X == nextCoords.X && x.Value.Y == nextCoords.Y).Key;

                    nextCoords = new Coords(num2, dictionary[secChar].Y);

                    c2 = dictionary.FirstOrDefault(x => x.Value.X == nextCoords.X && x.Value.Y == nextCoords.Y).Key;


                }
                else if (firstCoord.X == secondCord.X)
                {
                    int num1 = dictionary[firstChar].Y - 1;
                    int num2 = dictionary[secChar].Y - 1;
                    if (num1 == -1) num1 = 4;
                    if (num2 == -1) num2 = 4;
                    Coords nextCoords = new Coords(dictionary[firstChar].X, num1);
                    c1 = dictionary.FirstOrDefault(x => x.Value.X == nextCoords.X && x.Value.Y == nextCoords.Y).Key;

                    nextCoords = new Coords(dictionary[secChar].X, num2);
                    c2 = dictionary.FirstOrDefault(x => x.Value.X == nextCoords.X && x.Value.Y == nextCoords.Y).Key;


                }
                else
                {
                    Coords nextCoords = new Coords(dictionary[secChar].X, dictionary[firstChar].Y);
                    c1 = dictionary.FirstOrDefault(x => x.Value.X == nextCoords.X && x.Value.Y == nextCoords.Y).Key;

                    nextCoords = new Coords(dictionary[firstChar].X, dictionary[secChar].Y);
                    c2 = dictionary.FirstOrDefault(x => x.Value.X == nextCoords.X && x.Value.Y == nextCoords.Y).Key;

                }

                if (firstIsUpper) { c1 = char.ToUpper(c1); firstIsUpper = false; }

                if (secIsUpper) { c2 = char.ToUpper(c2); secIsUpper = true; }
                if (checkDuplicate == true)
                {
                    if (c1 == char.ToUpper(newWord[i - 2]) || c1 == char.ToLower(newWord[i - 2]))
                    {
                        newWord = newWord.Substring(0, newWord.Length - 1);
                    }
                }
                newWord += c1;
                newWord += c2;
                if (c2 == 'x') checkDuplicate = true;
                if (i != cipherText.Length - 1 && cipherText[i + 1] == firstChar) i++;
                else i += 2;

            }
            return newWord;

        }
    }
}
