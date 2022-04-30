using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int modular_pow(int b, int exponent, int modulus)
        {
            int c = 1;

            for (int i = 1; i <= exponent; i++)
            {
                c = (c * b) % modulus;
            }
            return c;
        }
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int A1 = 1;
            int A2 = 0;
            int A3 = baseN;
            int B1 = 0;
            int B2 = 1;
            int B3 = number;
            int Q;
            int R1, R2, R3;

            while (true)
            {
                if (B3 == 0)
                    return -1;
                else if (B3 == 1)
                {
                    while (B2 < 0)
                    {
                        B2 += baseN;

                    }
                    return B2;
                }

                Q = A3 / B3;
                R1 = A1 - Q * B1;
                R2 = A2 - Q * B2;
                R3 = A3 - Q * B3;
                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = R1;
                B2 = R2;
                B3 = R3;

            }



        }
        public int Encrypt(int p, int q, int M, int e)
        {
       

            int n = p * q;


            return (modular_pow(M, e, n));
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            

            int F = (p - 1) * (q - 1);

            int d = GetMultiplicativeInverse(e, F);
            int n = p * q;


            return (modular_pow(C, d, n));

        }
    }
}
