using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libmd5
{
    public class Md5
    {
        private const uint T_MASK = ~0u;
        private const uint T1 = /* 0xd76aa478 */ T_MASK ^ 0x28955b87;
        private const uint T2 = /* 0xe8c7b756 */ T_MASK ^ 0x173848a9;
        private const uint T3 = 0x242070db;
        private const uint T4 = /* 0xc1bdceee */ T_MASK ^ 0x3e423111;
        private const uint T5 = /* 0xf57c0faf */ T_MASK ^ 0x0a83f050;
        private const uint T6 = 0x4787c62a;
        private const uint T7 = /* 0xa8304613 */ T_MASK ^ 0x57cfb9ec;
        private const uint T8 = /* 0xfd469501 */ T_MASK ^ 0x02b96afe;
        private const uint T9 = 0x698098d8;
        private const uint T10 = /* 0x8b44f7af */ T_MASK ^ 0x74bb0850;
        private const uint T11 = /* 0xffff5bb1 */ T_MASK ^ 0x0000a44e;
        private const uint T12 = /* 0x895cd7be */ T_MASK ^ 0x76a32841;
        private const uint T13 = 0x6b901122;
        private const uint T14 = /* 0xfd987193 */ T_MASK ^ 0x02678e6c;
        private const uint T15 = /* 0xa679438e */ T_MASK ^ 0x5986bc71;
        private const uint T16 = 0x49b40821;
        private const uint T17 = /* 0xf61e2562 */ T_MASK ^ 0x09e1da9d;
        private const uint T18 = /* 0xc040b340 */ T_MASK ^ 0x3fbf4cbf;
        private const uint T19 = 0x265e5a51;
        private const uint T20 = /* 0xe9b6c7aa */ T_MASK ^ 0x16493855;
        private const uint T21 = /* 0xd62f105d */ T_MASK ^ 0x29d0efa2;
        private const uint T22 = 0x02441453;
        private const uint T23 = /* 0xd8a1e681 */ T_MASK ^ 0x275e197e;
        private const uint T24 = /* 0xe7d3fbc8 */ T_MASK ^ 0x182c0437;
        private const uint T25 = 0x21e1cde6;
        private const uint T26 = /* 0xc33707d6 */ T_MASK ^ 0x3cc8f829;
        private const uint T27 = /* 0xf4d50d87 */ T_MASK ^ 0x0b2af278;
        private const uint T28 = 0x455a14ed;
        private const uint T29 = /* 0xa9e3e905 */ T_MASK ^ 0x561c16fa;
        private const uint T30 = /* 0xfcefa3f8 */ T_MASK ^ 0x03105c07;
        private const uint T31 = 0x676f02d9;
        private const uint T32 = /* 0x8d2a4c8a */ T_MASK ^ 0x72d5b375;
        private const uint T33 = /* 0xfffa3942 */ T_MASK ^ 0x0005c6bd;
        private const uint T34 = /* 0x8771f681 */ T_MASK ^ 0x788e097e;
        private const uint T35 = 0x6d9d6122;
        private const uint T36 = /* 0xfde5380c */ T_MASK ^ 0x021ac7f3;
        private const uint T37 = /* 0xa4beea44 */ T_MASK ^ 0x5b4115bb;
        private const uint T38 = 0x4bdecfa9;
        private const uint T39 = /* 0xf6bb4b60 */ T_MASK ^ 0x0944b49f;
        private const uint T40 = /* 0xbebfbc70 */ T_MASK ^ 0x4140438f;
        private const uint T41 = 0x289b7ec6;
        private const uint T42 = /* 0xeaa127fa */ T_MASK ^ 0x155ed805;
        private const uint T43 = /* 0xd4ef3085 */ T_MASK ^ 0x2b10cf7a;
        private const uint T44 = 0x04881d05;
        private const uint T45 = /* 0xd9d4d039 */ T_MASK ^ 0x262b2fc6;
        private const uint T46 = /* 0xe6db99e5 */ T_MASK ^ 0x1924661a;
        private const uint T47 = 0x1fa27cf8;
        private const uint T48 = /* 0xc4ac5665 */ T_MASK ^ 0x3b53a99a;
        private const uint T49 = /* 0xf4292244 */ T_MASK ^ 0x0bd6ddbb;
        private const uint T50 = 0x432aff97;
        private const uint T51 = /* 0xab9423a7 */ T_MASK ^ 0x546bdc58;
        private const uint T52 = /* 0xfc93a039 */ T_MASK ^ 0x036c5fc6;
        private const uint T53 = 0x655b59c3;
        private const uint T54 = /* 0x8f0ccc92 */ T_MASK ^ 0x70f3336d;
        private const uint T55 = /* 0xffeff47d */ T_MASK ^ 0x00100b82;
        private const uint T56 = /* 0x85845dd1 */ T_MASK ^ 0x7a7ba22e;
        private const uint T57 = 0x6fa87e4f;
        private const uint T58 = /* 0xfe2ce6e0 */ T_MASK ^ 0x01d3191f;
        private const uint T59 = /* 0xa3014314 */ T_MASK ^ 0x5cfebceb;
        private const uint T60 = 0x4e0811a1;
        private const uint T61 = /* 0xf7537e82 */ T_MASK ^ 0x08ac817d;
        private const uint T62 = /* 0xbd3af235 */ T_MASK ^ 0x42c50dca;
        private const uint T63 = 0x2ad7d2bb;
        private const uint T64 = /* 0xeb86d391 */ T_MASK ^ 0x14792c6e;

        /* Define the state of the MD5 Algorithm. */
        private class Md5State
        {
            public readonly uint[] Count = new uint[2]; /* message length in bits, lsw first */
            public readonly uint[] Abcd = new uint[4]; /* digest buffer */
            public readonly byte[] Buf = new byte[64]; /* accumulate block */
        }

        private uint t;
        private uint[] X = new uint[16];

        public byte[] ComputeHash(byte[] buffer)
        {
            var state = new Md5State();

            Init(state);
            Append(state, buffer, buffer.Length);
            var digest = Finish(state);

            return digest;
        }

        private void Process(Md5State pms, byte[] data /*[64]*/)
        {
            uint a = pms.Abcd[0],
                 b = pms.Abcd[1],
                 c = pms.Abcd[2],
                 d = pms.Abcd[3];

            if (BitConverter.IsLittleEndian)
            {
                /*
                 * On little-endian machines, we can just copy the data to the buffer.
                 */
                Buffer.BlockCopy(data, 0, X, 0, 64);
            }
            else
            {
                /*
	             * On big-endian machines, we must arrange the bytes in the
	             * right order.
	             */
                for (int i = 0, j = 0; i < 16; ++i, j += 4)
                {
                    X[i] = (uint)(data[j] + (data[j + 1] << 8) + (data[j + 2] << 16) + (data[j + 3] << 24));
                }
            }

            /* Round 1. */
            /* Let [abcd k s i] denote the operation
               a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s). */
            SetF(ref a, b, c, d, 0, 7, T1);
            SetF(ref d, a, b, c, 1, 12, T2);
            SetF(ref c, d, a, b, 2, 17, T3);
            SetF(ref b, c, d, a, 3, 22, T4);
            SetF(ref a, b, c, d, 4, 7, T5);
            SetF(ref d, a, b, c, 5, 12, T6);
            SetF(ref c, d, a, b, 6, 17, T7);
            SetF(ref b, c, d, a, 7, 22, T8);
            SetF(ref a, b, c, d, 8, 7, T9);
            SetF(ref d, a, b, c, 9, 12, T10);
            SetF(ref c, d, a, b, 10, 17, T11);
            SetF(ref b, c, d, a, 11, 22, T12);
            SetF(ref a, b, c, d, 12, 7, T13);
            SetF(ref d, a, b, c, 13, 12, T14);
            SetF(ref c, d, a, b, 14, 17, T15);
            SetF(ref b, c, d, a, 15, 22, T16);

            /* Round 2. */
            /* Let [abcd k s i] denote the operation
                 a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s). */
            SetG(ref a, b, c, d, 1, 5, T17);
            SetG(ref d, a, b, c, 6, 9, T18);
            SetG(ref c, d, a, b, 11, 14, T19);
            SetG(ref b, c, d, a, 0, 20, T20);
            SetG(ref a, b, c, d, 5, 5, T21);
            SetG(ref d, a, b, c, 10, 9, T22);
            SetG(ref c, d, a, b, 15, 14, T23);
            SetG(ref b, c, d, a, 4, 20, T24);
            SetG(ref a, b, c, d, 9, 5, T25);
            SetG(ref d, a, b, c, 14, 9, T26);
            SetG(ref c, d, a, b, 3, 14, T27);
            SetG(ref b, c, d, a, 8, 20, T28);
            SetG(ref a, b, c, d, 13, 5, T29);
            SetG(ref d, a, b, c, 2, 9, T30);
            SetG(ref c, d, a, b, 7, 14, T31);
            SetG(ref b, c, d, a, 12, 20, T32);

            /* Round 3. */
            /* Let [abcd k s t] denote the operation
                 a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s). */
            SetH(ref a, b, c, d, 5, 4, T33);
            SetH(ref d, a, b, c, 8, 11, T34);
            SetH(ref c, d, a, b, 11, 16, T35);
            SetH(ref b, c, d, a, 14, 23, T36);
            SetH(ref a, b, c, d, 1, 4, T37);
            SetH(ref d, a, b, c, 4, 11, T38);
            SetH(ref c, d, a, b, 7, 16, T39);
            SetH(ref b, c, d, a, 10, 23, T40);
            SetH(ref a, b, c, d, 13, 4, T41);
            SetH(ref d, a, b, c, 0, 11, T42);
            SetH(ref c, d, a, b, 3, 16, T43);
            SetH(ref b, c, d, a, 6, 23, T44);
            SetH(ref a, b, c, d, 9, 4, T45);
            SetH(ref d, a, b, c, 12, 11, T46);
            SetH(ref c, d, a, b, 15, 16, T47);
            SetH(ref b, c, d, a, 2, 23, T48);

            /* Round 4. */
            /* Let [abcd k s t] denote the operation
                 a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s). */
            SetI(ref a, b, c, d, 0, 6, T49);
            SetI(ref d, a, b, c, 7, 10, T50);
            SetI(ref c, d, a, b, 14, 15, T51);
            SetI(ref b, c, d, a, 5, 21, T52);
            SetI(ref a, b, c, d, 12, 6, T53);
            SetI(ref d, a, b, c, 3, 10, T54);
            SetI(ref c, d, a, b, 10, 15, T55);
            SetI(ref b, c, d, a, 1, 21, T56);
            SetI(ref a, b, c, d, 8, 6, T57);
            SetI(ref d, a, b, c, 15, 10, T58);
            SetI(ref c, d, a, b, 6, 15, T59);
            SetI(ref b, c, d, a, 13, 21, T60);
            SetI(ref a, b, c, d, 4, 6, T61);
            SetI(ref d, a, b, c, 11, 10, T62);
            SetI(ref c, d, a, b, 2, 15, T63);
            SetI(ref b, c, d, a, 9, 21, T64);

            /* Then perform the following additions. (That is increment each
               of the four registers by the value it had before this block
               was started.) */
            pms.Abcd[0] += a;
            pms.Abcd[1] += b;
            pms.Abcd[2] += c;
            pms.Abcd[3] += d;
        }

        private uint RotateLeft(uint x, int n)
        {
            return (x << n) | (x >> (32 - n));
        }

        /* Round 1 operations */
        private uint F(uint x, uint y, uint z)
        {
            return (x & y) | (~x & z);
        }
        private void SetF(ref uint a, uint b, uint c, uint d, int k, int s, uint Ti)
        {
            t = a + F(b, c, d) + X[k] + Ti;
            a = RotateLeft(t, s) + b;
        }

        /* Round 2 operations */
        private uint G(uint x, uint y, uint z)
        {
            return (x & z) | (y & ~z);
        }
        private void SetG(ref uint a, uint b, uint c, uint d, int k, int s, uint Ti)
        {
            t = a + G(b, c, d) + X[k] + Ti;
            a = RotateLeft(t, s) + b;
        }

        /* Round 3 operations */
        private uint H(uint x, uint y, uint z)
        {
            return x ^ y ^ z;
        }
        private void SetH(ref uint a, uint b, uint c, uint d, int k, int s, uint Ti)
        {
            t = a + H(b, c, d) + X[k] + Ti;
            a = RotateLeft(t, s) + b;
        }

        /* Round 4 operations */
        private uint I(uint x, uint y, uint z)
        {
            return y ^ (x | ~z);
        }
        private void SetI(ref uint a, uint b, uint c, uint d, int k, int s, uint Ti)
        {
            t = a + I(b, c, d) + X[k] + Ti;
            a = RotateLeft(t, s) + b;
        }

        private void Init(Md5State pms)
        {
            pms.Count[0] = pms.Count[1] = 0;
            pms.Abcd[0] = 0x67452301;
            pms.Abcd[1] = /*0xefcdab89*/ T_MASK ^ 0x10325476;
            pms.Abcd[2] = /*0x98badcfe*/ T_MASK ^ 0x67452301;
            pms.Abcd[3] = 0x10325476;
        }

        private void Append(Md5State pms, byte[] data, int nbytes)
        {
            if (nbytes <= 0)
            {
                return;
            }

            var p = 0;
            var left = nbytes;
            var offset = (int) (pms.Count[0] >> 3) & 63;
            var nbits = (uint) (nbytes << 3);

            /* Update the message length. */
            pms.Count[1] += (uint) nbytes >> 29;
            pms.Count[0] += nbits;
            if (pms.Count[0] < nbits)
            {
                pms.Count[1]++;
            }

            /* Process an initial partial block. */
            if (offset != 0)
            {
                var copy = offset + nbytes > 64 ? 64 - offset : nbytes;

                Buffer.BlockCopy(data, 0, pms.Buf, offset, copy);
                if (offset + copy < 64)
                {
                    return;
                }

                p += copy;
                left -= copy;
                Process(pms, pms.Buf);
            }

            /* Process full blocks. */
            for (; left >= 64; p += 64, left -= 64)
            {
                var chunk = new byte[64];
                Buffer.BlockCopy(data, p, chunk, 0, 64);

                Process(pms, chunk);
            }

            /* Process a final partial block. */
            if (left != 0)
            {
                Buffer.BlockCopy(data, p, pms.Buf, 0, left);
            }
        }

        private byte[] Finish(Md5State pms)
        {
            var pad = new byte[64] {
                0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            var data = new byte[8];

            /* Save the length before padding. */
            for (var i = 0; i < 8; ++i)
            {
                data[i] = (byte) (pms.Count[i >> 2] >> ((i & 3) << 3));
            }

            /* Pad to 56 bytes mod 64. */
            Append(pms, pad, (int) (((55 - (pms.Count[0] >> 3)) & 63) + 1));

            /* Append the length. */
            Append(pms, data, 8);

            var digest = new byte[16];

            for (var i = 0; i < 16; ++i)
            {
                digest[i] = (byte) (pms.Abcd[i >> 2] >> ((i & 3) << 3));
            }

            return digest;
        }
    }
}
