﻿namespace AES_GCM_cs;

// This is the original implementation of AES128 found online
class aes128e
{
	public static byte xtime(byte a)
	{
		var b = (a & 0x80) != 0;
		return ((byte)(b ? (((a) << 1) ^ 0x1b) : ((a) << 1)));
	}

	private const int Nb = 4;
	private const int Nr = 10;
	private const int Nk = 4;

	public static readonly byte[] sbox = new byte[256]
	{
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b,
		0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82,
		0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
		0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5,
		0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96,
		0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
		0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
		0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
		0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d,
		0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3,
		0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
		0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7,
		0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
		0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32,
		0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95,
		0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56,
		0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
		0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
		0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1,
		0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
		0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6,
		0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
	};

	public static readonly byte[] rcon = new byte[10]
	{
		0x01, 0x02, 0x04, 0x08, 0x10,
		0x20, 0x40, 0x80, 0x1b, 0x36
	};

	static void keyExpansion(byte[] key, byte[] roundKey, int keyLength)
    {
		int i = 0, j;
		byte[] temp = new byte[4];
		byte k;

		while (i < keyLength)
        {
			roundKey[i * 4] = key[i * 4];
			roundKey[i * 4 + 1] = key[i * 4 + 1];
			roundKey[i * 4 + 2] = key[i * 4 + 2];
			roundKey[i * 4 + 3] = key[i * 4 + 3];

			i++;
		}

		i = keyLength;

		while (i < (Nb * (Nr + 1)))
		{
			for (j = 0; j < 4; j++)
            {
				temp[j] = roundKey[(i - 1) * 4 + j];
            }

			if (i % keyLength == 0)
            {
				k = temp[0];
				temp[0] = temp[1];
				temp[1] = temp[2];
				temp[2] = temp[3];
				temp[3] = k;

				temp[0] = sbox[temp[0]];
				temp[1] = sbox[temp[1]];
				temp[2] = sbox[temp[2]];
				temp[3] = sbox[temp[3]];

				temp[0] = (byte)(temp[0] ^ rcon[i / keyLength - 1]);
			}
			else if (keyLength > 6 && i % keyLength == 4)
            {
				temp[0] = sbox[temp[0]];
				temp[1] = sbox[temp[1]];
				temp[2] = sbox[temp[2]];
				temp[3] = sbox[temp[3]];
			}
			roundKey[i * 4 + 0] = (byte)(roundKey[((i - keyLength) * 4) + 0] ^ temp[0]);
			roundKey[i * 4 + 1] = (byte)(roundKey[(i - keyLength) * 4 + 1] ^ temp[1]);
			roundKey[i * 4 + 2] = (byte)(roundKey[(i - keyLength) * 4 + 2] ^ temp[2]);
			roundKey[i * 4 + 3] = (byte)(roundKey[(i - keyLength) * 4 + 3] ^ temp[3]);

			i++;
		}
	}

	static void addRoundKey(byte[,] state, byte[] roundKey, int round)
    {
		int i, j;
		for (i = 0; i < 4; i++)
		{
			for (j = 0; j < 4; j++)
			{
				state[j,i] ^= roundKey[round * Nb * 4 + i * Nb + j];
			}
		}
	}

	static void subBytes(byte[,] state)
	{
		int i, j;
		for (i = 0; i < 4; i++)
		{
			for (j = 0; j < 4; j++)
			{
				state[i,j] = sbox[state[i,j]];
			}
		}
	}

	static void shiftRows(byte[,] state)
    {
		byte temp;
		int i, j;
		for (i = 1; i < 4; i++)
		{
			int tempIndex = 0;
			temp = state[i,tempIndex];

			for (j = 0; j < 4; j++)
			{

				if (j == 3)
				{
					state[i,tempIndex] = temp;
					continue;
				}

				if (i == 2 && tempIndex == 2)
				{
					state[i,i] = temp;
					tempIndex = i - 1;
					continue;
				}

				int secIndex = (j + i) % 4;
				if (secIndex == 0)
				{
					if (i == 2)
					{
						temp = state[i,tempIndex];
						secIndex = tempIndex + 2;
					}
					if (i == 3)
					{
						secIndex = i - j;
					}
				}

				state[i,tempIndex] = state[i,secIndex];
				tempIndex = secIndex;

			}

		}
	}

	static void mixColumns(byte[,] state)
	{
		int i, j;
		byte temp, tempXor, tempXtime;

		for (i = 0; i < 4; i++)
		{
			temp = state[0, i];
			tempXor = (byte)(state[0, i] ^ state[1, i] ^ state[2, i] ^ state[3, i]);

			for (j = 0; j < 4; j++)
			{
				tempXtime = (byte)(state[j, i] ^ state[(j + 1) % 4, i]);
				if ((j + 1) % 4 == 0)
				{
					tempXtime = (byte)(state[j, i] ^ temp);
				}
				tempXtime = xtime(tempXtime);
				state[j, i] ^= (byte)(tempXtime ^ tempXor);
			}
		}
	}

	public static void AES128E(byte[] c, byte[] p, byte[] k)
    {
		int i, j = 0;

		byte[,] state = new byte[4,Nb];
		byte[] roundKey = new byte[176];

		for (i = 0; i < Nk * 4; i++)
		{
			if (i < 4)
			{
				for (j = 0; j < 4; j++)
				{
					state[j,i] = p[i * 4 + j];
				}
			}
		}


		keyExpansion(k, roundKey, Nk);

		addRoundKey(state, roundKey, 0);

			

		int round;

		for (round = 1; round < Nr; round++)
		{
			subBytes(state);
			shiftRows(state);
			mixColumns(state);

			addRoundKey(state, roundKey, round);
		}

		subBytes(state);
		shiftRows(state);
		addRoundKey(state, roundKey, Nr);

		for (i = 0; i < 4; i++)
		{
			for (j = 0; j < 4; j++)
			{
				c[i * 4 + j] = state[j,i];
			}
		}
	}
}

