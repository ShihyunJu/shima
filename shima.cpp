#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring> /// sha3에서만 사용
#include <stdint.h>

using namespace std;

/** SHA#-256 시작 */
static unsigned int keccakRate = 0;
static unsigned int keccakCapacity = 0;
static unsigned int keccakSuffix = 0;

static uint8_t keccak_state[200] = { 0x00, };
static int end_offset;

static const uint32_t keccakf_rndc[24][2] =
{
	{0x00000001, 0x00000000}, {0x00008082, 0x00000000},
	{0x0000808a, 0x80000000}, {0x80008000, 0x80000000},
	{0x0000808b, 0x00000000}, {0x80000001, 0x00000000},
	{0x80008081, 0x80000000}, {0x00008009, 0x80000000},
	{0x0000008a, 0x00000000}, {0x00000088, 0x00000000},
	{0x80008009, 0x00000000}, {0x8000000a, 0x00000000},

	{0x8000808b, 0x00000000}, {0x0000008b, 0x80000000},
	{0x00008089, 0x80000000}, {0x00008003, 0x80000000},
	{0x00008002, 0x80000000}, {0x00000080, 0x80000000},
	{0x0000800a, 0x00000000}, {0x8000000a, 0x80000000},
	{0x80008081, 0x80000000}, {0x00008080, 0x80000000},
	{0x80000001, 0x00000000}, {0x80008008, 0x80000000}
};

static const unsigned keccakf_rotc[24] =
{
	 1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
	27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const unsigned keccakf_piln[24] =
{
	10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
	15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};


void ROL64(uint32_t* in, uint32_t* out, int offset)
{
	int shift = 0;

	if (offset == 0)
	{
		out[1] = in[1];
		out[0] = in[0];
	}
	else if (offset < 32)
	{
		shift = offset;

		out[1] = (uint32_t)((in[1] << shift) ^ (in[0] >> (32 - shift)));
		out[0] = (uint32_t)((in[0] << shift) ^ (in[1] >> (32 - shift)));
	}
	else if (offset < 64)
	{
		shift = offset - 32;

		out[1] = (uint32_t)((in[0] << shift) ^ (in[1] >> (32 - shift)));
		out[0] = (uint32_t)((in[1] << shift) ^ (in[0] >> (32 - shift)));
	}
	else
	{
		out[1] = in[1];
		out[0] = in[0];
	}
}


void keccakf(uint8_t* state)
{
	uint32_t t[2], bc[5][2], s[25][2] = { 0x00, };
	int i, j, round;

	for (i = 0; i < 25; i++)
	{
		s[i][0] = (uint32_t)(state[i * 8 + 0]) |
			(uint32_t)(state[i * 8 + 1] << 8) |
			(uint32_t)(state[i * 8 + 2] << 16) |
			(uint32_t)(state[i * 8 + 3] << 24);
		s[i][1] = (uint32_t)(state[i * 8 + 4]) |
			(uint32_t)(state[i * 8 + 5] << 8) |
			(uint32_t)(state[i * 8 + 6] << 16) |
			(uint32_t)(state[i * 8 + 7] << 24);
	}

	for (round = 0; round < 24; round++)
	{
		/* Theta */
		for (i = 0; i < 5; i++)
		{
			bc[i][0] = s[i][0] ^ s[i + 5][0] ^ s[i + 10][0] ^ s[i + 15][0] ^ s[i + 20][0];
			bc[i][1] = s[i][1] ^ s[i + 5][1] ^ s[i + 10][1] ^ s[i + 15][1] ^ s[i + 20][1];
		}

		for (i = 0; i < 5; i++)
		{
			ROL64(bc[(i + 1) % 5], t, 1);

			t[0] ^= bc[(i + 4) % 5][0];
			t[1] ^= bc[(i + 4) % 5][1];

			for (j = 0; j < 25; j += 5)
			{
				s[j + i][0] ^= t[0];
				s[j + i][1] ^= t[1];
			}
		}

		/* Rho & Pi */
		t[0] = s[1][0];
		t[1] = s[1][1];

		for (i = 0; i < 24; i++)
		{
			j = keccakf_piln[i];
			bc[0][0] = s[j][0];
			bc[0][1] = s[j][1];
			ROL64(t, s[j], keccakf_rotc[i]);
			t[0] = bc[0][0];
			t[1] = bc[0][1];
		}

		/* Chi */
		for (j = 0; j < 25; j += 5)
		{
			for (i = 0; i < 5; i++)
			{
				bc[i][0] = s[j + i][0];
				bc[i][1] = s[j + i][1];
			}

			for (i = 0; i < 5; i++)
			{
				s[j + i][0] ^= (~bc[(i + 1) % 5][0]) & bc[(i + 2) % 5][0];
				s[j + i][1] ^= (~bc[(i + 1) % 5][1]) & bc[(i + 2) % 5][1];
			}
		}
		s[0][0] ^= keccakf_rndc[round][0];
		s[0][1] ^= keccakf_rndc[round][1];
	}

	for (i = 0; i < 25; i++)
	{
		state[i * 8 + 0] = (uint8_t)(s[i][0]);
		state[i * 8 + 1] = (uint8_t)(s[i][0] >> 8);
		state[i * 8 + 2] = (uint8_t)(s[i][0] >> 16);
		state[i * 8 + 3] = (uint8_t)(s[i][0] >> 24);
		state[i * 8 + 4] = (uint8_t)(s[i][1]);
		state[i * 8 + 5] = (uint8_t)(s[i][1] >> 8);
		state[i * 8 + 6] = (uint8_t)(s[i][1] >> 16);
		state[i * 8 + 7] = (uint8_t)(s[i][1] >> 24);
	}
}


void keccak_absorb(uint8_t* input, int rate, int capacity)
{
	uint8_t* buf = input;
	int iLen = 32;
	int rateInBytes = rate / 8;
	int blockSize = 0;
	int i = 0;

	while (iLen > 0)
	{
		if ((end_offset != 0) && (end_offset < rateInBytes))
		{
			blockSize = (((iLen + end_offset) < rateInBytes) ? (iLen + end_offset) : rateInBytes);
			for (i = end_offset; i < blockSize; i++)
				keccak_state[i] ^= buf[i - end_offset];
			buf += blockSize - end_offset;
			iLen -= blockSize - end_offset;
		}
		else
		{
			blockSize = ((iLen < rateInBytes) ? iLen : rateInBytes);
			for (i = 0; i < blockSize; i++)
				keccak_state[i] ^= buf[i];
			buf += blockSize;
			iLen -= blockSize;
		}
		if (blockSize == rateInBytes)
		{
			keccakf(keccak_state);
			blockSize = 0;
		}
		end_offset = blockSize;
	}
}


void keccak_squeeze(uint8_t* output, int outLen, int rate, int suffix)
{
	uint8_t* buf = output;
	int oLen = outLen;
	int rateInBytes = rate / 8;
	int blockSize = end_offset;
	int i = 0;
	keccak_state[blockSize] ^= suffix;
	if (((suffix & 0x80) != 0) && (blockSize == (rateInBytes - 1)))
		keccakf(keccak_state);
	keccak_state[rateInBytes - 1] ^= 0x80;
	keccakf(keccak_state);

	while (oLen > 0)
	{
		blockSize = ((oLen < rateInBytes) ? oLen : rateInBytes);
		for (i = 0; i < blockSize; i++)
			buf[i] = keccak_state[i];
		buf += blockSize;
		oLen -= blockSize;
		if (oLen > 0)
			keccakf(keccak_state);
	}
}

void sha3_final(uint8_t* output, int outLen)
{
	keccak_squeeze(output, outLen, keccakRate, keccakSuffix);
	keccakRate = 0;
	keccakCapacity = 0;
	keccakSuffix = 0;
	memset(keccak_state, 0x00, 200);
}


void sha3(uint8_t* output)
{
	keccakCapacity = 512;
	keccakRate = 1600 - keccakCapacity;
	keccakSuffix = 0x06;
	memset(keccak_state, 0x00, 200);
	end_offset = 0;

    uint8_t* input = (uint8_t*)malloc(sizeof(uint8_t)*32);
    for(uint8_t i=0;i<32;i++)
        input[i] = output[i];
	keccak_absorb(input, keccakRate, keccakCapacity);
	sha3_final(output, 32);
    free(input);
}

void sha3(uint8_t* output, uint8_t* input)
{
	keccakCapacity = 512;
	keccakRate = 1600 - keccakCapacity;
	keccakSuffix = 0x06;
	memset(keccak_state, 0x00, 200);
	end_offset = 0;
	keccak_absorb(input, keccakRate, keccakCapacity);
	sha3_final(output, 32);
}
/** SHA#-256 끝 */

void _add(uint8_t *x, uint8_t *y)
{
    uint8_t tmp = 0;
    for(uint8_t i=15;i<UINT8_MAX;i--)
    {
        uint64_t t = (tmp+ *(x+i)+ *(y+i));
        *(x+i) = t%256;
        tmp = t/256;
    }
    /// x에덮어쓰기
}

void _min(uint8_t *x, uint8_t *y)
{
    int8_t tmp = 0;
    for(uint8_t i=15;i<UINT8_MAX;i--)
    {
        int16_t t = (tmp+ *(x+i) - *(y+i));
		if(t<0)
		{
			tmp = -1;
        	*(x+i) = (t+256)%256;
		}
		else
		{
			tmp=0;
			*(x+i) = t;
		}
    }
}

void _ror(uint8_t* x, uint8_t num)
{
    uint8_t y[16];
    uint8_t num0=num/8;
    num%=8;
    for(uint8_t i=0;i<16;i++)
    {
        y[(i+num0)%16] = *(x+i);
    }
    uint8_t tmp = y[15]<<(8-num);
    for(uint8_t i=0;i<16;i++)
    {
        *(x+i) = tmp | (y[i]>>num);
        tmp = y[i]<<(8-num);
    }
}

void _rol(uint8_t* x, uint8_t num)
{
    uint8_t y[16];
    uint8_t num0=num/8;
    num%=8;
    for(uint8_t i=0;i<16;i++)
    {
        y[(i+16-num0)%16] = *(x+i);
    }
    uint8_t tmp = y[0]>>(8-num);
    for(uint8_t i=15;i<UINT8_MAX;i--)
    {
        *(x+i) = tmp | (y[i]<<num);
        tmp = y[i]>>(8-num);
    }
}

class shima
{
    private:
        uint8_t* data;
        uint8_t padding;
        uint64_t len;
    public:
        void init();
        void encrypt();
        void decrypt();

        void set(uint8_t* key, uint8_t* uint_data, uint64_t inp_len);
        void prt_key();
        void prt_data();
};

void shima::init()
{
    if(data != nullptr)
        free(data);
}

void shima::encrypt()
{
    if(data==NULL)
        return;

    uint8_t* backup = (uint8_t*)malloc(sizeof(uint8_t)*32);
    for(uint8_t i=0;i<32;i++)
        backup[i] = data[i];

    for(uint8_t round=0;round<32;round++)
    {
        /// key 수동으로 addiction하기
        for(uint64_t i=32;i<len+16;i+=16)
        {
            _add(data+i, data+i+16);
        }
        _add(data+len+16, data);
        for(uint64_t i=32;i<len+32;i++)
        {
            data[i] = data[i] ^ data[16+(i%16)];
        }
        for(uint64_t i=32;i<len+32;i+=16)
        {
            _ror(data+i, i%128);
        }
        for(uint64_t i=len;i>16;i-=16)
        {
            _add(data+i+16, data+i);
        }
        _add(data+32, data);
        for(uint64_t i=32;i<len+32;i++)
        {
            data[i] = ~data[i];
        }
        sha3(data);
    }

    for(uint8_t i=0;i<32;i++)
        data[i] = backup[i];
    free(backup);
}

void shima::decrypt() /// 고치기
{
    if(data==NULL)
        return;

    uint8_t* key[32];
	key[0] = (uint8_t*)malloc(sizeof(uint8_t)*32);
    for(uint8_t i=0;i<32;i++)
        key[0][i] = data[i];
    for(uint8_t i=1;i<32;i++)
    {
        key[i] = (uint8_t*)malloc(sizeof(uint8_t)*32);
        sha3(key[i], key[i-1]);
    }

    for(uint8_t round=31;round<UINT8_MAX;round--)
    {
        for(uint64_t i=32;i<len+32;i++)
        {
            data[i] = ~data[i];
        }
        _min(data+32, key[round]);
        for(uint64_t i=32;i<len+16;i+=16)
        {
            _min(data+i+16, data+i);
        }
        for(uint64_t i=32;i<len+32;i+=16)
        {
            _rol(data+i, i%128);
        }
        for(uint64_t i=32;i<len+32;i++)
        {
            data[i] = data[i] ^ key[round][16+(i%16)];
        }
        _min(data+len+16, key[round]);
        for(uint64_t i=len;i>16;i-=16)
        {
            _min(data+i, data+i+16);
        }
    }
	for(uint8_t i=0;i<32;i++)
		free(key[i]);
}

void shima::prt_key()
{
    for(uint8_t i=0;i<32;i++)
        printf("%u ", data[i]);
    printf("\n");
}

void shima::set(uint8_t* key, uint8_t* uint_data, uint64_t inp_len)
{
    len = inp_len+16;
    padding = 16;
    if(len%16)
    {
        len -= inp_len%16;
        padding = 16-(inp_len%16);
    }
    data = (uint8_t*)malloc(sizeof(uint8_t)*(len+32));
    for(uint8_t i=0;i<32;i++)
        data[i] = key[i];
    for(uint64_t i=0;i<len-padding;i++)
    {
        data[i+32] = uint_data[i];
    }
    if(padding==16)
    {
        for(uint8_t i=0;i<16;i++)
            data[len-padding+32+i] = 16;
    }
    else {
        for(uint8_t i=16-padding;i<16;i++)
            data[len-padding+32+i] = padding;
    }
}

void shima::prt_data()
{///////////
    for(uint64_t i=32;i<len+32;i++)
    {
        printf("%u ", data[i]);
    }
    printf("\n");
}