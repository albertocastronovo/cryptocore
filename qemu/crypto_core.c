#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "hw/misc/crypto_core.h"

#include <string.h> // CBC mode, for memset
#include <stdint.h>
#include <stddef.h>

#define TYPE_CRYPTO_CORE "crypto_core"

#define REG_ID 		0x0
#define REG_MODE 	0x8
#define REG_FORMAT 	0x10
#define REG_START	0x18
#define REG_VALID	0x20

#define REG_KEY_0	0x28
#define REG_KEY_1	0x30
#define REG_KEY_2	0x38
#define REG_KEY_3	0x40
#define REG_KEY_4	0x48
#define REG_KEY_5	0x50
#define REG_KEY_6	0x58
#define REG_KEY_7	0x60	// each var is 32 bit. The key is 256 bit. So we need 8 vars

#define REG_IV_0	0x68
#define REG_IV_1	0x70
#define REG_IV_2	0x78
#define REG_IV_3	0x80	// IV is 128 bit only (16 byte)

#define REG_IN_0	0x88
#define REG_IN_1	0x90
#define REG_IN_2	0x98
#define REG_IN_3	0x100

#define REG_OUT_0	0x108
#define REG_OUT_1	0x110
#define REG_OUT_2	0x118
#define REG_OUT_3	0x120

#define REG_KEY_CHAR	0x128
#define REG_IV_CHAR	0x130
#define REG_IN_CHAR	0x138
#define REG_OUT_CHAR	0x140

// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define CBC 1
#define ECB 1
#define CTR 1

#define AES256 1
#define AES_BLOCKLEN 16

#define AES_KEYLEN 32
#define AES_keyExpSize 240

#define Nb 4

#if defined(AES256) && (AES256 == 1)
    #define Nk 8
    #define Nr 14
#elif defined(AES192) && (AES192 == 1)
    #define Nk 6
    #define Nr 12
#else
    #define Nk 4        // The number of 32 bit words in a key.
    #define Nr 10       // The number of rounds in AES Cipher.
#endif

// jcallan@github points out that declaring Multiply as a function 
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif

// device variables
typedef uint8_t state_t[4][4];
typedef struct CryptoCoreState CryptoCoreState;
DECLARE_INSTANCE_CHECKER(CryptoCoreState, CRYPTO_CORE, TYPE_CRYPTO_CORE)

typedef union
{
	uint8_t b8_arr[8];
	uint64_t b64;

} regarr;


/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.


// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM - 
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
#endif

// The round constant word array, Rcon[i], contains the values given by 
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/*
 * Jordan Goulder points out in PR #12 (https://github.com/kokke/tiny-AES-C/pull/12),
 * that you can remove most of the elements in the Rcon array, because they are unused.
 *
 * From Wikipedia's article on the Rijndael key schedule @ https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
 * 
 * "Only the first some of these constants are actually used – up to rcon[10] for AES-128 (as 11 round keys are needed), 
 *  up to rcon[8] for AES-192, up to rcon[7] for AES-256. rcon[0] is not used in AES algorithm."
 */


/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
/*
static uint8_t getSBoxValue(uint8_t num)
{
  return sbox[num];
}
*/
#define getSBoxValue(num) (sbox[(num)])

struct AES_ctx
{
	uint8_t RoundKey[AES_keyExpSize];
	uint8_t Iv[AES_BLOCKLEN];
};

struct CryptoCoreState
{
	SysBusDevice parent_obj;
	MemoryRegion iomem;
	uint32_t proc_id;
	uint32_t mode;
	uint32_t format;
	uint32_t valid;
	uint32_t start;
	uint32_t key_0;
	uint32_t key_1;
	uint32_t key_2;
	uint32_t key_3;
        uint32_t key_4;
        uint32_t key_5;
        uint32_t key_6;
        uint32_t key_7;
	uint32_t key_char;

	uint32_t iv_0;
	uint32_t iv_1;
	uint32_t iv_2;
	uint32_t iv_3;
	uint32_t iv_char;

	uint32_t in_0;
	uint32_t in_1;
	uint32_t in_2;
	uint32_t in_3;
	uint32_t in_char;

	uint32_t out_0;
	uint32_t out_1;
	uint32_t out_2;
	uint32_t out_3;
	uint32_t out_char;
};

static struct AES_ctx actx;
static uint8_t key[32];
static uint8_t vec[16];
static uint8_t to_enc_dec[16];

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations
  
  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if (i % Nk == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
#if defined(AES256) && (AES256 == 1)
    if (i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
#endif
    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

//static void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
//{
//  KeyExpansion(ctx->RoundKey, key);
//}
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
static void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  KeyExpansion(ctx->RoundKey, key);
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
//static void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
//{
//  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
//}
#endif

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to left  
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left  
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
/*
static uint8_t getSBoxInvert(uint8_t num)
{
  return rsbox[num];
}
*/
#define getSBoxInvert(num) (rsbox[(num)])

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i)
  { 
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
  }
}

static void InvShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to right  
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  // Rotate second row 2 columns to right 
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without MixColumns()
  for (round = 1; ; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    if (round == Nr) {
      break;
    }
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  // Add round key to last round
  AddRoundKey(Nr, state, RoundKey);
}

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without InvMixColumn()
  for (round = (Nr - 1); ; --round)
  {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, state, RoundKey);
    if (round == 0) {
      break;
    }
    InvMixColumns(state);
  }

}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
#if defined(ECB) && (ECB == 1)


static void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call encrypts the PlainText with the Key using AES algorithm.
  Cipher((state_t*)buf, ctx->RoundKey);
}

static void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call decrypts the PlainText with the Key using AES algorithm.
  InvCipher((state_t*)buf, ctx->RoundKey);
}


#endif // #if defined(ECB) && (ECB == 1)





#if defined(CBC) && (CBC == 1)


static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
  uint8_t i;
  for (i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
  {
    buf[i] ^= Iv[i];
  }
}

static void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)
{
  size_t i;
  uint8_t *Iv = ctx->Iv;
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    XorWithIv(buf, Iv);
    Cipher((state_t*)buf, ctx->RoundKey);
    Iv = buf;
    buf += AES_BLOCKLEN;
  }
  /* store Iv in ctx for next call */
  memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}

static void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  size_t i;
  uint8_t storeNextIv[AES_BLOCKLEN];
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    memcpy(storeNextIv, buf, AES_BLOCKLEN);
    InvCipher((state_t*)buf, ctx->RoundKey);
    XorWithIv(buf, ctx->Iv);
    memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
    buf += AES_BLOCKLEN;
  }

}

#endif // #if defined(CBC) && (CBC == 1)



#if defined(CTR) && (CTR == 1)

/* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key */
static void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t buffer[AES_BLOCKLEN];
  
  size_t i;
  int bi;
  for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
  {
    if (bi == AES_BLOCKLEN) /* we need to regen xor compliment in buffer */
    {
      
      memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
      Cipher((state_t*)buffer,ctx->RoundKey);

      /* Increment Iv and handle overflow */
      for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
      {
	/* inc will overflow */
        if (ctx->Iv[bi] == 255)
	{
          ctx->Iv[bi] = 0;
          continue;
        } 
        ctx->Iv[bi] += 1;
        break;   
      }
      bi = 0;
    }

    buf[i] = (buf[i] ^ buffer[bi]);
  }
}

#endif // #if defined(CTR) && (CTR == 1)

static void uint32_to_uint8(const uint32_t input32, uint8_t *output8)
{
	output8[0] = (uint8_t)(input32 & 0xFF);
	output8[1] = (uint8_t)((input32 >> 8) & 0xFF);
	output8[2] = (uint8_t)((input32 >> 16) & 0xFF);
	output8[3] = (uint8_t)((input32 >> 24) & 0xFF);
}

static uint32_t uint8_to_uint32(uint8_t *input8)
{
	uint32_t result = 0;
	result |= (uint32_t)input8[0];
	result |= ((uint32_t)input8[1] << 8);
	result |= ((uint32_t)input8[2] << 16);
	result |= ((uint32_t)input8[3] << 24);

	return result;
}


static uint64_t crypto_core_read(
	void *opaque, hwaddr offset, unsigned int size
)
{
	CryptoCoreState *s = (CryptoCoreState *)opaque;
	switch(offset)
	{
		case REG_ID:
			return (uint64_t)s->proc_id;
		case REG_MODE:
			return (uint64_t)s->mode;
		case REG_FORMAT:
			return (uint64_t)s->format;
		case REG_START:
			return (uint64_t)s->start;
		case REG_VALID:
			return (uint64_t)s->valid;
		case REG_IN_0:
			return (uint64_t)s->in_0;
		case REG_IN_1:
			return (uint64_t)s->in_1;
		case REG_IN_2:
			return (uint64_t)s->in_2;
		case REG_IN_3:
			return (uint64_t)s->in_3;
		case REG_OUT_0:
			return (uint64_t)s->out_0;
		case REG_OUT_1:
			return (uint64_t)s->out_1;
		case REG_OUT_2:
			return (uint64_t)s->out_2;
		case REG_OUT_3:
			return (uint64_t)s->out_3;

		case REG_IN_CHAR:
			return (uint64_t)s->in_char;
		case REG_OUT_CHAR:
			return (uint64_t)s->out_char;
		default:
			return 0xCCCCAAAA;
	
	}
	return 0;
}

static void crypto_core_write(
	void *opaque, hwaddr offset, uint64_t value, unsigned int size
)
{
	CryptoCoreState *s = (CryptoCoreState *)opaque;
	switch(offset)
	{
		case REG_ID:
			break;

		case REG_MODE:
			s->mode = (uint32_t)value;
			break;

		case REG_FORMAT:
			s->format = (uint32_t)value;
			break;

		case REG_START:
			s->start = (uint32_t)value;
			if(s->start == 0)
			{
				break;
			}

			uint32_to_uint8(s->key_0, key);
			uint32_to_uint8(s->key_1, key+4);
			uint32_to_uint8(s->key_2, key+8);
			uint32_to_uint8(s->key_3, key+12);
			uint32_to_uint8(s->key_4, key+16);
			uint32_to_uint8(s->key_5, key+20);
			uint32_to_uint8(s->key_6, key+24);
			uint32_to_uint8(s->key_7, key+28);

			uint32_to_uint8(s->iv_0, vec);
			uint32_to_uint8(s->iv_1, vec+4);
			uint32_to_uint8(s->iv_2, vec+8);
			uint32_to_uint8(s->iv_3, vec+12);

			uint32_to_uint8(s->in_0, to_enc_dec);
			uint32_to_uint8(s->in_1, to_enc_dec+4);
			uint32_to_uint8(s->in_2, to_enc_dec+8);
			uint32_to_uint8(s->in_3, to_enc_dec+12);

			AES_init_ctx_iv(&actx, key, vec);

			// operation

			if(s->mode == (uint32_t)0)	// encrypt
			{
				if(s->format == (uint32_t)0)			// ECB
				{
					AES_ECB_encrypt(&actx, to_enc_dec);
				} else if (s->format == (uint32_t)1)		// CBC
				{
					AES_CBC_encrypt_buffer(&actx, to_enc_dec, 16);
				} else						// CTR
				{
					AES_CTR_xcrypt_buffer(&actx, to_enc_dec, 16);
				}


			} else				// decrypt
			{

				if(s->format == (uint32_t)0)			// ECB
				{
					AES_ECB_decrypt(&actx, to_enc_dec);
				} else if (s->format == (uint32_t)1)		// CBC
				{
					AES_CBC_decrypt_buffer(&actx, to_enc_dec, 16);
				} else						// CTR
				{
					AES_CTR_xcrypt_buffer(&actx, to_enc_dec, 16);
				}
			}

			// output writing

			s->out_0 = uint8_to_uint32(to_enc_dec);
			s->out_1 = uint8_to_uint32(to_enc_dec+4);
			s->out_2 = uint8_to_uint32(to_enc_dec+8);
			s->out_3 = uint8_to_uint32(to_enc_dec+12);

			break;

		case REG_VALID:
			s->valid = (uint32_t)value;
			break;

		case REG_KEY_0:
			s->key_0 = (uint32_t)value;
			break;

		case REG_KEY_1:
			s->key_1 = (uint32_t)value;
			break;

		case REG_KEY_2:
			s->key_2 = (uint32_t)value;
			break;

		case REG_KEY_3:
			s->key_3 = (uint32_t)value;
			break;

		case REG_KEY_4:
			s->key_4 = (uint32_t)value;
			break;

		case REG_KEY_5:
			s->key_5 = (uint32_t)value;
			break;

		case REG_KEY_6:
			s->key_6 = (uint32_t)value;
			break;

		case REG_KEY_7:
			s->key_7 = (uint32_t)value;
			break;

		case REG_IV_0:
			s->iv_0 = (uint32_t)value;
			break;

		case REG_IV_1:
			s->iv_1 = (uint32_t)value;
			break;
	
		case REG_IV_2:
			s->iv_2 = (uint32_t)value;
			break;

		case REG_IV_3:
			s->iv_3 = (uint32_t)value;
			break;

		case REG_IN_0:
			s->in_0 = (uint32_t)value;
			break;

		case REG_IN_1:
			s->in_1 = (uint32_t)value;
			break;

		case REG_IN_2:
			s->in_2 = (uint32_t)value;
			break;

		case REG_IN_3:
			s->in_3 = (uint32_t)value;
			break;

		case REG_KEY_CHAR:
			s->key_char = (uint32_t)value;
			break;

		case REG_IN_CHAR:
			s->in_char = (uint32_t)value;
			break;

		case REG_IV_CHAR:
			s->iv_char = (uint32_t)value;
			break;

		default:
			break;
	}
}

static const MemoryRegionOps crypto_core_ops = {
	.read = crypto_core_read,
	.write = crypto_core_write,
	.endianness = DEVICE_NATIVE_ENDIAN,
};

static void crypto_core_instance_init(Object *obj)
{
	CryptoCoreState *s = CRYPTO_CORE(obj);

	memory_region_init_io(&s->iomem, obj, &crypto_core_ops, s, TYPE_CRYPTO_CORE, 0x200);
	sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->iomem);

	s->proc_id = 0xBACCCCAB;
	s->start = 0x00000000;
}

static const TypeInfo crypto_core_info = {
	.name = TYPE_CRYPTO_CORE,
	.parent = TYPE_SYS_BUS_DEVICE,
	.instance_size = sizeof(CryptoCoreState),
	.instance_init = crypto_core_instance_init,
};

static void crypto_core_register_types(void)
{
	type_register_static(&crypto_core_info);
}

type_init(crypto_core_register_types)

DeviceState *crypto_core_create(hwaddr addr)
{
	DeviceState *dev = qdev_new(TYPE_CRYPTO_CORE);
	sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
	sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, addr);
	return dev;
}
