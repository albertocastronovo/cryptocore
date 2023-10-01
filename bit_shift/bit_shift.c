#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#define DEVICE_DIR      "/sys/bus/platform/devices/crypto_core@8000000"
#define DIR_START       "/start"
#define DIR_MODE        "/mode"
#define DIR_FORMAT      "/format"
#define DIR_IN          "/in_char"
#define DIR_OUT         "/out_char"
#define DIR_IV		"/iv_char"
//#define DIR_KEY		"/key_char"

char file_path[100];

static void byte_xor(const uint8_t *in_1, const uint8_t *in_2, uint8_t *out, size_t len);
static int dev_file_open(char *subdir, int flag);
static void ssepstring_to_uint8(const uint8_t *input, uint8_t *output);
static void check_op(ssize_t op);
static void print_buf_char(const uint8_t *buf, size_t len);
static void print_buf_uint(const uint8_t *buf, size_t len);


int main(int argc, char **argv)
{
	// argv[1] is the message we want to force at the output registers

	uint8_t msg_1[16] = "xxxxxxxxxxxxxxxx";
	uint8_t msg_2[17];
	uint8_t x[16];		// msg1 XOR msg2
	uint8_t out_1[16];	// from encryption of msg1
	uint8_t out_2[16];	// out1 XOR x
	uint8_t out_3[16];	// from decryption of out2
	uint8_t out_buf[100];
	uint8_t out_buf_2[100];
	const uint8_t mode_buf[3] = "0\0";
	const uint8_t mode_buf_2[3] = "1\0";
	const uint8_t format_buf[3] = "2\0";
	const uint8_t start_buf[3] = "1\0";
	const uint8_t iv[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
//	const uint8_t key[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	ssize_t readB, writeB;
	int fd[10];

	// receive input arguments

	if(strlen(argv[1]) != 16)
	{
		printf("Invalid message length\n");
		exit(EXIT_FAILURE);
	}
	sscanf(argv[1], "%s", msg_2);

	printf("Performing bit-shift attack.\n");
	printf("P1: ");
	print_buf_uint(msg_1, 16);
	printf("P2: ");
	print_buf_uint(msg_2, 16);

	// XOR between the input messages
	byte_xor(msg_1, msg_2, x, 16);
	printf("Performed the XOR of the inputs.\n");
	printf("X: ");
	print_buf_uint(x, 16);

	// Encrypt msg_1 with the cryptocore
	//	1. open the required device files

	fd[0] = dev_file_open(DIR_IN,		O_RDWR);
	fd[1] = dev_file_open(DIR_MODE, 	O_RDWR);
	fd[2] = dev_file_open(DIR_FORMAT,	O_RDWR);
	fd[3] = dev_file_open(DIR_START,	O_RDWR);
	fd[4] = dev_file_open(DIR_OUT,		O_RDONLY);
	fd[5] = dev_file_open(DIR_IV,		O_WRONLY);
//	fd[6] = dev_file_open(DIR_KEY,		O_WRONLY);
	fd[7] = dev_file_open(DIR_OUT,		O_RDONLY);
	//	2. write msg_1 into the input registers

	writeB = write(fd[0], msg_1, 16);
	check_op(writeB);

	//	3. configure the IV register
//	writeB = write(fd[6], key, 32);
//	check_op(writeB);

	writeB = write(fd[5], iv, 16);
	check_op(writeB);

	//	4. configure the operation: CTR xcrypt
	writeB = write(fd[1], mode_buf, 1);
	check_op(writeB);

	writeB = write(fd[2], format_buf, 1);
	check_op(writeB);

	//	5. start the operation

	writeB = write(fd[3], start_buf, 1);
	check_op(writeB);

	for(uint32_t k = 0; k < 100000; k += 2) { k -= 1; } // wait

	//	6. collect the output
	readB = read(fd[4], out_buf, 100);
	ssepstring_to_uint8(out_buf, out_1);

	printf("Encrypted msg_1 with the cryptocore.\n");
	printf("C1: ");
	print_buf_uint(out_1, 16);

	// tamper the ciphertext

	byte_xor(x, out_1, out_2, 16);
	printf("Perform XOR of output with x.\n");
	printf("C2: ");
	print_buf_uint(out_2, 16);

	// perform decryption
	//	1. set input
	writeB = write(fd[0], out_2, 16);
	check_op(writeB);

	//	2. set IV

//	writeB = write(fd[6], key, 32);
//	check_op(writeB);

	writeB = write(fd[5], iv, 16);
	check_op(writeB);

	//	3. start the operation
	writeB = write(fd[3], start_buf, 1);
	check_op(writeB);

	for(uint32_t k = 0; k < 100000; k += 2) { k -= 1; } // wait

	//	4. collect the output
	readB = read(fd[7], out_buf_2, 100);
	check_op(readB);

	ssepstring_to_uint8(out_buf_2, out_3);


	for(uint8_t i = 0; i < 8; i += 1)
	{
		close(fd[i]);
	} 

	printf("Decrypt C2 with the cryptocore.\n");
	printf("C3: ");
	print_buf_uint(out_3, 16);
	printf("In characters:\n");
	print_buf_char(out_3, 16);

	return 0;
}


static void print_buf_char(const uint8_t *buf, size_t len)
{
        for(size_t i = 0; i < len; i += 1)
        {
                printf("%c", (char)buf[i]);
        }
        printf("\n");
}

static void print_buf_uint(const uint8_t *buf, size_t len)
{
        for(size_t i = 0; i < len; i += 1)
        {
                printf("%u ", (uint8_t)buf[i]);
        }
        printf("\n");
}



static void byte_xor(const uint8_t *in_1, const uint8_t *in_2, uint8_t *out, size_t len)
{
	for(size_t i = 0; i < len; i += 1)
	{
		out[i] = in_1[i] ^ in_2[i];
	}
}

static int dev_file_open(char *subdir, int flag)
{
	int fd;
	sprintf(file_path, "%s%s", DEVICE_DIR, subdir);
	fd = open(file_path, flag);
	if(fd == -1)
	{
		exit(EXIT_FAILURE);
	}
	return fd;
}

static void ssepstring_to_uint8(const uint8_t *input, uint8_t *output)
{
	uint8_t num = 0;
	size_t out_idx = 0;
	for(size_t i = 0; input[i] != '\0' && out_idx < 16; i += 1)
	{
		if(input[i] >= '0' && input[i] <= '9')
		{
			num = num*10 + (input[i] - '0');
		} else
		{
			output[out_idx++] = num;
			num = 0;
		}
	}
	output[out_idx] = num;
}

static void check_op(ssize_t op)
{
	if(op == -1)
	{
		exit(EXIT_FAILURE);
	}
}
