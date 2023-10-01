#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#define DEVICE_DIR 	"/sys/bus/platform/devices/crypto_core@8000000"
#define DIR_PROC_ID 	"/proc_id"
#define DIR_MODE	"/mode"
#define DIR_FORMAT	"/format"
#define DIR_START	"/start"
#define DIR_VALID	"/valid"
#define DIR_KEY		"/key_char"
#define DIR_IV		"/iv_char"
#define DIR_IN		"/in_char"
#define DIR_OUT		"/out_char"

char file_path[100];

static int dev_file_open(char *subdir, int flag);
static uint32_t uint8_to_uint32(const uint8_t *input8);
static void print_buf_char(const uint8_t *buf, size_t len);
static void print_buf_uint(const uint8_t *buf, size_t len);
static void check_op(ssize_t op);

int main(int argc, char **argv)
{
	// argv[1] is the key
	// argv[2] is the init vector
	// argv[3] is the input string
	// argv[4] is the mode (0 for encrypt, other for decrypt)
	// argv[5] is the format (0 for ECB, 1 for CBC, other for CTR)

	int fd[10];
	char proc_id[8];
	ssize_t readB, writeB;
	char write_buf[12];
	char read_buf[100];
	char start_buf[3] = "1\0";
	char mode_buf[3] = "0\0";
	char format_buf[3] = "0\0";

	uint8_t key[33];
	uint8_t in_str[17];
	uint8_t iv[17];

	// TO-DO: better input check!

	if(argc != 6)
	{
		printf("Invalid number of arguments.\n");
		exit(EXIT_FAILURE);
	}

	if(strlen(argv[1]) != 32)
	{
		printf("Key argument of invalid length.\n");
		exit(EXIT_FAILURE);
	}
	sscanf(argv[1], "%s", key);

	if(strlen(argv[2]) != 16)
	{
		printf("Init vector argument of invalid length.\n");
		exit(EXIT_FAILURE);
	}
	sscanf(argv[2], "%s", iv);

	if(strlen(argv[3]) != 16)
	{
		printf("Input string of invalid length.\n");
		exit(EXIT_FAILURE);
	}
	sscanf(argv[3], "%s", in_str);

	if(strlen(argv[4]) != 1)
	{
		printf("Mode argument of invalid length.\n");
		exit(EXIT_FAILURE);
	}
	sscanf(argv[4], "%s", mode_buf);

	if(strlen(argv[5]) != 1)
	{
		printf("Format argument of invalid length.\n");
		exit(EXIT_FAILURE);
	}
	sscanf(argv[5], "%s", format_buf);

	printf("Starting program with arguments:\n");
	printf("[1] %s\n", key);
	printf("[2] %s\n", iv);
	printf("[3] %s\n", in_str);
	printf("[4] %s\n", mode_buf);
	printf("[5] %s\n", format_buf);

	printf("Opening device files...\n");

	fd[0] = dev_file_open(DIR_PROC_ID,	O_RDONLY);
	fd[1] = dev_file_open(DIR_MODE,		O_RDWR);
	fd[2] = dev_file_open(DIR_FORMAT, 	O_RDWR);
	fd[3] = dev_file_open(DIR_START, 	O_RDWR);
	fd[4] = dev_file_open(DIR_VALID,	O_RDWR);
	fd[5] = dev_file_open(DIR_KEY,		O_WRONLY);
	fd[6] = dev_file_open(DIR_IV,		O_WRONLY);
	fd[7] = dev_file_open(DIR_IN,		O_RDWR);
	fd[8] = dev_file_open(DIR_OUT,		O_RDONLY);
	
	printf("Device files opened with no issues.\n");

	// LETTURA ID

	printf("Reading processor ID...\n");
	readB = read(fd[0], proc_id, sizeof(readB));
	check_op(readB);
	printf("Processor ID successfully read.\n");
	print_buf_char(proc_id, 8);

	// SCRITTURA CHIAVE

	printf("Writing key into registers.\n");
	writeB = write(fd[5], key, 32);
	check_op(writeB);

	// SCRITTURA IV
	printf("Writing IV into registers.\n");
	writeB =write(fd[6], iv, 16);
	check_op(writeB);

	// SCRITTURA INPUT

	printf("Writing input string into registers.\n");
	writeB = write(fd[7], in_str, 16);
	check_op(writeB);

	// PARAMETRI

	printf("Writing mode and format configuration into registers.\n");
	//	MODE: 	0 to encrypt, !=0 to decrypt
	//	FORMAT:	0 for ECB, 1 for CBC, other for CTR
	writeB = write(fd[1], mode_buf, 2);
	check_op(writeB);
	writeB = write(fd[2], format_buf, 2);
	check_op(writeB);

	// AVVIO CONVERSIONE

	printf("Starting operation.\n");
	writeB = write(fd[3], start_buf, 3);
	check_op(writeB);

	for(uint32_t k = 0; k < 100000; k += 2) {k -= 1;}	// aspetta la conversione

	// LETTURA OUTPUT

	printf("Reading output registers.\n");

	readB = read(fd[8], read_buf, 100);
	check_op(readB);

	for(uint8_t i = 0; i < 100; i += 1)
	{
		printf("%c", read_buf[i]);
	}
	printf("\n");


	for(uint8_t i = 0; i < 9; i += 1)
	{
		close(fd[i]);
	}

	return 0;
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

uint32_t uint8_to_uint32(const uint8_t *input8)
{
        uint32_t result = 0;
        result |= (uint32_t)input8[0];
        result |= ((uint32_t)input8[1] << 8);
        result |= ((uint32_t)input8[2] << 16);
        result |= ((uint32_t)input8[3] << 24);

        return result;
}

static void print_buf_char(const uint8_t *buf, size_t len)
{
	for(size_t i = 0; i < len; i += 1)
	{
		printf("%c ", (char)buf[i]);
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

static void check_op(ssize_t op)
{
	if(op == -1)
	{
		exit(EXIT_FAILURE);
	}
}
