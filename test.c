#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Enable both ECB and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DECB=1
#define CBC 1
#define ECB 1

#include "aes.h"

static void phex(uint8_t* str);
static void test_encrypt_ecb(void);
static void test_decrypt_ecb(void);
static void test_encrypt_ecb_verbose(void);
static void test_encrypt_cbc(void);
static void test_decrypt_cbc(void);

static void encrypt_cbc_ts();
static void decrypt_cbc_ts();




int main(void)
{
    test_encrypt_cbc();
    test_decrypt_cbc();
    test_decrypt_ecb();
    test_encrypt_ecb();
    test_encrypt_ecb_verbose();
    
    encrypt_cbc_ts();
	//decrypt_cbc_ts();
	
    return 0;
}

#include <sys/stat.h>  
  
unsigned long get_file_size(const char *path)  
{  
    unsigned long filesize = -1;      
    struct stat statbuff;  
    if(stat(path, &statbuff) < 0){  
        return filesize;  
    }else{  
        filesize = statbuff.st_size;  
    }  
    return filesize;  
}  

#include <stdio.h>
#include <stdlib.h>

static void encrypt_cbc_ts()
{
  uint8_t key[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x61, 0x62, 0x63, 0x64, 0x65, 0x0a };
  uint8_t iv[]  = { 0x4b, 0xb2, 0x77, 0x87, 0x77, 0xb8, 0x8b, 0xe0, 0xf8, 0x53, 0x4b, 0x7b, 0xd5, 0xba, 0x91, 0x30 };
  /*
  uint8_t in[]  = { 0x28, 0x93, 0x77, 0xc4, 0x9f, 0x3e, 0xd4, 0x9a, 0x1e, 0x85, 0x84, 0x58, 0x6b, 0x40, 0x23, 0xf8,
					0xff, 0xbd, 0x21, 0x0f, 0x2a, 0x62, 0xe5, 0x4e, 0x6e, 0x89, 0xad, 0x96, 0xee, 0x2e, 0xf2, 0xb9,
                    0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16, 
                    0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };
  uint8_t out[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
					*/
  unsigned long file_size = get_file_size("file0.ts");
  
  int remainder = file_size % 16;
  if (remainder)
  {
     file_size += 16 - remainder;
  }
  else 
  {
	file_size += 16;
  }
  
  char *in = (char *)malloc(file_size);
  char *out = (char *)malloc(file_size);
  memset(in, 0, file_size);
  memset(out, 0, file_size);
  FILE *fp1, *fp2;
  if((fp1=fopen("file0.ts","rb"))==NULL)
  {
  printf("不能打开文件");
  exit(0);
  }
  fread(in, file_size, 1, fp1);
  fclose(fp1);
  //uint8_t buffer[64];
  printf("CBC ecrypt: \n");
  
  if (remainder)
  {
    int j;
	for (j = 0; j < 16-remainder; j++)
	{
		in[file_size-16+remainder+j] = 16-remainder;
	}
  }
  else 
  {
    int j;
	for (j = 16; j > 0; j--)
	{
		in[file_size-j] = 0x10;
	}
  }
  
  AES128_CBC_encrypt_buffer((uint8_t*)out, (uint8_t*)in, file_size, key, iv);
  phex(out);
  if((fp2=fopen("enfile0.ts","wb"))==NULL)
  {
  printf("不能打开文件");
  exit(0);
  }
  fwrite(out, file_size, 1, fp2);
  fclose(fp2);
  
  //AES128_CBC_decrypt_buffer(buffer+16, in+16, 16, 0, 0);
  //phex(buffer+16);
  //AES128_CBC_decrypt_buffer(buffer+32, in+32, 16, 0, 0);
  //AES128_CBC_decrypt_buffer(buffer+48, in+48, 16, 0, 0);
/*
  if(0 == strncmp((char*) out, (char*) buffer, 64))
  {
    printf("SUCCESS!\n");
  }
  else
  {
    printf("FAILURE!\n");
  }
  */
}

static void decrypt_cbc_ts()
{

}

// prints string as hex
static void phex(uint8_t* str)
{
    unsigned char i;
    for(i = 0; i < 16; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

static void test_encrypt_ecb_verbose(void)
{
    // Example of more verbose verification

    uint8_t i, buf[64], buf2[64];

    // 128bit key
    uint8_t key[16] =        { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
    // 512bit text
    uint8_t plain_text[64] = { (uint8_t) 0x6b, (uint8_t) 0xc1, (uint8_t) 0xbe, (uint8_t) 0xe2, (uint8_t) 0x2e, (uint8_t) 0x40, (uint8_t) 0x9f, (uint8_t) 0x96, (uint8_t) 0xe9, (uint8_t) 0x3d, (uint8_t) 0x7e, (uint8_t) 0x11, (uint8_t) 0x73, (uint8_t) 0x93, (uint8_t) 0x17, (uint8_t) 0x2a,
                               (uint8_t) 0xae, (uint8_t) 0x2d, (uint8_t) 0x8a, (uint8_t) 0x57, (uint8_t) 0x1e, (uint8_t) 0x03, (uint8_t) 0xac, (uint8_t) 0x9c, (uint8_t) 0x9e, (uint8_t) 0xb7, (uint8_t) 0x6f, (uint8_t) 0xac, (uint8_t) 0x45, (uint8_t) 0xaf, (uint8_t) 0x8e, (uint8_t) 0x51,
                               (uint8_t) 0x30, (uint8_t) 0xc8, (uint8_t) 0x1c, (uint8_t) 0x46, (uint8_t) 0xa3, (uint8_t) 0x5c, (uint8_t) 0xe4, (uint8_t) 0x11, (uint8_t) 0xe5, (uint8_t) 0xfb, (uint8_t) 0xc1, (uint8_t) 0x19, (uint8_t) 0x1a, (uint8_t) 0x0a, (uint8_t) 0x52, (uint8_t) 0xef,
                               (uint8_t) 0xf6, (uint8_t) 0x9f, (uint8_t) 0x24, (uint8_t) 0x45, (uint8_t) 0xdf, (uint8_t) 0x4f, (uint8_t) 0x9b, (uint8_t) 0x17, (uint8_t) 0xad, (uint8_t) 0x2b, (uint8_t) 0x41, (uint8_t) 0x7b, (uint8_t) 0xe6, (uint8_t) 0x6c, (uint8_t) 0x37, (uint8_t) 0x10 };

    memset(buf, 0, 64);
    memset(buf2, 0, 64);

    // print text to encrypt, key and IV
    printf("ECB encrypt verbose:\n\n");
    printf("plain text:\n");
    for(i = (uint8_t) 0; i < (uint8_t) 4; ++i)
    {
        phex(plain_text + i * (uint8_t) 16);
    }
    printf("\n");

    printf("key:\n");
    phex(key);
    printf("\n");

    // print the resulting cipher as 4 x 16 byte strings
    printf("ciphertext:\n");
    for(i = 0; i < 4; ++i)
    {
        AES128_ECB_encrypt(plain_text + (i*16), key, buf+(i*16));
        phex(buf + (i*16));
    }
    printf("\n");
}


static void test_encrypt_ecb(void)
{
  uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  uint8_t in[]  = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
  uint8_t out[] = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};
  uint8_t buffer[16];

  AES128_ECB_encrypt(in, key, buffer);

  printf("ECB decrypt: ");

  if(0 == strncmp((char*) out, (char*) buffer, 16))
  {
    printf("SUCCESS!\n");
  }
  else
  {
    printf("FAILURE!\n");
  }
}

static void test_decrypt_cbc(void)
{
  // Example "simulating" a smaller buffer...

  uint8_t key[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x61, 0x62, 0x63, 0x64, 0x65, 0x0a };
  uint8_t iv[]  = { 0x4b, 0xb2, 0x77, 0x87, 0x77, 0xb8, 0x8b, 0xe0, 0xf8, 0x53, 0x4b, 0x7b, 0xd5, 0xba, 0x91, 0x30 };
  /*uint8_t in[]  = { 0x28, 0x93, 0x77, 0xc4, 0x9f, 0x3e, 0xd4, 0x9a, 0x1e, 0x85, 0x84, 0x58, 0x6b, 0x40, 0x23, 0xf8,
					0xff, 0xbd, 0x21, 0x0f, 0x2a, 0x62, 0xe5, 0x4e, 0x6e, 0x89, 0xad, 0x96, 0xee, 0x2e, 0xf2, 0xb9,
                    0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16, 
                    0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };
  uint8_t out[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
	*/ 
  char in[32] = "1234567890abcdef";
	char out[64] = {0};
 uint8_t buffer[64] = {0};

int j;
  for ( j = 16; j<32; j++)
{
	in[j] = 0x10;
}

  printf("xtx CBC encrypt: \n");
  AES128_CBC_encrypt_buffer(buffer+0, in+0,  32, key, iv);
  phex(buffer);
  //AES128_CBC_decrypt_buffer(buffer+16, in+16, 16, 0, 0);
  phex(buffer+16);
  //AES128_CBC_decrypt_buffer(buffer+32, in+32, 16, 0, 0);
  //AES128_CBC_decrypt_buffer(buffer+48, in+48, 16, 0, 0);

  printf("xtx  CBC encrypt: \n");
  int i;
      for(i = 0; i < 4; ++i)
    {
        //AES128_CBC_decrypt_buffer(buffer + (i*16), in+(i*16), 16, key, iv);
        //phex(buffer + (i*16));
    }
    printf("\n");

  if(0 == strncmp((char*) out, (char*) buffer, 64))
  {
    printf("SUCCESS!\n");
  }
  else
  {
    printf("FAILURE!\n");
  }
}

static void test_encrypt_cbc(void)
{
  uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
  uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
  uint8_t in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
  uint8_t out[] = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                    0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16, 
                    0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };
  uint8_t buffer[64];

  AES128_CBC_encrypt_buffer(buffer, in, 64, key, iv);

  printf("CBC encrypt: ");

  if(0 == strncmp((char*) out, (char*) buffer, 64))
  {
    printf("SUCCESS!\n");
  }
  else
  {
    printf("FAILURE!\n");
  }
}


static void test_decrypt_ecb(void)
{
  uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  uint8_t in[]  = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};
  uint8_t out[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
  uint8_t buffer[16];

  AES128_ECB_decrypt(in, key, buffer);

  printf("ECB decrypt: ");

  if(0 == strncmp((char*) out, (char*) buffer, 16))
  {
    printf("SUCCESS!\n");
  }
  else
  {
    printf("FAILURE!\n");
  }
}


