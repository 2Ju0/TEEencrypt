/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>
#include <unistd.h>

#define MAX_LEN 100

int main(int argc, char *argv[])
{
   TEEC_Result res;
   TEEC_Context ctx;
   TEEC_Session sess;
   TEEC_Operation op;
   TEEC_UUID uuid = TA_TEEencrypt_UUID;
   uint32_t err_origin;

   /* Buffer */
   char plaintext[MAX_LEN] = {0, };
   char ciphertext[MAX_LEN] = {0, };

   FILE* fp;

   /* Initialize a context connecting us to the TEE */
   res = TEEC_InitializeContext(NULL, &ctx);
   if (res != TEEC_SUCCESS)
	errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

   res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

   if (res != TEEC_SUCCESS)
	errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);

   /* Clear the TEEC_Operation struct */
   memset(&op, 0, sizeof(op));
   
   op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
   op.params[0].tmpref.buffer = plaintext;
   op.params[0].tmpref.size = MAX_LEN;

   /* Check options */
   if (argc != 4){
	perror("Invalid options\n");
	return 1;
   }

   /* Encrypt */
   if(strcmp(argv[1], "-e") == 0){
 
	/* Func(1): open, read plaintext */	
	fp = fopen(argv[2], "r");

	if(fp == NULL){
		perror("File not found");
		return 1;
	}
	fread(plaintext, 1, MAX_LEN, fp);
	fclose(fp);

	printf("\n========================Encryption========================\n");
	printf("------------------------Plaintext-------------------------\n%s\n", plaintext);

	/* Caesar */
	if(strcmp(argv[3], "Caesar") == 0){

		/* Func(2): send plaintext to TA*/
		memcpy(op.params[0].tmpref.buffer, plaintext, MAX_LEN);
		op.params[0].tmpref.size = MAX_LEN;
		
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC, &op, &err_origin);

		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);

		/* Func(3): receive ciphertext, enc_key from TA*/
		memcpy(ciphertext, op.params[0].tmpref.buffer, MAX_LEN);
		printf("------------------------Cyphertext-------------------------\n%s\n", ciphertext);

		/* Func(4): save ciphertext.txt */
                fp = fopen("ciphertext.txt", "w");
		fputs(ciphertext, fp); 
		fclose(fp);

		/* Func(5): save enckey.txt */
		fp = fopen("encryptedkey.txt", "w");
		int enc_key = op.params[1].value.a;
		fprintf(fp, "%d", enc_key);
		fclose(fp);
	}
	/* RSA */
	else if(strcmp(argv[3], "RSA") == 0){
		return 1;
	}
	/* Error */
	else{
		perror("Invalid algorithmn\n");
		return 1;
	}
   }
   /* Decrypt */
   else if(strcmp(argv[1], "-d") == 0){ 

   }
   /* Error */
   else{
	perror("Invalid option\n");
	return 1;
   }

   TEEC_CloseSession(&sess);
   TEEC_FinalizeContext(&ctx);

   return 0;
}
