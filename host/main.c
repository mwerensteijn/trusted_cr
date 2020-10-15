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
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <optee_app_migrator_ta.h>

char * read_file_contents(const char * fileName, long * fileSize);


enum checkpoint_file_types { 
	CORE_FILE,				// core-*.img
	MM_FILE,				// mm-*.img
	PAGEMAP_FILE,			// pagemap-*.img
	PAGES_BINARY_FILE,		// pages-*.img
	EXECUTABLE_BINARY_FILE	// The binary itself that is checkpointed
};

struct checkpoint_file {
	enum checkpoint_file_types file_type;
	uint64_t buffer_index;
	uint64_t file_size;
};

struct checkpoint {
	struct checkpoint_file core_file;
	struct checkpoint_file mm_file;
	struct checkpoint_file pagemap_file;
	struct checkpoint_file pages_binary_file;
	struct checkpoint_file executable_binary_file;	
};

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_SharedMemory sharedMemoryFile, sharedMemoryPages;
	// TEEC_UUID uuid = TA_APP_MIGRATOR_UUID;
	TEEC_UUID uuid = PTA_CRIU_UUID;
	uint32_t err_origin;

	// int file_index = 0;
	// int last_buffer_index = 0;
	// struct checkpoint_file * checkpoint_files = malloc(sizeof(struct checkpoint_file) * 5);	
	// checkpoint_files[0].file_type = CORE_FILE;
	// checkpoint_files[0].buffer_index = 0;
	// checkpoint_files[0].file_size = 1000;
	// last_buffer_index += checkpoint_files[0].file_size;


	// struct checkpoint_file {
	// 	enum checkpoint_file_types file_type;
	// 	uint64_t file_index;
	// 	uint64_t file_size;
	// };

	printf("OP-TEE App Migrator\n");

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/*
	 * Open a session to the "hello world" TA, the TA will print "hello
	 * world!" in the log when the session is created.
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	long fileSize = -1, pagedataSize = -1;
	char * fileContents = read_file_contents("loop2", &fileSize);
	char * pagedataContents = read_file_contents("pages-1.img", &pagedataSize);

	if(fileSize && fileContents && pagedataSize && pagedataContents) {
		// Setup shared memory
		sharedMemoryFile.size = fileSize;
		sharedMemoryFile.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
		sharedMemoryFile.buffer = fileContents;

		sharedMemoryPages.size = pagedataSize;
		sharedMemoryPages.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
		sharedMemoryPages.buffer = pagedataContents;

		res = TEEC_RegisterSharedMemory(&ctx, &sharedMemoryFile);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_AllocateSharedMemory failed with code 0x%x origin 0x%x",
				res, err_origin);

		res = TEEC_RegisterSharedMemory(&ctx, &sharedMemoryPages);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_AllocateSharedMemory failed with code 0x%x origin 0x%x",
				res, err_origin);

		/* Clear the TEEC_Operation struct */
		memset(&op, 0, sizeof(op));

		/*
		* Prepare the argument. Pass a value in the first parameter,
		* the remaining three parameters are unused.
		*/
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE,
					TEEC_NONE, TEEC_NONE);

		op.params[0].memref.parent = &sharedMemoryFile;
		op.params[0].memref.size = fileSize;
		op.params[0].memref.offset = 0;

		op.params[1].memref.parent = &sharedMemoryPages;
		op.params[1].memref.size = pagedataSize;
		op.params[1].memref.offset = 0;

		/*
		* TA_OPTEE_APP_MIGRATOR_CMD_INC_VALUE is the actual function in the TA to be
		* called.
		*/
		printf("Invoking TA with message: \"%s\"\n", (char *) op.params[0].memref.parent->buffer);
		res = TEEC_InvokeCommand(&sess, TA_OPTEE_APP_MIGRATOR_CMD_PRINT_STRING, &op,
					&err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		printf("TA changed message to \"%s\"\n", (char *) op.params[0].memref.parent->buffer);


		// Give the memory back
		TEEC_ReleaseSharedMemory(&sharedMemoryFile);
		TEEC_ReleaseSharedMemory(&sharedMemoryPages);
	}

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}

char * read_file_contents(const char * fileName, long * fileSize) {
	char * message = NULL;
	FILE *f = fopen(fileName, "rb");

	if(f) {
		// Determine file size
		fseek(f, 0, SEEK_END);
		*fileSize = ftell(f);
		fseek(f, 0, SEEK_SET);

		message = malloc(*fileSize + 1);
		if(message) {
			fread(message, 1, *fileSize, f);
			message[*fileSize] = 0;
		} else {
			// Unable to malloc.
			printf("Unable to malloc %ld bytes for file contents.\n", *fileSize + 1);
			*fileSize = -1;
		}

		fclose(f);
	} else {
		printf("Unable to read file: %s\n", fileName);
	}

	return message;
}