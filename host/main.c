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

enum checkpoint_file_types { 
	CORE_FILE = 0,				// core-*.img
	MM_FILE,				// mm-*.img
	PAGEMAP_FILE,			// pagemap-*.img
	PAGES_BINARY_FILE,		// pages-*.img
	EXECUTABLE_BINARY_FILE	// The binary itself that is checkpointed
};

// Subtract the last enum from the first to determine the number of 
// elements in the enum. By doing this we can use the enum values as indexes
// to the checkpoint_files array. Example checkpoint_files[CORE_FILE].
static const int CHECKPOINT_FILES = EXECUTABLE_BINARY_FILE - CORE_FILE + 1; 

struct checkpoint_file {
	enum checkpoint_file_types file_type;
	uint64_t buffer_index;
	uint64_t file_size;
};

int get_file_size(const char * fileName);
bool insert_file_contents(const char * fileName, char * buffer, long * buffer_index, struct checkpoint_file * checkpoint_file);


int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_SharedMemory sharedBuffer, sharedBufferInformation;
	// TEEC_UUID uuid = TA_APP_MIGRATOR_UUID;
	TEEC_UUID uuid = PTA_CRIU_UUID;
	uint32_t err_origin;

	printf("OP-TEE App Migrator\n\n");

	printf("Total checkpoint size to migrate: ");
	int total_buffer_size = 0;
	total_buffer_size += get_file_size("mm-2956.txt");
	total_buffer_size += get_file_size("core-2956.txt");
	total_buffer_size += get_file_size("pages-1.img");
	total_buffer_size += get_file_size("loop2");
	total_buffer_size += get_file_size("pagemap-2956.txt");
	printf("%d bytes\n", total_buffer_size);

	struct checkpoint_file * checkpoint_files = malloc(sizeof(struct checkpoint_file) * CHECKPOINT_FILES);
	char * dataBuffer = malloc(total_buffer_size + 1);
	if(dataBuffer == NULL) {
		printf("Unable to allocate %d bytes for the buffer.", total_buffer_size);
		return -1;
	}

	printf("Loading checkpoint files into the buffer... ");
	long buffer_index = 0;
	insert_file_contents("core-2956.txt", dataBuffer, &buffer_index, &checkpoint_files[CORE_FILE]);
	insert_file_contents("mm-2956.txt", dataBuffer, &buffer_index, &checkpoint_files[MM_FILE]);
	insert_file_contents("pages-1.img", dataBuffer, &buffer_index, &checkpoint_files[PAGES_BINARY_FILE]);
	insert_file_contents("loop2", dataBuffer, &buffer_index, &checkpoint_files[EXECUTABLE_BINARY_FILE]);
	insert_file_contents("pagemap-2956.txt", dataBuffer, &buffer_index, &checkpoint_files[PAGEMAP_FILE]);
	printf("done!\n");

	// Setting the file types
	for(int i = 0; i < CHECKPOINT_FILES; i++) {
		checkpoint_files[i].file_type = (enum checkpoint_file_types) i;
	}

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

	// Setup shared memory
	sharedBuffer.size = total_buffer_size;
	sharedBuffer.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	sharedBuffer.buffer = dataBuffer;

	sharedBufferInformation.size = sizeof(struct checkpoint_file) * CHECKPOINT_FILES;
	sharedBufferInformation.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	sharedBufferInformation.buffer = checkpoint_files;

	res = TEEC_RegisterSharedMemory(&ctx, &sharedBuffer);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_AllocateSharedMemory failed with code 0x%x origin 0x%x",
			res, err_origin);

	res = TEEC_RegisterSharedMemory(&ctx, &sharedBufferInformation);
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

	op.params[0].memref.parent = &sharedBuffer;
	op.params[0].memref.size = sharedBuffer.size;
	op.params[0].memref.offset = 0;

	op.params[1].memref.parent = &sharedBufferInformation;
	op.params[1].memref.size = sharedBufferInformation.size;
	op.params[1].memref.offset = 0;

#ifdef DEBUG
	struct checkpoint_file * checkpoint_file_var = checkpoint_files;
	for(int i = 0; i < CHECKPOINT_FILES; i++) {
		printf("checkpoint file: type %lu - index %lu - size %lu\n", checkpoint_file_var[i].file_type, checkpoint_file_var[i].buffer_index, checkpoint_file_var[i].file_size);
	}
#endif

	/*
	* TA_OPTEE_APP_MIGRATOR_CMD_INC_VALUE is the actual function in the TA to be
	* called.
	*/
	printf("\nInvoking TA\n");
	res = TEEC_InvokeCommand(&sess, TA_OPTEE_APP_MIGRATOR_CMD_PRINT_STRING, &op,
				&err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	printf("TA returned from secure world\n");

	// As the memory buffers where shared, the data can be changed in the secure world.
	// That data can again be retrieved in op.params[0].memref.parent->buffer);

	// Give the memory back
	TEEC_ReleaseSharedMemory(&sharedBuffer);
	TEEC_ReleaseSharedMemory(&sharedBufferInformation);
	free(dataBuffer);
	free(checkpoint_files);

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

int get_file_size(const char * fileName) {
	FILE *f = fopen(fileName, "rb");

	int fileSize = 0;

	if(f) {
		// Determine file size
		fseek(f, 0, SEEK_END);
		fileSize = ftell(f);
		fclose(f);
	} else {
		printf("Unable to read file: %s\n", fileName);
	}

	return fileSize;
}

bool insert_file_contents(const char * fileName, char * buffer, long * buffer_index, struct checkpoint_file * checkpoint_file) {
	FILE *f = fopen(fileName, "rb");

	if(f) {
		// Determine file size
		fseek(f, 0, SEEK_END);
		checkpoint_file->file_size = ftell(f) + 1;
		fseek(f, 0, SEEK_SET);

		if(buffer) {
			fread(buffer + *buffer_index, 1, checkpoint_file->file_size, f);
			buffer[*buffer_index + checkpoint_file->file_size] = 0;
			checkpoint_file->buffer_index = *buffer_index;
		} else {
			// Unable to malloc.
			printf("Unable to malloc %ld bytes for file contents.\n", checkpoint_file->file_size);
			checkpoint_file->file_size = -1;
			return false;
		}

		fclose(f);
	} else {
		printf("Unable to read file: %s\n", fileName);
		return false;
	}

	*buffer_index += checkpoint_file->file_size;
	return true;
}