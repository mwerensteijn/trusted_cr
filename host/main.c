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
#include "jsmn.h"

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <optee_app_migrator_ta.h>

typedef uintptr_t vaddr_t;

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

struct criu_checkpoint_regs {
	uint64_t vregs[64];
	uint64_t regs[31];
	uint64_t entry_addr;
	uint64_t stack_addr;
	uint64_t tpidr_el0_addr;
};

struct checkpoint_file {
	enum checkpoint_file_types file_type;
	uint64_t buffer_index;
	uint64_t file_size;
};

struct criu_pagemap_entry {
	vaddr_t vaddr_start;
	unsigned long file_page_index;
	unsigned long nr_pages;
	uint8_t flags;
};

struct criu_checkpoint_dirty_pages {
	uint32_t dirty_page_count;
	uint32_t offset;
};

struct checkpoint_file_data {
	char * filename;
	void * buffer;
	long file_size;
};

bool insert_file_contents(const char * fileName, char * buffer, long * buffer_index, struct checkpoint_file * checkpoint_file);
void print_substring(char * buffer, int start_index, int end_index);

bool read_file(struct checkpoint_file_data * c_file) {
	FILE *f = fopen(c_file->filename, "rb");

	if(f) {
		// Determine file size
		fseek(f, 0, SEEK_END);
		c_file->file_size = ftell(f);
		fseek(f, 0, SEEK_SET);

		c_file->buffer = malloc(c_file->file_size);

		fclose(f);
	} else {
		printf("Unable to read file: %s\n", c_file->filename);
		return false;
	}

	return true;
}

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

	char mm_filename[]      = "mm-3017.txt";
	char core_filename[]    = "core-3017.txt";
	char pages_filename[]   = "pages-1.img";
	char binary_filename[]  = "loop2";
	char pagemap_filename[] = "pagemap-3017.txt";

	struct checkpoint_file_data files[5] = {
		{ .filename = mm_filename },
		{ .filename = core_filename },
		{ .filename = pages_filename },
		{ .filename = binary_filename },
		{ .filename = pagemap_filename }
	};
	
	int total_buffer_size = 0;
	for(int i = 0; i < 5; i++) {
		read_file(&files[i]);
		printf("size of %s is %d\n", files[i].filename, files[i].file_size);
		total_buffer_size += files[i].file_size;
	}

	printf("Total checkpoint size to migrate: ");
	printf("%d bytes\n", total_buffer_size);

	struct checkpoint_file * checkpoint_files = malloc(sizeof(struct checkpoint_file) * CHECKPOINT_FILES);
	char * dataBuffer = malloc(total_buffer_size + 1);
	if(dataBuffer == NULL) {
		printf("Unable to allocate %d bytes for the buffer.", total_buffer_size);
		return -1;
	}

	printf("Loading checkpoint files into the buffer... ");
	long buffer_index = 0;
	insert_file_contents("core-3017.txt", dataBuffer, &buffer_index, &checkpoint_files[CORE_FILE]);
	insert_file_contents("mm-3017.txt", dataBuffer, &buffer_index, &checkpoint_files[MM_FILE]);
	insert_file_contents("pages-1.img", dataBuffer, &buffer_index, &checkpoint_files[PAGES_BINARY_FILE]);
	insert_file_contents("loop2", dataBuffer, &buffer_index, &checkpoint_files[EXECUTABLE_BINARY_FILE]);
	insert_file_contents("pagemap-3017.txt", dataBuffer, &buffer_index, &checkpoint_files[PAGEMAP_FILE]);
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
	if(op.params[1].memref.size > sizeof(struct checkpoint_file));
	long index = 0;
	struct criu_checkpoint_regs * checkpoint = op.params[0].memref.parent->buffer;
	index += sizeof(struct criu_checkpoint_regs);

	printf("Got an updated PC of: \"%p\"\n", checkpoint->entry_addr);
	printf("Got an updated SP of: \"%p\"\n", checkpoint->stack_addr);
	printf("Got an updated TPIDR_EL0 of: %llu\n", checkpoint->tpidr_el0_addr);

	printf("\nregs:\n");
	for(int i = 0; i < 31; i++) {
		if(checkpoint->regs[i])
			printf("\"%p\",\n", checkpoint->regs[i]);
		else
			printf("\"0x0\",\n");
	}

	printf("\nvregs:\n");
	for(int i = 0; i < 64; i++) {
		printf("%llu,\n", checkpoint->vregs[i]);
	}

	struct criu_checkpoint_dirty_pages * dirty_pages_info = op.params[0].memref.parent->buffer + index;
	index += sizeof(struct criu_checkpoint_dirty_pages);


	FILE *fp = fopen("pages-1.new.img", "w+");
	// FILE *f  = fopen("pages-1.img", "rb");

	printf("Number of dirty pages: %d\n", dirty_pages_info->dirty_page_count);
	struct criu_pagemap_entry * pagemap_entry = NULL;

	if(fp) {
		long entry_page_offset = 0;
		for(int y = 0; y < dirty_pages_info->dirty_page_count; y++) {
			pagemap_entry = op.params[0].memref.parent->buffer + index + (sizeof(struct criu_pagemap_entry) * y) ;
			printf("Dirty page at: %p - entries: %d - entry: %d\n", pagemap_entry->vaddr_start, pagemap_entry->nr_pages, pagemap_entry->file_page_index);
			fwrite(op.params[0].memref.parent->buffer + dirty_pages_info->offset + entry_page_offset * 4096, 1, (pagemap_entry->nr_pages * 4096), fp);
			entry_page_offset += pagemap_entry->nr_pages;
		}

		fclose(fp);
	}

	// FILE *fpp = fopen("modified_core.txt", "w+");
	// if(fpp) {
	// 	// fwrite(op.params[0].memref.parent->buffer + dirty_pages_info->offset + entry_page_offset * 4096, 1, (pagemap_entry->nr_pages * 4096), fpp);

	// 	// Initialize the JSMN json parser
	// 	jsmn_parser parser;
	// 	jsmn_init(&parser);

	// 	// First only determine the number of tokens.
	// 	int items = jsmn_parse(&parser, json, strlen(json), NULL, 128);

	// 	jsmntok_t tokens[items];
		
	// 	// Reset position in stream
	// 	jsmn_init(&parser);
	// 	int left = jsmn_parse(&parser, json, strlen(json), tokens, items);

	// 	// Invalid file.
	// 	if (items < 1 || tokens[0].type != JSMN_OBJECT) {
	// 		printf("CRIU: INVALID JSON\n");
	// 		return -1;
	// 	}

	// 	// TLS indexes
	// 	int before_tls_value = 0;
	// 	int  after_tls_value = 0;

	// 	// Regs indexes
	// 	int before_regs_value = 0;
	// 	int  after_regs_value = 0;

	// 	// SP indexes
	// 	int before_sp_value = 0;
	// 	int  after_sp_value = 0;

	// 	// PC indexes
	// 	int before_pc_value = 0;
	// 	int  after_pc_value = 0;

	// 	// Vregs indexes
	// 	int before_vregs_value = 0;
	// 	int  after_vregs_value = 0;

	// 	// Parse the JSON version of the core checkpoint file (example core-2956.img)
	// 	for(int i = 1; i < items; i++) {
	// 		if (jsoneq(json, &tokens[i], "tls") == 0) { 
	// 			before_tls_value = tokens[i+1].start;
	// 			after_tls_value = tokens[i+1].end;
	// 		} else if (jsoneq(json, &tokens[i], "regs") == 0) { 
	// 			before_regs_value = tokens[i+1].start;
	// 			after_regs_value = tokens[i+1].end;
	// 		} else if (jsoneq(json, &tokens[i], "sp") == 0) {
	// 			before_sp_value = tokens[i+1].start;
	// 			after_sp_value = tokens[i+1].end;
	// 		} else if (jsoneq(json, &tokens[i], "pc") == 0) {
	// 			before_pc_value = tokens[i+1].start;
	// 			after_pc_value = tokens[i+1].end;
	// 		} else if (jsoneq(json, &tokens[i], "vregs") == 0) {
	// 			before_vregs_value = tokens[i+1].start;
	// 			after_vregs_value = tokens[i+1].end;
	// 		}
	// 	}

	// 	print_substring(json, 0, before_tls_value);
	// 	printf("0xtls"); // write tpidr_el0
	// 	print_substring(json, after_tls_value, before_regs_value);
	// 	printf("[ print all regs... ]"); // write regs
	// 	print_substring(json, after_regs_value, before_sp_value);
	// 	printf("0xsp"); // write sp
	// 	print_substring(json, after_sp_value, before_pc_value);
	// 	printf("0xpc"); // write pc
	// 	print_substring(json, after_pc_value, before_vregs_value);
	// 	printf("[ print all vregs... ]"); // write vregs
	// 	print_substring(json, after_vregs_value, strlen(json));

	// 	fclose(fpp);
	// }

	// if(f) {
	// 	// Determine file size
	// 	fseek(f, 0, SEEK_END);
	// 	int page_count = ftell(f) / 4096;
	// 	fseek(f, 0, SEEK_SET);

	// 	printf("size: %d\n", page_count);
	// 	char buffer[4096];

	// 	for(int i = 0; i < page_count; i++) {
	// 		// Read from the original pages-1.img file
	// 		fread(buffer, 1, 4096, f);

	// 		// Track if this page is updated
	// 		bool dirty_page = false;

	// 		// Check every dirty page for a match
	// 		for(int y = 0; y < dirty_pages_info->dirty_page_count; y++) {
	// 			pagemap_entry = op.params[0].memref.parent->buffer + index + (sizeof(struct criu_pagemap_entry) * y) ;
	// 			if(pagemap_entry->file_page_index == i) {
	// 				printf("Dirty page at: %p - entries: %d - entry: %d\n", pagemap_entry->vaddr_start, pagemap_entry->nr_pages, pagemap_entry->file_page_index);
	// 				fwrite(op.params[0].memref.parent->buffer + dirty_pages_info->offset + pagemap_entry->file_page_index * 4096, 1, 4096 + (pagemap_entry->nr_pages - 1) * 4096, fp);
	// 				i += pagemap_entry->nr_pages - 1;
	// 				dirty_page = true;
	// 				break;
	// 			}
	// 		}

	// 		// The page is not dirty, so write the original
	// 		if(!dirty_page) {
	// 			fwrite(buffer, 1, 4096, fp);
	// 		}
	// 	}

	// 	fclose(f);
	// }

	// if(fp)
	// 	fclose(fp);

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

void print_substring(char * buffer, int start_index, int end_index) {
	char backup = buffer[end_index];
	buffer[end_index] = 0;
	printf(buffer + start_index);
	buffer[end_index] = backup;	
}