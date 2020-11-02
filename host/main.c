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
#define CHECKPOINT_FILES 5 
#define CHECKPOINT_FILENAME_MAXLENGTH 40

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
	char * buffer;
	long file_size;
	uint64_t buffer_index;
};

bool insert_file_contents(const char * fileName, char * buffer, long * buffer_index, struct checkpoint_file * checkpoint_file);
void print_substring(char * buffer, int start_index, int end_index);


static int jsoneq(const char *json, jsmntok_t *tok, const char *s);

bool read_file(struct checkpoint_file_data * c_file);

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_SharedMemory shared_memory_1, shared_memory_2;
	
	TEEC_UUID uuid = PTA_CRIU_UUID;
	uint32_t err_origin;

	printf("OP-TEE App Migrator\n\n");

	// To hold the checkpoint file info
	struct checkpoint_file_data files[CHECKPOINT_FILES] = {};
	char filenames[CHECKPOINT_FILES][CHECKPOINT_FILENAME_MAXLENGTH] = {
		"core-3017.txt",
		"mm-3017.txt",
		"pagemap-3017.txt",
		"pages-1.img",
		"loop2"
	};
	
	// Total size of the shared buffer 1, which contains all checkpoint files together.
	int shared_buffer_1_size = 0;
	for(int i = 0; i < CHECKPOINT_FILES; i++) {
		// Set the filename, load the filesize and read the file from disk into the buffer
		files[i].filename = filenames[i];
		read_file(&files[i]);

		// Increase the buffer size
		shared_buffer_1_size += files[i].file_size;
	}

	// Notice the ++? Reserve another byte for the \0 character
	printf("Total checkpoint size to migrate is %d bytes\n", ++shared_buffer_1_size);

	// Allocate space for shared buffer 1
	char * shared_buffer_1 = malloc(shared_buffer_1_size);
	if(shared_buffer_1 == NULL) {
		printf("Unable to allocate %d bytes for shared buffer 1.", shared_buffer_1_size);
		return -1;
	}

	printf("Loading checkpoint files into the buffer... ");
	long shared_buffer_1_index = 0;
	for(int i = 0; i < CHECKPOINT_FILES; i++) {
		// First copy the data from the checkpoint file buffer to shared buffer 1 at the correct index
		memcpy(shared_buffer_1 + shared_buffer_1_index, files[i].buffer, files[i].file_size);
		// Store the index so we can send that info later in shared buffer 2
		files[i].buffer_index = shared_buffer_1_index;
		// Will be overwritten by the next memcpy, except for the last entry
		shared_buffer_1[shared_buffer_1_index + files[i].file_size] = 0;

		shared_buffer_1_index += files[i].file_size;
	}
	printf("done!\n");

	// Setup the structs that will go into shared buffer 2
	struct checkpoint_file * checkpoint_files = malloc(sizeof(struct checkpoint_file) * CHECKPOINT_FILES);
	for(int i = 0; i < CHECKPOINT_FILES; i++) {
		checkpoint_files[i].file_type = (enum checkpoint_file_types) i;
		checkpoint_files[i].file_size = files[i].file_size;
		checkpoint_files[i].buffer_index = files[i].buffer_index;
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

	// Setup shared memory buffer 1
	shared_memory_1.size = shared_buffer_1_size;
	shared_memory_1.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	shared_memory_1.buffer = shared_buffer_1;

	res = TEEC_RegisterSharedMemory(&ctx, &shared_memory_1);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_AllocateSharedMemory failed with code 0x%x origin 0x%x",
			res, err_origin);

	// Setup shared memory buffer 2
	shared_memory_2.size = sizeof(struct checkpoint_file) * CHECKPOINT_FILES;
	shared_memory_2.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	shared_memory_2.buffer = checkpoint_files;

	res = TEEC_RegisterSharedMemory(&ctx, &shared_memory_2);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_AllocateSharedMemory failed with code 0x%x origin 0x%x",
			res, err_origin);

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	/*
	* Prepare the two arguments that will be passed to the secure world, which are two shared memory buffers.
	*/
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE,
				TEEC_NONE, TEEC_NONE);

	op.params[0].memref.parent = &shared_memory_1;
	op.params[0].memref.size = shared_memory_1.size;
	op.params[0].memref.offset = 0;

	op.params[1].memref.parent = &shared_memory_2;
	op.params[1].memref.size = shared_memory_2.size;
	op.params[1].memref.offset = 0;

#ifdef DEBUG
	struct checkpoint_file * checkpoint_file_var = checkpoint_files;
	for(int i = 0; i < CHECKPOINT_FILES; i++) {
		printf("checkpoint file: type %lu - index %lu\t- size %lu\n", checkpoint_file_var[i].file_type, checkpoint_file_var[i].buffer_index, checkpoint_file_var[i].file_size);
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
	// After running the checkpoint in the secure world, the secure world checkpoints back
	// and puts the updated checkpoint values in the parameters.
	
	// TODO: implement checking the parameter for correct lengths
	// if(op.params[1].memref.size > sizeof(struct checkpoint_file));

	long shared_buffer_2_index = 0;
	struct criu_checkpoint_regs * checkpoint = op.params[0].memref.parent->buffer;
	shared_buffer_2_index += sizeof(struct criu_checkpoint_regs);

	FILE *fpp = fopen("modified_core.txt", "w+");
	if(fpp) {
		// fwrite(op.params[0].memref.parent->buffer + dirty_pages_info->offset + entry_page_offset * 4096, 1, (pagemap_entry->nr_pages * 4096), fpp);

		char * buffer = files[CORE_FILE].buffer;
		long file_size = files[CORE_FILE].file_size;

		// Initialize the JSMN json parser
		jsmn_parser parser;
		jsmn_init(&parser);

		// First only determine the number of tokens.
		int items = jsmn_parse(&parser, buffer, file_size, NULL, 128);

		jsmntok_t tokens[items];
		
		// Reset position in stream
		jsmn_init(&parser);
		int left = jsmn_parse(&parser, buffer, file_size, tokens, items);

		// Invalid file.
		if (items < 1 || tokens[0].type != JSMN_OBJECT) {
			printf("CRIU: INVALID JSON\n");
			return -1;
		}

		// TLS indexes
		int before_tls_value = 0;
		int  after_tls_value = 0;

		// Regs indexes
		int before_regs_value = 0;
		int  after_regs_value = 0;

		// SP indexes
		int before_sp_value = 0;
		int  after_sp_value = 0;

		// PC indexes
		int before_pc_value = 0;
		int  after_pc_value = 0;

		// Vregs indexes
		int before_vregs_value = 0;
		int  after_vregs_value = 0;

		// Parse the JSON version of the core checkpoint file (example core-2956.img)
		for(int i = 1; i < items; i++) {
			if (jsoneq(buffer, &tokens[i], "tls") == 0) { 
				before_tls_value = tokens[i+1].start;
				after_tls_value = tokens[i+1].end;
			} else if (jsoneq(buffer, &tokens[i], "regs") == 0) { 
				before_regs_value = tokens[i+1].start;
				after_regs_value = tokens[i+1].end;
			} else if (jsoneq(buffer, &tokens[i], "sp") == 0) {
				before_sp_value = tokens[i+1].start;
				after_sp_value = tokens[i+1].end;
			} else if (jsoneq(buffer, &tokens[i], "pc") == 0) {
				before_pc_value = tokens[i+1].start;
				after_pc_value = tokens[i+1].end;
			} else if (jsoneq(buffer, &tokens[i], "vregs") == 0) {
				before_vregs_value = tokens[i+1].start;
				after_vregs_value = tokens[i+1].end;
			}
		}

		print_substring(buffer, 0, before_tls_value);

		// Write tpidr_el0
		printf("%llu", checkpoint->tpidr_el0_addr); 
		print_substring(buffer, after_tls_value, before_regs_value);

		// Write all updated registers
		putchar('[');
		for(int i = 0; i < 31; i++) {
			if(checkpoint->regs[i])
				printf("\"%p\"", checkpoint->regs[i]);
			else
				printf("\"0x0\"");

			if(i != 30)
				printf(",\n");
		}
		putchar(']');
		print_substring(buffer, after_regs_value, before_sp_value);

		// Write updated stack pointer
		printf("%p", checkpoint->stack_addr);
		print_substring(buffer, after_sp_value, before_pc_value);

		// Write updated program counter
		printf("%p", checkpoint->entry_addr);
		print_substring(buffer, after_pc_value, before_vregs_value);

		// Write all updated vregs
		putchar('[');
		for(int i = 0; i < 64; i++) {
			printf("%llu", checkpoint->vregs[i]);

			if(i != 63)
				printf(",\n");
		}
		putchar(']');
		print_substring(buffer, after_vregs_value, file_size);

		fclose(fpp);
	}

	// struct criu_checkpoint_dirty_pages * dirty_pages_info = op.params[0].memref.parent->buffer + shared_buffer_2_index;
	// shared_buffer_2_index += sizeof(struct criu_checkpoint_dirty_pages);

	// FILE *fp = fopen("pages-1.new.img", "w+");
	// // FILE *f  = fopen("pages-1.img", "rb");

	// printf("Number of dirty pages: %d\n", dirty_pages_info->dirty_page_count);
	// struct criu_pagemap_entry * pagemap_entry = NULL;

	// if(fp) {
	// 	long entry_page_offset = 0;
	// 	for(int y = 0; y < dirty_pages_info->dirty_page_count; y++) {
	// 		pagemap_entry = op.params[0].memref.parent->buffer + shared_buffer_2_index + (sizeof(struct criu_pagemap_entry) * y) ;
	// 		printf("Dirty page at: %p - entries: %d - entry: %d\n", pagemap_entry->vaddr_start, pagemap_entry->nr_pages, pagemap_entry->file_page_index);
	// 		fwrite(op.params[0].memref.parent->buffer + dirty_pages_info->offset + entry_page_offset * 4096, 1, (pagemap_entry->nr_pages * 4096), fp);
	// 		entry_page_offset += pagemap_entry->nr_pages;
	// 	}

	// 	fclose(fp);
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
	TEEC_ReleaseSharedMemory(&shared_memory_1);
	TEEC_ReleaseSharedMemory(&shared_memory_2);
	free(shared_buffer_1);
	free(checkpoint_files);

	for(int i = 0; i < 5; i++) {
		free(files[i].buffer);
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

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}

bool read_file(struct checkpoint_file_data * c_file) {
	FILE *f = fopen(c_file->filename, "rb");

	if(f) {
		// Determine file size
		fseek(f, 0, SEEK_END);
		c_file->file_size = ftell(f);
		fseek(f, 0, SEEK_SET);

		c_file->buffer = malloc(c_file->file_size + 1);

		if(c_file->buffer) {
			fread(c_file->buffer, 1, c_file->file_size, f);
			c_file->buffer[c_file->file_size] = 0;
		} else {
			// Unable to malloc.
			printf("Unable to malloc %ld bytes for file %s.\n", c_file->file_size, c_file->filename);
			c_file->file_size = -1;
			return false;
		}

		fclose(f);
	} else {
		printf("Unable to read file: %s\n", c_file->filename);
		return false;
	}

	return true;
}