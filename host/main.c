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
#include <sys/queue.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "jsmn.h"
#include "crit.h"
#include "encoding.h"
#include "decoding.h"
#include "file_handling.h"
#include "criu.h"

#include "trusted_cr/trusted_cr_checkpoint.h"
#include "trusted_cr/trusted_cr_checkpoint_parser.h"

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <trusted_cr_ta.h>

enum RUN_MODE {
	UNKNOWN,		
	START_MIGRATED,		// Run a binary from the very first instruction in the secure world
	DUMP_AND_MIGRATE,	// Dump and migrate an already running binary
	DUMP_MIGRATION_API	// Migrate a binary that asks to be migrated via the API
};

enum RUN_MODE parse_arguments(int argc, char *argv[]);

int parse_pid(enum RUN_MODE mode, int argc, char *argv[]);

void secure_execute(int pid, enum RUN_MODE mode);

void prepare_shared_buffer_1(struct trusted_cr_checkpoint * checkpoint, 
void ** shared_buffer_1, TEEC_SharedMemory * shared_memory_1);

void prepare_shared_buffer_2(struct checkpoint_file_data * checkpoint_files, 
void ** shared_buffer_2, TEEC_SharedMemory * shared_memory_2);

void print_usage() {
	printf( "Usage:\ttrusted_cr -p <pid>\n");
	printf(       "\ttrusted_cr <executable> <arguments>\n\n");

	printf("Examples:\t./trusted_cr -p `pidof nbench`>\n");
	printf(       "\t\t./trusted_cr ./nbench -CCOM.DAT\n");
}

int main(int argc, char *argv[])
{
	printf("Trusted-CR\n\n");

	enum RUN_MODE mode = parse_arguments(argc, argv);

	int pid = parse_pid(mode, argc, argv);

	if(pid == -1)
		errx(1, "Error: pid is %d\n", pid);

	secure_execute(pid, mode);

	// Close connection to critserver if it is open
	critserver_disconnect();

	return 0;
}

enum RUN_MODE parse_arguments(int argc, char *argv[]) {
	enum RUN_MODE mode;

	if(argc < 2) {
		print_usage();
		exit(-1);
	}

	if (!strcmp(argv[1], "-p")) {
		// Run a binary from the very first instruction in the secure world
		mode = DUMP_AND_MIGRATE;
	} else if(!strcmp(argv[1], "-m")) {
		// Migrate a binary that asks to be migrated via the API
		mode = DUMP_MIGRATION_API;
	} else {
		// Dump and migrate an already running binary
		mode = START_MIGRATED;
	}

	if((mode == DUMP_MIGRATION_API || mode == DUMP_AND_MIGRATE) && argc < 3)
		errx(1, "Missing process id\n");

	return mode;
}

int parse_pid(enum RUN_MODE mode, int argc, char *argv[]) {
	int pid = -1;
	
	if(mode == DUMP_MIGRATION_API || mode == DUMP_AND_MIGRATE) {
		pid = strtoul(argv[2], NULL, 10);
		if(pid < 0)
			errx(1, "Invalid pid\n");

		// Dump and migrate an already running binary
		criu_dump(pid);
	} else if(mode == START_MIGRATED) {
		// Run a binary from the very first instruction in the secure world
		// Skip the first argument which is ./trusted_cr self
		criu_start_migrated(argc - 1, argv + 1);

		// We don't know any pid yet. Parse it from pstree.img
		// First decode pstree.img with crit
		critserver_decode_pid();

		// Now read in the readable pstree.txt 
		struct checkpoint_file_data pstree_checkpoint_file = { .filename = "pstree.txt" };
		read_file(&pstree_checkpoint_file);

		// And parse the pid
		pid = parse_checkpoint_pstree(&pstree_checkpoint_file);
		
		free(pstree_checkpoint_file.buffer);
	}

	return pid;
}

void secure_execute(int pid, enum RUN_MODE mode) {
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_SharedMemory shared_memory_1, shared_memory_2;
	void * shared_buffer_1, * shared_buffer_2;
	TEEC_UUID uuid = PTA_TRUSTED_CR_UUID;
	uint32_t err_origin;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%lx", res);

	/* Open a session to the TA */
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%lx origin 0x%lx", res, err_origin);

	// To hold the checkpoint file info
	struct checkpoint_file_data checkpoint_files[NUMBER_OF_CHECKPOINT_FILES] = {};
	struct trusted_cr_checkpoint checkpoint;
	
	bool stop_execution = false;
	bool migrate_back = false;
	bool migrated = false;

	while(!stop_execution) {
		// Decode all checkpoint files with CRIT and parse the checkpoint files, store it in &checkpoint.
		parse_checkpoint_files(pid, &checkpoint_files, &checkpoint);

		// For binaries that use the migration API
		// Change the register to exit the loop
		if(mode == DUMP_MIGRATION_API && !migrated) {
			migrated = true;
			checkpoint.regs.regs[0] = 0;
		}

		// Fill shared buffer 1 with the checkpoint struct: registers, vma's, pagemap entries, etc.
		prepare_shared_buffer_1(&checkpoint, &shared_buffer_1, &shared_memory_1);

		// Fill shared buffer 2 with the executable data and binary pagedata
		prepare_shared_buffer_2(&checkpoint_files, &shared_buffer_2, &shared_memory_2);

		// Register the shared memory buffers
		res = TEEC_RegisterSharedMemory(&ctx, &shared_memory_1);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_AllocateSharedMemory failed with code 0x%lx origin 0x%lx",
				res, err_origin);

		res = TEEC_RegisterSharedMemory(&ctx, &shared_memory_2);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_AllocateSharedMemory failed with code 0x%lx origin 0x%lx",
				res, err_origin);

		// Prepare the two arguments that are passed to the secure world, which are two shared memory buffers.
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE);

		op.params[0].memref.parent = &shared_memory_1;
		op.params[0].memref.size = shared_memory_1.size;
		op.params[0].memref.offset = 0;

		op.params[1].memref.parent = &shared_memory_2;
		op.params[1].memref.size = shared_memory_2.size;
		op.params[1].memref.offset = 0;
		
		/* TRUSTED_CR_EXECUTE_CHECKPOINT is the actual function in the TA to be called. */
		printf("\nLoading & executing checkpoint: %s\n", checkpoint_files[EXECUTABLE_BINARY_FILE].filename);

		res = TEEC_InvokeCommand(&sess, TRUSTED_CR_EXECUTE_CHECKPOINT, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%lx origin 0x%lx", res, err_origin);

		do {
			bool continue_execution = false;
			
			memcpy(&checkpoint.result, op.params[1].memref.parent->buffer, sizeof(enum trusted_cr_return_types));
			memcpy(&checkpoint.regs, op.params[1].memref.parent->buffer + sizeof(enum 	trusted_cr_return_types), sizeof(struct trusted_cr_checkpoint_regs));

			printf("TA returned from secure world: ");
			switch(checkpoint.result) {
				case TRUSTED_CR_SYSCALL_EXIT:
					stop_execution = true;
					printf("EXIT system call!\n");
					break;
				case TRUSTED_CR_SYSCALL_UNSUPPORTED:
					printf("unsupported system call.\n");
					break;
				case TRUSTED_CR_SYSCALL_MIGRATE_BACK:
					stop_execution = true;
					migrate_back = true;
					printf("Secure world wants to migrate back.\n");
					break;
				default:
					printf("no idea what happened.\n");
					break;
			}

			if(continue_execution) {
				printf("\nContinuing execution\n");
				res = TEEC_InvokeCommand(&sess, TRUSTED_CR_CONTINUE_EXECUTION, &op, &err_origin);
				if (res != TEEC_SUCCESS) {
					errx(1, "TEEC_InvokeCommand failed with code 0x%lx origin 0x%lx", res, err_origin);
					break;
				}
			} else {
				break;
			}
		} while(checkpoint.result != TRUSTED_CR_SYSCALL_EXIT &&
				checkpoint.result != TRUSTED_CR_SYSCALL_UNSUPPORTED &&
				checkpoint.result != TRUSTED_CR_SYSCALL_MIGRATE_BACK);
		
		// Invoke command TRUSTED_CR_CHECKPOINT_BACK to ask the TA to put the dirty checkpoint data in shared buffer 1.
		res = TEEC_InvokeCommand(&sess, TRUSTED_CR_CHECKPOINT_BACK, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%lx origin 0x%lx", res, err_origin);

		// Now parse the data in shared buffer 1 and use it to update the checkpoint files: update the registers,
		// add dirty pagemap entries and patch the pages-1.img file.
		update_checkpoint_files(&checkpoint, &checkpoint_files, op.params[1].memref.parent->buffer);

		// Release and free all allocated memory
		TEEC_ReleaseSharedMemory(&shared_memory_1);
		TEEC_ReleaseSharedMemory(&shared_memory_2);

		free(shared_buffer_1);
		free(shared_buffer_2);

		for(int i = 0; i < NUMBER_OF_CHECKPOINT_FILES; i++) {
			free(checkpoint_files[i].buffer);
		}

		// Re-encode the updated .txt checkpoint files to .img files
		critserver_encode_checkpoint(pid);

		// Copy back the patched pages-1.img file
		system("cp -rf modified_pages-1.img check/pages-1.img");

		if(!stop_execution) {
			// Execute one single system call with CRIU
			system("./criu.sh execute -D check --shell-job -v0");
		}
	}

	if(migrate_back) {
		// The binary has asked to migrate back to the normal world via the
		// migration API. Now restore it with CRIU like a normal checkpoint.
		system("./criu.sh restore -D check --shell-job --restore-detached -v0");
	}
	
	// We're done with the TA, close the session and destroy the context.
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
}

void prepare_shared_buffer_1(struct trusted_cr_checkpoint * checkpoint, void ** shared_buffer_1, TEEC_SharedMemory * shared_memory_1) {
	long shared_buffer_1_index = 0;
	int  shared_buffer_1_size  = sizeof(struct trusted_cr_checkpoint) 
							   + checkpoint->vm_area_count * sizeof(struct trusted_cr_vm_area)
							   + checkpoint->pagemap_entry_count * sizeof(struct trusted_cr_pagemap_entry);
	// printf("Shared buffer 1 is %d bytes big\n", shared_buffer_1_size);

	// Allocate space for shared buffer 1
	*shared_buffer_1 = malloc(shared_buffer_1_size);
	if(*shared_buffer_1 == NULL)
		errx(1, "Unable to allocate %d bytes for shared buffer 1.", shared_buffer_1_size);
		

	// Copy the checkpoint struct with the registers
	int size = sizeof(struct trusted_cr_checkpoint);
	memcpy(*shared_buffer_1 + shared_buffer_1_index, checkpoint, size);
	shared_buffer_1_index += size;
	
	// Copy over the vm areas
	size = checkpoint->vm_area_count * sizeof(struct trusted_cr_vm_area);
	memcpy(*shared_buffer_1 + shared_buffer_1_index, checkpoint->vm_areas, size);
	shared_buffer_1_index += size;

	// Copy over the pagemap entries
	size = checkpoint->pagemap_entry_count * sizeof(struct trusted_cr_pagemap_entry);
	memcpy(*shared_buffer_1 + shared_buffer_1_index, checkpoint->pagemap_entries, size);
	shared_buffer_1_index += size;

	// Setup shared memory buffer 1
	shared_memory_1->size = shared_buffer_1_size;
	shared_memory_1->flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	shared_memory_1->buffer = *shared_buffer_1;
}

void prepare_shared_buffer_2(struct checkpoint_file_data * checkpoint_files, void ** shared_buffer_2, TEEC_SharedMemory * shared_memory_2) {
	int  shared_buffer_2_index = 0;
	long shared_buffer_2_size  = 2 * sizeof(struct checkpoint_file) 
								+ checkpoint_files[EXECUTABLE_BINARY_FILE].file.file_size
								+ checkpoint_files[PAGES_BINARY_FILE].file.file_size;
	// printf("Shared buffer 2 is %d bytes big\n", shared_buffer_2_size);

	*shared_buffer_2 = malloc(shared_buffer_2_size);
	if(*shared_buffer_2 == NULL)
		errx(1, "Unable to allocate %d bytes for shared buffer 2.", shared_buffer_2_size);
	
	struct checkpoint_file * binary_data = *shared_buffer_2;
	// Store the executable file descriptor
	binary_data[EXECUTABLE_BINARY_FILE].file_type = (enum checkpoint_file_types) EXECUTABLE_BINARY_FILE;
	binary_data[EXECUTABLE_BINARY_FILE].file_size = checkpoint_files[EXECUTABLE_BINARY_FILE].file.file_size;
	binary_data[EXECUTABLE_BINARY_FILE].buffer_index = 2 * sizeof(struct checkpoint_file);
	shared_buffer_2_index += sizeof(struct checkpoint_file);

	// Store the pagedata descriptor
	binary_data[PAGES_BINARY_FILE].file_type = (enum checkpoint_file_types) PAGES_BINARY_FILE;
	binary_data[PAGES_BINARY_FILE].file_size = checkpoint_files[PAGES_BINARY_FILE].file.file_size;
	binary_data[PAGES_BINARY_FILE].buffer_index = binary_data[EXECUTABLE_BINARY_FILE].buffer_index
												+ binary_data[EXECUTABLE_BINARY_FILE].file_size;
	shared_buffer_2_index += sizeof(struct checkpoint_file);

	// Store the executable
	int size = checkpoint_files[EXECUTABLE_BINARY_FILE].file.file_size;
	memcpy(*shared_buffer_2 + shared_buffer_2_index, checkpoint_files[EXECUTABLE_BINARY_FILE].buffer, size);
	shared_buffer_2_index += size;

	// Store the pagedata
	size = checkpoint_files[PAGES_BINARY_FILE].file.file_size;
	memcpy(*shared_buffer_2 + shared_buffer_2_index, checkpoint_files[PAGES_BINARY_FILE].buffer, size);
	shared_buffer_2_index += size;

	// Setup shared memory buffer 2
	shared_memory_2->size = shared_buffer_2_size;
	shared_memory_2->flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	shared_memory_2->buffer = *shared_buffer_2;
}