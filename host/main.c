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
#include "file_handling.h"
#include "criu.h"

#include "criu/criu_checkpoint.h"
#include "criu/criu_checkpoint_parser.h"

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <optee_app_migrator_ta.h>

#define CHECKPOINT_FILES 7 
#define CHECKPOINT_FILENAME_MAXLENGTH 100

void print_usage() {
	printf( "Usage:\toptee_app_migrator -p <pid>\n");
	printf(       "\toptee_app_migrator <executable> <arguments>\n\n");

	printf("Examples:\t./optee_app_migrator -p `pidof nbench`>\n");
	printf(       "\t\t./optee_app_migrator ./nbench -CCOM.DAT\n");
}

enum RUN_MODE {
	UNKNOWN,		
	START_MIGRATED,		// Run a binary from the very first instruction in the secure world
	DUMP_AND_MIGRATE,	// Dump and migrate an already running binary
	DUMP_MIGRATION_API	// Migrate a binary that asks to be migrated via the API
};

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


int main(int argc, char *argv[])
{
	printf("OP-TEE App Migrator\n\n");

	enum RUN_MODE mode = parse_arguments(argc, argv);

	int pid = -1;

	if(mode == DUMP_MIGRATION_API || mode == DUMP_AND_MIGRATE) {
		pid = strtoul(argv[2], NULL, 10);
		if(pid < 0)
			errx(1, "Invalid pid\n");

		if(mode == DUMP_MIGRATION_API) {
			criu_dump_migration_api(pid);
		} else if (mode == DUMP_AND_MIGRATE) {
			criu_dump(pid);
		}
	} else if(mode == START_MIGRATED) {
		char command[] = "./criu.sh start -D check --shell-job --exec-cmd -v0 -- ";

		//  All of this just to determine the full size of the final string
		int arguments = argc - 1;
		int total_size = strlen(command) + 1; // +1 for the 0-terminator
		for(int i = 0; i < arguments; i++) {
			total_size += strlen(argv[i+1]);

 			// Because we need a space between the arguments
			if((i+1) != arguments)
				total_size += 1;
		}

		// We can now allocate the full command.
		char * full_command = malloc(total_size);

		// Copy over the first part of the command "./criu.sh start -D check --shell-job --exec-cmd -- " 
		int index = 0;
		int size = strlen(command);
		memcpy(full_command, command, size);
		index += size;

		// Now append the rest of the arguments after the first part of the command
		for(int i = 0; i < arguments; i++) {
			size = strlen(argv[i+1]);

			if((i+1) != arguments) {
				snprintf(full_command + index, total_size - index, "%s ", argv[i+1]);
				index += size + 1;
			} else {
				snprintf(full_command + index, total_size - index, "%s", argv[i+1]);
				index += size;
			}			
		}

		printf("Executing: %s\n", full_command);
		int res = system(full_command);
		if(res) {
			printf("Error: %d\n", res);
			exit(res);
		}

		free(full_command);
	}

	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_SharedMemory shared_memory_1, shared_memory_2;
	TEEC_UUID uuid = PTA_CRIU_UUID;
	uint32_t err_origin;

	// To hold the checkpoint file info
	struct checkpoint_file_data checkpoint_files[CHECKPOINT_FILES] = {};

	if(pid == -1) {
		decode_pid();
		checkpoint_files[PSTREE_FILE].filename = "pstree.txt";
		read_file(&checkpoint_files[PSTREE_FILE]);
		pid = parse_checkpoint_pstree(&checkpoint_files);
		printf("pid: %d\n", pid);
		if(pid == -1) {
			printf("Error: unable to parse the pid from pstree.img\n");
			exit(-1);
		}
	}

	bool stop_execution = false;
	bool migrate_back = false;

	while(!stop_execution) {
		system("cp check/pages-1.img pages-1.img");

		if(!decode_checkpoint(pid)) {
			perror("Unable to decode checkpoint\n");
		}

		// TODO: make it a if(true) otherwise exit
		read_checkpoint_files(pid, checkpoint_files);

		struct criu_checkpoint checkpoint;

		if(!parse_checkpoint_core(&checkpoint, &checkpoint_files)) {
			perror("Unable to parse core-file.\n");
		}

		if(!parse_checkpoint_mm(&checkpoint, &checkpoint_files)) {
			perror("Unable to parse mm-file.\n");
		}

		if(!parse_checkpoint_pagemap(&checkpoint, &checkpoint_files)) {
			perror("Unable to parse pagemap-file.\n");
		}

		if(!parse_executable_name(&checkpoint_files)) {
			perror("Unable the parse the executable name from files.img.\n");
		}

		// Now that we have parsed the executable filename from the checkpoint file, we can load it.
		read_file(&checkpoint_files[EXECUTABLE_BINARY_FILE]);

		int shared_buffer_1_size = sizeof(struct criu_checkpoint) 
									+ checkpoint.vm_area_count * sizeof(struct criu_vm_area)
									+ checkpoint.pagemap_entry_count * sizeof(struct criu_pagemap_entry);
		
		// printf("Total checkpoint size to migrate is %d bytes\n", shared_buffer_1_size);
		// Allocate space for shared buffer 1
		void * shared_buffer_1 = malloc(shared_buffer_1_size);
		long   shared_buffer_1_index = 0;
		if(shared_buffer_1 == NULL) {
			printf("Unable to allocate %d bytes for shared buffer 1.", shared_buffer_1_size);
			return -1;
		}

		// printf("Loading checkpoint files into the buffer... ");

		// Copy the checkpoint struct with the registers
		int size = sizeof(struct criu_checkpoint);
		memcpy(shared_buffer_1 + shared_buffer_1_index, &checkpoint, size);
		shared_buffer_1_index += size;
		
		// Copy over the vm areas
		size = checkpoint.vm_area_count * sizeof(struct criu_vm_area);
		memcpy(shared_buffer_1 + shared_buffer_1_index, checkpoint.vm_areas, size);
		shared_buffer_1_index += size;

		// Copy over the pagemap entries
		size = checkpoint.pagemap_entry_count * sizeof(struct criu_pagemap_entry);
		memcpy(shared_buffer_1 + shared_buffer_1_index, checkpoint.pagemap_entries, size);
		shared_buffer_1_index += size;

		// printf("done!\n");

		// Setup the structs that will go into shared buffer 2
		long shared_buffer_2_size = 2 * sizeof(struct checkpoint_file) 
										+ checkpoint_files[EXECUTABLE_BINARY_FILE].file.file_size
										+ checkpoint_files[PAGES_BINARY_FILE].file.file_size;
		void * shared_buffer_2 = malloc(shared_buffer_2_size);
		int shared_buffer_2_index = 0;
		
		struct checkpoint_file * binary_data = shared_buffer_2;
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
		size = checkpoint_files[EXECUTABLE_BINARY_FILE].file.file_size;
		memcpy(shared_buffer_2 + shared_buffer_2_index, checkpoint_files[EXECUTABLE_BINARY_FILE].buffer, size);
		shared_buffer_2_index += size;
		// Store the pagedata
		size = checkpoint_files[PAGES_BINARY_FILE].file.file_size;
		memcpy(shared_buffer_2 + shared_buffer_2_index, checkpoint_files[PAGES_BINARY_FILE].buffer, size);
		shared_buffer_2_index += size;
		
		/* Initialize a context connecting us to the TEE */
		res = TEEC_InitializeContext(NULL, &ctx);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InitializeContext failed with code 0x%lx", res);

		/*
		* Open a session to the TA
		*/
		res = TEEC_OpenSession(&ctx, &sess, &uuid,
					TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_Opensession failed with code 0x%lx origin 0x%lx",
				res, err_origin);

		// Setup shared memory buffer 1
		shared_memory_1.size = shared_buffer_1_size;
		shared_memory_1.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
		shared_memory_1.buffer = shared_buffer_1;

		res = TEEC_RegisterSharedMemory(&ctx, &shared_memory_1);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_AllocateSharedMemory failed with code 0x%lx origin 0x%lx",
				res, err_origin);

		// Setup shared memory buffer 2
		shared_memory_2.size = shared_buffer_2_size;
		shared_memory_2.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
		shared_memory_2.buffer = shared_buffer_2;

		res = TEEC_RegisterSharedMemory(&ctx, &shared_memory_2);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_AllocateSharedMemory failed with code 0x%lx origin 0x%lx",
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
		
		/*
		* CRIU_LOAD_CHECKPOINT is the actual function in the TA to be
		* called.
		*/
		printf("\nLoading & executing checkpoint: %s\n", checkpoint_files[EXECUTABLE_BINARY_FILE].filename);
		res = TEEC_InvokeCommand(&sess, CRIU_LOAD_CHECKPOINT, &op,
					&err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%lx origin 0x%lx",
				res, err_origin);

		do {
			bool continue_execution = false;
			
			memcpy(&checkpoint.result, op.params[1].memref.parent->buffer, sizeof(enum criu_return_types));
			memcpy(&checkpoint.regs, op.params[1].memref.parent->buffer + sizeof(enum 	criu_return_types), sizeof(struct criu_checkpoint_regs));

			printf("TA returned from secure world: ");
			switch(checkpoint.result) {
				case CRIU_SYSCALL_EXIT:
					stop_execution = true;
					printf("EXIT system call!\n");
					break;
				case CRIU_SYSCALL_UNSUPPORTED:
					printf("unsupported system call.\n");
					break;
				case CRIU_SYSCALL_MIGRATE_BACK:
					// TODO: stop execution but restore normal execution with criu.
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
				res = TEEC_InvokeCommand(&sess, CRIU_CONTINUE_EXECUTION, &op,
							&err_origin);
				if (res != TEEC_SUCCESS) {
					errx(1, "TEEC_InvokeCommand failed with code 0x%lx origin 0x%lx",
						res, err_origin);
					break;
				}
			} else {
				break;
			}
		} while(checkpoint.result != CRIU_SYSCALL_EXIT &&
				checkpoint.result != CRIU_SYSCALL_UNSUPPORTED &&
				checkpoint.result != CRIU_SYSCALL_MIGRATE_BACK);
		
		// printf("\nCheckpointing data back\n");
		res = TEEC_InvokeCommand(&sess, CRIU_CHECKPOINT_BACK, &op,
					&err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%lx origin 0x%lx",
				res, err_origin);
		// printf("TA returned from secure world\n");

				// As the memory buffers where shared, the data can be changed in the secure world.
				// After running the checkpoint in the secure world, the secure world checkpoints back
				// and puts the updated checkpoint values in the parameters.
				
				// TODO: implement checking the parameter for correct lengths
				// if(op.params[1].memref.size > sizeof(struct checkpoint_file));


		shared_buffer_2_index = 0;
		memcpy(&checkpoint.regs, op.params[1].memref.parent->buffer, sizeof(struct criu_checkpoint_regs));
		shared_buffer_2_index += sizeof(struct criu_checkpoint_regs);

		struct criu_checkpoint_dirty_pages * dirty_pages_info = op.params[1].memref.parent->buffer + shared_buffer_2_index;
		shared_buffer_2_index += sizeof(struct criu_checkpoint_dirty_pages);

		struct criu_dirty_page * dirty_entry = op.params[1].memref.parent->buffer + shared_buffer_2_index;
		shared_buffer_2_index += dirty_pages_info->dirty_page_count * sizeof(struct criu_dirty_page);

		struct criu_merged_pagemap merged_map;
		TAILQ_INIT(&merged_map);

		create_merged_map(&merged_map, &checkpoint, dirty_entry, dirty_pages_info->dirty_page_count);

		// struct criu_merged_page * e = NULL;
		// TAILQ_FOREACH(e, &merged_map, link) {
		// 	printf("[%d] entry: %p - nr pages: %d\n", e->is_new, e->entry.vaddr_start, e->entry.nr_pages);
		// }

		write_updated_core_checkpoint("modified_core.txt", checkpoint_files[CORE_FILE].buffer, checkpoint_files[CORE_FILE].file.file_size, &checkpoint);


		write_updated_pagemap_checkpoint(&merged_map, checkpoint_files[PAGEMAP_FILE].buffer, checkpoint_files[PAGEMAP_FILE].file.file_size);

		write_updated_pages_checkpoint(&merged_map, dirty_entry, dirty_pages_info->dirty_page_count, op.params[1].memref.parent->buffer + shared_buffer_2_index, checkpoint_files[PAGES_BINARY_FILE].buffer);


		// // Give the memory back
		TEEC_ReleaseSharedMemory(&shared_memory_1);
		TEEC_ReleaseSharedMemory(&shared_memory_2);

		free(shared_buffer_1);

		// Do this better.. cleaner.. I now do -1 because PSTREE_FILE might not be allocated..
		for(int i = 0; i < CHECKPOINT_FILES - 1; i++) {
			free(checkpoint_files[i].buffer);
		}

		// Free all allocated criu_pagemap_entry structs
		struct criu_merged_page * entry = NULL;
		TAILQ_FOREACH(entry, &merged_map, link) {
			free(entry);
		}
		
		encode_checkpoint(pid);

		// /*
		//  * We're done with the TA, close the session and
		//  * destroy the context.
		//  *
		//  * The TA will print "Goodbye!" in the log when the
		//  * session is closed.
		//  */
		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);

		system("cp -rf modified_pages-1.img check/pages-1.img");

		// Check return value of criu, on fail exit.
		if(!stop_execution) {
			printf("Going to execute criu.sh\n");
			system("./criu.sh execute -D check --shell-job -v0");
		}
	}

	if(migrate_back) {
		system("./criu.sh restore -D check --shell-job --restore-detached -v0");
	}

	// Check if it is actually used.. otherwise we are freeing a non-malloced entry..
	// Do this in a pretty way.
	free(checkpoint_files[PSTREE_FILE].buffer);

	// Close connection to the critserver
	disconnect_critserver();

	return 0;
}