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

#include <sys/socket.h> 
#include <arpa/inet.h> 

#include "criu/criu.h"

#define PORT 50007

#define O_PATH		010000000


#include "criu/criu_checkpoint.h"
#include "criu/criu_checkpoint_parser.h"

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <optee_app_migrator_ta.h>

#define CHECKPOINT_FILES 5 
#define CHECKPOINT_FILES_TO_TRANSFER 5
#define CHECKPOINT_FILENAME_MAXLENGTH 40

void fprintf_substring(FILE * file, char * buffer, int start_index, int end_index);
bool read_file(struct checkpoint_file_data * c_file);

// void write_updated_core_checkpoint(char * new_filename, void * buffer, long file_size, struct criu_checkpoint_regs * checkpoint) {
// 	FILE *fpp = fopen(new_filename, "w+");
// 	if(fpp) {
// 		// Initialize the JSMN json parser
// 		jsmn_parser parser;
// 		jsmn_init(&parser);

// 		// First only determine the number of tokens.
// 		int items = jsmn_parse(&parser, buffer, file_size, NULL, 128);

// 		jsmntok_t tokens[items];
		
// 		// Reset position in stream
// 		jsmn_init(&parser);
// 		int left = jsmn_parse(&parser, buffer, file_size, tokens, items);

// 		// Invalid file.
// 		if (items < 1 || tokens[0].type != JSMN_OBJECT) {
// 			printf("CRIU: INVALID JSON\n");
// 			return -1;
// 		}

// 		// TLS indexes
// 		int before_tls_value = 0;
// 		int  after_tls_value = 0;

// 		// Regs indexes
// 		int before_regs_value = 0;
// 		int  after_regs_value = 0;

// 		// SP indexes
// 		int before_sp_value = 0;
// 		int  after_sp_value = 0;

// 		// PC indexes
// 		int before_pc_value = 0;
// 		int  after_pc_value = 0;

// 		// Pstate indexes
// 		int before_pstate_value = 0;
// 		int  after_pstate_value = 0;

// 		// Vregs indexes
// 		int before_vregs_value = 0;
// 		int  after_vregs_value = 0;

// 		// FPSR indexes
// 		int before_fpsr_value = 0;
// 		int  after_fpsr_value = 0;

// 		// FPCR indexes
// 		int before_fpcr_value = 0;
// 		int  after_fpcr_value = 0;

// 		// Parse the JSON version of the core checkpoint file (example core-2956.img)
// 		for(int i = 1; i < items; i++) {
// 			if (jsoneq(buffer, &tokens[i], "tls") == 0) { 
// 				before_tls_value = tokens[i+1].start;
// 				after_tls_value = tokens[i+1].end;
// 			} else if (jsoneq(buffer, &tokens[i], "regs") == 0) { 
// 				before_regs_value = tokens[i+1].start;
// 				after_regs_value = tokens[i+1].end;
// 			} else if (jsoneq(buffer, &tokens[i], "sp") == 0) {
// 				before_sp_value = tokens[i+1].start;
// 				after_sp_value = tokens[i+1].end;
// 			} else if (jsoneq(buffer, &tokens[i], "pc") == 0) {
// 				before_pc_value = tokens[i+1].start;
// 				after_pc_value = tokens[i+1].end;
// 			} else if (jsoneq(buffer, &tokens[i], "pstate") == 0) {
// 				before_pstate_value = tokens[i+1].start;
// 				after_pstate_value = tokens[i+1].end;
// 			} else if (jsoneq(buffer, &tokens[i], "vregs") == 0) {
// 				before_vregs_value = tokens[i+1].start;
// 				after_vregs_value = tokens[i+1].end;
// 			} else if (jsoneq(buffer, &tokens[i], "fpsr") == 0) {
// 				before_fpsr_value = tokens[i+1].start;
// 				after_fpsr_value = tokens[i+1].end;
// 			} else if (jsoneq(buffer, &tokens[i], "fpcr") == 0) {
// 				before_fpcr_value = tokens[i+1].start;
// 				after_fpcr_value = tokens[i+1].end;
// 			}
// 		}

// 		fprintf_substring(fpp, buffer, 0, before_tls_value);

// 		// Write tpidr_el0
// 		fprintf(fpp, "%llu", checkpoint->tpidr_el0_addr); 
// 		fprintf_substring(fpp, buffer, after_tls_value, before_regs_value);

// 		// Write all updated registers
// 		fputc('[', fpp);
// 		for(int i = 0; i < 31; i++) {
// 			fprintf(fpp, "\"0x%lx\"", checkpoint->regs[i]);
			
// 			if(i != 30)
// 				fprintf(fpp, ",\n");
// 		}
// 		fputc(']', fpp);
// 		fprintf_substring(fpp, buffer, after_regs_value, before_sp_value);

// 		// Write updated stack pointer
// 		fprintf(fpp, "0x%lx", checkpoint->stack_addr);
// 		fprintf_substring(fpp, buffer, after_sp_value, before_pc_value);

// 		// Write updated program counter
// 		fprintf(fpp, "0x%lx", checkpoint->entry_addr);
// 		fprintf_substring(fpp, buffer, after_pc_value, before_pstate_value);
		
// 		// Write updated pstate
// 		fprintf(fpp, "0x%lx", checkpoint->pstate);
// 		fprintf_substring(fpp, buffer, after_pstate_value, before_vregs_value);

// 		// Write all updated vregs
// 		fputc('[', fpp);
// 		for(int i = 0; i < 64; i++) {
// 			fprintf(fpp, "%llu", checkpoint->vregs[i]);

// 			if(i != 63)
// 				fprintf(fpp, ",\n");
// 		}
// 		fputc(']', fpp);
// 		fprintf_substring(fpp, buffer, after_vregs_value, before_fpsr_value);

// 		// Write updated fpsr
// 		fprintf(fpp, "%lu", checkpoint->fpsr);
// 		fprintf_substring(fpp, buffer, after_fpsr_value, before_fpcr_value);
		
// 		// Write updated fpcr
// 		fprintf(fpp, "%lu", checkpoint->fpcr);
// 		fprintf_substring(fpp, buffer, after_fpcr_value, file_size);

// 		fclose(fpp);
// 	}
// }

// void write_updated_pages_checkpoint(void * parameter_buffer, struct criu_pagemap_entries * pagemap_entries,
// 									struct criu_checkpoint_dirty_pages * dirty_pages_info,
// 									long * shared_buffer_2_index, char * original_buffer) {
// 	FILE *fpages = fopen("modified_pages-1.img", "w+");
// 	if(fpages) {
// 		struct criu_pagemap_entry_tracker * entry = NULL;
// 		struct criu_pagemap_entry * pagemap_entry = NULL;
// 		TAILQ_FOREACH(entry, pagemap_entries, link) {
// 			for(int i = 0; i < entry->entry.nr_pages; i++) {
// 				vaddr_t addr = entry->entry.vaddr_start + i * 4096;

// 				bool dirty_page = false;
// 				for(int y = 0; y < dirty_pages_info->dirty_page_count; y++) {
// 					pagemap_entry = parameter_buffer + *shared_buffer_2_index + (sizeof(struct criu_pagemap_entry) * y) ;
					
// 					if(addr == pagemap_entry->vaddr_start) {
// 						// Write dirty page
// 						fwrite(parameter_buffer + dirty_pages_info->offset + y * 4096, 1, 4096, fpages);
// 						// printf("dirty page at: %p - index: %d\n", addr, entry->entry.file_page_index + i);
// 						dirty_page = true;
// 						break;
// 					}
// 				}

// 				if(!dirty_page) {
// 					// Write the original
// 					fwrite(original_buffer + (entry->entry.file_page_index + i) * 4096, 1, 4096, fpages);
// 					// printf("clean page at: %p - index: %d\n", addr, entry->entry.file_page_index + i);
// 				}
// 			}
// 		}

// 		fclose(fpages);
// 	} else {
// 		printf("Unable to open pages-1.img for writing..");
// 	}
// }

// void write_updated_pagemap_checkpoint(void * parameter_buffer, struct criu_pagemap_entries * pagemap_entries,
// 									struct criu_checkpoint_dirty_pages * dirty_pages_info,
// 									long * shared_buffer_2_index, char * buffer, long file_size) {
// 	FILE *fpagemap = fopen("modified_pagemap.txt", "w+");

// 	if(fpagemap) {
// 		// Initialize the JSMN json parser
// 		jsmn_parser parser;
// 		jsmn_init(&parser);

// 		// First only determine the number of tokens.
// 		int items = jsmn_parse(&parser, buffer, file_size, NULL, 128);

// 		jsmntok_t tokens[items];
		
// 		// Reset position in stream
// 		jsmn_init(&parser);
// 		int left = jsmn_parse(&parser, buffer, file_size, tokens, items);

// 		// Invalid file.
// 		if (items < 1 || tokens[0].type != JSMN_OBJECT) {
// 			printf("CRIU: INVALID JSON\n");
// 			return -1;
// 		}

// 		// First vaddr index
// 		int vaddr_start = 0;

// 		// Parse the JSON version of the core checkpoint file (example core-2956.img)
// 		for(int i = 1; i < items; i++) {
// 			if (jsoneq(buffer, &tokens[i], "vaddr") == 0) { 
// 				vaddr_start = tokens[i-1].start;
// 				break;
// 			}
// 		}

// 		char backup = buffer[vaddr_start];
// 		buffer[vaddr_start] = 0;
// 		fprintf(fpagemap, "%s", buffer);
// 		buffer[vaddr_start] = backup;	
// 		struct criu_pagemap_entry_tracker * entry = NULL;

// 		// FILE *fp = fopen("pages-1.new.img", "w+");
// 		// // FILE *f  = fopen("pages-1.img", "rb");

// 		// printf("Number of dirty pages: %d\n", dirty_pages_info->dirty_page_count);
// 		struct criu_pagemap_entry * pagemap_entry = NULL;



// 		for(int y = 0; y < dirty_pages_info->dirty_page_count; y++) {
// 			pagemap_entry = parameter_buffer + *shared_buffer_2_index + (sizeof(struct criu_pagemap_entry) * y) ;
// 			bool skip = false;
// 			bool insert_before = false;
// 			TAILQ_FOREACH(entry, pagemap_entries, link) {
// 				if((entry->entry.vaddr_start <= pagemap_entry->vaddr_start)  &&
// 				(pagemap_entry->vaddr_start < (entry->entry.vaddr_start + entry->entry.nr_pages * 4096))) {
// 					skip = true;
// 					break;
// 				} else if(pagemap_entry->vaddr_start < entry->entry.vaddr_start) {
// 					insert_before = true;
// 					break;
// 				}
// 			}		

// 			if(skip)
// 				continue;

// 			struct criu_pagemap_entry_tracker * new_entry = calloc(1, sizeof(struct criu_pagemap_entry_tracker));
			
// 			new_entry->entry.vaddr_start = pagemap_entry->vaddr_start;
// 			new_entry->entry.nr_pages = pagemap_entry->nr_pages;
// 			new_entry->entry.file_page_index = pagemap_entry->file_page_index;
// 			new_entry->entry.flags = PE_LAZY | PE_PRESENT;

// 			if(insert_before)
// 				TAILQ_INSERT_BEFORE(entry, new_entry, link);
// 			else
// 				TAILQ_INSERT_TAIL(pagemap_entries, new_entry, link);
// 		}


// 		TAILQ_FOREACH(entry, pagemap_entries, link) {
// 			fprintf(fpagemap, "{\n\t\"vaddr\": \"0x%lx\",\n\t\"nr_pages\": %d,\n\t\"flags\": \"", entry->entry.vaddr_start, entry->entry.nr_pages);
			
// 			bool require_seperator = false;
// 			if(entry->entry.flags & PE_LAZY) {
// 				fprintf(fpagemap, "PE_LAZY");
// 				require_seperator = true;
// 			}

// 			if(entry->entry.flags & PE_PRESENT) {
// 				if(require_seperator)
// 					fprintf(fpagemap, " | ");

// 				fprintf(fpagemap, "PE_PRESENT");
// 			}

// 			fprintf(fpagemap, "\"\n}");

// 			if(entry->link.tqe_next != NULL)
// 				fprintf(fpagemap, ",\n");
// 		}

// 		fprintf(fpagemap, "] }");

// 		fclose(fpagemap);
// 	} else {
// 		printf("Unable to open modified_pagemap.txt");
// 	}
// }

int crit_execute(int sock, char * command, char * buffer) {
    send(sock, command , strlen(command) , 0 ); 
    printf("CRIU decode message sent: %s\n", command); 
    int valread = read( sock , buffer, 1024); 
	buffer[valread] = '\0';
    printf("%s\n",buffer ); 
	return valread;
}

bool decode_checkpoint(int pid) {
	int sock = 0; 
    struct sockaddr_in serv_addr; 
    char buffer[1024] = {0}; 
	char command[100];

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    } 
   
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(PORT); 
       
    // Convert IPv4 and IPv6 addresses from text to binary form 
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)  
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    } 

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("Connection to CRIT server failed.\n");
        printf("Is it running?\n"); 
        return -1; 
    } 
	
	snprintf(command, 100, "decode -i check/core-%d.img --pretty -o core-%d.txt", pid, pid);
	crit_execute(sock, command, buffer);

	snprintf(command, 100, "decode -i check/pagemap-%d.img --pretty -o pagemap-%d.txt", pid, pid);
	crit_execute(sock, command, buffer);

	snprintf(command, 100, "decode -i check/mm-%d.img --pretty -o mm-%d.txt", pid, pid);
	crit_execute(sock, command, buffer);

	return true;
}

int read_checkpoint_files(int pid, char * executable_name, struct checkpoint_file_data * files) {
	char filenames[CHECKPOINT_FILES][CHECKPOINT_FILENAME_MAXLENGTH] = {};

	snprintf(filenames[CORE_FILE], CHECKPOINT_FILENAME_MAXLENGTH, "core-%d.txt", pid);
	snprintf(filenames[MM_FILE], CHECKPOINT_FILENAME_MAXLENGTH, "mm-%d.txt", pid);
	snprintf(filenames[PAGEMAP_FILE], CHECKPOINT_FILENAME_MAXLENGTH, "pagemap-%d.txt", pid);
	snprintf(filenames[PAGES_BINARY_FILE], CHECKPOINT_FILENAME_MAXLENGTH, "pages-1.img");
	snprintf(filenames[EXECUTABLE_BINARY_FILE], CHECKPOINT_FILENAME_MAXLENGTH, "%s", executable_name);
	
	// Total size of the shared buffer 1, which contains all checkpoint files together.
	int shared_buffer_1_size = 1; // At least 1 for the ending \0 character.
	for(int i = 0; i < CHECKPOINT_FILES; i++) {
		// printf("%d: %s\n", i, filenames[i]);

		// Set the filename, load the filesize and read the file from disk into the buffer
		files[i].filename = filenames[i];
		read_file(&files[i]);

		// Increase the buffer size
		if (i < CHECKPOINT_FILES_TO_TRANSFER)
			shared_buffer_1_size += files[i].file.file_size;
	}

	return shared_buffer_1_size;
}

int main(int argc, char *argv[])
{
	// printf("OP-TEE App Migrator\n\n");

	if(argc < 3) {
		printf("Usage: optee_app_migrator $pid $executable_name\n");
		exit(-1);
	}

	int pid = strtoul(argv[1], NULL, 10);
	char * executable_name = argv[2];

	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_SharedMemory shared_memory_1, shared_memory_2;
	TEEC_UUID uuid = PTA_CRIU_UUID;
	uint32_t err_origin;

	if(!decode_checkpoint(pid)) {
		perror("Unable to decode checkpoint\n");
	}

	// To hold the checkpoint file info
	struct checkpoint_file_data checkpoint_files[CHECKPOINT_FILES] = {};
	int shared_buffer_1_size = read_checkpoint_files(pid, executable_name, checkpoint_files);

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
	
	// printf("Checkpoint:\n");
	// for(int i = 0; i < checkpoint.vm_area_count; i++) {
	// 	printf("vm_area[%d]: %p-%p\n", i, checkpoint.vm_areas[i].vm_start, checkpoint.vm_areas[i].vm_end);
	// }

	// printf("----------:\n");
	// for(int i = 0; i < checkpoint.pagemap_entry_count; i++) {
	// 	printf("vm_area[%d]: %p - %d pages\n", i, checkpoint.pagemap_entries[i].vaddr_start, checkpoint.pagemap_entries[i].nr_pages);
	// }

	// printf("----------:\n");
	// printf("start: %p\n", checkpoint.regs.entry_addr);
	// printf("stack: %p\n", checkpoint.regs.stack_addr);
	// printf("pstate: %p\n", checkpoint.regs.pstate);


// 	printf("Total checkpoint size to migrate is %d bytes\n", shared_buffer_1_size);

// 	// Allocate space for shared buffer 1
// 	char * shared_buffer_1 = malloc(shared_buffer_1_size);
// 	if(shared_buffer_1 == NULL) {
// 		printf("Unable to allocate %d bytes for shared buffer 1.", shared_buffer_1_size);
// 		return -1;
// 	}

// 	// printf("Loading checkpoint files into the buffer... ");
// 	long shared_buffer_1_index = 0;
// 	for(int i = 0; i < CHECKPOINT_FILES_TO_TRANSFER; i++) {
// 		// First copy the data from the checkpoint file buffer to shared buffer 1 at the correct index
// 		memcpy(shared_buffer_1 + shared_buffer_1_index, checkpoint_files[i].buffer, checkpoint_files[i].file.file_size);
// 		// Store the index so we can send that info later in shared buffer 2
// 		checkpoint_files[i].file.buffer_index = shared_buffer_1_index;
// 		// Will be overwritten by the next memcpy, except for the last entry
// 		shared_buffer_1[shared_buffer_1_index + checkpoint_files[i].file.file_size] = 0;

// 		shared_buffer_1_index += checkpoint_files[i].file.file_size;
// 	}
// 	// printf("done!\n");

// 	// Setup the structs that will go into shared buffer 2
// 	struct checkpoint_file * checkpoint_files = malloc(sizeof(struct checkpoint_file) * CHECKPOINT_FILES);
// 	for(int i = 0; i < CHECKPOINT_FILES_TO_TRANSFER; i++) {
// 		checkpoint_files[i].file_type = (enum checkpoint_file_types) i;
// 		checkpoint_files[i].file_size = files[i].file.file_size;
// 		checkpoint_files[i].buffer_index = files[i].file.buffer_index;
// 	}

// 	/* Initialize a context connecting us to the TEE */
// 	res = TEEC_InitializeContext(NULL, &ctx);
// 	if (res != TEEC_SUCCESS)
// 		errx(1, "TEEC_InitializeContext failed with code 0x%lx", res);

// 	/*
// 	 * Open a session to the "hello world" TA, the TA will print "hello
// 	 * world!" in the log when the session is created.
// 	 */
// 	res = TEEC_OpenSession(&ctx, &sess, &uuid,
// 			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
// 	if (res != TEEC_SUCCESS)
// 		errx(1, "TEEC_Opensession failed with code 0x%lx origin 0x%lx",
// 			res, err_origin);

// 	// Setup shared memory buffer 1
// 	shared_memory_1.size = shared_buffer_1_size;
// 	shared_memory_1.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
// 	shared_memory_1.buffer = shared_buffer_1;

// 	res = TEEC_RegisterSharedMemory(&ctx, &shared_memory_1);
// 	if (res != TEEC_SUCCESS)
// 		errx(1, "TEEC_AllocateSharedMemory failed with code 0x%lx origin 0x%lx",
// 			res, err_origin);

// 	// Setup shared memory buffer 2
// 	shared_memory_2.size = sizeof(struct checkpoint_file) * CHECKPOINT_FILES_TO_TRANSFER;
// 	shared_memory_2.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
// 	shared_memory_2.buffer = checkpoint_files;

// 	res = TEEC_RegisterSharedMemory(&ctx, &shared_memory_2);
// 	if (res != TEEC_SUCCESS)
// 		errx(1, "TEEC_AllocateSharedMemory failed with code 0x%lx origin 0x%lx",
// 			res, err_origin);

// 	/* Clear the TEEC_Operation struct */
// 	memset(&op, 0, sizeof(op));

// 	/*
// 	* Prepare the two arguments that will be passed to the secure world, which are two shared memory buffers.
// 	*/
// 	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE,
// 				TEEC_NONE, TEEC_NONE);

// 	op.params[0].memref.parent = &shared_memory_1;
// 	op.params[0].memref.size = shared_memory_1.size;
// 	op.params[0].memref.offset = 0;

// 	op.params[1].memref.parent = &shared_memory_2;
// 	op.params[1].memref.size = shared_memory_2.size;
// 	op.params[1].memref.offset = 0;

// #ifdef DEBUG
// 	struct checkpoint_file * checkpoint_file_var = checkpoint_files;
// 	for(int i = 0; i < CHECKPOINT_FILES_TO_TRANSFER; i++) {
// 		printf("checkpoint file: type %lu - index %lu\t- size %lu\n", checkpoint_file_var[i].file_type, checkpoint_file_var[i].buffer_index, checkpoint_file_var[i].file_size);
// 	}
// #endif

	/*
	* CRIU_LOAD_CHECKPOINT is the actual function in the TA to be
	* called.
	*/
	// printf("\nLoading & executing checkpoint\n");
	res = TEEC_InvokeCommand(&sess, CRIU_LOAD_CHECKPOINT, &op,
				&err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%lx origin 0x%lx",
			res, err_origin);

	enum criu_return_types * return_type = op.params[0].memref.parent->buffer;
	enum criu_return_types ret_type;
	do {
		ret_type = *return_type;
		bool continue_execution = false;
		long index = 0;
		index += sizeof(enum criu_return_types);
		struct criu_checkpoint_regs * checkpoint_regs = op.params[0].memref.parent->buffer + index;
		index += sizeof(struct criu_checkpoint_regs);

		// printf("TA returned from secure world: ");
		switch(ret_type) {
			case CRIU_SYSCALL_EXIT:
				printf("EXIT system call!\n");
				break;
			case CRIU_SYSCALL_UNSUPPORTED:
				printf("unsupported system call.\n");
				break;
			case CRIU_MIGRATE_BACK:
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
	} while(ret_type != CRIU_SYSCALL_EXIT &&
		    ret_type != CRIU_SYSCALL_UNSUPPORTED &&
			ret_type != CRIU_MIGRATE_BACK);
	
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


	// long shared_buffer_2_index = 0;
	// struct criu_checkpoint_regs * checkpoint = op.params[0].memref.parent->buffer;
	// shared_buffer_2_index += sizeof(struct criu_checkpoint_regs);

	// write_updated_core_checkpoint("modified_core.txt", files[CORE_FILE].buffer, files[CORE_FILE].file.file_size, checkpoint);

	// struct criu_checkpoint c;
	// TAILQ_INIT(&c.dirty_pagemap);

	// parse_checkpoint_pagemap(&c, files[PAGEMAP_FILE].buffer, files[PAGEMAP_FILE].file.file_size);

	// struct criu_checkpoint_dirty_pages * dirty_pages_info = op.params[0].memref.parent->buffer + shared_buffer_2_index;
	// shared_buffer_2_index += sizeof(struct criu_checkpoint_dirty_pages);

	// write_updated_pagemap_checkpoint(op.params[0].memref.parent->buffer, &pagemap_entries, dirty_pages_info, &shared_buffer_2_index, files[PAGEMAP_FILE].buffer, files[PAGEMAP_FILE].file.file_size);
	
	// write_updated_pages_checkpoint(op.params[0].memref.parent->buffer, &pagemap_entries, dirty_pages_info, &shared_buffer_2_index, files[PAGES_BINARY_FILE].buffer);

	// // Give the memory back
	// TEEC_ReleaseSharedMemory(&shared_memory_1);
	// TEEC_ReleaseSharedMemory(&shared_memory_2);

	// free(shared_buffer_1);
	// free(checkpoint_files);

	// for(int i = 0; i < CHECKPOINT_FILES; i++) {
	// 	free(files[i].buffer);
	// }

	// // Free all allocated criu_pagemap_entry structs
	// struct criu_pagemap_entry_tracker * entry = NULL;
	// TAILQ_FOREACH(entry, &pagemap_entries, link) {
	// 	free(entry);
	// }
	
	// snprintf(command, 100, "encode -i modified_core.txt -o check/core-%s.img", argv[1], argv[1]);
    // send(sock , command , strlen(command) , 0 ); 
    // // printf("CRIU encode message sent: %s\n", command); 
    // valread = read( sock , buffer, 1024); 
	// buffer[valread] = '\0';
    // // printf("%s\n",buffer ); 

	// snprintf(command, 100, "encode -i modified_pagemap.txt -o check/pagemap-%s.img", argv[1], argv[1]);
    // send(sock , command , strlen(command) , 0 ); 
    // // printf("CRIU encode message sent: %s\n", command); 
    // valread = read( sock , buffer, 1024); 
	// buffer[valread] = '\0';
    // // printf("%s\n",buffer );

	// /*
	//  * We're done with the TA, close the session and
	//  * destroy the context.
	//  *
	//  * The TA will print "Goodbye!" in the log when the
	//  * session is closed.
	//  */
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}

void fprintf_substring(FILE * file, char * buffer, int start_index, int end_index) {
	char backup = buffer[end_index];
	buffer[end_index] = 0;
	fprintf(file, buffer + start_index);
	buffer[end_index] = backup;	
}

bool read_file(struct checkpoint_file_data * c_file) {
	FILE *f = fopen(c_file->filename, "rb");

	if(f) {
		// Determine file size
		fseek(f, 0, SEEK_END);
		c_file->file.file_size = ftell(f);
		fseek(f, 0, SEEK_SET);

		c_file->buffer = malloc(c_file->file.file_size + 1);

		if(c_file->buffer) {
			fread(c_file->buffer, 1, c_file->file.file_size, f);
			c_file->buffer[c_file->file.file_size] = 0;
		} else {
			// Unable to malloc.
			printf("Unable to malloc %ld bytes for file %s.\n", c_file->file.file_size, c_file->filename);
			c_file->file.file_size = -1;
			return false;
		}

		fclose(f);
	} else {
		printf("Unable to read file: %s\n", c_file->filename);
		return false;
	}

	return true;
}