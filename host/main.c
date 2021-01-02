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

#define PORT 50007

#define O_PATH		010000000


#include "criu/criu_checkpoint.h"
#include "criu/criu_checkpoint_parser.h"

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <optee_app_migrator_ta.h>

#define CHECKPOINT_FILES 7 
#define CHECKPOINT_FILENAME_MAXLENGTH 100

void fprintf_substring(FILE * file, char * buffer, int start_index, int end_index);
bool read_file(struct checkpoint_file_data * c_file);

void write_updated_core_checkpoint(char * new_filename, void * buffer, long file_size, struct criu_checkpoint * checkpoint) {
	FILE *fpp = fopen(new_filename, "w+");
	if(fpp) {
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

		// Pstate indexes
		int before_pstate_value = 0;
		int  after_pstate_value = 0;

		// Vregs indexes
		int before_vregs_value = 0;
		int  after_vregs_value = 0;

		// FPSR indexes
		int before_fpsr_value = 0;
		int  after_fpsr_value = 0;

		// FPCR indexes
		int before_fpcr_value = 0;
		int  after_fpcr_value = 0;

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
			} else if (jsoneq(buffer, &tokens[i], "pstate") == 0) {
				before_pstate_value = tokens[i+1].start;
				after_pstate_value = tokens[i+1].end;
			} else if (jsoneq(buffer, &tokens[i], "vregs") == 0) {
				before_vregs_value = tokens[i+1].start;
				after_vregs_value = tokens[i+1].end;
			} else if (jsoneq(buffer, &tokens[i], "fpsr") == 0) {
				before_fpsr_value = tokens[i+1].start;
				after_fpsr_value = tokens[i+1].end;
			} else if (jsoneq(buffer, &tokens[i], "fpcr") == 0) {
				before_fpcr_value = tokens[i+1].start;
				after_fpcr_value = tokens[i+1].end;
			}
		}

		fprintf_substring(fpp, buffer, 0, before_tls_value);

		// Write tpidr_el0
		fprintf(fpp, "%llu", checkpoint->regs.tpidr_el0_addr); 
		fprintf_substring(fpp, buffer, after_tls_value, before_regs_value);

		// Write all updated registers
		fputc('[', fpp);
		for(int i = 0; i < 31; i++) {
			fprintf(fpp, "\"0x%lx\"", checkpoint->regs.regs[i]);
			
			if(i != 30)
				fprintf(fpp, ",\n");
		}
		fputc(']', fpp);
		fprintf_substring(fpp, buffer, after_regs_value, before_sp_value);

		// Write updated stack pointer
		fprintf(fpp, "0x%lx", checkpoint->regs.stack_addr);
		fprintf_substring(fpp, buffer, after_sp_value, before_pc_value);

		// Write updated program counter
		fprintf(fpp, "0x%lx", checkpoint->regs.entry_addr);
		fprintf_substring(fpp, buffer, after_pc_value, before_pstate_value);
		
		// Write updated pstate
		fprintf(fpp, "0x%lx", checkpoint->regs.pstate);
		fprintf_substring(fpp, buffer, after_pstate_value, before_vregs_value);

		// Write all updated vregs
		fputc('[', fpp);
		for(int i = 0; i < 64; i++) {
			fprintf(fpp, "%llu", checkpoint->regs.vregs[i]);

			if(i != 63)
				fprintf(fpp, ",\n");
		}
		fputc(']', fpp);
		fprintf_substring(fpp, buffer, after_vregs_value, before_fpsr_value);

		// Write updated fpsr
		fprintf(fpp, "%lu", checkpoint->regs.fpsr);
		fprintf_substring(fpp, buffer, after_fpsr_value, before_fpcr_value);
		
		// Write updated fpcr
		fprintf(fpp, "%lu", checkpoint->regs.fpcr);
		fprintf_substring(fpp, buffer, after_fpcr_value, file_size);

		fclose(fpp);
	}
}

void write_updated_pages_checkpoint(struct criu_merged_pagemap * merged_map, struct criu_dirty_page * dirty_page, int dirty_page_count, void * page_data, char * original_buffer) {
	FILE *fpages = fopen("modified_pages-1.img", "w+");
	if(fpages) {
		struct criu_merged_page * entry = NULL;
		TAILQ_FOREACH(entry, merged_map, link) {
			for(int i = 0; i < entry->entry.nr_pages; i++) {
				vaddr_t addr = entry->entry.vaddr_start + i * 4096;
	
				bool dirty = false;
				for(int y = 0; y < dirty_page_count; y++) {
					if(addr == dirty_page[y].vaddr_start) {
						// Write dirty page
						fwrite(page_data + y * 4096, 1, 4096, fpages);
						// printf("dirty page at: %p - index: %d\n", addr, entry->entry.file_page_index + i);
						dirty = true;
						break;
					}
				}

				if(!dirty) {
					// Write the original
					fwrite(original_buffer + (entry->entry.file_page_index + i) * 4096, 1, 4096, fpages);
					// printf("clean page at: %p - index: %d\n", addr, entry->entry.file_page_index + i);
				}
			}
		}

		fclose(fpages);
	} else {
		printf("Unable to open pages-1.img for writing..");
	}
}

void write_updated_pagemap_checkpoint(struct criu_merged_pagemap * merged_pagemap, char * buffer, long file_size) {
	FILE *fpagemap = fopen("modified_pagemap.txt", "w+");

	if(fpagemap) {
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

		// First vaddr index
		int vaddr_start = 0;

		// Parse the JSON version of the core checkpoint file (example core-2956.img)
		for(int i = 1; i < items; i++) {
			if (jsoneq(buffer, &tokens[i], "vaddr") == 0) { 
				vaddr_start = tokens[i-1].start;
				break;
			}
		}

		char backup = buffer[vaddr_start];
		buffer[vaddr_start] = 0;
		fprintf(fpagemap, "%s", buffer);
		buffer[vaddr_start] = backup;	

		struct criu_merged_page * entry = NULL;
		TAILQ_FOREACH(entry, merged_pagemap, link) {
			fprintf(fpagemap, "{\n\t\"vaddr\": \"0x%lx\",\n\t\"nr_pages\": %d,\n\t\"flags\": \"", entry->entry.vaddr_start, entry->entry.nr_pages);
			
			bool require_seperator = false;
			if(entry->entry.flags & PE_LAZY) {
				fprintf(fpagemap, "PE_LAZY");
				require_seperator = true;
			}

			if(entry->entry.flags & PE_PRESENT) {
				if(require_seperator)
					fprintf(fpagemap, " | ");

				fprintf(fpagemap, "PE_PRESENT");
			}

			fprintf(fpagemap, "\"\n}");

			if(entry->link.tqe_next != NULL)
				fprintf(fpagemap, ",\n");
		}

		fprintf(fpagemap, "] }");

		fclose(fpagemap);
	} else {
		printf("Unable to open modified_pagemap.txt");
	}
}

int crit_execute(int sock, char * command, char * buffer) {
    send(sock, command , strlen(command) , 0 ); 
    // printf("CRIU decode message sent: %s\n", command); 
    int valread = read( sock , buffer, 1024); 
	buffer[valread] = '\0';
    // printf("%s\n",buffer ); 
	return valread;
}



bool decode_pid() {
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
	
	snprintf(command, 100, "decode -i check/pstree.img --pretty -o pstree.txt");
	crit_execute(sock, command, buffer);

	close(sock);

	return true;
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

	snprintf(command, 100, "decode -i check/files.img --pretty -o files.txt", pid, pid);
	crit_execute(sock, command, buffer);

	close(sock);

	return true;
}

bool encode_checkpoint(int pid) {
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

	snprintf(command, 100, "encode -i modified_core.txt -o check/core-%d.img", pid, pid);
	crit_execute(sock, command, buffer);

	snprintf(command, 100, "encode -i modified_pagemap.txt -o check/pagemap-%d.img", pid, pid);
	crit_execute(sock, command, buffer);

	close(sock);

	return true;
}

void read_checkpoint_files(int pid, struct checkpoint_file_data * files) {
	char filenames[CHECKPOINT_FILES][CHECKPOINT_FILENAME_MAXLENGTH] = {};

	snprintf(filenames[CORE_FILE], CHECKPOINT_FILENAME_MAXLENGTH, "core-%d.txt", pid);
	snprintf(filenames[MM_FILE], CHECKPOINT_FILENAME_MAXLENGTH, "mm-%d.txt", pid);
	snprintf(filenames[PAGEMAP_FILE], CHECKPOINT_FILENAME_MAXLENGTH, "pagemap-%d.txt", pid);
	snprintf(filenames[FILES_FILE], CHECKPOINT_FILENAME_MAXLENGTH, "files.txt");
	snprintf(filenames[PAGES_BINARY_FILE], CHECKPOINT_FILENAME_MAXLENGTH, "pages-1.img");
	
	// Skip the last EXECUTABLE_BINARY_FILE, because we do not know the executable name yet which is parsed from FILES_FILE
	for(int i = PAGES_BINARY_FILE; i <= FILES_FILE; i++) {
		// Set the filename, load the filesize and read the file from disk into the buffer
		files[i].filename = filenames[i];
		read_file(&files[i]);

		// printf("%d: %s - size: %d\n", i, filenames[i], files[i].file.file_size);
	}
}

void create_merged_map(struct criu_merged_pagemap * merged_map, struct criu_checkpoint * checkpoint, struct criu_dirty_page * dirty_entry, int dirty_page_count);

void print_usage() {
	printf("Usage: optee_app_migrator $pid\n");
}

int parse_checkpoint_pstree(struct checkpoint_file_data * checkpoint_files) {
	char * json = checkpoint_files[PSTREE_FILE].buffer;
	uint64_t file_size = checkpoint_files[PSTREE_FILE].file.file_size;

	// Initialize the JSMN json parser
	jsmn_parser parser;
	jsmn_init(&parser);

	// First only determine the number of tokens.
	int items = jsmn_parse(&parser, json, file_size, NULL, 128);

	jsmntok_t tokens[items];
	
	// Reset position in stream
	jsmn_init(&parser);
	int left = jsmn_parse(&parser, json, file_size, tokens, items);

	// Invalid file.
	if (items < 1 || tokens[0].type != JSMN_OBJECT) {
		DMSG("CRIU: INVALID JSON\n");
		return false;
	}

	for(int i = 1; i < items; i++) {
		// Find entry with id 1 and parse the filename. This is the executable
		if (jsoneq(json, &tokens[i], "pid") == 0) {
			if(tokens[i+1].type == JSMN_PRIMITIVE) {
				int pid = strtoul(json + tokens[i+1].start, NULL, 10);
				return pid;
			}
		}
	}

	return -1;
}

int main(int argc, char *argv[])
{
	printf("OP-TEE App Migrator\n\n");

	if(argc < 2) {
		print_usage();
		exit(-1);
	}

	int pid = -1;

	if(!strcmp(argv[1], "-m")) {
		if(argc < 3) {
			printf("Missing process id\n");
			printf("Usage: -m <pid>\n");
			exit(-1);
		}

		pid = strtoul(argv[2], NULL, 10);
	} else if (!strcmp(argv[1], "-p")) {
		if(argc < 3) {
			printf("Missing process id\n");
			printf("Usage: -p <pid>\n");
			exit(-1);
		}

		pid = strtoul(argv[2], NULL, 10);
	} else {
		char command[] = "./criu.sh start -D check --shell-job --exec-cmd -- ";

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

	while(!stop_execution) {
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
		printf("\nLoading & executing checkpoint\n");
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
		} while(checkpoint.result != CRIU_SYSCALL_EXIT &&
				checkpoint.result != CRIU_SYSCALL_UNSUPPORTED &&
				checkpoint.result != CRIU_MIGRATE_BACK);
		
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

		for(int i = 0; i < CHECKPOINT_FILES; i++) {
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

		stop_execution = true;

		// IF result != SYS_EXIT
		printf("Going to execute criu.sh\n");
		system("cp -rf modified_pages-1.img check/pages-1.img");
		// system("./criu.sh execute -D check --shell-job -v4");
	}

	return 0;
}


void create_merged_map(struct criu_merged_pagemap * merged_map, struct criu_checkpoint * checkpoint, 
					   struct criu_dirty_page * dirty_entry, int dirty_page_count) {
	for(int i = 0; i < checkpoint->pagemap_entry_count; i++) {
		struct criu_merged_page * new_entry = calloc(1, sizeof(struct criu_merged_page));
		new_entry->is_new = false;
		memcpy(&new_entry->entry, &checkpoint->pagemap_entries[i], sizeof(struct criu_pagemap_entry));

		TAILQ_INSERT_TAIL(merged_map, new_entry, link);
	}

	for(int i = 0; i < dirty_page_count; i++) {
		bool skip = false;
		bool insert_before = false;
		struct criu_merged_page * entry = NULL;
		TAILQ_FOREACH(entry, merged_map, link) {
			if((entry->entry.vaddr_start <= dirty_entry[i].vaddr_start)  &&
			(dirty_entry[i].vaddr_start < (entry->entry.vaddr_start + entry->entry.nr_pages * 4096))) {
				skip = true;
				break;
			} else if(dirty_entry[i].vaddr_start < entry->entry.vaddr_start) {
				insert_before = true;
				break;
			}
		}		

		if(skip)
			continue;

		struct criu_merged_page * new_entry = calloc(1, sizeof(struct criu_merged_page));
		
		new_entry->entry.vaddr_start = dirty_entry[i].vaddr_start;
		new_entry->entry.nr_pages = 1;
		new_entry->entry.file_page_index = -1;
		new_entry->entry.flags = PE_LAZY | PE_PRESENT;
		new_entry->is_new = true;

		if(insert_before)
			TAILQ_INSERT_BEFORE(entry, new_entry, link);
		else
			TAILQ_INSERT_TAIL(merged_map, new_entry, link);
	}
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