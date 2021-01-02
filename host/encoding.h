#ifndef ENCODING_H
#define ENCODING_H

#include "criu/criu_checkpoint.h"
#include "criu/criu_checkpoint_parser.h"

void fprintf_substring(FILE * file, char * buffer, int start_index, int end_index) {
	char backup = buffer[end_index];
	buffer[end_index] = 0;
	fprintf(file, buffer + start_index);
	buffer[end_index] = backup;	
}

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

void encode_modified_data(struct criu_checkpoint * checkpoint, struct checkpoint_file_data * checkpoint_files, void * shared_memory_buffer) {
	int shared_buffer_2_index = 0;
	memcpy(&checkpoint->regs, shared_memory_buffer, sizeof(struct criu_checkpoint_regs));
	shared_buffer_2_index += sizeof(struct criu_checkpoint_regs);

	struct criu_checkpoint_dirty_pages * dirty_pages_info = shared_memory_buffer + shared_buffer_2_index;
	shared_buffer_2_index += sizeof(struct criu_checkpoint_dirty_pages);

	struct criu_dirty_page * dirty_entry = shared_memory_buffer + shared_buffer_2_index;
	shared_buffer_2_index += dirty_pages_info->dirty_page_count * sizeof(struct criu_dirty_page);

	struct criu_merged_pagemap merged_map;
	TAILQ_INIT(&merged_map);

	create_merged_map(&merged_map, checkpoint, dirty_entry, dirty_pages_info->dirty_page_count);

	// struct criu_merged_page * e = NULL;
	// TAILQ_FOREACH(e, &merged_map, link) {
	// 	printf("[%d] entry: %p - nr pages: %d\n", e->is_new, e->entry.vaddr_start, e->entry.nr_pages);
	// }

	write_updated_core_checkpoint("modified_core.txt", checkpoint_files[CORE_FILE].buffer, checkpoint_files[CORE_FILE].file.file_size, checkpoint);

	write_updated_pagemap_checkpoint(&merged_map, checkpoint_files[PAGEMAP_FILE].buffer, checkpoint_files[PAGEMAP_FILE].file.file_size);

	write_updated_pages_checkpoint(&merged_map, dirty_entry, dirty_pages_info->dirty_page_count, shared_memory_buffer + shared_buffer_2_index, checkpoint_files[PAGES_BINARY_FILE].buffer);

	// Free all allocated criu_pagemap_entry structs
	struct criu_merged_page * entry = NULL;
	TAILQ_FOREACH(entry, &merged_map, link) {
		free(entry);
	}
}

#endif /* ENCODING_H */