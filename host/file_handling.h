#ifndef FILE_HANDLING_H
#define FILE_HANDLING_H

#include "criu/criu_checkpoint.h"
#include "criu/criu_checkpoint_parser.h"

#define CHECKPOINT_FILENAME_MAXLENGTH 100

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

void read_checkpoint_files(int pid, struct checkpoint_file_data * files) {
	char filenames[NUMBER_OF_CHECKPOINT_FILES][CHECKPOINT_FILENAME_MAXLENGTH] = {};

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

#endif /* FILE_HANDLING_H */