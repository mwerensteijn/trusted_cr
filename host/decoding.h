#ifndef DECODING_H
#define DECODING_H


#include <stdlib.h>

#include "crit.h"
#include "file_handling.h"

#include "criu/criu_checkpoint.h"
#include "criu/criu_checkpoint_parser.h"

void parse_checkpoint_files(int pid, struct checkpoint_file_data * checkpoint_files, struct criu_checkpoint * checkpoint) {
	// Copy over pages-1.img
	system("cp check/pages-1.img pages-1.img");

	if(!critserver_decode_checkpoint(pid))
		perror("Unable to decode checkpoint\n");

	// TODO: make it a if(true) otherwise exit
	read_checkpoint_files(pid, checkpoint_files);

	if(!parse_checkpoint_core(checkpoint, checkpoint_files))
		perror("Unable to parse core-file.\n");

	if(!parse_checkpoint_mm(checkpoint, checkpoint_files))
		perror("Unable to parse mm-file.\n");

	if(!parse_checkpoint_pagemap(checkpoint, checkpoint_files))
		perror("Unable to parse pagemap-file.\n");

	if(!parse_executable_name(checkpoint_files))
		perror("Unable the parse the executable name from files.img.\n");

	// Now that we have parsed the executable filename from the checkpoint file, we can load it.
	read_file(&checkpoint_files[EXECUTABLE_BINARY_FILE]);
}

#endif /* DECODING_H */