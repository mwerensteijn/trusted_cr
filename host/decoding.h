#ifndef DECODING_H
#define DECODING_H


#include <stdlib.h>
#include <sys/time.h>

struct timeval  start_time, end_time;

#include "crit.h"
#include "file_handling.h"

#include "trusted_cr/trusted_cr_checkpoint.h"
#include "trusted_cr/trusted_cr_checkpoint_parser.h"

void parse_checkpoint_files(int pid, struct checkpoint_file_data * checkpoint_files, struct trusted_cr_checkpoint * checkpoint) {
	// Copy over pages-1.img
	
	gettimeofday(&start_time, NULL);

	system("cp check/pages-1.img pages-1.img");

	gettimeofday(&end_time, NULL);
	printf ("Copying a fresh pages-1.img: Total time = %f seconds \n", 
	(double) (end_time.tv_sec - start_time.tv_sec) + ((double) (end_time.tv_usec - start_time.tv_usec) / 1000000.0));
	gettimeofday(&start_time, NULL);

	if(!critserver_decode_checkpoint(pid))
		perror("Unable to decode checkpoint\n");

	gettimeofday(&end_time, NULL);
	printf ("Decode all checkpoint images: Total time = %f seconds \n", 
	(double) (end_time.tv_sec - start_time.tv_sec) + ((double) (end_time.tv_usec - start_time.tv_usec) / 1000000.0));
	gettimeofday(&start_time, NULL);

	// TODO: make it a if(true) otherwise exit
	read_checkpoint_files(pid, checkpoint_files);

	gettimeofday(&end_time, NULL);
	printf ("Read all checkpoint files: Total time = %f seconds \n", 
	(double) (end_time.tv_sec - start_time.tv_sec) + ((double) (end_time.tv_usec - start_time.tv_usec) / 1000000.0));
	gettimeofday(&start_time, NULL);

	if(!parse_checkpoint_core(checkpoint, checkpoint_files))
		perror("Unable to parse core-file.\n");

	if(!parse_checkpoint_mm(checkpoint, checkpoint_files))
		perror("Unable to parse mm-file.\n");

	if(!parse_checkpoint_pagemap(checkpoint, checkpoint_files))
		perror("Unable to parse pagemap-file.\n");

	if(!parse_executable_name(checkpoint_files))
		perror("Unable the parse the executable name from files.img.\n");

	gettimeofday(&end_time, NULL);
	printf ("Parse all checkpoint files: Total time = %f seconds \n", 
	(double) (end_time.tv_sec - start_time.tv_sec) + ((double) (end_time.tv_usec - start_time.tv_usec) / 1000000.0));
	gettimeofday(&start_time, NULL);

	// Now that we have parsed the executable filename from the checkpoint file, we can load it.
	read_file(&checkpoint_files[EXECUTABLE_BINARY_FILE]);
		gettimeofday(&end_time, NULL);

	printf ("Reading the executable file: Total time = %f seconds \n", 
	(double) (end_time.tv_sec - start_time.tv_sec) + ((double) (end_time.tv_usec - start_time.tv_usec) / 1000000.0));
	gettimeofday(&start_time, NULL);
}

#endif /* DECODING_H */