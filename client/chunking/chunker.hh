/*
	Define Class : Chunker to chunking files 
	main work : return the chunk end index in the input file and the total chunk number
*/

#ifndef __CHUNKER_HH__
#define __CHUNKER_HH__

#include <bits/stdc++.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint> 

#define FIX_SIZE_TYPE 0	//macro for the type of fixed-size chunker
#define VAR_SIZE_TYPE 1	//macro for the type of variable-size chunker

using namespace std;

class Chunker{

	private:
		//chunker type setting (FIX_SIZE_TYPE or VAR_SIZE_TYPE)
		bool chunkerType_;	
		//chunk size setting 
		int avgChunkSize_; 
		int minChunkSize_; 
		int maxChunkSize_; 
		//sliding window size
		int slidingWinSize_; 
		/*the base for calculating the value of the polynomial in rolling hash*/
		uint32_t polyBase_; 
		/*the modulus for limiting the value of the polynomial in rolling hash*/
		uint32_t polyMOD_; 		
		/*note: to avoid overflow, polyMOD_*255 should be in the range of "uint32_t"*/
		/*      here, 255 is the max value of "unsigned char"                       */
		/*the lookup table for accelerating the power calculation in rolling hash*/
		uint32_t *powerLUT_; 
		/*the lookup table for accelerating the byte remove in rolling hash*/
		uint32_t *removeLUT_; 
		/*the mask for determining an anchor*/
		uint32_t anchorMask_;	
		/*the value for determining an anchor*/
		uint32_t anchorValue_; 

		/*
			function : divide a buffer into a number of fixed-size chunks
			input : data buffer(unsigned char *) buffer size(int *) 
			output : chunk index list(int *) number of chunks(int)  
	
 			@param buffer - a buffer to be chunked
			@param bufferSize - the size of the buffer
 			@param chunkEndIndexList - a list for returning the end index of each chunk <return>
 			@param numOfChunks - the number of chunks <return>
		*/
		void fixSizeChunking(unsigned char *buffer, int bufferSize, int *chunkEndIndexList, int *numOfChunks);

		/*
			function : divide a buffer into a number of variable-size chunks
			input : data buffer(unsigned char *) buffer size(int *) 
			output : chunk index list(int *) number of chunks(int)  

			note: to improve performance, we use the optimization in open-vcdiff: "http://code.google.com/p/open-vcdiff/"
	
 			@param buffer - a buffer to be chunked
			@param bufferSize - the size of the buffer
 			@param chunkEndIndexList - a list for returning the end index of each chunk <return>
 			@param numOfChunks - the number of chunks <return>
		*/
		void varSizeChunking(unsigned char *buffer, int bufferSize, int *chunkEndIndexList, int *numOfChunks);

	public:
	
		/*
			function : constructor of Chunker
			input : chunker type(int [macro]) avgChunkSize(int) minChunkSize(int) maxChunkSize(int) slidingWinSize(int)
			output : NULL 
	
 			@param chunkerType - chunker type (FIX_SIZE_TYPE or VAR_SIZE_TYPE)
 			@param avgChunkSize - average chunk size
 			@param minChunkSize - minimum chunk sizea
 			@param maxChunkSize - maximum chunk size
 			@param slidingWinSize - sliding window size
		*/
		Chunker(bool chunkerType = VAR_SIZE_TYPE, 
				int avgChunkSize = (8<<10), 
				int minChunkSize = (2<<10), 
				int maxChunkSize = (16<<10), 
				int slidingWinSize = 48);

		/*
			function: destructor of Chunker
		*/
		~Chunker();

		/*
 			function : accroding chunking type setting to call the select function
			input : data buffer(unsigned char *) buffer size(int *) 
			output : chunk index list(int *) number of chunks(int)  

 			@param buffer - a buffer to be chunked
 			@param bufferSize - the size of the buffer
 			@param chunkEndIndexList - a list for returning the end index of each chunk <return>
 			@param numOfChunks - the number of chunks <return>
		*/
		void chunking(unsigned char *buffer, int bufferSize, int *chunkEndIndexList, int *numOfChunks);
};

#endif
