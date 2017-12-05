#include "chunker.hh"
using namespace std;

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
Chunker::Chunker(bool chunkerType, int avgChunkSize, int minChunkSize, int maxChunkSize, int slidingWinSize) {

	chunkerType_ = chunkerType;
	/*fixed-size chunker*/
	if (chunkerType_ == FIX_SIZE_TYPE) { 

		avgChunkSize_ = avgChunkSize;
		cerr<<endl<<"A fixed-size chunker has been constructed!"<<endl;
		cerr<<"Parameters:"<<endl;
		cerr<<setw(6)<<"avgChunkSize_: "<<avgChunkSize_<<endl;	
		cerr<<endl;
	}
	/*variable-size chunker*/
	if (chunkerType_ == VAR_SIZE_TYPE) { 
		int numOfMaskBits;

		if (minChunkSize >= avgChunkSize)  {
			cerr<<"Error: minChunkSize should be smaller than avgChunkSize!"<<endl;	
			exit(1);
		}
		if (maxChunkSize <= avgChunkSize)  {
			cerr<<"Error: maxChunkSize should be larger than avgChunkSize!"<<endl;
			exit(1);
		}
		avgChunkSize_ = avgChunkSize;
		minChunkSize_ = minChunkSize;	
		maxChunkSize_ = maxChunkSize;
		slidingWinSize_ = slidingWinSize;
		/*initialize the base and modulus for calculating the fingerprint of a window*/
		/*these two values were employed in open-vcdiff: "http://code.google.com/p/open-vcdiff/"*/
		polyBase_ = 257; /*a prime larger than 255, the max value of "unsigned char"*/
		polyMOD_ = (1 << 23); /*polyMOD_ - 1 = 0x7fffff: use the last 23 bits of a polynomial as its hash*/
		/*initialize the lookup table for accelerating the power calculation in rolling hash*/
		powerLUT_ = (uint32_t *) malloc(sizeof(uint32_t) * slidingWinSize_);
		/*powerLUT_[i] = power(polyBase_, i) mod polyMOD_*/
		powerLUT_[0] = 1;
		for (int i = 1; i < slidingWinSize_; i++) {
			/*powerLUT_[i] = (powerLUT_[i-1] * polyBase_) mod polyMOD_*/
			powerLUT_[i] = (powerLUT_[i-1] * polyBase_) & (polyMOD_ - 1); 
		}
		/*initialize the lookup table for accelerating the byte remove in rolling hash*/
		removeLUT_ = (uint32_t *) malloc(sizeof(uint32_t) * 256); /*256 for unsigned char*/
		for (int i = 0; i < 256; i++) {
			/*removeLUT_[i] = (- i * powerLUT_[slidingWinSize_-1]) mod polyMOD_*/
			removeLUT_[i] = (i * powerLUT_[slidingWinSize_-1]) & (polyMOD_ - 1); 
			if (removeLUT_[i] != 0) {
				
				removeLUT_[i] = polyMOD_ - removeLUT_[i];
			}
			/*note: % is a remainder (rather than modulus) operator*/
			/*      if a < 0,  -polyMOD_ < a % polyMOD_ <= 0       */
		}

		/*initialize the mask for depolytermining an anchor*/
		/*note: power(2, numOfMaskBits) = avgChunkSize_*/
		numOfMaskBits = 1;		
		while ((avgChunkSize_ >> numOfMaskBits) != 1) {
			
			numOfMaskBits++;
		}
		anchorMask_ = (1 << numOfMaskBits) - 1;
		/*initialize the value for depolytermining an anchor*/
		anchorValue_ = 0;		
		cerr<<endl<<"A variable-size chunker has been constructed!"<<endl;
		cerr<<"Parameters: "<<endl;	
		cerr<<setw(6)<<"avgChunkSize_: "<<avgChunkSize_<<endl;		
		cerr<<setw(6)<<"minChunkSize_: "<<minChunkSize_<<endl;	
		cerr<<setw(6)<<"maxChunkSize_: "<<maxChunkSize_<<endl;
		cerr<<setw(6)<<"slidingWinSize_: "<<slidingWinSize_<<endl;		
		cerr<<setw(6)<<"polyBase_: 0x"<<hex<<polyBase_<<endl;	
		cerr<<setw(6)<<"polyMOD_: 0x"<<hex<<polyMOD_<<endl;
		cerr<<setw(6)<<"anchorMask_: 0x"<<hex<<anchorMask_<<endl;
		cerr<<setw(6)<<"anchorValue_: 0x"<<hex<<anchorValue_<<endl;	
		cerr<<endl;
	}	
}

/*
	function: destructor of Chunker
*/
Chunker::~Chunker() {

	if (chunkerType_ == VAR_SIZE_TYPE) { /*variable-size chunker*/
		free(powerLUT_);
		free(removeLUT_);
		cerr<<endl<<"The variable-size chunker has been destructed!"<<endl;	
		cerr<<endl;
	}
	if (chunkerType_ == FIX_SIZE_TYPE) { /*variable-size chunker*/
		cerr<<endl<<"The fixed-size chunker has been destructed!"<<endl;
		cerr<<endl;
	}
}

/*
	function : divide a buffer into a number of fixed-size chunks
	input : data buffer(unsigned char *) buffer size(int *) 
	output : chunk index list(int *) number of chunks(int)  
	
 	@param buffer - a buffer to be chunked
	@param bufferSize - the size of the buffer
 	@param chunkEndIndexList - a list for returning the end index of each chunk <return>
 	@param numOfChunks - the number of chunks <return>
*/
void Chunker::fixSizeChunking(unsigned char *buffer, int bufferSize, int *chunkEndIndexList, int *numOfChunks){

	int chunkEndIndex;
	(*numOfChunks) = 0;
	chunkEndIndex = -1 + avgChunkSize_;
	/*divide the buffer into chunks*/
	while (chunkEndIndex < bufferSize) {
		/*record the end index of a chunk*/
		chunkEndIndexList[(*numOfChunks)] = chunkEndIndex;
		/*go on for the next chunk*/
		chunkEndIndex = chunkEndIndexList[(*numOfChunks)] + avgChunkSize_;		
		(*numOfChunks)++;
	}	
	/*deal with the tail of the buffer*/
	if (((*numOfChunks) == 0) || (((*numOfChunks) > 0) && (chunkEndIndexList[(*numOfChunks)-1] != bufferSize -1))) { 
		/*note: such a tail chunk has a size < avgChunkSize_*/
		chunkEndIndexList[(*numOfChunks)] = bufferSize -1;		
		(*numOfChunks)++;
	}	
}

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
void Chunker::varSizeChunking(unsigned char *buffer, int bufferSize, int *chunkEndIndexList, int *numOfChunks) {

	int chunkEndIndex, chunkEndIndexLimit;
	uint32_t winFp;	//the fingerprint of a window
	(*numOfChunks) = 0; //init the number of chunks
	chunkEndIndex = -1 + minChunkSize_;
	chunkEndIndexLimit = -1 + maxChunkSize_;
	/*divide the buffer into chunks*/
	while (chunkEndIndex < bufferSize) {	

		if (chunkEndIndexLimit >= bufferSize) {
			
			chunkEndIndexLimit = bufferSize - 1;		
		}
		/*calculate the fingerprint of the first window*/
		winFp = 0;
		for (int i = 0; i < slidingWinSize_; i++) {
			/*winFp = winFp + ((buffer[chunkEndIndex-i] * powerLUT_[i]) mod polyMOD_)*/
			winFp = winFp + ((buffer[chunkEndIndex-i] *	powerLUT_[i]) & (polyMOD_ - 1));
		}
		/*winFp = winFp mod polyMOD_*/
		winFp = winFp & (polyMOD_ - 1);
		while (((winFp & anchorMask_) != anchorValue_) && (chunkEndIndex < chunkEndIndexLimit)) {
			/*move the window forward by 1 byte*/
			chunkEndIndex++;
			/*update the fingerprint based on rolling hash*/
			/*winFp = ((winFp + removeLUT_[buffer[chunkEndIndex-slidingWinSize_]]) * polyBase_ + buffer[chunkEndIndex]) mod polyMOD_*/
			winFp = ((winFp + removeLUT_[buffer[chunkEndIndex-slidingWinSize_]]) * polyBase_ + buffer[chunkEndIndex]) & (polyMOD_ - 1); 
		}
		/*record the end index of a chunk*/	
		chunkEndIndexList[(*numOfChunks)] = chunkEndIndex;
		/*go on for the next chunk*/
		chunkEndIndex = chunkEndIndexList[(*numOfChunks)] + minChunkSize_;
		chunkEndIndexLimit = chunkEndIndexList[(*numOfChunks)] + maxChunkSize_;
		(*numOfChunks)++;
	}
	/*deal with the tail of the buffer*/
	if (((*numOfChunks) == 0) || (((*numOfChunks) > 0) && (chunkEndIndexList[(*numOfChunks)-1] != bufferSize -1))) { 
		/*note: such a tail chunk has a size < minChunkSize_*/
		chunkEndIndexList[(*numOfChunks)] = bufferSize -1;		
		(*numOfChunks)++;
	}
}

/*
 	function : accroding chunking type setting to call the select function
	input : data buffer(unsigned char *) buffer size(int *) 
	output : chunk index list(int *) number of chunks(int)  

 	@param buffer - a buffer to be chunked
 	@param bufferSize - the size of the buffer
 	@param chunkEndIndexList - a list for returning the end index of each chunk <return>
 	@param numOfChunks - the number of chunks <return>
*/
void Chunker::chunking(unsigned char *buffer, int bufferSize, int *chunkEndIndexList, int *numOfChunks) {
	/*fixed-size chunker*/ 
	if (chunkerType_ == FIX_SIZE_TYPE) { 

		fixSizeChunking(buffer, bufferSize, chunkEndIndexList, numOfChunks);
	}
	/*variable-size chunker*/
	if (chunkerType_ == VAR_SIZE_TYPE) { 

		varSizeChunking(buffer, bufferSize, chunkEndIndexList, numOfChunks);
	}	
}

