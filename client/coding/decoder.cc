/*
 * decoder.cc
 * decode by stub & chunks
 */

#include "decoder.hh"

using namespace std;

/*
 * thread handler for decode shares into secret
 */
void* Decoder::thread_handler(void* param) { 

	/* parse parameters */
	int index = ((param_decoder*)param)->index;
	Decoder* obj = ((param_decoder*)param)->obj;
	free(param);
	/* main loop for decode shares into secret */
	while (true) {

		ShareChunk_t temp;
		Secret_t input;
		/* get share objects */
		obj->inputbuffer_[index]->Extract(&temp);
		/* decode shares */
		input.secretSize = temp.secretSize;
		memcpy(temp.data+temp.shareSize*obj->n_, obj->stubBuffer_+temp.secretID*64,64);
		int ret_size;
		obj->aontObj_[index]->decode((unsigned char*)temp.data, temp.shareSize*obj->n_+64, (unsigned char*)input.data, &ret_size);
		/* add secret into output buffer */
		obj->outputbuffer_[index]->Insert(&input,sizeof(input));
	}
	return NULL;
}

/*
 * collect thread for sequencially get secrets
 */
void* Decoder::collect(void* param) {

	/* parse parameters */
	char* buf = (char*)malloc(FWRITE_BUFFER_SIZE);
	Decoder* obj = (Decoder*)param;
	int count = 0;
	int out_index = 0;

	/* main loop for get secrets */
	while(true){
		/* according to thread sequence */
		for(int i = 0; i < DECODE_NUM_THREADS; i++){
			
			Secret_t temp;
			/* extract secret object */
			obj->outputbuffer_[i]->Extract(&temp);
			/* if write buffer full then write to file */
			if(out_index + temp.secretSize > FWRITE_BUFFER_SIZE){
				fwrite(buf, out_index,1,obj->fw_);
				out_index = 0;
			}

			/* copy secret to write buffer */
			memcpy(buf+out_index, temp.data, temp.secretSize);
			out_index += temp.secretSize;

			/* if this is the last secret, write to file and  exit the collect */
			count++;
			if(count == obj->totalSecrets_) {
				if(out_index > 0) {
					fwrite(buf, out_index, 1, obj->fw_);
				}
				free(buf);
				pthread_exit(NULL);
			}
		}
	}
	return NULL;
}

/*
 * decoder constructor
 *
 * @param n - total number of shares created from a secret
 * @param securetype - encryption and hash type
 */
Decoder::Decoder(int n, int securetype) {

	n_ = n;
	/* initialization */
	cryptoObj_ = (CryptoPrimitive**)malloc(sizeof(CryptoPrimitive*)*n_);
	inputbuffer_ = (RingBuffer<ShareChunk_t>**)malloc(sizeof(RingBuffer<ShareChunk_t>*)*DECODE_NUM_THREADS);
	outputbuffer_ = (RingBuffer<Secret_t>**)malloc(sizeof(RingBuffer<Secret_t>*)*DECODE_NUM_THREADS);
	stubBuffer_ = (unsigned char*)malloc(sizeof(unsigned char)*STUB_BUFFER_SIZE);
	/* initialization for variables of each thread */
	for (int i = 0; i < DECODE_NUM_THREADS; i++){
		inputbuffer_[i] = new RingBuffer<ShareChunk_t>(DECODE_RB_SIZE, true, 1);
		outputbuffer_[i] = new RingBuffer<Secret_t>(DECODE_RB_SIZE, true, 1);
		cryptoObj_[i]  = new CryptoPrimitive(securetype);
		//decodeObj_[i] = new CDCodec(type,n,m,r,cryptoObj_[i]);
		aontObj_[i] = new Aont(cryptoObj_[i], 1);
		param_decoder* temp = (param_decoder*)malloc(sizeof(param_decoder));
		temp->index = i;
		temp->obj = this;

		/* create decode threads */
		pthread_create(&tid_[i],0,&thread_handler,(void*)temp);
	}
	/* create collect thread */
	pthread_create(&tid_[DECODE_NUM_THREADS],0,&collect,(void*)this);
}
/*
 *init stubfile path 
 */
bool Decoder::init(char* filename) {

	char recipeName[256];
	sprintf(recipeName, "%s.stub.d", filename);
	cout<<"filename: "<<recipeName<<endl;
	FILE* fp = fopen(recipeName, "r");
	if(fp == NULL) {
		cout<<"error to open meta file"<<endl;
		return false;
	}
	fseek(fp, 0, SEEK_END);
	int recipeSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	int ret = fread(stubBuffer_, recipeSize, 1, fp);
	if(ret < 0){
		printf("fail to load meta file\n");
		return false;
	}
	else {
		return true;
	}
}

/* 
 * test whether the decode thread returned
 */
int Decoder::indicateEnd() {
	
	pthread_join(tid_[DECODE_NUM_THREADS], NULL);
	return 1;
}

/*
 * decoder destructor
 */
Decoder::~Decoder() {

	for (int i = 0; i < DECODE_NUM_THREADS; i++){
		
		delete(aontObj_[i]);
		delete(cryptoObj_[i]);
		delete(inputbuffer_[i]);
		delete(outputbuffer_[i]);
	}
	free(inputbuffer_);
	free(outputbuffer_);
	free(cryptoObj_);
}

/*
 * add interface for add item into decode input buffer
 *
 * @param item - the input object
 * @param index - the index of thread
 *
 */
int Decoder::add(ShareChunk_t* item, int index) {

	inputbuffer_[index]->Insert(item, sizeof(ShareChunk_t));
	return 1;
}

/*
 * set the file pointer
 *
 * @param fp - the output file pointer
 */
int Decoder::setFilePointer(FILE* fp){
	
	fw_ = fp;
	return 1;
}

/*
 * set the share list
 *
 * @param list - the share ID list indicate the shares come from which clouds
 */
int Decoder::setShareIDList(int* list) {

	kShareIDList_ = list;
	return 1;
}

/*
 * pass the total secret number to decoder
 *
 * @param n - the total number of secrets in the file
 *
 */
int Decoder::setTotal(int totalSecrets) {

	totalSecrets_ = totalSecrets;
	return 1;
}




