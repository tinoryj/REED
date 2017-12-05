#include <bits/stdc++.h>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sys/time.h>

#include "chunker.hh"
#include "encoder.hh"
#include "decoder.hh"
#include "uploader.hh"
#include "downloader.hh"
#include "CryptoPrimitive.hh"
#include "exchange.hh"
#include "conf.hh"

using namespace std;

Chunker* chunkerObj;
Decoder* decoderObj;
Encoder* encoderObj;
Uploader* uploaderObj;
CryptoPrimitive* cryptoObj;
Downloader* downloaderObj;
Configuration* confObj;
KeyEx* keyObj;
/*
	function : get start time 
	input & output : t(double)
*/
void timerStart(double *t) {

	struct timeval tv;
	gettimeofday(&tv, NULL);
	*t = (double)tv.tv_sec+(double)tv.tv_usec*1e-6;
}

/*
	function : get time split 
	input & output : t(double)
*/
double timerSplit(const double *t) {

	struct timeval tv;
	double cur_t;
	gettimeofday(&tv, NULL);
	cur_t = (double)tv.tv_sec + (double)tv.tv_usec*1e-6;
	return (cur_t - *t);
}

/*
	function : output usage massage
	input : NULL
	output : kill program
*/
void usage() {

	cout<<"usage: "<<endl;
	cout<<setw(4)<<"upload file: "<<endl;
	cout<<setw(6)<<"./CLIENT -u [filename] [policy] [secutiyType]"<<endl;
	cout<<setw(4)<<"download file: "<<endl;
	cout<<setw(6)<<"./CLIENT -d [filename] [privateKeyFileName] [secutiyType]"<<endl;
	cout<<setw(4)<<"rekeying file: "<<endl;
	cout<<setw(6)<<"./CLIENT -r [filename] [oldPrivateKeyFileName] [policy] [secutiyType]"<<endl;
	cout<<setw(4)<<"keygen: "<<endl;
	cout<<setw(6)<<"./CLIENT -k [attribute] [privateKeyFileName]"<<endl;

	cout<<setw(2)<<"- [filename]: full path of the file;"<<endl;
	cout<<setw(2)<<"- [policy]: like 'id = 1 or id = 2', provide the policy for CA-ABE encrytion;"<<endl;
	cout<<setw(2)<<"- [attribute]: like 'id = 1', provide the attribute for CA-ABE secret key generation;"<<endl;
	cout<<setw(2)<<"- [securityType]: [HIGH] AES-256 & SHA-256; [LOW] AES-128 & SHA-1"<<endl;
	cout<<setw(2)<<"- [privateKeyFileName]: get the private key by keygen function"<<endl;

	exit(1);
}
int main(int argc, char *argv[]) {
	/* argument check */
	if (argc < 1) {
		
		usage();
	}
	/* get options */
	// int userID = atoi(argv[2]);
	char* opt = argv[1];
	// char* securesetting = argv[4];

	/* read file test*/

	if (strncmp(opt,"-u",2) == 0) {
		if (argc != 5) {
			usage();
		}
		/* object initialization */
		fstream inputFile;
		inputFile.open(argv[2], ios::in | ios::binary);
		long readInFileSize = 0;
		unsigned char * buffer;
		if (inputFile.is_open()) {

			inputFile.seekg(0, ios::end);
			readInFileSize = inputFile.tellg();
			inputFile.clear();
			inputFile.seekg(0, ios::beg);
			inputFile.close();
			
		}
		else {
			cout<<"read your file error, exiting......"<<endl;
			exit(1);
		}
		/* full file name process */
		int namesize = 0;
		while(argv[2][namesize] != '\0'){
			namesize++;
		}
		namesize++;
		/*cpabe*/
		char* policy = argv[3];
		/* parse secure parameters */
		char* securesetting = argv[4];
		int securetype;
		if(strncmp(securesetting,"HIGH", 4) == 0) {
			securetype = HIGH_SEC_PAIR_TYPE;
		}
		else {

			if (strncmp(securesetting,"LOW", 4) == 0) {
				securetype = HIGH_SEC_PAIR_TYPE;
			}
			else {
				cerr<<"Securetype setting error!"<<endl;
				exit(1);
			}
		}
		int *chunkEndIndexList;
		int numOfChunks;
		int n, *kShareIDList;
		/* initialize openssl locks */
		if (!CryptoPrimitive::opensslLockSetup()) {

			printf("fail to set up OpenSSL locks\n");

			return 0;
		}

		confObj = new Configuration();

		n = confObj->getN(); //n -> data stores number
		int bufferSize = 1024*1024*1024;
		int chunkEndIndexListSize = 1024*1024;
		int secretBufferSize = 16*1024;
		int shareBufferSize = n*16*1024;
		unsigned char *secretBuffer, *shareBuffer;
		unsigned char tmp[secretBufferSize];
		memset(tmp,0,secretBufferSize);
		long zero = 0;
		buffer = (unsigned char*) malloc (sizeof(unsigned char)*bufferSize);
		chunkEndIndexList = (int*)malloc(sizeof(int)*chunkEndIndexListSize);
		secretBuffer = (unsigned char*)malloc(sizeof(unsigned char) * secretBufferSize);
		shareBuffer = (unsigned char*)malloc(sizeof(unsigned char) * shareBufferSize);
		/* initialize share ID list */
		kShareIDList = (int*)malloc(sizeof(int)*n);
		for (int i = 0; i < n; i++) {
			
			kShareIDList[i] = i;
		}
		
		uploaderObj = new Uploader(n,n,0, confObj);
		encoderObj = new Encoder(n, securetype, uploaderObj);
		keyObj = new KeyEx(encoderObj, securetype, confObj->getkmIP(), confObj->getkmPort(), confObj->getServerConf(0), CHARA_MIN_HASH,VAR_SEG);
		keyObj->readKeyFile("./keys/public.pem");
		keyObj->newFile(0, argv[2], namesize, policy);

		chunkerObj = new Chunker(VAR_SIZE_TYPE);
		double timer,split,bw, timer2, split2;
		double total_t = 0;
		timerStart(&timer2);

		/* init the file header */
		Encoder::Secret_Item_t header;
		header.type = 1;
		memcpy(header.file_header.data, argv[2], namesize);
		header.file_header.fullNameSize = namesize;
		header.file_header.fileSize = readInFileSize;

		/* add the file header to encoder */
		encoderObj->add(&header);

		/* main loop for adding chunks */
		long total = 0;
		int totalChunks = 0;
		inputFile.open(argv[2], ios::in);

		while (total < readInFileSize) {
			
			timerStart(&timer);

			/* read in a batch of data in buffer */
			inputFile.read((char *)buffer,bufferSize);
			int ret = inputFile.gcount();
			//int ret = fread(buffer,1,bufferSize,fin);

			/* perform chunking on the data */
			chunkerObj->chunking(buffer,ret,chunkEndIndexList,&numOfChunks);
			split = timerSplit(&timer);
			total_t += split;

			int count = 0;
			int preEnd = -1;
			encoderObj->setTotalChunk(numOfChunks);
			/* adding chunks */
			while (count < numOfChunks) {

				/* create structure */
				KeyEx::Chunk_t input;
				input.chunkID = totalChunks;
				input.chunkSize = chunkEndIndexList[count] - preEnd;
				memcpy(input.data, buffer+preEnd+1, input.chunkSize);
				/* zero counting */
				if(memcmp(buffer+preEnd+1, tmp, input.chunkSize) == 0){
					zero += input.chunkSize;
				}
				/* set end indicator */
				input.end = 0;
				if(ret+total == readInFileSize && count+1 == numOfChunks){
					input.end = 1;
				}
				/* add chunk to key client */
				keyObj->add(&input);  			
				/* increase counter */
				totalChunks++;
				preEnd = chunkEndIndexList[count];
				count++;
			}
			total+=ret;
		}
		long long tt, unique;
		tt = 0;
		unique = 0;
		uploaderObj->indicateEnd(&tt, &unique);
		// encrypt stub file
		encoderObj->encStub(argv[2], keyObj->current_key);

		// upload stub file to server
		uploaderObj->uploadStub(argv[2],namesize);

		//encoderObj->indicateEnd();
		split2 = timerSplit(&timer2);

		bw = readInFileSize/1024/1024/(split2-total_t);
		printf("%lf\t%lf\t%lld\t%lld\t%ld\n",bw,(split2-total_t), tt, unique, zero);
		delete uploaderObj;
		delete chunkerObj;
		delete encoderObj;
		inputFile.close();
		char cmd_1[256];
		sprintf(cmd_1, "rm -rf %s.stub", argv[2]);
		char cmd_2[256];
		sprintf(cmd_2, "rm -rf %s.meta", argv[2]);
		system(cmd_1);
		system(cmd_2);

		free(buffer);
		free(chunkEndIndexList);
		free(secretBuffer);
		free(shareBuffer);
		free(kShareIDList);
		CryptoPrimitive::opensslLockCleanup();
		inputFile.close();

		cout << "upload file done"<<endl;
	}

	/* download procedure */
	if (strncmp(opt,"-d",2) == 0){
		if(argc != 5)
			usage();
		/* object initialization */
		unsigned char * buffer;

		/* full file name process */
		int namesize = 0;
		while(argv[2][namesize] != '\0'){
			namesize++;
		}
		namesize++;
		/*cpabe*/
		char* sk = argv[3];
		/* parse secure parameters */
		char* securesetting = argv[4];
		int securetype;
		if(strncmp(securesetting,"HIGH", 4) == 0) {
			securetype = HIGH_SEC_PAIR_TYPE;
		}
		else {

			if (strncmp(securesetting,"LOW", 4) == 0) {
				securetype = HIGH_SEC_PAIR_TYPE;
			}
			else {
				cerr<<"Securetype setting error!"<<endl;
				exit(1);
			}
		}
		int *chunkEndIndexList;
		// int numOfChunks;
		int n, *kShareIDList;
		/* initialize openssl locks */
		if (!CryptoPrimitive::opensslLockSetup()) {

			printf("fail to set up OpenSSL locks\n");

			return 0;
		}

		confObj = new Configuration();

		n = confObj->getN(); //n -> data stores number
		int bufferSize = 1024*1024*1024;
		int chunkEndIndexListSize = 1024*1024;
		int secretBufferSize = 16*1024;
		int shareBufferSize = n*16*1024;
		unsigned char *secretBuffer, *shareBuffer;
		unsigned char tmp[secretBufferSize];
		memset(tmp,0,secretBufferSize);
		// long zero = 0;
		buffer = (unsigned char*) malloc (sizeof(unsigned char)*bufferSize);
		chunkEndIndexList = (int*)malloc(sizeof(int)*chunkEndIndexListSize);
		secretBuffer = (unsigned char*)malloc(sizeof(unsigned char) * secretBufferSize);
		shareBuffer = (unsigned char*)malloc(sizeof(unsigned char) * shareBufferSize);
		/* initialize share ID list */
		kShareIDList = (int*)malloc(sizeof(int)*n);
		for (int i = 0; i < n; i++) {
			
			kShareIDList[i] = i;
		}
		



		/* init objects */
		decoderObj = new Decoder(n, securetype);
		downloaderObj = new Downloader(n,n,0,decoderObj,confObj);
		downloaderObj->downloadStub(argv[2],namesize);
		keyObj = new KeyEx(encoderObj, securetype, confObj->getkmIP(), confObj->getkmPort(), confObj->getServerConf(0), CHARA_MIN_HASH,VAR_SEG);
		if((keyObj->downloadFile(0, argv[2], namesize,sk) == -1)){
			char cmd[256];
			sprintf(cmd, "rm -rf %s.stub.d", argv[2]);
			system(cmd);
			sprintf(cmd, "rm -rf cipher");
			system(cmd);
			sprintf(cmd, "rm -rf cipher.cpabe");
			system(cmd);
			sprintf(cmd, "rm -rf temp_cpabe.cpabe");
			system(cmd);
			exit(1);
		}
		double timer; //bw;
		string downloadPath(argv[2]);
		downloadPath += ".d";
		FILE * fw = fopen(downloadPath.c_str(),"wb");
		timerStart(&timer);
		/* download stub first */

		decoderObj->init(argv[2]);
		decoderObj->setFilePointer(fw);
		decoderObj->setShareIDList(kShareIDList);

		/* start download procedure */
		downloaderObj->downloadFile(argv[2], namesize, n);
		/* see if download finished */
		decoderObj->indicateEnd();

		fclose(fw);
		delete downloaderObj;
		delete decoderObj;
		char cmd[256];
		sprintf(cmd, "rm -rf %s.stub.d", argv[2]);
		system(cmd);
		sprintf(cmd, "rm -rf cipher");
		system(cmd);
		sprintf(cmd, "rm -rf cipher.cpabe");
		system(cmd);
		sprintf(cmd, "rm -rf temp_cpabe.cpabe");
		system(cmd);
		free(buffer);
		free(chunkEndIndexList);
		free(secretBuffer);
		free(shareBuffer);
		free(kShareIDList);
		CryptoPrimitive::opensslLockCleanup();
		cout<<"temp file clean up, download end"<<endl;


	}
	


	if (strncmp(opt,"-r",2) == 0){

		if (argc != 6) {
			usage();
		}
		/* object initialization */
		/* full file name process */
		int namesize = 0;
		while(argv[2][namesize] != '\0'){
			namesize++;
		}
		namesize++;
		/*cpabe*/
		char* oldsk = argv[3];
		char* policy = argv[4];
		/* parse secure parameters */
		char* securesetting = argv[5];
		int securetype;
		if(strncmp(securesetting,"HIGH", 4) == 0) {
			securetype = HIGH_SEC_PAIR_TYPE;
		}
		else {

			if (strncmp(securesetting,"LOW", 4) == 0) {
				securetype = HIGH_SEC_PAIR_TYPE;
			}
			else {
				cerr<<"Securetype setting error!"<<endl;
				exit(1);
			}
		}
		int n, *kShareIDList;
		/* initialize openssl locks */
		if (!CryptoPrimitive::opensslLockSetup()) {

			printf("fail to set up OpenSSL locks\n");

			return 0;
		}

		confObj = new Configuration();

		n = confObj->getN(); //n -> data stores number

		kShareIDList = (int*)malloc(sizeof(int)*n);
		for (int i = 0; i < n; i++) {
			
			kShareIDList[i] = i;
		}

		decoderObj = new Decoder(n, securetype);
		downloaderObj = new Downloader(n,n,0,decoderObj,confObj);
		downloaderObj->downloadStub(argv[2],namesize);
		keyObj = new KeyEx(encoderObj, securetype, confObj->getkmIP(), confObj->getkmPort(), confObj->getServerConf(0), CHARA_MIN_HASH,VAR_SEG);
		if((keyObj->downloadFile(0, argv[2], namesize,oldsk)) == -1){
			char cmd[256];
			sprintf(cmd, "rm -rf cipher");
			system(cmd);
			sprintf(cmd, "rm -rf cipher.cpabe");
			system(cmd);
			sprintf(cmd, "rm -rf temp_cpabe.cpabe");
			system(cmd);
			char name[256];
			sprintf(name, "%s.stub", argv[2]);
			sprintf(cmd, "rm -rf %s",name);
			system(cmd);
			sprintf(name, "%s.stub.d", argv[2]);
			sprintf(cmd, "rm -rf %s",name);
			system(cmd);
			exit(0);
		}
		uploaderObj = new Uploader(n,n,0,confObj);
		encoderObj = new Encoder(n, securetype, uploaderObj);
		
		keyObj->readKeyFile("./keys/public.pem");
		keyObj->updateFileByPolicy(0, argv[2], namesize, oldsk,policy);
		uploaderObj->uploadStub(argv[2],namesize);
		char cmd[256];
		sprintf(cmd, "rm -rf cipher");
		system(cmd);
		sprintf(cmd, "rm -rf cipher.cpabe");
		system(cmd);
		sprintf(cmd, "rm -rf temp_cpabe.cpabe");
		system(cmd);
		char name[256];
		sprintf(name, "%s.stub", argv[2]);
		sprintf(cmd, "rm -rf %s",name);
		system(cmd);
		sprintf(name, "%s.stub.d", argv[2]);
		sprintf(cmd, "rm -rf %s",name);
		system(cmd);		
		cout << "rekey file over"<<endl;
	}
		

	if (strncmp(opt, "-k", 2) == 0){

		if (argc != 4) {
			usage();
		}
		char* policy = argv[2];
		char *skName = argv[3];
		cpabeKeygen(skName,policy);

		cout << "keygen over"<<endl;
	}


	return 0;
}
