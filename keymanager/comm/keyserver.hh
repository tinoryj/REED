/*
 * keyserver.hh
 */

#ifndef __SERVER_HH__
#define __SERVER_HH__

#include <arpa/inet.h>
#include <bits/stdc++.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/ssl.h"
#include <err.h>
#include <signal.h>
#include <sys/types.h>
#include <sysexits.h>

// client cerificate
#define CACRT "keys/sslKeys/ca-cert.pem"
#define SECRT "keys/sslKeys/server-cert.pem"
#define SEKEY "keys/sslKeys/server-key.pem"
// hash value size 256 bits
#define HASH_SIZE 32
// rsa size 1024 bits
#define RSA_LENGTH 128
// buffer size
#define BUFFER_SIZE (32 * 1024 * 1024)

using namespace std;

class KeyServer {

private:
    //port number
    int hostPort_;
    //server address struct
    struct sockaddr_in myAddr_;
    //receiving socket
    int hostSock_;
    //socket size
    socklen_t addrSize_;
    //client socket
    int* clientSock_;
    //socket address
    struct sockaddr_in sadr_;
    //thread ID
    pthread_t threadId_;
    // SSL context
    SSL_CTX* ctx_;

public:
    // SSL connection structure
    SSL* ssl_;
    // constructor
    KeyServer(int port);
    // destructor
    ~KeyServer();
    // main loop
    void runReceive();
    //	void* SocketHandler(void* lp);
};

#endif
