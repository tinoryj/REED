CC = g++
CFLAGS = -g -Wall -fno-operator-names -Wno-write-strings  -Wunreachable-code -Wshadow -DLINUX -std=c++0x
LIBS = -lcrypto -lssl -lpthread 
INCLUDES =-I./utils -I./lib/cryptopp -I./comm -I./coding -I./chunking -I./keyClient  
MAIN_OBJS = ./chunking/chunker.o ./utils/CryptoPrimitive.o ./coding/encoder.o ./comm/uploader.o ./utils/socket.o ./comm/downloader.o ./coding/decoder.o ./keyClient/exchange.o ./coding/aont.o ./utils/ssl.o

all: client
	$(shell ! test -d "keys/sk" && mkdir keys/sk)

%.o: %.cc %.hh
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

client: ./main.cc $(MAIN_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o CLIENT ./main.cc $(MAIN_OBJS) $(LIBS)

clean:
	@rm -f CLIENT
	@rm -f $(MAIN_OBJS)
	@rm -rf cache.db
	@rm -rf decoded_copy
	@rm -rf temp_cpabe.cpabe
	@rm -rf keys/sk
