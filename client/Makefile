CC=gcc
CFLAGS=-Wall -g -D_FILE_OFFSET_BITS=64
SRC=lib/*.c src/*.c main.c
HEADERS=lib/*.h src/*.h
PROGRAM=ndfs
LIBS=-lpthread
DIRECTORY=mount1

################################################################################

all: $(PROGRAM)

$(PROGRAM): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS) -o $(PROGRAM) $(SRC) `pkg-config fuse --cflags --libs` \
$(LIBS)

run:
	./$(PROGRAM) $(DIRECTORY)
runf:
	./$(PROGRAM) $(DIRECTORY) -f
runs:
	./$(PROGRAM) $(DIRECTORY) -f -s
umount:
	fusermount -u $(DIRECTORY)
	sudo umount $(DIRECTORY)

clean:
	rm -f $(PROGRAM) src/*~ src/*.o lib/*~ *~ *.o nul

install:
	sudo apt-get install libcurl4-gnutls-dev 
	sudo apt-get install libfuse-dev
	sudo apt-get install libssl-dev
	sudo apt-get install check

# print logs
n=10
pl:
	tac /var/log/syslog | grep ndfs\ started -B2000 -m1 | tac \
	| grep $(PROGRAM) | tail -n $(n)

plnotice:
	tac /var/log/syslog | grep ndfs\ started -B2000 -m1 | tac \
	| grep $(PROGRAM) | grep "<NOTICE>" | tail -n $(n)

plinfo:
	tac /var/log/syslog | grep ndfs\ started -B2000 -m1 | tac \
	| grep $(PROGRAM) | grep "<INFO>" | tail -n $(n)
plerror:
	tac /var/log/syslog | grep ndfs\ started -B2000 -m1 | tac \
	| grep $(PROGRAM) | grep "<ERROR>" | tail -n $(n)

pldebug:
	tac /var/log/syslog | grep ndfs\ started -B2000 -m1 | tac \
	| grep $(PROGRAM) | grep "<DEBUG>" | tail -n $(n)

################################################################################
# FLYMAKE (Emacs)

CHK_SOURCES=$(SRC)

check-syntax:
	$(CC) $(CFLAGS) -o nul -S ${CHK_SOURCES} $(LIBS)
################################################################################
# TESTS
LINK=-lrt -lpthread -lm -lcurl
SSL=`pkg-config fuse --cflags --libs` -lssl -lcrypto


c_file:
	checkmk test/code/test_file.check > test/code/test_file.c
	$(CC) -g -D_FILE_OFFSET_BITS=64 -I./src/  \
	test/code/test_file.c -lcheck -o test/code/test_file \
	$(LINK) $(SSL)

t_file:
	./test/code/test_file

c_helper:
	checkmk test/code/test_helper.check > test/code/test_helper.c
	$(CC) -g -D_FILE_OFFSET_BITS=64 -I./src/  \
	test/code/test_helper.c -lcheck -o test/code/test_helper \
	$(LINK) $(SSL)

t_helper:
	./test/code/test_helper

c_json:
	checkmk test/code/test_json.check > test/code/test_json.c
	$(CC) -std=c99 -g -D_FILE_OFFSET_BITS=64 -I./src/  \
	test/code/test_json.c -lcheck -o test/code/test_json \
	$(LINK) $(SSL)

t_json:
	./test/code/test_json


test:
	$(MAKE) c_file
	$(MAKE) c_helper
	$(MAKE) c_json
	$(MAKE) t_file
	$(MAKE) t_helper
	$(MAKE) t_json

.PHONY:	test
