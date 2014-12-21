CC=gcc
CFLAGS=-Wall -g 
SRC=lib/*.c src/*.c main.c
HEADERS=lib/*.h src/*.h
PROGRAM=server
LIBS=-lpthread
DIRECTORY=filesystem

################################################################################

all: $(PROGRAM)

$(PROGRAM): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS) -o $(PROGRAM) $(SRC) $(LIBS)

run:
	./$(PROGRAM) $(DIRECTORY) 5555

clean:
	rm -f $(PROGRAM) src/*~ src/*.o lib/*~ *~ *.o nul

# print logs
n=10
pl:
	tac /var/log/syslog | grep server\ started -B2000 -m1 | tac \
	| grep $(PROGRAM) | tail -n $(n)

plnotice:
	tac /var/log/syslog | grep server\ started -B2000 -m1 | tac \
	| grep $(PROGRAM) | grep "<NOTICE>" | tail -n $(n)

plinfo:
	tac /var/log/syslog | grep server\ started -B2000 -m1 | tac \
	| grep $(PROGRAM) | grep "<INFO>" | tail -n $(n)
plerror:
	tac /var/log/syslog | grep server\ started -B2000 -m1 | tac \
	| grep $(PROGRAM) | grep "<ERROR>" | tail -n $(n)

pldebug:
	tac /var/log/syslog | grep server\ started -B2000 -m1 | tac \
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
