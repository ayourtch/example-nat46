all: example-nat46 test-nat46-core test
CC=gcc
CFLAGS=-Wall -I.. -g -Wno-unused-function
LDFLAGS=-L .. -lay -lpcap

OBJECTS=example-nat46.o nat46-core.o nat46-glue.o
SOURCE=example-nat46.c nat46-core.c nat46-glue.c

TEST_OBJS=test-nat46-core.o nat46-core.o nat46-glue.o

example-nat46: $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o example-nat46 $(LDFLAGS)

test-nat46-core: $(TEST_OBJS)
	$(CC) $(CFLAGS) $(TEST_OBJS) -o test-nat46-core $(LDFLAGS)

gen-test: test-nat46-core
	./test-nat46-core 2>result-test-nat46-core.txt

test: gen-test
	diff -c result-test-nat46-core-saved.txt result-test-nat46-core.txt

test-save: gen-test
	rm -f result-test-nat46-core-saved.txt
	mv result-test-nat46-core.txt result-test-nat46-core-saved.txt

.PHONY: clean
clean:
	rm -f *~ *.o example-nat46

