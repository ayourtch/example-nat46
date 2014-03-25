CC=gcc
CFLAGS=-Wall -I..
LDFLAGS=-L .. -lay -lpcap

OBJECTS=example-nat46.o nat46-core.o nat46-glue.o
SOURCE=example-nat46.c nat46-core.c nat46-glue.c


example-pcap: $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o example-nat46 $(LDFLAGS)

all:example-nat46

.PHONY: clean
clean:
	rm -f *~ *.o example-nat46

