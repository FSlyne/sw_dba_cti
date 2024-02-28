CC=gcc
CFLAGS=-I.
DEPS =
OBJ_PUB=zmq_pub.o
OBJ_SUB=zmq_sub.o
LIBS=-lzmq

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: zmq_pub zmq_sub

zmq_pub: $(OBJ_PUB)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

zmq_sub: $(OBJ_SUB)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f *.o *~ core zmq_pub zmq_sub

