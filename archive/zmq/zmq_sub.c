#include <zmq.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h> // Include for gettimeofday

typedef struct {
    long long timestamp;
    int rnti;
    int rb;
} MessageData;


int main(void) {
    void *context = zmq_ctx_new();
    void *subscriber = zmq_socket(context, ZMQ_SUB);
    
    int rc = zmq_connect(subscriber, "tcp://localhost:5555");
    if (rc != 0) {
        perror("zmq_connect failed");
        return -1;
    }
    
    zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, "", 0);

    while (1) {
	    int more = 1;
	    size_t more_size = sizeof(more);
    
	    while (more) {
            	zmq_msg_t message;
          	zmq_msg_init(&message);
        
        	// Receive a message from the publisher
        	int size = zmq_msg_recv(&message, subscriber,ZMQ_DONTWAIT);
       		if (size > 0) { 
        	// Assuming the message is a long long value representing microseconds
		MessageData* msgData = (MessageData*) zmq_msg_data(&message);
        
        	// Get current time in microseconds
        	struct timeval tv;
        	gettimeofday(&tv, NULL);
        	long long currentMicroseconds = (long long)tv.tv_sec * 1000000 + tv.tv_usec;

		printf("Subscribed: %lld, %lld, %lld\n", currentMicroseconds, msgData->timestamp, currentMicroseconds-msgData->timestamp);
        
		} else {
			more = 0;
		}
        
        	zmq_msg_close(&message);
		zmq_getsockopt(subscriber, ZMQ_RCVMORE, &more, &more_size);
	}

    	usleep(100000);
    }
    
    zmq_close(subscriber);
    zmq_ctx_destroy(context);
    
    return 0;
}

