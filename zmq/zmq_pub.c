#include <zmq.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h> // Include for gettimeofday
#include <string.h>

typedef struct {
    long long timestamp;
    int rnti;
    int rb;
} MessageData;


int main(void) {
    void *context = zmq_ctx_new();
    void *publisher = zmq_socket(context, ZMQ_PUB);
    int rc = zmq_bind(publisher, "tcp://*:5555");
    if (rc != 0) {
        perror("zmq_bind failed");
        return -1;
    }

    while (1) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        long long microseconds = (long long)tv.tv_sec * 1000000 + tv.tv_usec;

	MessageData msgData;
	msgData.timestamp = microseconds;
	msgData.rnti = 123; // Example value
	msgData.rb = 456; // Example value

        zmq_msg_t message;
        zmq_msg_init_size(&message, sizeof(microseconds));
        memcpy(zmq_msg_data(&message), &msgData, sizeof(MessageData));
        zmq_msg_send(&message, publisher, 0);
        zmq_msg_close(&message);
        
        printf("Published: Timestamp %lld, RNTI %d, RB %d\n", msgData.timestamp, msgData.rnti, msgData.rb);
        sleep(1);
    }

    zmq_close(publisher);
    zmq_ctx_destroy(context);
    return 0;
}

