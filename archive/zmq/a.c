#include <zmq.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main()
{
    void *context = zmq_ctx_new();
    void *subscriber = zmq_socket(context, ZMQ_SUB);
    int rc = zmq_connect(subscriber, "tcp://192.168.53.11:5554");
    assert(rc == 0);
    zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, "", 0);

    char message[15] = "";

    while(1)
    {
        zmq_msg_t msg;
        zmq_msg_init(&msg);
        zmq_msg_recv(subscriber, &msg, 0);
        int size = zmq_msg_size(&msg);
        memcpy(message, zmq_msg_data(&msg), size);
        zmq_msg_close(&msg);
        printf("%s\n", message);
    }

    zmq_close(subscriber);
    zmq_ctx_destroy(context);

    return 0;
}
