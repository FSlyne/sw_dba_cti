/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdbool.h>

#include <rte_args.h> /* hard-code the arguments used */
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <zmq.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h> // Include for gettimeofday

#include "dba.h"

#define OVERRIDE_BW             5000 // 32789
#define CTRL_PORT		"0000:10:00.1"
#define TRAF_PORT		"0000:10:00.0"
#define ZMQ_DEBUG
// #define DEBUG
// #define CTI_STICKY
#define TRAF_MTU		3000
#define CTRL_BRIDGE		"lxdbr0" // Of container
#define ZMQ_BROKER		"127.0.0.1:5555" // host:port
//#define ZMQ_BROKER		"10.10.10.247:5558"


typedef struct {
    long long timestamp;
    int rnti;
    int rb;
} MessageData;

struct thread_args {
    struct rte_mempool *mbuf_pool;
    struct rte_ring *ring;
};

volatile uint16_t broadcast_interval_usec = 70;

volatile struct dba_stats stats;
volatile int capture;
rte_pcapng_t *capture_hdl;

uint16_t ctrl_port, traf_port;
uint16_t tibit_ports[MAX_SUPPORTED_TIBIT_PORTS];
uint8_t tibit_ports_num = 0;

struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

static inline void
get_headers(struct rte_mbuf *mb, struct rte_ether_hdr **ehdr,
		struct rte_vlan_hdr **vhdr,
		char **body,
		uint16_t *vlan_tag,
		uint16_t *ether_type)
{
	uint16_t etype;

	*ehdr = rte_pktmbuf_mtod(mb, void *);
	*body = (void *)&(*ehdr)[1];
	*vhdr = NULL;
	*vlan_tag = 0;
	etype = htons((*ehdr)->ether_type);

	if (etype == RTE_ETHER_TYPE_VLAN || etype == RTE_ETHER_TYPE_QINQ) {
		*vhdr = (void *)*body;
		*vlan_tag = htons((*vhdr)->vlan_tci) & 0xFFF;
		*body = (void *)&(*vhdr)[1];
		etype = htons((*vhdr)->eth_proto);
	}

	*ether_type = etype;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
 /* Basic forwarding application lcore. 8< */
static __rte_noreturn void
lcore_main(void *arg)
{
	struct thread_args *args = (struct thread_args *)arg;
	uint16_t port;
	uint16_t sched_resp = 0;
	int init_run = 0;
	union sched_elem elems[4] = {0};
	uint32_t cur_counter = 0; /* tracks current dba round */
	uint64_t next_broadcast = rte_get_timer_cycles();

	#ifdef ZMQ_BROKER
        void *context = zmq_ctx_new();
        void *subscriber = zmq_socket(context, ZMQ_SUB);

        int rc = zmq_connect(subscriber, "tcp://127.0.0.1:5555");
        if (rc != 0) {
           perror("zmq_connect failed");
           return -1;
        }  
	zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, "", 0);
	printf("Starting with ZMQ based CTI enabled\n");
	#endif 

	printf("Using physical traffic port %u\n", traf_port);
	printf("Using physical controller port %u\n", ctrl_port);
	printf("Using tibit 1 queue 0 %u\n", tibit_ports[0]);
	printf("Using tibit 1 queue 1 %u\n", tibit_ports[1]);
	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());

	uint16_t port_poll_order[] = {tibit_ports[0], tibit_ports[1], tibit_ports[0], traf_port, ctrl_port};
        //uint16_t port_poll_order[] = {tibit_ports[0], tibit_ports[1], traf_port, ctrl_port};

	int i =0;
	long bw =  OVERRIDE_BW;

	/* Main work of application loop. 8< */
	for (;;) {
		const uint64_t interval = rte_get_timer_hz() * broadcast_interval_usec / (1000 * 1000);
		const uint64_t now = rte_get_timer_cycles();

		if (now > next_broadcast) {

			if (init_run > 0) {
				#ifdef ZMQ_BROKER
    				struct rte_mbuf *mbuf;
    				if (rte_ring_dequeue(args->ring, (void **)&mbuf) != 0) {
					#ifndef CTI_STICKY
					bw = OVERRIDE_BW;
					bw=0;
					#endif
                                        #ifdef ZMQ_DEBUG
                                        //printf("override bw %d\n", bw);
                                        #endif

    				} else {
    					MessageData *msgData_buf = rte_pktmbuf_mtod(mbuf, MessageData *);
    					MessageData msgData;
    					rte_memcpy(&msgData, msgData_buf, sizeof(MessageData));
    					rte_pktmbuf_free(mbuf);
					bw=conv_rb_to_bw(msgData.rb);
					#ifdef ZMQ_DEBUG
					printf("received bw %d\n", bw);
					#endif
				}
				#else 
				bw = OVERRIDE_BW;
				#endif

				struct rte_mbuf *grant_response1 = NULL;
				if (sched_resp > 0) {
					/* Ignore scheduling replies and use an override grant */
					//struct rte_mbuf *grant_response1 = create_grant_response(pool, cur_counter, elems);
					grant_response1 = create_grant_override_response(args->mbuf_pool, cur_counter, elems, bw);
				} else {
					grant_response1 = create_default_grant_override_response(args->mbuf_pool, cur_counter, bw);
				}

				if (capture > 0) {
					struct rte_mbuf *cp = rte_pcapng_copy(tibit_ports[0], 0,
										grant_response1, args->mbuf_pool, UINT32_MAX, rte_rdtsc(),
										RTE_PCAPNG_DIRECTION_OUT, NULL);
					rte_pcapng_write_packets(capture_hdl, &cp, 1);
					capture--;
				}


				if (rte_eth_tx_burst(tibit_ports[0], 0, &grant_response1, 1) != 1)
					rte_pktmbuf_free(grant_response1);
			}

			uint32_t counter;
			struct rte_mbuf *bcast_message = create_bcast_message(args->mbuf_pool, &counter);
			cur_counter = counter;
			if (capture > 0) {
				struct rte_mbuf *cp = rte_pcapng_copy(tibit_ports[0], 0,
						bcast_message, args->mbuf_pool, UINT32_MAX, rte_rdtsc(),
						RTE_PCAPNG_DIRECTION_OUT, NULL);
				rte_pcapng_write_packets(capture_hdl, &cp, 1);
				capture--;

			}

			if (rte_eth_tx_burst(tibit_ports[0], 0, &bcast_message, 1) != 1)
				rte_pktmbuf_free(bcast_message);

			sched_resp = 0;
			init_run = 1;
			next_broadcast = next_broadcast + interval;

			stats.sched_request_bcasts++;

			/* flush out any unsent buffered packets */
			RTE_ETH_FOREACH_DEV(port)
				rte_eth_tx_buffer_flush(port, 0, tx_buffer[port]);
		}

		for (uint16_t i = 0; i < RTE_DIM(port_poll_order); i++) {

			port = port_poll_order[i];
			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
			
			if (unlikely(nb_rx == 0)) {
				continue;
			}

			uint16_t forwarded = nb_rx;

			if (capture > 0) {
				struct rte_mbuf *cp[BURST_SIZE];
				uint16_t n = RTE_MIN(nb_rx, capture);
				uint64_t tsc = rte_rdtsc();

				for (uint16_t i = 0; i < n; i++)
					cp[i] = rte_pcapng_copy(port, 0, bufs[i], args->mbuf_pool, UINT32_MAX,
							tsc, RTE_PCAPNG_DIRECTION_IN, NULL);
				rte_pcapng_write_packets(capture_hdl, cp, n);

				capture -= n;
			}

			for (uint16_t i = 0; i < nb_rx; i++) {
				struct rte_ether_hdr *ehdr;
				struct rte_vlan_hdr *vhdr;
				char *body;
				uint16_t vlan_tag;
				uint16_t etype;
				char dst_address[18] = {0};
				char src_address[18] = {0};


				get_headers(bufs[i], &ehdr, &vhdr, &body, &vlan_tag, &etype);
				snprintf(dst_address, sizeof(dst_address), RTE_ETHER_ADDR_PRT_FMT,
						RTE_ETHER_ADDR_BYTES(&ehdr->dst_addr));

				snprintf(src_address, sizeof(src_address), RTE_ETHER_ADDR_PRT_FMT,
						RTE_ETHER_ADDR_BYTES(&ehdr->src_addr));

				/* Options based on ethertype
				 * ARP request and response between traf port and tibit
				 * IPv4 and IPv6 between traf port and tibit
				 * 0xad3f tibit scheduling between tibit and ctrl port
				 * 0xa8c8 control plane message between tibit and ctrl port
				 */


				switch (etype) {
				case RTE_ETHER_TYPE_IPV4: 
				case RTE_ETHER_TYPE_IPV6:
					stats.port_types[port].ip++;
					if (port == traf_port) {
						#ifdef DEBUG
						printf("IP traf to tibit\n");
						#endif
						rte_eth_tx_buffer(tibit_ports[0], 0, tx_buffer[tibit_ports[0]], bufs[i]);
					} else if (port == tibit_ports[0]) {
						#ifdef DEBUG
						printf("IP tibit 0 to traf\n");
						#endif
						rte_eth_tx_buffer(traf_port, 0, tx_buffer[traf_port], bufs[i]);
                                        } else if (port == tibit_ports[1]) {
						#ifdef DEBUG
                                                printf("IP tibit 1 to traf\n");
						#endif
                                                rte_eth_tx_buffer(traf_port, 0, tx_buffer[traf_port], bufs[i]);
					} else {
						#ifdef DEBUG
						printf("IP traffic from port %d\n", port);
						#endif 
						rte_eth_tx_buffer(port, 0, tx_buffer[traf_port], bufs[i]);
					}
					break;

                                case RTE_ETHER_TYPE_ARP:
                                        stats.port_types[port].ip++;
                                        if (port == traf_port) {
						#ifdef DEBUG
                                                printf("arp traf to tibit\n");
						#endif 
                                                rte_eth_tx_buffer(tibit_ports[0], 0, tx_buffer[tibit_ports[0]], bufs[i]);
                                        } else if (port == tibit_ports[0]) {
						#ifdef DEBUG
                                                printf("arp tibit 0 to traf\n");
						#endif
                                               rte_eth_tx_buffer(traf_port, 0, tx_buffer[traf_port], bufs[i]);
                                        } else if (port == tibit_ports[1]) {
						#ifdef DEBUG
                                                printf("arp tibit 1 to traf\n");
						#endif
                                                rte_eth_tx_buffer(traf_port, 0, tx_buffer[traf_port], bufs[i]);
                                        } else {
						#ifdef DEBUG
                                                printf("arp traffic from port %d\n", port);
						#endif
						rte_eth_tx_buffer(port, 0, tx_buffer[traf_port], bufs[i]);
                                        }
                                        break;


				case MSG_ETH_PROTO:
					stats.port_types[port].tibit++;
					forwarded--;
					if (vlan_tag != VLAN_ID) {
						printf("Got request with invalid vlan tag %u(%x) not %u(%x)\n",
								vlan_tag, vlan_tag, VLAN_ID, VLAN_ID);
						break;
					}
					stats.sched_request_replies++;

					/* send back request as reply */
					rte_ether_addr_copy(&dba_addr, &ehdr->src_addr);
					rte_ether_addr_copy(&bcast_addr, &ehdr->dst_addr);
					struct cascading_group_msg *cgm = (void *)body;
					uint32_t olt_count = ntohl(cgm->count);
					if (olt_count != cur_counter) {
						#ifdef DEBUG
						printf("Got request with invalid count number %u(%x) not %u(%x)\n",
						       olt_count , olt_count , cur_counter, cur_counter);
						#endif
						stats.sched_late_replies++;
						if (cgm->sched_elems[0].val != 0)
							stats.sched_late_non_zero_replies++;
						else
							stats.sched_late_zero_replies++;

						rte_pktmbuf_free(bufs[i]);
						continue; // process next packet
					} else {
						sched_resp++;
					}

					cgm->source_port_id = 0;
					cgm->timestamp = htonl(ntohl(cgm->timestamp) + 50);
					if (cgm->sched_elems[0].val != 0)
						stats.sched_non_zero_replies++;
					else
						stats.sched_zero_replies++;

					/* Copy all scheduling elements from first OLT
					 * if populated.
					 */
					memcpy(elems, cgm->sched_elems, sizeof(elems));
					rte_pktmbuf_free(bufs[i]);
					continue; // process next packet
					break;

				case 0xa8c8:
					#ifdef DEBUG
					// printf("ctrl plane\n");
					#endif
					stats.port_types[port].other++;
					if (port == ctrl_port) {
						rte_eth_tx_buffer(tibit_ports[0], 0, tx_buffer[tibit_ports[0]], bufs[i]);
					} else if (port == tibit_ports[0]){
						rte_eth_tx_buffer(ctrl_port, 0, tx_buffer[ctrl_port], bufs[i]);
                                        } else if (port == tibit_ports[1]){
                                                rte_eth_tx_buffer(ctrl_port, 0, tx_buffer[ctrl_port], bufs[i]);
					} else {
						printf("unexpected 0xa8c8 port %d\n", port);
					}
					break;

				default:
                                        stats.port_types[port].ip++;
                                        if (port == traf_port) {
						#ifdef DEBUG
						printf("default: traf_port to tibit etype %x\n", etype);
						#endif
                                                rte_eth_tx_buffer(tibit_ports[0], 0, tx_buffer[tibit_ports[0]], bufs[i]);
                                        } else {
						#ifdef DEBUG
						printf("default: tibit to traf_port etype %x\n", etype);
						#endif
                                                rte_eth_tx_buffer(traf_port, 0, tx_buffer[traf_port], bufs[i]);
                                        }
                                        break;

				}
			} /* end foreach nb_rx packets */

			if (port == ctrl_port || port == traf_port)
				/* we received from upstream so sent downstream */
				stats.data_pkts_downstream += forwarded;
			else
				/* otherwise received from downstream so sent up */
				stats.data_pkts_upstream += forwarded;
		} /* end foreach port */
	} /* >8 End of main for(;;) loop. */
}
/* >8 End Basic forwarding application lcore. */

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;
	uint16_t discovered_ports[MAX_SUPPORTED_PORTS];
	uint16_t discovered_ports_idx = 0;
	char af_xdp0_arg[128];
	char af_xdp1_arg[128];

	struct rte_ring *zmq_ring;
	struct rte_mempool *zmq_mbuf_pool;

	if (argc != 2) {
                fprintf(stderr, "Error: Need parameter for AF_XDP device with device name and two queue numbers, e.g. eth0,0,1\n");
                return 1;
        }

        char *iface_name = strtok(argv[1], ",");
        char *queue1_num = strtok(NULL, ",");
        if (queue1_num == NULL)
                queue1_num = "0";
        char *queue2_num = strtok(NULL, ",");
        if (queue2_num == NULL)
                queue2_num = "1";

        snprintf(af_xdp0_arg, RTE_DIM(af_xdp0_arg), "--vdev=net_af_xdp0,iface=%s,start_queue=%s",
                        iface_name, queue1_num);

        snprintf(af_xdp1_arg, RTE_DIM(af_xdp1_arg), "--vdev=net_af_xdp1,iface=%s,start_queue=%s",
                        iface_name, queue2_num);

	/* TODO - add proper args parsing here */
	struct rte_args *args = rte_args_create(argc, argv);
	if (!rte_args_has_arg(args, "-l") && !rte_args_has_arg(args, "-c"))
		rte_args_add_list(args, 2, "-l", "0-1");
	if (!rte_args_has_arg(args, "--in-memory") && !rte_args_has_arg(args, "--no-huge"))
		rte_args_add(args, "--in-memory");

	
	// @note For now only single port works with on NIC filtering
	// @note port configuration required:
	// ethtool -L ens6f0 combined 2
	// ethtool -K ens6f0 receive-hashing off
	// ethtool -N ens6f0 flow-type ip4 action 1
	// ethtool -N ens6f0 flow-type udp4 action 1
	// ethtool -N ens6f0 flow-type tcp4 action 1

	// ONU port 0 - Tibit 1
	// rte_args_add(args, "--vdev=net_af_xdp0,iface=ens6f0,start_queue=0");
	// rte_args_add(args, "--vdev=net_af_xdp1,iface=ens6f0,start_queue=1");
	rte_args_add(args, af_xdp0_arg);
	rte_args_add(args, af_xdp1_arg);
	rte_args_add(args, "--vdev=net_tap0,iface=tap0");

	printf("Initializing EAL with args:\n ");
	for (int i = 0; i < rte_args_get_argc(args); i++)
		printf(" '%s'%c", rte_args_get_argv(args, NULL)[i],
				i < rte_args_get_argc(args) - 1 ? ',' : '\n');
	int ret = rte_args_eal_init(args);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	#ifdef DEBUG
	RTE_ETH_FOREACH_DEV(portid) {
		port_diag(portid);
	}
	#endif

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	printf("***\n The number of ports is %u\n ", nb_ports);
	if (nb_ports != 5)
		rte_exit(EXIT_FAILURE, "This app is build to use 4 ports. 2 physical ports to (a) ctrl (b) traffic and 2 af_xdp ports\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid) {
		if (port_init(portid, mbuf_pool) != 0) {
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);
		} else {
			// Save info on each initialiesd port to figure out Upstream and Tibit ports
			discovered_ports[discovered_ports_idx] = portid;
			discovered_ports_idx++;
		}
	}

	int status;
	char cmd[256];

        // Check if the bridge exists
        snprintf(cmd, sizeof(cmd), "ip link show %s > /dev/null 2>&1", CTRL_BRIDGE);
        status = system(cmd);
	if (status != 0) {
	      fprintf(stderr, "Error: Bridge '%s' does not exist.\n", CTRL_BRIDGE);
	      return EXIT_FAILURE;
	}
        // Attempt to bind tap0 to the bridge
    	snprintf(cmd, sizeof(cmd), "ip link set dev tap0 master %s", CTRL_BRIDGE);
        status = system(cmd);
        if (status != 0) {
	      fprintf(stderr, "Error: Failed to bind 'tap0' to '%s'.\n", CTRL_BRIDGE);
              return EXIT_FAILURE;
        }
	printf("Successfully bound 'tap0' to '%s'.\n", CTRL_BRIDGE);
	
	// Identify port funcion
	printf("\n\nEnumerating ports\n");
	tibit_ports_num = 0;

	for (uint8_t i = 0; i < discovered_ports_idx; i++) {
		uint16_t port = discovered_ports[i];
		uint16_t mtu;
		struct rte_eth_dev_info dev_info;
		char portname[RTE_ETH_NAME_MAX_LEN];

		rte_eth_dev_info_get(port, &dev_info);
		rte_eth_dev_get_name_by_port(port, portname);

		if (strncmp(portname, CTRL_PORT, 12) == 0) {
			// to ctrl port 
			printf("Assigning Controller port [%d] to %s\n", port, portname);
			ctrl_port = port;
		} else if (strncmp(portname, TRAF_PORT,12) == 0) {
			// to traffic port
			rte_eth_dev_stop(port);
			rte_eth_dev_set_mtu(port, TRAF_MTU);
			rte_eth_dev_start(port);
			rte_eth_dev_get_mtu(port, &mtu);
			printf("Assigning Traffic port [%d] to %s with MTU %d\n", port, portname, mtu);
			traf_port = port;
		} else if (strncmp(portname, "net_af_xdp", 10) == 0) {
			// Tibit Ports
			// @note needs better way to group tibit queue 0 and queue 1 for clear distinction in a
			// multi Tibit environment, for now with single Tibit, port 0 is q 0 port 1 g 1
			rte_eth_dev_stop(port);
			rte_eth_dev_set_mtu(port, TRAF_MTU);
			rte_eth_dev_start(port);
			rte_eth_dev_get_mtu(port, &mtu);
			printf("Assigning Tibit port %d [%d] to %s with MTU %d\n", tibit_ports_num, port, portname, mtu);
			printf(".. with Rx queues: %d, Tx queues: %d\n", dev_info.nb_rx_queues, dev_info.nb_tx_queues);
			tibit_ports[tibit_ports_num] = port;	
			tibit_ports_num++;
		} else if (strncmp(portname, "net_tap0",8)== 0) {
			printf("Assigning Net Tap port 0 [%d] to %s\n", port, portname);
			ctrl_port=port;
		}
	}

	#ifdef ZMQ_BROKER

        /* Creates a new mempool in memory to hold the zmq mbufs. */
        zmq_mbuf_pool = rte_pktmbuf_pool_create("ZMQ_MBUF_POOL", NUM_MBUFS, 
                MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        if (zmq_mbuf_pool == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create zmq mbuf pool\n");

	zmq_ring = rte_ring_create("ZMQ_RING", 1024, rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (zmq_ring == NULL)
    		rte_exit(EXIT_FAILURE, "Failed to create ring\n");

	int lcore_id = rte_get_next_lcore(-1, 1, 0);
	struct thread_args args2;
	args2.mbuf_pool = zmq_mbuf_pool;
	args2.ring = zmq_ring;
	if (lcore_id == RTE_MAX_LCORE) {
    	     fprintf(stderr, "No available lcore found.\n");
        } else if (rte_eal_remote_launch(zmq_thread_handler, &args2, lcore_id) != 0) {
             fprintf(stderr, "Could not launch thread on lcore %u\n", lcore_id);
        }

	#endif

        dba_telemetry_init();

	struct thread_args args3;
        args3.mbuf_pool = mbuf_pool;
        args3.ring = zmq_ring;
	lcore_main(&args3);

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}

static int zmq_thread_handler(void *arg) {
       struct thread_args *args = (struct thread_args *) arg;
       void *context = zmq_ctx_new();
       void *subscriber = zmq_socket(context, ZMQ_SUB);


        char zmq_broker[256];
        // Check if the bridge exists
        snprintf(zmq_broker, sizeof(zmq_broker), "tcp://%s", ZMQ_BROKER);

       int rc = zmq_connect(subscriber, zmq_broker);
       if (rc != 0) {
          perror("zmq_connect failed");
          return -1;
       }
       zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, "", 0);

       // logic for ranging of ONU. Use ZMQ to delay request and grant.

       // expect one request, but loop stale requests
       while (1 > 0 ) {
	      int more = 1;
	      size_t more_size = sizeof(more);
              while (more) {
                    zmq_msg_t message;
                    zmq_msg_init(&message);

                    // Receive a message from the CTI message bus
                    int size = zmq_msg_recv(&message, subscriber,ZMQ_DONTWAIT);
                    // int size =0;
                    if (size > 0) {
                          // Assuming the message is a long long value representing microseconds
                          MessageData* msgData = (MessageData*) zmq_msg_data(&message);
                          // Get current time in microseconds
                          struct timeval tv;
                          gettimeofday(&tv, NULL);
                          long long currentMicroseconds = (long long)tv.tv_sec * 1000000 + tv.tv_usec;
                          // printf("Timestamps: %lld, %lld, %lld\n", currentMicroseconds, msgData->timestamp, currentMicroseconds-msgData->timestamp);
                          //printf("Received: Timestamp %lld, RNTI %d, RB %d\n", msgData->timestamp, msgData->rnti, msgData->rb);

			struct rte_mbuf *mbuf = rte_pktmbuf_alloc(args->mbuf_pool);
			if (mbuf == NULL) {
    				printf("zmq mbuf allocation failure\n");
    				return; // Exit or handle the error appropriately
			}			

			// Ensure there's enough space in the mbuf for MessageData
			MessageData* data_ptr = (MessageData*)rte_pktmbuf_append(mbuf, sizeof(MessageData));
			if (data_ptr == NULL) {
    				// Handle insufficient space in mbuf
    				rte_pktmbuf_free(mbuf);
    				return; // Exit or handle the error appropriately
			}

			// Copy the populated MessageData into the mbuf
			rte_memcpy(data_ptr, msgData, sizeof(MessageData));

			// enqueue the mbuf to the ring
			if (rte_ring_enqueue(args->ring, mbuf) != 0) {
    				// Enqueue failed, the ring might be full
    				printf("Failed to enqueue mbuf to ring\n");
    				rte_pktmbuf_free(mbuf);
    				return; // Exit or handle the error appropriately
			}
                     } else {
                          more = 0;
                     }
             zmq_msg_close(&message);
             zmq_getsockopt(subscriber, ZMQ_RCVMORE, &more, &more_size);
             }
       // rte_delay_us_block(100);
       usleep(100);
       }
       return 0;
}


