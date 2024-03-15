/*
 * dba.h
 *
 *  Created on: Oct 25, 2023
 *      Author: bruce
 */

#ifndef EXAMPLES_SW_DBA_DBA_H_
#define EXAMPLES_SW_DBA_DBA_H_

#include <stdint.h>
#include <rte_pcapng.h>

#define NUM_MBUFS		8191
#define MBUF_CACHE_SIZE		250
#define BURST_SIZE		32

#define MAX_SUPPORTED_PORTS	10
#define MAX_SUPPORTED_TIBIT_PORTS 8 // 4 PFs and 4 VFs
#define MSG_ETH_PROTO 0xad3f
#define VLAN_ID 111

union sched_elem {
	struct {
		uint64_t time:24;
		uint64_t size:18;
		uint64_t link_id:10;
		uint64_t prio:4;
		uint64_t grant_type:2;
		uint64_t olt_port_id:6;
	};
	uint64_t val;
} __attribute__((packed));

struct cascading_group_msg {
	uint8_t group_id:7;  /* bits 0->6 */
	uint8_t version:1;   /* bit  7 */

	uint8_t source_port_id: 6;  /* bits 0->5 */
	uint8_t reserved:1;
	uint8_t sched_request:1;    /* bit 7 */

	uint32_t timestamp;

	union sched_elem sched_elems[4];

	uint32_t count;
} __attribute__((packed));

struct pkt_type_stats {
	uint64_t ip;
	uint64_t tibit;
	uint64_t other;
};

struct dba_stats {
	uint64_t sched_request_bcasts;
	uint64_t sched_request_replies;
	uint64_t sched_non_zero_replies;
	uint64_t sched_zero_replies;
	uint64_t sched_late_replies;
	uint64_t sched_late_zero_replies;
	uint64_t sched_late_non_zero_replies;
	uint64_t data_pkts_upstream;
	uint64_t data_pkts_downstream;

	struct pkt_type_stats port_types[RTE_MAX_ETHPORTS];
};
extern volatile struct dba_stats stats;
extern volatile int capture;
extern rte_pcapng_t *capture_hdl;

extern uint16_t ctrl_port, traf_port;
extern uint16_t tibit_ports[MAX_SUPPORTED_TIBIT_PORTS];
extern uint8_t tibit_ports_num;

extern struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

extern volatile uint16_t broadcast_interval_usec;

static const struct rte_ether_addr dba_addr = { .addr_bytes = {0x02} };
static const struct rte_ether_addr bcast_addr = { .addr_bytes = { [0 ... 5] = 0xff }};

extern int dba_telemetry_init(void);
extern int port_init(uint16_t port, struct rte_mempool *mbuf_pool);
extern void port_diag(uint16_t port);
extern struct rte_mbuf *create_bcast_message(struct rte_mempool *pool, uint32_t *c);
extern struct rte_mbuf *create_default_grant_override_response(
		struct rte_mempool *pool, uint32_t counter, uint32_t bw);
extern struct rte_mbuf *create_grant_override_response(struct rte_mempool *pool,
		uint32_t counter, union sched_elem *elems, uint32_t bw);

// CTI prototypes
extern int conv_rb_to_bw(uint16_t rb);
static int zmq_thread_handler(void *arg);


#endif /* EXAMPLES_SW_DBA_DBA_H_ */
