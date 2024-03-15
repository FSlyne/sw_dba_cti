/*
 * message_gen.c
 *
 *  Created on: Oct 25, 2023
 *      Author: bruce
 */

#include <byteswap.h>

#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_hexdump.h>

#include "dba.h"

#define OVERRIDE_BW		32768
//#define OVERRIDE_BW		16384
#define OVERRIDE_GRANT_TYPE	1

struct rte_mbuf *
create_bcast_message(struct rte_mempool *pool, uint32_t *c)
{
	static const uint16_t priority = 7;
	static uint64_t tsc_khz;
	static int printed;
	static int counter;

	if (tsc_khz == 0)
		tsc_khz = rte_get_timer_hz() / 1000;

	struct rte_mbuf *msg = rte_pktmbuf_alloc(pool);
	if (msg == NULL)
		rte_exit(EXIT_FAILURE, "Error allocating packet buffer [counter = %d]\n",
				counter);

	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(msg, void *);
	struct rte_vlan_hdr *vlan = (void *)&eth[1];
	struct cascading_group_msg *body = (void *)&vlan[1];
	*body = (struct cascading_group_msg){0};

	/* set payload size */
	rte_pktmbuf_append(msg, sizeof(*eth) + sizeof(*vlan) + sizeof(*body));

	rte_ether_addr_copy(&bcast_addr, &eth->dst_addr);
	rte_ether_addr_copy(&dba_addr, &eth->src_addr);
	eth->ether_type = htons(RTE_ETHER_TYPE_QINQ);
	vlan->vlan_tci = htons((priority << 13) | VLAN_ID);
	vlan->eth_proto = htons(MSG_ETH_PROTO);
	body->group_id = 1;
	body->sched_request = 1;
	body->timestamp = htonl((uint32_t)(rte_rdtsc() * 62500 / tsc_khz));
	body->count = htonl(counter);
	if (!printed) {
		rte_hexdump(stdout, "Broadcast packet",
				rte_pktmbuf_mtod(msg, void *), msg->data_len);
		printed = 1;
	}
	*c = counter++;
	return msg;
}

struct rte_mbuf *
create_default_grant_override_response(struct rte_mempool *pool, uint32_t counter, uint32_t bw)
{
	static const uint16_t priority = 7;
	static uint64_t tsc_khz;
	static int printed;
	static union sched_elem override_elems[4] = {0};

	if (tsc_khz == 0)
		tsc_khz = rte_get_timer_hz() / 1000;

	struct rte_mbuf *msg = rte_pktmbuf_alloc(pool);
	if (msg == NULL)
		rte_exit(EXIT_FAILURE, "Error allocating packet buffer [counter = %d]\n",
			counter);

	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(msg, void *);
	struct rte_vlan_hdr *vlan = (void *)&eth[1];
	struct cascading_group_msg *body = (void *)&vlan[1];
	*body = (struct cascading_group_msg){0};
	struct cascading_group_msg *cgm = (void *)body;

	/*
	 * Grant type : 1 (Best Effort)
	 * Grant type 3: Unsolicited  not supported
	 */
	override_elems[0].grant_type = OVERRIDE_GRANT_TYPE;

	/* Set payload size to 20K */
	override_elems[0].size = bw;

	override_elems[0].link_id = 130;

	override_elems[0].olt_port_id = 1;

	override_elems[0].prio = 0;

	cgm->sched_elems[0].val = bswap_64(override_elems[0].val);

	/* set payload size */
	rte_pktmbuf_append(msg, sizeof(*eth) + sizeof(*vlan) + sizeof(*body));

	rte_ether_addr_copy(&bcast_addr, &eth->dst_addr);
	rte_ether_addr_copy(&dba_addr, &eth->src_addr);
	eth->ether_type = htons(RTE_ETHER_TYPE_QINQ);
	vlan->vlan_tci = htons((priority << 13) | VLAN_ID);
	vlan->eth_proto = htons(MSG_ETH_PROTO);
	body->group_id = 1;
	body->sched_request = 0;
	body->timestamp = htonl((uint32_t)(rte_rdtsc() * 62500 / tsc_khz));
	body->count = htonl(counter);
	if (!printed) {
		rte_hexdump(stdout, "Broadcast packet",
				rte_pktmbuf_mtod(msg, void *), msg->data_len);
		printed = 1;
	}
	return msg;
}

struct rte_mbuf *
create_grant_override_response(struct rte_mempool *pool, uint32_t counter, union sched_elem *elems, uint32_t bw)
{
	static const uint16_t priority = 7;
	static uint64_t tsc_khz;
	static int printed;
	static union sched_elem override_elems[4] = {0};

	if (tsc_khz == 0)
		tsc_khz = rte_get_timer_hz() / 1000;

	struct rte_mbuf *msg = rte_pktmbuf_alloc(pool);
	if (msg == NULL)
		rte_exit(EXIT_FAILURE, "Error allocating packet buffer [counter = %d]\n",
								counter);

	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(msg, void *);
	struct rte_vlan_hdr *vlan = (void *)&eth[1];
	struct cascading_group_msg *body = (void *)&vlan[1];
	*body = (struct cascading_group_msg){0};
	struct cascading_group_msg *cgm = (void *)body;

	/* Construct over-ride elements - for max upstream traffic */

	if (elems[0].val != 0) { /* at least one element should have been provided in OLT reply */

		memcpy(&override_elems[0], &elems[0], sizeof(override_elems[0]));

		override_elems[0].val = bswap_64(override_elems[0].val);
		/*
		 * Grant type : 1 (Best Effort)
		 * Grant type 3: Unsolicited  not supported
		 */
		//override_elems[0].grant_type = OVERRIDE_GRANT_TYPE;

		/* Set payload size to 32786 bytes */
		override_elems[0].size = bw;

		cgm->sched_elems[0].val = bswap_64(override_elems[0].val);
	}

	if (elems[1].val != 0) {
		memcpy(&override_elems[1], &elems[1], sizeof(override_elems[1]));

		override_elems[1].val = bswap_64(override_elems[1].val);
		/*
		 * Grant type : 1 (Best Effort)
		 * Grant type 3: Unsolicited  not supported
		 */
		//override_elems[1].grant_type = OVERRIDE_GRANT_TYPE;

		/* Set payload size to 32786 bytes */
		override_elems[1].size = bw;

		cgm->sched_elems[1].val = bswap_64(override_elems[1].val);
	}

	if (elems[2].val != 0) {
		memcpy(&override_elems[2], &elems[2], sizeof(override_elems[2]));
		override_elems[2].val = bswap_64(override_elems[2].val);
		/*
		 * Grant type : 1 (Best Effort)
		 * Grant type 3: Unsolicited  not supported
		 */
		//override_elems[2].grant_type = OVERRIDE_GRANT_TYPE;

		/* Set payload size to 32786 bytes */
		override_elems[2].size = bw;

		/* Fill up any empty scheduling elements */
		if (cgm->sched_elems[0].val == 0)
			cgm->sched_elems[0].val = bswap_64(override_elems[2].val);
		else if (cgm->sched_elems[1].val == 0)
			cgm->sched_elems[1].val = bswap_64(override_elems[2].val);
		else
			cgm->sched_elems[2].val = bswap_64(override_elems[2].val);
	}

	if (elems[3].val != 0) {
		memcpy(&override_elems[3], &elems[3], sizeof(override_elems[3]));
		override_elems[3].val = bswap_64(override_elems[3].val);
		/*
		 * Grant type : 1 (Best Effort)
		 * Grant type 3: Unsolicited  not supported
		 */
		//override_elems[3].grant_type = OVERRIDE_GRANT_TYPE;

		/* Set payload size to 32786 bytes */
		override_elems[3].size = bw;

		if (cgm->sched_elems[1].val == 0)
			cgm->sched_elems[1].val = bswap_64(override_elems[3].val);
		else
			cgm->sched_elems[3].val = bswap_64(override_elems[3].val);
	}

	/* set payload size */
	rte_pktmbuf_append(msg, sizeof(*eth) + sizeof(*vlan) + sizeof(*body));

	rte_ether_addr_copy(&bcast_addr, &eth->dst_addr);
	rte_ether_addr_copy(&dba_addr, &eth->src_addr);
	eth->ether_type = htons(RTE_ETHER_TYPE_QINQ);
	vlan->vlan_tci = htons((priority << 13) | VLAN_ID);
	vlan->eth_proto = htons(MSG_ETH_PROTO);
	body->group_id = 1;
	body->sched_request = 0;
	body->timestamp = htonl((uint32_t)(rte_rdtsc() * 62500 / tsc_khz));
	body->count = htonl(counter);
	if (!printed) {
		rte_hexdump(stdout, "Broadcast packet",
					rte_pktmbuf_mtod(msg, void *), msg->data_len);
		printed = 1;
	}
	return msg;
}

// convert 5GNR resource blocks to PON bandwidth bytes
int conv_rb_to_bw(uint16_t rb)
{
	return rb;
}
