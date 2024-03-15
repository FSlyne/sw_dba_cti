/*
 * Telemetry related functions
 */
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_telemetry.h>

#include "dba.h"

#define INFO_CMD "/sw_dba/info"
#define STATS_CMD "/sw_dba/stats"
#define SET_SCHED_CMD "/sw_dba/set_bcast_interval_usec"
#define CAPTURE_CMD "/sw_dba/pcap_capture"
#define ADD_STAT(x) rte_tel_data_add_dict_uint(d, #x, stats.x)
#define ADD_NAMED_STAT(n, x) rte_tel_data_add_dict_uint(d, n, stats.x)

static int
dba_telemetry_set_capture(const char *cmd  __rte_unused,
		const char *param, struct rte_tel_data *d)
{
	static int capture_count;
	char pcap_name[32];

	if (param == NULL || strlen(param) == 0 || !isdigit(param[0]))
		return -1;

	snprintf(pcap_name, sizeof(pcap_name), "capture%u.pcap", capture_count++);
	const int fd = open(pcap_name, O_CREAT | O_WRONLY, 0664);
	if (fd < 0) {
		printf("Error opening file: %s\n", pcap_name);
		return -1;
	}
	capture_hdl = rte_pcapng_fdopen(fd, NULL, NULL, "sw_dba",
			"Capture of packets from SW DBA");
	rte_pcapng_add_interface(capture_hdl, upstream_port, NULL, "Upstream port", NULL);
	rte_pcapng_add_interface(capture_hdl, tibit_ports[0], NULL, "Tibit Port Q0", NULL);
	rte_pcapng_add_interface(capture_hdl, tibit_ports[1], NULL, "Tibit Port Q1", NULL);

	capture = atoi(param);
	while (capture > 0)
		usleep(1);

	rte_pcapng_close(capture_hdl);
	close(fd);
	rte_tel_data_string(d, "Done");
	return 0;
}

static int
dba_telemetry_set_bcast_interval(const char *cmd  __rte_unused,
		const char *param, struct rte_tel_data *d)
{
	if (param == NULL || strlen(param) == 0 || !isdigit(param[0]))
		return -1;
	broadcast_interval_usec = RTE_MAX(1, atoi(param));
	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_uint(d, "bcast_interval_usec", broadcast_interval_usec);
	return 0;
}

static int
dba_telemetry_info(const char *cmd, const char *param __rte_unused,
		struct rte_tel_data *d)
{
	rte_tel_data_start_dict(d);
	if (strcmp(cmd, INFO_CMD) == 0) {
		char portname[RTE_ETH_NAME_MAX_LEN];

		rte_tel_data_add_dict_uint(d, "bcast_interval_usec", broadcast_interval_usec);
		rte_tel_data_add_dict_uint(d, "upstream_port_id", upstream_port);
		rte_eth_dev_get_name_by_port(upstream_port, portname);
		rte_tel_data_add_dict_string(d, "upstream_port_name", portname);
		rte_tel_data_add_dict_uint(d, "downstream_port_id1", tibit_ports[1]);
		rte_eth_dev_get_name_by_port(tibit_ports[1], portname);
		rte_tel_data_add_dict_string(d, "downstream_port_name1", portname);


	} else if (strcmp(cmd, STATS_CMD) == 0){
		ADD_STAT(sched_request_bcasts);
		ADD_STAT(sched_request_replies);
		ADD_STAT(sched_non_zero_replies);
		ADD_STAT(sched_zero_replies);
		ADD_STAT(sched_late_replies);
		ADD_STAT(sched_late_zero_replies);
		ADD_STAT(sched_late_non_zero_replies);
		ADD_STAT(data_pkts_upstream);
		ADD_STAT(data_pkts_downstream);

		for (uint16_t i = 0; i < 3; i++) {
			char stat_name[32];
			char *port_names[] = {"Upstream", "XDP_Q0", "XDP_Q1"};
			snprintf(stat_name, sizeof(stat_name), "%s_IP_pkts", port_names[i]);
			ADD_NAMED_STAT(stat_name, port_types[i].ip);
			snprintf(stat_name, sizeof(stat_name), "%s_tibit_pkts", port_names[i]);
			ADD_NAMED_STAT(stat_name, port_types[i].tibit);
			snprintf(stat_name, sizeof(stat_name), "%s_other_pkts", port_names[i]);
			ADD_NAMED_STAT(stat_name, port_types[i].other);
		}
	} else
		return -1;
	return 0;
}

int
dba_telemetry_init(void)
{
	rte_telemetry_register_cmd(INFO_CMD, dba_telemetry_info,
			"Show info about the running sw_dba");
	rte_telemetry_register_cmd(STATS_CMD, dba_telemetry_info,
			"Show the stats about pkts and scheduling requests");
	rte_telemetry_register_cmd(SET_SCHED_CMD, dba_telemetry_set_bcast_interval,
			"Set the interval (in usec) between scheduling broadcasts");
	rte_telemetry_register_cmd(CAPTURE_CMD, dba_telemetry_set_capture,
			"Capture approx N packets to a pcap file. Parameter: N, number of packets");

	return 0;
}
