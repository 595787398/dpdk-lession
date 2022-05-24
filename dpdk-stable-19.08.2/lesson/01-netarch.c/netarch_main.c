

#define TIMER_RESOLUTION_CYCLES 120000000000ULL // 10ms * 1000 = 10s * 6
#define MBUF_NUMS	8191
#define ARP_PROTOCOL_TYPE 0x0806
int g_port_id = 0;

#define IP_STR_COVER_UINT(a, b, c, d) (a + (b << 8) + (c << 16) + (d << 24))

uint32 g_local_src_ip = IP_STR_COVER_UINT(192, 168, 1, 2);

char* mac2string_print(uint8_t *mac)
{
	static char buf[sizeof("HH:HH:HH:HH:HH:HH")];

	snprintf(buf, sizeof(buf) -1 ,"%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return buf;
}

/* src-mac | dst-mac | frame-type*/
int eth_packet_encap(uint8 *packet, uint8 *src_mac, uint8 *dst_mac, uint16_t ether_type)
{
	struct rte_ether_hdr *eth_packet = packet;

	rte_memcpy(eth_packet->d_addr.addr_bytes, dst_mac, sizeof(eth_packet->d_addr.addr_bytes)) ,

	rte_memcpy(eth_packet->s_addr.addr_bytes, src_mac, sizeof(eth_packet->s_addr.addr_bytes)) ,

	eth_packet->ether_type = htons(ether_type);

	return 0;
}

/*
	|arp
*/
int arp_packet_encap(uint8 *packet, uint8_t *src_mac, uint8_t *dst_mac,
	uint32_t src_ip, uint32_t dst_ip, uint16_t opcode)
{
	struct rte_arp_hdr *arp_packet = packet;

	arp_packet->arp_hardware = htons(1);
	arp_packet->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp_packet->arp_hlen = RTE_ETHER_ADDR_LEN;
	arp_packet->arp_plen = sizeof(uint16_t);
	arp_packet->arp_opcode = htons(opcode);

	rte_memcpy(arp_packet->arp_data.arp_sha.addr_bytes, src_mac, sizeof(arp_packet->arp_data.arp_sha.addr_bytes));
	rte_memcpy(arp_packet->arp_data.arp_tha.addr_bytes, dst_mac, sizeof(arp_packet->arp_data.arp_tha.addr_bytes));
	arp_packet->arp_data.arp_sip = src_ip;
	arp_packet->arp_data.arp_tip = dst_ip;

	return 0;
}

struct rte_mbuf * arp_reply_packet_encap(struct rte_mempool *mp, int port_id,
	struct rte_ether_addr *dst_mac, uint32_t src_ip, uint32_t dst_ip)
{
	int packet_len;
	struct rte_ether_addr src_mac;

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mp);
	if (!mbuf) {
		rte_exit(-1, "arp replcy packet malloc failed");
	}

	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	rte_eth_macaddr_get(port_id, &src_mac);
	eth_packet_encap(eth_hdr, &src_mac, dst_mac, RTE_ETHER_TYPE_ARP);

	/* arp */
	struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
	arp_packet_encap(arp_hdr, &src_mac, dst_mac, src_ip, dst_ip, RTE_ARP_OP_REPLY);

	return mbuf;
}

/* arp请求 */
static void arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim,
	   void *arg)
{
	int i;
	uint8 *packet;
	struct rte_ether_addr mac_addr;
	struct rte_mempool *mem_pool =  (struct rte_mempool *)arg;
	uint8_t arp_dst_mac[RTE_ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	rte_eth_macaddr_get(port_id, &mac_addr);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mem_pool);
	if (!mbuf) {
		rte_exit(-1, "pktmbuf alloc failed");
	}

	for (i = 1; i <= 254; i++) {

		packet = rte_pktmbuf_mtod(mbuf, (uint8 *));

		/* 构造以太网头 */
		eth_packet_encap(packet, mac_addr, arp_dst_mac, RTE_ETHER_TYPE_ARP);

		/*构造arp报文*/
		arp_request_packet_encap(packet + sizeof(struct rte_ether_hdr),
			mac_addr, arp_dst_mac, g_local_src_ip, IP_STR_COVER_UINT(192, 168, 1, i), RTE_ARP_OP_REQUEST);

		/* 发送报文 */
		rte_eth_tx_burst(port_id, 0, &packet, 1);

	}
}

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
};


/* 设定网口的收发包队列 */
static dpdk_eth_dev_init(struct rte_mempool * mp)
{
	uint16_t ports;
	struct rte_eth_dev_info dev_info;

	ports = rte_eth_dev_count_avail(void);
	if (ports == 0) {
		rte_exit(-1, "dev count failed");
	}


	rte_eth_dev_info_get(g_port_id, &dev_info);

	rte_eth_dev_configure(g_port_id, 1, 1, &port_conf_default);

	/*初始化rx*/
	if (rte_eth_rx_queue_setup(g_port_id, 0, 1024, rte_eth_dev_socket_id(g_port_id), NULL, mp) < 0) {
		rte_exit(-1, "rx init failed");
	}

	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.rxmode.offloads;

	if (rte_eth_tx_queue_setup(g_port_id, 0, , 1024, rte_eth_dev_socket_id(g_port_id), &txq_conf) < 0) {
		rte_exit(-1, "tx init failed");
	}

	if (rte_eth_dev_start(g_port_id) < 0) {
		rte_exit(-1, "tx init failed");
	}

}

int arp_packet_parse(struct rte_mbuf *rx_packet, struct rte_ether_addr *src_mac,
		struct rte_ether_addr *dst_mac, uint32_t *src_ip ,uint32_t *dst_ip)
{
	struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod_offset(rx_packet, sizeof(struct rte_ether_addr));

	rte_memcpy(src_mac, &arp_hdr->arp_data.arp_sha, sizeof(struct rte_ether_addr));
	rte_memcpy(dst_mac, &arp_hdr->arp_data.arp_tha, sizeof(struct rte_ether_addr));
	*src_ip = arp_hdr->arp_data.arp_sip;
	*dst_ip = arp_hdr->arp_data.arp_tip;

	return 0;
}

#define BRUST_SIZE 32
int main(int argc, char **argv)
{
	uint16_t i, recv_nums;
	struct rte_timer arp_timer;
	struct rte_mempool *mempool;
	struct rte_mbuf *rx_pkts[BRUST_SIZE];
	struct rte_ether_hdr *ether_hdr;
	struct rte_mbuf *tx_pkts[BRUST_SIZE];
	struct rte_ether_addr src_mac;
	struct rte_ether_addr dst_mac;
	uint32_t src_ip, dst_ip;

	if (rte_eal_init(argc, argv) < 0) {
		rte_exit(-1, "eal init failed");
	}

	mempool = rte_pktmbuf_pool_create("mbuf pool", MBUF_NUMS, 0,
		0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (!mempool) {
		rte_exit(-1, "eal pool create failed");
	}

	dpdk_eth_dev_init(mempool);

	/* 初始化定时器，用于arp 发送定时请求报文 */
	rte_timer_subsystem_init();
	rte_timer_init(&arp_timer);

	uint64_t hz = rte_get_timer_hz();
	unsigned int core_id = rte_lcore_id();
	rte_timer_reset(&arp_timer, hz, PERIODICAL, core_id, arp_request_timer_cb, mempool);

	while (1) {
		recv_nums = rte_eth_rx_burst(g_port_id, 0, rx_pkts, BRUST_SIZE);
		if (recv_nums >= BRUST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}

		for (i = 0; i < recv_nums; i++) {
			ether_hdr = rte_pktmbuf_mtod(rx_pkts[i], struct rte_ether_hdr *);
			//if (ether_hdr->ether_type)
			printf("ether type:%d\n", ether_hdr->ether_type);

			if (ether_hdr->ether_type == RTE_ETHER_TYPE_ARP) {
				arp_packet_parse(rx_pkts[i], &src_mac, &dst_mac, &src_ip, &dst_ip);
				printf("arp packet:[%s:%s]--->", mac2string_print(src_mac.addr_bytes), inet_ntoa(src_ip));
				printf("arp packet:[%s:%s]", mac2string_print(dst_mac.addr_bytes), inet_ntoa(dst_ip));
				struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod_offset(rx_pkts[i], sizeof(struct rte_ether_addr));

				if (arp_hdr->arp_opcode == RTE_ARP_OP_REQUEST) {
					/* 接收arp请求报文，并发送响应报文 */

					struct rte_mbuf * tx_packet = arp_reply_packet_encap(mempool, g_port_id,
						dst_mac, src_ip, dst_ip);

					rte_eth_tx_burst(g_port_id, 0, &tx_packet, 1);

				} else if (arp_hdr->arp_opcode == RTE_ARP_OP_REPLY) {
					/* 接收arp响应报文 */

				}
			}

			rte_pktmbuf_free(rx_pkts[i]);

		}

		/* 执行定时器 */
		uint64_t prve_tsc = 0;
		uint64_t curr_tsc = rte_rdtsc();
		if ((curr_tsc - prve_tsc) > TIMER_RESOLUTION_CYCLES) {
			//rte_timer_manage();
		}
	}

}
