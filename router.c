//woerking laSt one 22:40 15 apr

#include <queue.h>
#include "skel.h"

#define INIT_ARP_TABLE_CAPACITY 50
#define MAX_ADDR_STRING_LEN 17		// xxx.xxx.xxx.xxx\0

// DATA STRUCTURES ---------------------------------------------------------------------------------------

struct route_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

struct trie_node
{
	struct trie_node *l;
	struct trie_node *r;
	struct route_entry *route;
};

struct arp_entry {
	uint32_t ip;
	uint8_t mac[ETH_ALEN];
};

struct arp_table {
	struct arp_entry **entries;
	uint32_t size;
	uint32_t capacity;
};

struct enqueued_packet
{ // struct that is added to the router queue
	packet *m;
	struct route_entry *route;
};

// HELPER FUNCTIONS --------------------------------------------------------------------------------------

// Returns the IP of given interface as an integer
// (The skel function, but without the inet_ntoa conversion)
uint32_t get_interface_ip_int32(int interface)
{
	struct ifreq ifr;
	if (interface == 0)
		sprintf(ifr.ifr_name, "rr-0-1");
	else {
		sprintf(ifr.ifr_name, "r-%u", interface - 1);
	}
	ioctl(interfaces[interface], SIOCGIFADDR, &ifr);
	return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}

void error(char* err_msg)
{
	fprintf(stderr, "%s\n", err_msg);
	exit(1);
}

// ROUTE TABLE --------------------------------------------------------------------------------------------
// Compares two rtable entries by prefix

struct trie_node *create_trie_node ()
{
	struct trie_node *node = (struct trie_node*) malloc(sizeof(struct trie_node));
	node->l = NULL;
	node->r = NULL;
	return node;
}

void add_route_entry(struct route_entry *route, struct trie_node *root)
{
	uint32_t bit_mask = 1 << 31;

	// Get the little endian representation
	uint32_t route_prefix = ntohl(route->prefix);
	uint32_t subnet_mask = ntohl(route->mask);

	while (bit_mask != 0 && subnet_mask != 0)
	{
		uint32_t bit_val = bit_mask & route_prefix;

		if (bit_val == 0)
		{
			if (root->l == NULL)
				root->l = create_trie_node();
			
			root = root->l;
		}
		else
		{
			if (root->r == NULL)
				root->r = create_trie_node();

			root = root->r;
		}
		
		bit_mask >>= 1;
		subnet_mask <<= 1;
	}

	root->route = route;
}

struct route_entry *get_best_route (uint32_t dst_ip, struct trie_node *root)
{
	uint32_t bit_mask = 1 << 31;
	struct route_entry *best_route = NULL;

	dst_ip = ntohl(dst_ip);

	while (bit_mask != 0 && root != NULL)
	{
		if (root->route != NULL)
			best_route = root->route;
		
		uint32_t bit_val = bit_mask & dst_ip;
		if (bit_val == 0)
			root = root->l;
		else
			root = root->r;

		bit_mask >>= 1;
	}

	return best_route;
}

struct trie_node *create_read_trie_rtable(char *rtable_file_name)
{
	struct trie_node *root = create_trie_node();

	FILE *in = fopen(rtable_file_name, "rt");
	if (!in)
		error("File opening error");

	char net_addr_str[MAX_ADDR_STRING_LEN];
	char next_hop_addr_str[MAX_ADDR_STRING_LEN];
	char subnet_mask_str[MAX_ADDR_STRING_LEN];
	int interface;

	struct in_addr tmp_in_addr;
	
	while (fscanf(in, "%s %s %s %d", net_addr_str, next_hop_addr_str, subnet_mask_str, &interface) == 4)
	{
		struct route_entry *entry = (struct route_entry*) malloc(sizeof(struct route_entry));

		inet_aton(net_addr_str, &tmp_in_addr);
		entry->prefix = tmp_in_addr.s_addr;

		inet_aton(next_hop_addr_str, &tmp_in_addr);
		entry->next_hop = tmp_in_addr.s_addr;

		inet_aton(subnet_mask_str, &tmp_in_addr);
		entry->mask = tmp_in_addr.s_addr;

		entry->interface = interface;

		add_route_entry(entry, root);
	}

	fclose(in);

	return root;
}

// ARP TABLE ---------------------------------------------------------------------------------------------

struct arp_table* create_arp_table ()
{
	struct arp_table *arptable = (struct arp_table*) malloc(sizeof(struct arp_table));
	if (arptable == NULL)
		error("ARP table allocation error.");

	arptable->size = 0;
	arptable->capacity = INIT_ARP_TABLE_CAPACITY;
	arptable->entries = (struct arp_entry**) malloc(sizeof(struct arp_entry*) * INIT_ARP_TABLE_CAPACITY);

	if (arptable->entries == NULL)
		error("ARP table entries allocation error.");
	
	return arptable;
}

void add_arp_entry(uint32_t ip, uint8_t *mac, struct arp_table *arptable)
{
	// If the given IP is already in the ARP table, update the coresponding
	// MAC of the entry with the new one

	for (int i = 0; i < arptable->size; i++)
	{
		if (arptable->entries[i]->ip == ip)
		{
			memcpy(arptable->entries[i]->mac, mac, ETH_ALEN);
			return;
		}
	}

	// Otherwise, add a new entry
	struct arp_entry *new_arp_entry = (struct arp_entry*) malloc(sizeof(struct arp_entry));
	memcpy(new_arp_entry->mac, mac, ETH_ALEN);
	new_arp_entry->ip = ip;

	arptable->entries[arptable->size++] = new_arp_entry;

	if (arptable->size == arptable->capacity)
	{
		arptable->capacity *= 2;
		struct arp_entry **tmp = (struct arp_entry**) realloc(arptable->entries, sizeof(struct arp_entry*) * arptable->capacity);
		if (!tmp)
			error("ARP Table memory reallocation fail.");
		arptable->entries = tmp;
	}
}

// Returns the arp table entry matching the given IP address
// Or NULL if the IP is not found
struct arp_entry *get_arp_entry(uint32_t ip, struct arp_table *arptable)
{
	for (int i = 0; i < arptable->size; i++)
		if (arptable->entries[i]->ip == ip)
			return arptable->entries[i];

	return NULL;
}

// arp_op = ARPOP_REQUEST / ARPOP_REPLY
void send_arp_wrapper (uint8_t *_dst_mac_addr, uint32_t dst_ip_addr, int interface, uint16_t arp_op)
{
	struct ether_header *eth_hdr = (struct ether_header*) malloc(sizeof(struct ether_header));
	
	uint8_t dst_mac_addr[ETH_ALEN];
	memcpy(dst_mac_addr, _dst_mac_addr, ETH_ALEN);
	uint8_t src_mac_addr[ETH_ALEN];
	get_interface_mac(interface, src_mac_addr);

	build_ethhdr(eth_hdr, src_mac_addr, dst_mac_addr, htons(ETHERTYPE_ARP));

	uint32_t src_ip_addr = get_interface_ip_int32(interface);
	
	send_arp(dst_ip_addr, src_ip_addr, eth_hdr, interface, htons(arp_op));

}

// ICMP ----------------------------------------------------------------------------------------------------- 

/*
	Builds an echo reply for the corresponding echo request;
	Returns the echo reply in the second parameter
*/
void build_echo_reply(packet *echo_request, packet *echo_reply)
{
	// Request headers
	struct ether_header *req_eth_hdr = (struct ether_header*)(echo_request->payload);//->ether_shost
	struct iphdr *req_ip_hdr = (struct iphdr*)(echo_request->payload + sizeof(struct ether_header));
	struct icmphdr *req_icmp_hdr = parse_icmp(echo_request->payload); 

	// Reply headers
	struct ether_header *eth_hdr = (struct ether_header *)(echo_reply->payload);
	struct iphdr *ip_hdr = (struct iphdr*)(echo_reply->payload + sizeof(struct ether_header));

	memset(echo_reply->payload, 0, sizeof(echo_reply->payload));

	// Length of ICMP payload (data field)
	int icmp_payload_len = ntohs(req_ip_hdr->tot_len) - (sizeof(struct iphdr) + sizeof(struct icmphdr));

	echo_reply->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + icmp_payload_len;

	// Build Ethernet header
	uint8_t src_mac_addr[ETH_ALEN];
	get_interface_mac(echo_request->interface, &src_mac_addr[0]);
	build_ethhdr(eth_hdr, &src_mac_addr[0], req_eth_hdr->ether_shost, htons(ETHERTYPE_IP));

	// Build IP header
	ip_hdr->version = 4;
	ip_hdr->ihl = 5;	// (IPv4 header length) / 4B ==  20B / 4B = 5
	ip_hdr->tos = 0;	// type of service
	
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + icmp_payload_len);
	ip_hdr->ttl = 64;
	ip_hdr->protocol = IPPROTO_ICMP;	// 1 (ICMP)
	ip_hdr->id = htons(1);
	ip_hdr->frag_off = 0;
	ip_hdr->saddr = req_ip_hdr->daddr;
	ip_hdr->daddr = req_ip_hdr->saddr;	
	ip_hdr->check = 0;
	ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));	// IP header checksum

	// Build ICMP header
	struct icmphdr *icmp_hdr = parse_icmp(echo_reply->payload);
	icmp_hdr->code = 0;
	icmp_hdr->type = 0;	// Echo reply

	icmp_hdr->un.echo.id = req_icmp_hdr->un.echo.id;
	icmp_hdr->un.echo.sequence = req_icmp_hdr->un.echo.sequence; 

	// Pointer arithmetics, icmp_hdr + 1 = data portion after the header ends
	memcpy (icmp_hdr + 1, req_icmp_hdr + 1, icmp_payload_len);

	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = icmp_checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + icmp_payload_len);
}

void forward_packet(packet *p, uint8_t *dha, uint8_t *sha, int interface)
{
	struct ether_header *eth_hdr = (struct ether_header*) p->payload;

	memcpy(eth_hdr->ether_dhost, dha, ETH_ALEN);
	memcpy(eth_hdr->ether_shost, sha, ETH_ALEN);
	send_packet(interface, p);
}

// DRIVER --------------------------------------------------------------------------------------------------
int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);

	struct trie_node *root = create_read_trie_rtable(argv[1]); // Routing table
	struct arp_table *arptable = create_arp_table(); 		   // ARP table

	// Queue 
	struct queue *pkt_queue = queue_create();

	// Broadcast MAC address
	uint8_t broadcast_mac_addr[ETH_ALEN];
	hwaddr_aton("ff:ff:ff:ff:ff:ff", broadcast_mac_addr);

	// Getting the MAC and IP addresses of the router interfaces
	uint32_t router_ip_addr[ROUTER_NUM_INTERFACES];
	uint8_t  router_mac_addr[ROUTER_NUM_INTERFACES][ETH_ALEN];

	for (int if_num = 0; if_num < ROUTER_NUM_INTERFACES; if_num++)
	{
		router_ip_addr[if_num] = get_interface_ip_int32(if_num);
		get_interface_mac(if_num, router_mac_addr[if_num]);
	}
	
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		
		struct ether_header *eth_hdr = (struct ether_header*) m.payload;

		// If it's an ARP packet
		struct arp_header *arp_hdr = (struct arp_header*) parse_arp(m.payload);
		if (arp_hdr != NULL)
		{
			// If it's an ARP Reply => update table, send potential packet from queue to dst
			if (arp_hdr->op == htons(ARPOP_REPLY))
			{
				add_arp_entry(arp_hdr->spa, arp_hdr->sha, arptable);

				// Check if packets from queue can be sent
				while (!queue_empty(pkt_queue))
				{
					struct enqueued_packet *enq_packet = queue_top(pkt_queue);

					// Get ARP entry for the next hop
					struct arp_entry *arp_result = get_arp_entry(enq_packet->route->next_hop, arptable);
					if (arp_result == NULL)	//No ARP entry => stop checking packets from queue
						break;
			
					forward_packet(enq_packet->m, arp_result->mac,
						router_mac_addr[enq_packet->route->interface], enq_packet->route->interface);
					queue_deq(pkt_queue);
				}

				continue;
			}

			// If the destination is the interface of this router which received the message
			// && If it's an ARP Request => Send an ARP reply
			else if (arp_hdr->op == htons(ARPOP_REQUEST) && arp_hdr->tpa == router_ip_addr[m.interface])
				send_arp_wrapper(arp_hdr->sha, arp_hdr->spa, m.interface, ARPOP_REPLY);
			
			else
				continue; // drop (ARP Requests are not forwarded to other networks)
		}

		// If it's an IP packet
		else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
		{
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

			// If the packet dst IP == the IP of one of the interfaces of this routers
			int this_router_is_dst = 0; //flag
			for (int if_num = 0; if_num < ROUTER_NUM_INTERFACES; if_num++)
			{
			 	if (ip_hdr->daddr == router_ip_addr[if_num])
			 	{
			 		this_router_is_dst = 1;
			 		break;
				}
			}

			if (this_router_is_dst == 1)
			{
		 		// If the packet is not ICMP Echo Request => drop
		 		if (ip_hdr->protocol != 1 || parse_icmp(m.payload)->type != 8)
		 			break;

			 	// Packet is ICMP
		 		packet echo_reply;
		 		build_echo_reply(&m, &echo_reply);
				send_packet(m.interface, &echo_reply);	
				continue;
			}

			// The packet dst is not the current router => Must be FORWARDED
			// Check if TTL <= 1
			if (ip_hdr->ttl <= 1)
			{
				// Time exceeded (type 11); TTL exceeded in transit (code 0)
				send_icmp_error(ip_hdr->saddr, router_ip_addr[m.interface],
					router_mac_addr[m.interface], eth_hdr->ether_shost, 11, 0, m.interface);
				continue; // drop packet
			}
			
			// Check CHECKSUM
			uint16_t packet_recv_checksum = ip_hdr->check;

			ip_hdr->check = 0;
			uint16_t packet_recalc_checksum = ip_checksum(ip_hdr, sizeof(struct iphdr));

			if (packet_recalc_checksum != packet_recv_checksum)	
				continue; // drop packet if checksum doesn't match

			// Decrement TTL
			ip_hdr->ttl--;

			// Recalculate CHECKSUM
			ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

			// Find route (next hop) in rtable
			struct route_entry *route = get_best_route(ip_hdr->daddr, root);

			if (route == NULL) // If no rtable entry exists
			{
				// Destination Unreachable (type 3), Net is unreachable (code 0)
				send_icmp_error(ip_hdr->saddr, router_ip_addr[m.interface],
					router_mac_addr[m.interface], eth_hdr->ether_shost, 3, 0, m.interface);
				continue; // drop packet
			}

			// Get ARP entry for the next hop
			struct arp_entry *arp_result = get_arp_entry(route->next_hop, arptable);
			
			if (arp_result == NULL) // If entry not in table
			{
				// Put message + corresponding routing table entry in queue
				struct enqueued_packet *enq_packet = (struct enqueued_packet*) malloc(sizeof(struct enqueued_packet));
				enq_packet->route = route;
				enq_packet->m = (packet*) malloc(sizeof(packet));
				memcpy(enq_packet->m, &m, sizeof(packet));

				queue_enq(pkt_queue, enq_packet);

				// Send an ARP request to find the MAC address of the next hop from the routing entry
				send_arp_wrapper (broadcast_mac_addr, route->next_hop, route->interface, ARPOP_REQUEST);
			}

			else
				forward_packet(&m, arp_result->mac, router_mac_addr[route->interface], route->interface);
		}
	}
}