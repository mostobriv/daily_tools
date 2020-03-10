typedef uint32_t addr_t;
typedef uint16_t port_t;

#pragma pack(push, 1)
typedef struct {
  uint8_t  dst_addr[6];
  uint8_t  src_addr[6];
  uint16_t llc_len;
} ether_header_t;

typedef struct {
  uint8_t  ver_ihl;  // 4 bits version and 4 bits internet header length
  uint8_t  tos;
  uint16_t total_length;
  uint16_t id;
  uint16_t flags_fo; // 3 bits flags and 13 bits fragment-offset
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t checksum;
  addr_t   src_addr;
  addr_t   dst_addr;
} ip_header_t;

typedef struct {
  port_t   src_port;
  port_t   dst_port;
  uint16_t length;
  uint16_t checksum;
} udp_header_t;

typedef struct  {
 unsigned short int tcph_srcport;
 unsigned short int tcph_destport;
 unsigned int tcph_seqnum;
 unsigned int tcph_acknum;
 unsigned char tcph_reserved:4, tcph_offset:4;
 unsigned char tcph_flags;
 unsigned short int tcph_win;
 unsigned short int tcph_chksum;
 unsigned short int tcph_urgptr;
} tcpheader;
#pragma pack(pop)
