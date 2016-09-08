//
// Created by royz on 8/19/2016.
//
#include <config.h>
#undef NDEBUG
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <setjmp.h>
#include "command-line.h"
#include "daemon.h"
#include "dynamic-string.h"
#include "ofpbuf.h"
#include "ovstest.h"
#include "packets.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"
#include "openvswitch/types.h"
#include "openvswitch/compiler.h"

static unixctl_cb_func test_ipfix_exit;
static void parse_options(int argc, char *argv[]);
OVS_NO_RETURN static void usage(void);

#ifdef __CHECKER__
#define OVS_BITWISE __attribute__((bitwise))
#define OVS_FORCE __attribute__((force))
#else
#define OVS_BITWISE
#define OVS_FORCE
#endif


typedef uint8_t OVS_BITWISE ovs_be8;
typedef uint64_t OVS_BITWISE ovs_be64;

/*IPFIX message header*/
struct ipfix_message_header{
    ovs_be16 version;
    ovs_be16 length;
    ovs_be32 export_time;
    ovs_be32 seq_number;
    ovs_be32 obs_dmID;
};

/*IPFIX set header*/
struct ipfix_set_header{
    ovs_be16 set_id;
    ovs_be16 length;
};

/*IPFIX data record for ethernet*/
struct ipfix_data_record_ethernet{
    ovs_be32 obs_point_id;
    ovs_be8 direction_ingress;
    ovs_be8 src_mac[6];
    ovs_be8 dst_mac[6];
    ovs_be16 eth_type;
    ovs_be8 eth_hdlen;
    ovs_be32 start_time;
    ovs_be32 end_time;
    ovs_be64 packets;
    ovs_be64 l2_octor_delta_count;
    ovs_be8 flow_end_reason;
};

/*IPFIX data record for icmp*/
struct ipfix_data_record_icmp{
    ovs_be32 obs_point_id;
    ovs_be8 direction_ingress;
    ovs_be8 src_mac[6];
    ovs_be8 dst_mac[6];
    ovs_be16 eth_type;
    ovs_be8 eth_hdlen;
    ovs_be8 ip_ver;
    ovs_be8 ip_ttl;
    ovs_be8 ip_pro;
    ovs_be8 dscp;
    ovs_be8 ip_pre;
    ovs_be8 ip_tos;
    ovs_be8 src_ip[4];
    ovs_be8 dst_ip[4];
    ovs_be8 icmp_type;
    ovs_be8 icmp_code;
    ovs_be32 start_time;
    ovs_be32 end_time;
    ovs_be64 packets;
    ovs_be64 l2_octor_delta_count;
    ovs_be8 flow_end_reason;
    ovs_be64 octets;
    ovs_be64 delta_oc_sq;
    ovs_be64 min_len;
    ovs_be64 max_len;

}; //93B

#define IPFIX_MES_HEADER_LEN sizeof(struct ipfix_message_header)
#define IPFIX_SET_HEADER_LEN sizeof(struct ipfix_set_header)
#define IPFIX_DATA_RECORD_ETH_LEN 45
#define IPFIX_DATA_RECORD_ICMP_LEN 93

#define ADDRESS_MAC 0
#define ADDRESS_IPV4 4
#define ADDRESS_IPV6 6

static void
print_address(void *rec, ovs_be8 add_type){
    ovs_be8 *p;
    p = &*rec;

    switch (add_type){
        case 0:{
            printf("src mac ");
            for (int i=0; i<6; ++i)
                printf("%x",*p++);
            printf(", ");

            printf("dst mac ");
            for (int j=0; j<6; ++j)
                printf("%x",*p++);

            break;
        }

        case 4:{
            printf("src ip ");
            for (int i=0; i<4;i++)
                printf("%"PRIu8,*(p++));
            printf(", ");

            printf("dst ip ");
            for (int i=0; i<4;i++)
                printf("%"PRIu8,*(p++));

            break;
        }

        default:
            break;
    }
//    free(p);
}


static void
print_record(void *rec, ovs_be16 dp){
    if(!rec){
        printf("truncated IPFIX packet header\n");
        return;
    }
    
    
    switch (ntohs(dp)){
        case 256:{
            struct ipfix_data_record_ethernet *p;
            p = (struct ipfix_data_record_ethernet *) rec;
            printf("set record: observation_point_id %"PRIu32", "
                    "packets %"PRIu64", ",
                    ntohl(p->obs_point_id),
                    ntohll(p->packets)
            );

            print_address(p->src_mac,ADDRESS_MAC);

            printf("\n");
//            free(p);
            break;
        }

        case 266:{
            struct ipfix_data_record_icmp *p;
            p = (struct ipfix_data_record_icmp *) rec;
            printf("set record: observation_point_id %"PRIu32", "
                    "packets %"PRIu64", ",
                    ntohl(p->obs_point_id),
                    p->packets
            );

            print_address(p->src_mac,ADDRESS_MAC);

            printf("IPVersion %"PRIu8", "
                    "Protocol %"PRIu8", ",
                    p->ip_ver,
                    p->ip_pro
            );

            print_address(p->src_ip,ADDRESS_IPV4);

            printf("\n");
//            free(p);
            break;
        }
        default:
            return;
    }
}

static void
print_ipfix(struct ofpbuf *buf){

    const struct ipfix_message_header *msg_hd;
    const struct ipfix_set_header *set_hd;

    msg_hd = ofpbuf_try_pull(buf, IPFIX_MES_HEADER_LEN);
    set_hd = ofpbuf_try_pull(buf, IPFIX_SET_HEADER_LEN);

    if(!msg_hd ){
        printf("truncated IPFIX packet header\n");
        return;
    }
    if(!set_hd){
        printf("truncated IPFIX set header\n");
        return;
    }


    //for so far  just print ethernet and icmp
    if(ntohs(set_hd->set_id)!=256 && ntohs(set_hd->set_id)!=266)
        return;

    //print ipfix header
    printf("header: v%"PRIu16", "
            "length %"PRIu16", "
            "seq %"PRIu32", "
            "ovservation domain %"PRIu32,
            ntohs(msg_hd->version),
            ntohs(msg_hd->length),
            ntohl(msg_hd->seq_number),
            ntohl(msg_hd->obs_dmID));
    printf("\n");

    //print ipfix set header
    printf("set header: setId %"PRIu16", "
            "set length %"PRIu16,
            ntohs(set_hd->set_id),
            ntohs(set_hd->length));
    printf("\n");


    //print ipfix record
    switch (ntohs(set_hd->set_id)){
        case 256: {
            struct ipfix_data_record_ethernet *rec;
            rec = ofpbuf_try_pull(buf, IPFIX_DATA_RECORD_ETH_LEN);
            if (!rec) {
                printf("truncated IPFIX ethernet data record\n");
                return;
            }
            print_record((void*)rec, set_hd->set_id);
            //free(rec);
            break;
        }
        case 266:{
            struct ipfix_data_record_icmp *rec;
            rec = ofpbuf_try_pull(buf, IPFIX_DATA_RECORD_ICMP_LEN);
            if(!rec){
                printf("truncated IPFIX icmp data record\n");
                return;
            }
            print_record((void*)rec,set_hd->set_id);
//            free(rec);
            break;
        }
        default:
            return;
    }

//    free(msg_hd);
//    free(set_hd);

}

static void
parse_options(int argc, char *argv[]){
    enum {
        DAEMON_OPTION_ENUMS,
        VLOG_OPTION_ENUMS
    };
    static const struct option long_options[] = {
            {"help", no_argument, NULL, 'h'},
            DAEMON_LONG_OPTIONS,
            VLOG_LONG_OPTIONS,
            {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);
    for (;;) {
        int c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }
        switch (c) {
            case 'h':
                usage();
                DAEMON_OPTION_HANDLERS
                        VLOG_OPTION_HANDLERS
            case '?':
                exit(EXIT_FAILURE);
            default:
                abort();
        }
    }
    free(short_options);
}

static void
usage(void){
    printf("%s: ipfix collector test utility\n"
                   "usage: %s [OPTIONS] PORT[:IP]\n"
                   "where PORT is the UDP port to listen on and IP is optionally\n"
                   "the IP address to listen on.\n",
           program_name, program_name);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
                   "  -h, --help                  display this help message\n");
    exit(EXIT_SUCCESS);
}

static void
test_ipfix_exit(struct unixctl_conn *conn,
                int argc OVS_UNUSED, const char *argv[] OVS_UNUSED,
                void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
}

static void
test_ipfix_main(int argc, char *argv[])
{
    struct unixctl_server *server;
    enum { MAX_RECV = 1500 };
    const char *target;
    struct ofpbuf buf;
    bool exiting = false;
    int error;
    int sock;
    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv);
    if (argc - optind != 1) {
        ovs_fatal(0, "exactly one non-option argument required "
                "(use --help for help)");
    }
    target = argv[optind];
    sock = inet_open_passive(SOCK_DGRAM, target, 0, NULL, 0, true);
    if (sock < 0) {
	printf("sock<0\n");
        ovs_fatal(0, "%s: failed to open (%s)", argv[1], ovs_strerror(-sock));
    }
    daemon_save_fd(STDOUT_FILENO);
    daemonize_start(false);

    error = unixctl_server_create(NULL, &server);
    if (error) {
        ovs_fatal(error, "failed to create unixctl server");
    }
    unixctl_command_register("exit", "", 0, 0, test_ipfix_exit, &exiting);
    daemonize_complete();

    ofpbuf_init(&buf, MAX_RECV);
    for (;;) {
        int retval;
        unixctl_server_run(server);
        ofpbuf_clear(&buf);
        do {
            retval = recv(sock, buf.data, buf.allocated, 0);
        } while (retval < 0 && errno == EINTR);
        if (retval > 0) {
            ofpbuf_put_uninit(&buf, retval);
            print_ipfix(&buf);
            fflush(stdout);
        }
        if (exiting) {
            break;
        }
        poll_fd_wait(sock, POLLIN);
        unixctl_server_wait(server);
        poll_block();
    }
    ofpbuf_uninit(&buf);
    unixctl_server_destroy(server);
}
OVSTEST_REGISTER("test-ipfix", test_ipfix_main);


