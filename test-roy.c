//
// Created by royz on 8/19/2016.
//
#include <config.h>
#undef NDEBUG
#include "netflow.h"
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
/*IPFIX message header*/
typedef struct ipfix_message_header{
    ovs_be16 version;
    ovs_be16 length;
    ovs_be32 export_time;
    ovs_be32 seq_number;
    ovs_be32 obs_dmID;
}ipfix_message_header_t;
#define IPFIX_MES_HEADER_LEN sizeof(ipfix_message_header_t)


/*IPFIX set header*/
typedef struct ipfix_set_header{
    ovs_be16 set_id;
    ovs_be16 length;
}ipfix_set_header_t;
#define IPFIX_SET_HEADER_LEN sizeof(ipfix_set_header_t)


/*IPFIX data record for ethernet*/
typedef struct ipfix_data_record_ethernet{
    ovs_be32 obs_point_id; //4
    ovs_be32 direction; //4
    ovs_be8 src_mac[6]; //6
    ovs_be8 dst_mac[6]; //6
//    ovs_be16 eth_type; //2
//    ovs_be16 eth_hdlen; //2
//    ovs_be32 start_time; //4
//    ovs_be32 end_time;  // 4
//    ovs_be8 packets[6];  // 6
//    ovs_be8 l2_octor_delta_count[6]; //6
//    ovs_be8 flow_end_reason; //1
}ipfix_data_record_ethernet_t;
#define IPFIX_DATA_RECORD_ETH_LEN sizeof(ipfix_data_record_ethernet_t) //


static void
print_ipfix(struct ofpbuf *buf){
    printf("!\n");
    printf("ipfix_message_header:%"PRIu32,IPFIX_MES_HEADER_LEN);
    printf("\n");
    printf("ipfix_set_header%"PRIu16,IPFIX_SET_HEADER_LEN);
    printf("\n");
    printf("ipfix_data_record_ethernet%"PRIu32,IPFIX_DATA_RECORD_ETH_LEN);
    printf("\n");

    const struct ipfix_message_header *ipfix_message_header1;
    ipfix_message_header1 = ofpbuf_try_pull(buf, IPFIX_MES_HEADER_LEN);

    if(!ipfix_message_header1){
        printf("truncated IPFIX packet header\n");
        return;
    }

    printf("header: v%"PRIu16", "
            "length %"PRIu16", "
            "export time %"PRIu32", "
            "seq %"PRIu32", "
            "ovservation domain %"PRIu32,
            ntohs(ipfix_message_header1->version),
            ntohs(ipfix_message_header1->length),
            ntohl(ipfix_message_header1->export_time),
            ntohl(ipfix_message_header1->seq_number),
            ntohl(ipfix_message_header1->obs_dmID));

    
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
    printf("------usage:TODO-----\n");
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












