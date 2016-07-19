/*
 * usbtables.c
 * usbtables is a user-space tool for the kernel with usbfilter enabled
 * Support for Prolog engine for rule conflict checking
 * Jan 1, 2016
 * just like iptables for the kernel with netfilter built-in.
 * Jul 23, 2015
 * OK, daveti is an idiot - reload saved rules into Prolog before adding a new rule
 * Feb 6, 2016
 * root@davejingtian.org
 * http://davejingtian.org
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <asm/types.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include "nlm.h"
#include "utils.h"
#include "logic.h"

/* Global defs */
#define USBTABLES_VERSION		"0.4"
#define USBTABLES_AUTHORS		"Dave (Jing) Tian"
#define USBTABLES_RECV_BUFF_LEN		1024*1024
#define USBTABLES_DB_PATH		"/root/git/usbfilter/usbtables/db/rdb.dat"	/* for eval */
#define USBTABLES_DB_PATH2		"./db/rdb.dat"

/* Global variables */
extern char *optarg;
static struct sockaddr_nl usbtables_nl_addr;
static struct sockaddr_nl usbtables_nl_dest_addr;
static pid_t usbtables_pid;
static int usbtables_sock_fd;
static FILE *usbtables_db_fp;
static void *recv_buff;
static int debug_enabled;
static int usbtables_perf = 1;
static nlmsgt usbtables_cmd;
static char proc_buff[USBTABLES_SUB_TABLE_LEN];
static char dev_buff[USBTABLES_SUB_TABLE_LEN];
static char pkt_buff[USBTABLES_SUB_TABLE_LEN];
static char lum_buff[USBTABLES_SUB_TABLE_LEN];
static char other_buff[USBTABLES_SUB_TABLE_LEN];
static int usbtables_act;
static int usbtables_ack_num;
static int usbtables_one_time_rule;
static int usbtables_ut;

/* Signal term handler */
static void usbtables_signal_term(int signal)
{
	/* Close the db */
	if (usbtables_db_fp)
		fclose(usbtables_db_fp);

	/* Close the socket */
	if (usbtables_sock_fd != -1)    
		close(usbtables_sock_fd);

	/* Free netlink receive buffer */
 	if (recv_buff != NULL)
		free(recv_buff);

	/* Shutdown the Prolog */
	exit_logic();

	exit(EXIT_SUCCESS);
}

/* Setup signal handler */
static int signals_init(void)
{
	int rc;
	sigset_t sigmask;
	struct sigaction sa;

	sigemptyset(&sigmask);
	if ((rc = sigaddset(&sigmask, SIGTERM)) || (rc = sigaddset(&sigmask, SIGINT))) {
		printf("usbtables - Error: sigaddset [%s]\n", strerror(errno));
		return -1;
 	}

	sa.sa_flags = 0;
	sa.sa_mask = sigmask;
	sa.sa_handler = usbtables_signal_term;
	if ((rc = sigaction(SIGTERM, &sa, NULL)) || (rc = sigaction(SIGINT, &sa, NULL))) {
		printf("usbtables - Error: signal SIGTERM or SIGINT not registered [%s]\n", strerror(errno));
		return -1;
	}

	return 0;
}

/* Send the nlmsgt via the netlink socket */
static int usbtables_netlink_send(nlmsgt *msg_ptr)
{
	struct nlmsghdr *nlh;
	struct iovec iov;
	struct msghdr msg;
	int rtn;
	unsigned char *data;
	int data_len;

	// Convert the nlmsgt into binary data
	data_len = NLM_MSG_LEN;
	data = (unsigned char *)malloc(data_len);
	memcpy(data, msg_ptr, NLM_MSG_LEN);

	// Init the stack struct to avoid potential error
	memset(&iov, 0, sizeof(iov));
	memset(&msg, 0, sizeof(msg));

	// Create the netlink msg
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(data_len));
	memset(nlh, 0, NLMSG_SPACE(data_len));
	nlh->nlmsg_len = NLMSG_SPACE(data_len);
	nlh->nlmsg_pid = usbtables_pid;
	nlh->nlmsg_flags = 0;

	// Copy the binary data into the netlink message
	memcpy(NLMSG_DATA(nlh), data, data_len);

	// Nothing to do for test msg - it is already what it is
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = (void *)&usbtables_nl_dest_addr;
	msg.msg_namelen = sizeof(usbtables_nl_dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	// Send the msg to the kernel
	rtn = sendmsg(usbtables_sock_fd, &msg, 0);
	if (rtn == -1) {
		printf("usbtables_netlink_send: Error on sending netlink msg to the kernel [%s]\n",
			strerror(errno));
		goto OUT;
	}

	if (debug_enabled)
		printf("usbtables_netlink_send: Info - send netlink msg to the kernel\n");

OUT:
	free(nlh);
	free(data);
	return 0;
}

/* Init the netlink with initial nlmsg */
static int usbtables_init_netlink(void)
{
	int result;
	nlmsgt init_msg;
	char *msg_str = "__usbtables_init__";

	// Add the opcode into the msg
	memset(&init_msg, 0, sizeof(nlmsgt));
	init_msg.opcode = USBFILTER_NETLINK_OPC_INIT;
	init_msg.type = USBFILTER_TYPE_SIM_RULE;
	memcpy(init_msg.sim_rule.name, msg_str, strlen(msg_str));

	// Send the msg to the kernel
	printf("usbtables_init_netlink: Info - send netlink init msg to the kernel\n");
	result = usbtables_netlink_send(&init_msg);
	if (result == -1)
		printf("usbtables_init_netlink: Error on sending netlink init msg to the kernel [%s]\n",
			strerror(errno));

	return result;
}

/* Sync one rule with the local RDB */
static int usbtables_sync_rule_local(nlmsgt *msg)
{
	int rtn;
	nlmsgt syn;

	if (!msg) {
		printf("usbtables - Error: null msg\n");
		return -1;
	}

	/* Ignore one-time rule */
	if (usbtables_one_time_rule)
		return 0;

	/* Open the RDB */
	usbtables_db_fp = fopen(USBTABLES_DB_PATH, "a+b");
        if (!usbtables_db_fp) {
                printf("usbtables - Info: fopen RDB [%s] failed - %s\n",
                        USBTABLES_DB_PATH, strerror(errno));
                return -1;
        }

	/* Update the opcode of the msg */
	memcpy(&syn, msg, sizeof(syn));
	syn.opcode = USBFILTER_NETLINK_OPC_SYN;

	/* Write to the RDB file */
	rtn = 0;
	if (fwrite(&syn, sizeof(syn), 1, usbtables_db_fp) != 1) {
		printf("usbtables - Error: fwrite failed\n");
		rtn = -1;
	}

	fclose(usbtables_db_fp);
	return rtn;	
}

/* Sync the RDB with the kernel */
static int usbtables_sync_rdb(void)
{
	int ret;
	nlmsgt msg;

	/* Open the db */
	usbtables_db_fp = fopen(USBTABLES_DB_PATH, "a+b");
	if (!usbtables_db_fp) {
		printf("usbtables - Info: fopen RDB [%s] failed - %s\n",
			USBTABLES_DB_PATH, strerror(errno));
		return -1;
	}

	/* Read-in the saved fingerprints */
	while (!feof(usbtables_db_fp)) {
		memset(&msg, 0x0, sizeof(msg));
		ret = fread(&msg, sizeof(msg), 1, usbtables_db_fp);
		if (ret == 0) {
			/* Done */
			break;
		}
		else if (ret != 1) {
			printf("usbtables - Error: fread failed\n");
			ret = -1;
			break;
		}

		/* Sync this fp with the kernel */
		ret = usbtables_netlink_send(&msg);
		if (ret != 0)
			printf("usbtables - Error: usbtables_netlink_send failed\n");
	}

	fclose(usbtables_db_fp);
	return ret;	
}

/* Synchronize the local rules with the Prolog Engine */
static int usbtables_sync_pdb(void)
{
	int ret;
	nlmsgt msg;

	/* Open the db */
	usbtables_db_fp = fopen(USBTABLES_DB_PATH, "a+b");
	if (!usbtables_db_fp) {
		printf("usbtables - Info: fopen RDB [%s] failed - %s\n",
			USBTABLES_DB_PATH, strerror(errno));
		return -1;
	}

	/* Read-in the saved fingerprints */
	while (!feof(usbtables_db_fp)) {
		memset(&msg, 0x0, sizeof(msg));
		ret = fread(&msg, sizeof(msg), 1, usbtables_db_fp);
		if (ret == 0) {
			/* Done */
			break;
		}
		else if (ret != 1) {
			printf("usbtables - Error: fread failed\n");
			ret = -1;
			break;
		}

		/* Sync this rule with the Prolog engine */
		ret = logic_add_rule(&msg.rule, 0);
		if (ret)
			printf("usbtables - Error: logic_add_rule failed\n");
	}

	fclose(usbtables_db_fp);
	return ret;	
}

static int validate_fill_lum_tab(struct lum_tab *lum, char *buf)
{
	if (debug_enabled)
		printf("%s: lum [%p], buf [%s]\n", __func__, lum, buf);

	/* Hunt for each field and ignore others */
	get_tab_field_str(USBTABLES_LUM_TBL_STR_NAME, buf, lum->name, USBFILTER_LUM_TAB_NAME_LEN);

	return 0;
}

static int validate_fill_pkt_tab(struct pkt_tab *pkt, char *buf)
{
	if (debug_enabled)
		printf("%s: pkt [%p], buf [%s]\n", __func__, pkt, buf);

	/* Hunt for each field and ignore others */
	pkt->type = get_tab_field_num(USBTABLES_PKT_TBL_STR_TYPE, buf);
	pkt->direction = get_tab_field_num(USBTABLES_PKT_TBL_STR_DIRECTION, buf);
	pkt->endpoint = get_tab_field_num(USBTABLES_PKT_TBL_STR_ENDPOINT, buf);
	pkt->address = get_tab_field_num(USBTABLES_PKT_TBL_STR_ADDRESS, buf);

	return 0;
}

static int validate_fill_dev_tab(struct dev_tab *dev, char *buf)
{
	if (debug_enabled)
		printf("%s: dev [%p], buf [%s]\n", __func__, dev, buf);

	/* Hunt for each field and ignore others */
	dev->busnum = get_tab_field_num(USBTABLES_DEV_TBL_STR_BUSNUM, buf);
	dev->devnum = get_tab_field_num(USBTABLES_DEV_TBL_STR_DEVNUM, buf);
	dev->portnum = get_tab_field_num(USBTABLES_DEV_TBL_STR_PORTNUM, buf);
	dev->ifnum = get_tab_field_num(USBTABLES_DEV_TBL_STR_IFNUM, buf);
	get_tab_field_str(USBTABLES_DEV_TBL_STR_DEVPATH, buf, dev->devpath, USBFILTER_DEV_TAB_DEVPATH_LEN);
	get_tab_field_str(USBTABLES_DEV_TBL_STR_PRODUCT, buf, dev->product, USBFILTER_DEV_TAB_PRODUCT_LEN);
	get_tab_field_str(USBTABLES_DEV_TBL_STR_MANUFACT, buf, dev->manufacturer, USBFILTER_DEV_TAB_MANUFACTURER_LEN);
	get_tab_field_str(USBTABLES_DEV_TBL_STR_SERIAL, buf, dev->serial, USBFILTER_DEV_TAB_SERIAL_LEN);

	return 0;
}

static int validate_fill_proc_tab(struct proc_tab *proc, char *buf)
{
	if (debug_enabled)
		printf("%s: proc [%p], buf [%s]\n", __func__, proc, buf);

	/* Hunt for each field and ignore others */
	proc->pid = get_tab_field_num(USBTABLES_PROC_TBL_STR_PID, buf);
	proc->ppid = get_tab_field_num(USBTABLES_PROC_TBL_STR_PPID, buf);
	proc->pgid = get_tab_field_num(USBTABLES_PROC_TBL_STR_PGID, buf);
	proc->uid = get_tab_field_num(USBTABLES_PROC_TBL_STR_UID, buf);
	proc->euid = get_tab_field_num(USBTABLES_PROC_TBL_STR_EUID, buf);
	proc->gid = get_tab_field_num(USBTABLES_PROC_TBL_STR_GID, buf);
	proc->egid = get_tab_field_num(USBTABLES_PROC_TBL_STR_EGID, buf);
	get_tab_field_str(USBTABLES_PROC_TBL_STR_COMM, buf, proc->comm, USBFILTER_TASK_COMM_LEN);

	return 0;
}

static int validate_action(void)
{
	if (!strcasecmp(other_buff, "allow"))
		return USBFILTER_RULE_ACTION_ALLOW;
	else if (!strcasecmp(other_buff, "drop"))
		return USBFILTER_RULE_ACTION_DROP;
	else
		return -1;
}

static int validate_command(void)
{
	int act;

	/*
	 * The netlink opcode will be rewritten during the command line
	 * parsing. Therefore, there should be only one valid opcode left.
	 * We only care about that command, ignoring all others overwritten.
	 * Then the commands we need to validate are the ones with arguments
	 * and the one with extra parameters, such as 'add'.
	 */
	switch (usbtables_cmd.opcode) {

	case USBFILTER_NETLINK_OPC_ADD:
		/* Need any of the X tables */
		if ((proc_buff[0] == '\0') && (dev_buff[0] == '\0')
			&& (pkt_buff[0] == '\0') && (lum_buff[0] == '\0')) {
				printf("usbtables - Error: no sub table is found\n");
				return -1;
		}
		if (proc_buff[0] != '\0') {
			if (validate_fill_proc_tab(&usbtables_cmd.rule.proc, proc_buff) != 0) {
				printf("usbtables - Error: proc table parsing failed\n");
				return -1;
			}
			usbtables_cmd.rule.proc.valid = 1;
		}
		if (dev_buff[0] != '\0') {
			if (validate_fill_dev_tab(&usbtables_cmd.rule.dev, dev_buff) != 0) {
				printf("usbtables - Error: dev table parsing failed\n");
				return -1;
			}
			usbtables_cmd.rule.dev.valid = 1;
		}
		if (pkt_buff[0] != '\0') {
			if (validate_fill_pkt_tab(&usbtables_cmd.rule.pkt, pkt_buff) != 0) {
				printf("usbtables - Error: pkt table parsing failed\n");
				return -1;
			}
			usbtables_cmd.rule.pkt.valid = 1;
		}
		if (lum_buff[0] != '\0') {
			if (validate_fill_lum_tab(&usbtables_cmd.rule.lum, lum_buff) != 0) {
				printf("usbtables - Error: lum table parsing failed\n");
				return -1;
			}
			usbtables_cmd.rule.lum.valid = 1;
		}
		/* Need the action */
		act = validate_action();
		if (act == -1) {
			printf("usbtables - Error: invalid action [%s]\n", other_buff);
			return -1;
		}
		usbtables_cmd.rule.action = act;
		break;

	case USBFILTER_NETLINK_OPC_CHG:
		/* Need the new behavior */
		act = validate_action();
		if (act == -1) {
			printf("usbtables - Error: invalid behavior [%s]\n", other_buff);
			return -1;
		}
		usbtables_cmd.behavior = act;
		break;

	default:
		/* Do not need validation for other cases */
		break;
	}

	return 0;
}

static void usage(void)
{
	fprintf(stderr, "\tusage: usbtables version [%s] developed by [%s]\n\n",
		USBTABLES_VERSION, USBTABLES_AUTHORS);
	fprintf(stderr, "\t-d|--debug\tenable debug mode\n");
	fprintf(stderr, "\t-c|--config\tpath to configuration file (TBD)\n");
	fprintf(stderr, "\t-h|--help\tdisplay this help message\n");
	fprintf(stderr, "\t-p|--dump\tdump all the rules\n");
	fprintf(stderr, "\t-a|--add\tadd a new rule\n");
	fprintf(stderr, "\t-r|--remove\tremove an existing rule\n");
	fprintf(stderr, "\t-s|--sync\tsynchronize rules with kernel\n");
	fprintf(stderr, "\t-e|--enable\tenable usbfilter\n");
	fprintf(stderr, "\t-q|--disable\tdisable usbfilter\n");
	fprintf(stderr, "\t-b|--behave\tchange the default behavior of usbfilter\n");
	fprintf(stderr, "\t-o|--proc\tprocess table rule\n");
	fprintf(stderr, "\t-v|--dev\tdevice table rule\n");
	fprintf(stderr, "\t-k|--pkt\tpacket table rule\n");
	fprintf(stderr, "\t-l|--lum\tLUM table rule\n");
	fprintf(stderr, "\t-t|--act\ttable rule action\n");
	fprintf(stderr, "\t-i|--ignore\tdo not save the rule locally\n");
	fprintf(stderr, "\t-u|--ut unit testing without triggering the kernel\n");
	fprintf(stderr, "\t------------------------------------------\n");
	fprintf(stderr, "\tproc: pid,ppid,pgid,uid,euid,gid,egid,comm\n");
	fprintf(stderr, "\tdev: busnum,devnum,portnum,ifnum,devpath,product,manufacturer,serial\n");
	fprintf(stderr, "\tpkt: type,direction,endpoint,address\n");
	fprintf(stderr, "\tlum: name\n");
	fprintf(stderr, "\tbehavior,action: allow|drop\n");
	fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
	int result;
	int c, option_index = 0;
	int recv_size;
	int num_of_msg;
	int i;
	int done;
	nlmsgt *msg_ptr;
	struct option long_options[] = {
		{"help", 0, NULL, 'h'},
		{"debug", 0, NULL, 'd'},
		{"config", 1, NULL, 'c'},
		{"dump", 0, NULL, 'p'},
		{"add", 1, NULL, 'a'},
		{"remove", 1, NULL, 'r'},
		{"sync", 0, NULL, 's'},
		{"enable", 0, NULL, 'e'},
		{"disable", 0, NULL, 'q'},
		{"behave", 1, NULL, 'b'},
		{"proc", 1, NULL, 'o'},
		{"dev", 1, NULL, 'v'},
		{"pkt", 1, NULL, 'k'},
		{"lum", 1, NULL, 'l'},
		{"act", 1, NULL, 't'},
		{"ignore", 0, NULL, 'i'},
		{"ut", 0, NULL, 'u'},
		{0, 0, 0, 0}
	};
	struct nlmsghdr *nh;
	struct nlmsgerr *nlm_err_ptr;
	struct timeval start_tv, end_tv;

	/* Start perf */
	if (usbtables_perf)
		gettimeofday(&start_tv, NULL);

	/* Process the arguments */
	while ((c = getopt_long(argc, argv, "hdc:pa:r:seqb:o:v:k:l:t:iu", long_options, &option_index)) != -1) {
		switch (c) {

		case 'd':
			printf("usbtables - Info: debug mode enabled\n");
			debug_enabled = 1;
			break;
		case 'c':
			printf("usbtables - Warning: may support in future\n");
			break;
		case 'p':
			printf("usbtables - Info: dump all the rules\n");
			usbtables_cmd.opcode = USBFILTER_NETLINK_OPC_DMP;
			break;
		case 'a':
			printf("usbtables - Info: add a new rule [%s]\n", optarg);
			usbtables_cmd.opcode = USBFILTER_NETLINK_OPC_ADD;
			snprintf(usbtables_cmd.rule.name, USBFILTER_RULE_NAME_LEN, "%s", optarg);
			break;
		case 'r':
			printf("usbtables - Info: remove rule [%s]\n", optarg);
			usbtables_cmd.opcode = USBFILTER_NETLINK_OPC_DEL;
			snprintf(usbtables_cmd.rule.name, USBFILTER_RULE_NAME_LEN, "%s", optarg);
			break;
		case 's':
			printf("usbtables - Info: synchronize rules\n");
			usbtables_cmd.opcode = USBFILTER_NETLINK_OPC_SYN;
			break;
		case 'e':
			printf("usbtables - Info: enable usbfilter\n");
			usbtables_cmd.opcode = USBFILTER_NETLINK_OPC_ENA;
			break;
		case 'q':
			printf("usbtables - Info: disable usbfilter\n");
			usbtables_cmd.opcode = USBFILTER_NETLINK_OPC_DIS;
			break;
		case 'b':
			printf("usbtables - Info: change default behavior\n");
			usbtables_cmd.opcode = USBFILTER_NETLINK_OPC_CHG;
			snprintf(other_buff, USBTABLES_SUB_TABLE_LEN, "%s", optarg);
			break;
		case 'o':
			printf("usbtables - Info: process table\n");
			snprintf(proc_buff, USBTABLES_SUB_TABLE_LEN, "%s", optarg);
			break;
		case 'v':
			printf("usbtables - Info: device table\n");
			snprintf(dev_buff, USBTABLES_SUB_TABLE_LEN, "%s", optarg);
			break;
		case 'k':
			printf("usbtables - Info: packet table\n");
			snprintf(pkt_buff, USBTABLES_SUB_TABLE_LEN, "%s", optarg);
			break;
		case 'l':
			printf("usbtables - Info: lum table\n");
			snprintf(lum_buff, USBTABLES_SUB_TABLE_LEN, "%s", optarg);
			break;
		case 't':
			printf("usbtables - Info: action\n");
			snprintf(other_buff, USBTABLES_SUB_TABLE_LEN, "%s", optarg);
			break;
		case 'i':
			printf("usbtables - Info: one-time rule\n");
			usbtables_one_time_rule = 1;
			break;
		case 'u':
			printf("usbtables - Info: unit testing\n");
			usbtables_ut = 1;
			break;
		case 'h':
			/* fall through */
		default:
			usage();
			return -1;
		}
	}

	/* Validate the command request */
	if (validate_command() != 0) {
		printf("usbtables - Error: invalid command request\n");
		return -1;
	}

	/* Set the signal handlers */
	if (signals_init() != 0) {
		printf("usbtables - Error: failed to set up the signal handlers\n");
		return -1;
	}

	/* Init the NLM queue */
	nlm_init_queue();

	/* Init the logic */
	init_logic();

	do{
		/* Create the netlink socket */
		printf("usbtables - Info: waiting for a new connection\n");
		while ((usbtables_sock_fd = socket(PF_NETLINK, SOCK_RAW, USBFILTER_NETLINK)) < 0);

		/* Bind the socket */
		memset(&usbtables_nl_addr, 0, sizeof(usbtables_nl_addr));
		usbtables_nl_addr.nl_family = AF_NETLINK;
		usbtables_pid = getpid();
		printf("usbtables - Info: pid [%u]\n", usbtables_pid);
		usbtables_nl_addr.nl_pid = usbtables_pid;
		if (bind(usbtables_sock_fd,
			(struct sockaddr*)&usbtables_nl_addr, sizeof(usbtables_nl_addr)) == -1) {
			printf("usbtables - Error: netlink bind failed [%s], aborting\n", strerror(errno));
			return -1;
		}

		/* Setup the netlink destination socket address */
		memset(&usbtables_nl_dest_addr, 0, sizeof(usbtables_nl_dest_addr));
		usbtables_nl_dest_addr.nl_family = AF_NETLINK;
		usbtables_nl_dest_addr.nl_pid = 0;
		usbtables_nl_dest_addr.nl_groups = 0;
		printf("usbtables - Info: gud netlink socket init done\n");

		/* Prepare the recv buffer */
		recv_buff = calloc(1, USBTABLES_RECV_BUFF_LEN);
		struct iovec iov = { recv_buff, USBTABLES_RECV_BUFF_LEN };
		struct msghdr msg = { &usbtables_nl_dest_addr,
			sizeof(usbtables_nl_dest_addr),
			&iov, 1, NULL, 0, 0 };

		/* Send the initial testing nlmsgt to the kernel module */
		result = usbtables_init_netlink();
		if (result != 0) {
			printf("usbtables - Error: usbtables_init_netlink failed\n");
			return -1;
		}

		/* Retrive the data from the kernel */
		recv_size = recvmsg(usbtables_sock_fd, &msg, 0);
		if (debug_enabled) {
			nlm_display_msg((nlmsgt *)(NLMSG_DATA(recv_buff)));
			printf("usbtables - Info: got netlink init msg response from the kernel [%s]\n",
				((nlmsgt *)(NLMSG_DATA(recv_buff)))->sim_rule.name);
		}

		/* Send the command to the kernel */
		printf("usbtables - Info: sending the command\n");
		if (debug_enabled)
			nlm_display_msg(&usbtables_cmd);

		/* UT mode */
		if (usbtables_ut) {
			printf("usbtables - UT:\n");
			nlm_display_msg(&usbtables_cmd);
			goto CLEANUP;
		}

		/* NOTE:
		 * Assume that no simple rule would be created from usbtables.
		 * The rule in the usbtables_cmd should be always typeof(struct usbfilter_rule).
		 * Jan 1, 2016
		 * daveti
		 */

		switch (usbtables_cmd.opcode) {

		case USBFILTER_NETLINK_OPC_SYN:
			result = usbtables_sync_rdb();
			if (result)
				printf("usbtables - Error: usbtables_sync_rdb failed\n");
			break;

		case USBFILTER_NETLINK_OPC_ADD:
			/* Rebuild the Prolog DB */
			result = usbtables_sync_pdb();
			if (result)
				printf("usbtables - Error: usbtables_sync_pdb failed\n");
			/* Check for potential conflict before adding */
			if (logic_no_conflict(&usbtables_cmd.rule)) {
				(void)usbtables_netlink_send(&usbtables_cmd);
				result = usbtables_sync_rule_local(&usbtables_cmd);
				if (result)
					printf("usbtables - Error: usbtables_sync_rule_local failed\n");
			} else {
				printf("usbtables - Error: found conflict with existing rules (aborted)\n");
				goto CLEANUP;
			}
			break;

		case USBFILTER_NETLINK_OPC_DEL:
			/* FIXME: we need to remove the rule from local DB as well */
			(void)usbtables_netlink_send(&usbtables_cmd);
			break;

		default:
			(void)usbtables_netlink_send(&usbtables_cmd);
			break;
		}

		done = 0;
		do {
			/* Recv the msg from the kernel */
			printf("usbtables - Info: waiting for ack(s)\n");
			recv_size = recvmsg(usbtables_sock_fd, &msg, 0);
			if (recv_size == -1) {
				printf("usbtables - Error: recv failed [%s]\n", strerror(errno));
				continue;
            		}
			else if (recv_size == 0) {
   				printf("usbtables - Warning: kernel netlink socket is closed\n");
				continue;
			}
			printf("usbtables - Info: received ack(s)\n");

			/* Pop nlmsgs into the NLM queue
			 * Note that we do not allow multipart msg from the kernel.
			 * So we do not have to call NLMSG_NEXT() and only one msg
			 * would be recv'd for each recvmsg call. NLM queue seems
			 * to be redundant if gud is single thread. But it is
			 * needed if gud supports multiple threads.
			 * Feb 9, 2015
			 * daveti
			 */
			nh = (struct nlmsghdr *)recv_buff;
			if (NLMSG_OK(nh, recv_size)) {
				/* Make sure the msg is alright */
				if (nh->nlmsg_type == NLMSG_ERROR) {
					nlm_err_ptr = (struct nlmsgerr *)(NLMSG_DATA(nh));
					printf("usbtables - Error: nlmsg error [%d]\n",
						nlm_err_ptr->error);
					continue;
				}

				/* Ignore the noop */
				if (nh->nlmsg_type == NLMSG_NOOP)
					continue;

				/* Defensive checking - should always be non-multipart msg */
				if (nh->nlmsg_type != NLMSG_DONE) {
					printf("usbtables - Error: nlmsg type [%d] is not supported\n",
						nh->nlmsg_type);
					continue;
				}

				/* Pop the msg into the NLM queue */
				if (nlm_add_msg_queue(NLMSG_DATA(nh)) != 0) {
					printf("usbtables - Error: nlm_add_raw_msg_queue failed\n");
					continue;
				}
			}
			else {
				printf("usbtables - Error: netlink msg is corrupted\n");
				continue;
			}

			/* NOTE: even if nlm_add_raw_msg_queue may fail, there may be msgs in queue
			 * Right now, gud is single thread - recving msgs from the kernel space
			 * and then processing each msg upon this recving. However, the code below
			 * could be separated into a worker thread which could run parallelly with
			 * the main thread. This may be an option to improve the performance even
			 * the mutex has to be added into NLM queue implementation...
			 * Feb 24, 2014
			 * daveti
			 */

			/* Go thru the queue */
			num_of_msg = nlm_get_msg_num_queue(); /* should be always 1 */
			if (debug_enabled)
				printf("usbtables - Debug: got [%d] msgs(packets) in the queue\n", num_of_msg);

			for (i = 0; i < num_of_msg; i++) {
				/* Get the nlmsgt msg */
				msg_ptr = nlm_get_msg_queue(i);

				/* Debug */
				if (debug_enabled)
					nlm_display_msg(msg_ptr);

				switch (msg_ptr->opcode) {

				case USBFILTER_NETLINK_OPC_ACK:
					if (msg_ptr->result == USBFILTER_NETLINK_RES_SUCCESS) {
						printf("usbtables - Info: operation succeeded\n");
						/* Dump the rule if it was a dump request */
						if (usbtables_cmd.opcode == USBFILTER_NETLINK_OPC_DMP)
							dump_rule(msg_ptr);
						else
							done = 1;
					} else if (msg_ptr->result == USBFILTER_NETLINK_RES_LAST) {
						/* Mark usbtables done */
						done = 1;
					} else {
						printf("usbtables - Error: operation failed\n");
						done = 1;
					}
					break;

				default:
					printf("usbtables - Error: unsupported opcode [%u]\n", msg_ptr->opcode);
					done = 1;
					break;
				}
			}

			/* Clear the queue before receiving again */
			nlm_clear_all_msg_queue();

			/* Check to break */
			if (done)
				break;
		} while (1);

CLEANUP:
		/* Clean up before next connection */
		printf("usbtables - Info: closing the current connection\n");
		nlm_clear_all_msg_queue();
		close(usbtables_sock_fd);
		usbtables_sock_fd = -1;
		free(recv_buff);
		recv_buff = NULL;
		exit_logic();

		/* End perf */
		if (usbtables_perf) {
			gettimeofday(&end_tv, NULL);
			printf("usbtables-perf: usbtables took [%lu] us\n",
				USBTABLES_MBM_SUB_TV(start_tv, end_tv));
		}

	} while (0);

	return 0;
}
