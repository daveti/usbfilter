/*
 * nlm.c
 * Source file for protocol NLM used by usbtables
 * Jul 28, 2015
 * root@davejingtian.org
 * http://davejingtian.org
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nlm.h"
#include "utils.h"

/* NLM queue definitions */
static nlmsgt nlm_queue[NLM_QUEUE_MSG_NUM];
static int nlm_queue_index; /* Always pointing to the next avalible position */

/* NLM protocol related methods */

/* Display the uchar given length */
void nlm_display_uchar(unsigned char *src, int len, char *header)
{
	int i;

	printf("%s\n", header);
	for (i = 0; i < len; i++) {
		if ((i+1) % NLM_UCHAR_NUM_PER_LINE != 0)
			printf("%02x ", src[i]);
		else
			printf("%02x\n", src[i]);
	}
	printf("\n");   
}

/* Display the NLM message */
void nlm_display_msg(nlmsgt *msg)
{
	printf("Dump the usbfilter nlmsg:\n"
		"opcode = [%d]\n"
		"type = [%d]\n"
		"behavior = [%d]\n"
		"result = [%d]\n",
		msg->opcode, msg->type, msg->behavior, msg->result);

	switch (msg->opcode) {

	case USBFILTER_NETLINK_OPC_ACK:
		/* This is the only legal nlmsg recv'd from the kernel */
		printf("Ack:\n");
		dump_rule(msg);
		break;

	/* All others here should be sent to the kernel */
	case USBFILTER_NETLINK_OPC_INIT:
		printf("Init: sim rule name [%s]\n", msg->sim_rule.name);
		break;

	case USBFILTER_NETLINK_OPC_ADD:
	case USBFILTER_NETLINK_OPC_SYN:
		printf("Add/Syn:\n");
		dump_rule(msg);
		break;

	case USBFILTER_NETLINK_OPC_DEL:
		printf("Del: rule name [%s]\n", get_rule_name(msg));
		break;

	case USBFILTER_NETLINK_OPC_ENA:
		printf("Ena: enable usbfilter\n");
		break;

	case USBFILTER_NETLINK_OPC_DIS:
		printf("Dis: disable usbfilter\n");
		break;

	case USBFILTER_NETLINK_OPC_CHG:
		printf("Chg: change default behavior\n");
		break;

	case USBFILTER_NETLINK_OPC_DMP:
		printf("Dmp: dump the rules from the kernel\n");
		break;

	default:
		printf("Error: invalid opcode [%u]\n", msg->opcode);
		break;
	}
}

/* NLM queue related methods */

/* Init the NLM queue */
void nlm_init_queue(void)
{
	memset((unsigned char *)nlm_queue, 0x0, NLM_QUEUE_SIZE);
	nlm_queue_index = 0;
}

/* Add msgs into the NLM queue from raw binary data */
int nlm_add_msg_queue(nlmsgt *msg)
{
	/* Save the TLV into nlm msg queue */
	if (nlm_queue_index < NLM_QUEUE_MSG_NUM)
		nlm_queue[nlm_queue_index++] = *msg;
	else {
		printf("nlm_add_raw_msg_queue: Error - nlm queue is full\n");
		return -1;
	}

	return 0;
}

/* Clear all the msgs in the queue */
void nlm_clear_all_msg_queue(void)
{
	int i;

	/* Zero out the structs */
	for (i = 0; i < nlm_queue_index; i++)
		memset(&nlm_queue[i], 0x0, sizeof(nlmsgt));

	/* Reinit the index */
	nlm_queue_index = 0;
}

/* Get the number of msgs in the queue */
int nlm_get_msg_num_queue(void)
{
	return nlm_queue_index;
}

/* Get the msg from the queue based on the index */
nlmsgt * nlm_get_msg_queue(int index)
{
	return &(nlm_queue[index]);
}
