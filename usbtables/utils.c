/*
 * utils.c
 * Helpers used by usbtables
 * Jul 24, 2015
 * root@davejingtian.org
 * http://davejingtian.org
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "utils.h"

/* A global buff breaking the thread-safe but convenient */
char global_buf[USBTABLES_SUB_TABLE_LEN];

void dump_usbfilter_rule_proc_tab(struct proc_tab *tab)
{
	if (!tab)
		return;

	printf("valid=%d,"
		"pid=%d,"
		"ppid=%d,"
		"pgid=%d,"
		"uid=%d,"
		"euid=%d,"
		"gid=%d,"
		"egid=%d,"
		"comm=%s\n",
		tab->valid,
		tab->pid,
		tab->ppid,
		tab->pgid,
		tab->uid,
		tab->euid,
		tab->gid,
		tab->egid,
		tab->comm);
}

void dump_usbfilter_rule_dev_tab(struct dev_tab *tab)
{
	if (!tab)
		return;

	printf("valid=%d,"
		"busnum=%d,"
		"devnum=%d,"
		"portnum=%d,"
		"ifnum=%d,"
		"devpath=%s,"
		"product=%s,"
		"manufacturer=%s,"
		"serial=%s\n",
		tab->valid,
		tab->busnum,
		tab->devnum,
		tab->portnum,
		tab->ifnum,
		tab->devpath,
		tab->product,
		tab->manufacturer,
		tab->serial);
}

void dump_usbfilter_rule_pkt_tab(struct pkt_tab *tab)
{
	if (!tab)
		return;

	printf("valid=%d,"
		"type=%d,"
		"direction=%d,"
		"endpoint=%d,"
		"address=%d\n",
		tab->valid,
		tab->type,
		tab->direction,
		tab->endpoint,
		tab->address);
}

void dump_usbfilter_rule_lum_tab(struct lum_tab *tab)
{
	if (!tab)
		return;

	printf("valid=%d,"
		"name=%s\n",
		tab->valid,
		tab->name);
}

void dump_usbfilter_sim_rule_pgid_tab(struct sim_pgid_tab *tab)
{
	int i;

	if (!tab)
		return;

	printf("pgid: ");
	for (i=0; i<USBFILTER_SIM_RULE_ENTRY_NUM; i++)
		printf("%d,", tab->pgid[i]);
	printf("\n");
}

void dump_usbfilter_sim_rule_comm_tab(struct sim_comm_tab *tab)
{
	int i;

	if (!tab)
		return;

	printf("comm: ");
	for (i=0; i<USBFILTER_SIM_RULE_ENTRY_NUM; i++) {
		if (tab->comm[i])
			printf("%s,", tab->comm[i]);
		else
			printf("null,");
	}
	printf("\n");
}

void dump_usbfilter_rule(struct usbfilter_rule *rule)
{
	if (!rule)
		return;

	printf("action=%d,"
		"name=%s,"
		"mod=%p\n",
		rule->action,
		rule->name,
		rule->mod);

	dump_usbfilter_rule_proc_tab(&rule->proc);
	dump_usbfilter_rule_dev_tab(&rule->dev);
	dump_usbfilter_rule_pkt_tab(&rule->pkt);
	dump_usbfilter_rule_lum_tab(&rule->lum);
}

void dump_usbfilter_sim_rule(struct usbfilter_sim_rule *sim)
{
	if (!sim)
		return;

	printf("action=%d,"
		"name=%s,"
		"type=%d\n",
		sim->action,
		sim->name,
		sim->type);

	switch (sim->type) {

	case USBFILTER_SIM_RULE_TYPE_PGID:
		dump_usbfilter_sim_rule_pgid_tab(&sim->pgid_tab);
		break;

	case USBFILTER_SIM_RULE_TYPE_COMM:
		dump_usbfilter_sim_rule_comm_tab(&sim->comm_tab);
		break;

	default:
		printf("Error: [%s] - unknown rule type [%d]\n",
			__func__, sim->type);
		break;
	}
}

void dump_rule(nlmsgt *msg)
{
	if (!msg)
		return;

	printf("opcode=%d,"
		"type=%d,"
		"behavior=%d,"
		"result=%d\n",
		msg->opcode,
		msg->type,
		msg->behavior,
		msg->result);

	switch (msg->type) {

	case USBFILTER_TYPE_RULE:
		dump_usbfilter_rule(&msg->rule);
		break;

	case USBFILTER_TYPE_SIM_RULE:
		dump_usbfilter_sim_rule(&msg->sim_rule);
		break;

	default:
		printf("Error: [%s] - unknown msg type [%d]\n",
			__func__, msg->type);
		break;
	}
}

char *get_rule_name(nlmsgt *msg)
{
	if (!msg)
		return NULL;

	switch (msg->type) {

	case USBFILTER_TYPE_RULE:
		return msg->rule.name;
		break;

	case USBFILTER_TYPE_SIM_RULE:
		return msg->sim_rule.name;
		break;

	default:
		printf("Error: [%s] - unknown msg type [%d]\n",
			__func__, msg->type);
		break;
	}

	return NULL;
}

int get_tab_field_num(char *match, char *str)
{
	char *start, *end;

	start = strcasestr(str, match);
	if (!start)
		return -1;

	/* Get the value */
	memset(global_buf, 0x0, USBTABLES_SUB_TABLE_LEN);
	start += strlen(match);
	end = start;
	while ((*end != '\0') && (*end != ','))
		end++;
	memcpy(global_buf, start, end-start);

	return strtol(global_buf, NULL, 10);
}

void get_tab_field_str(char *match, char *str, char *buf, int len)
{
	char *start, *end;

	start = strcasestr(str, match);
	if (!start) {
		buf[0] = '\0';
		return;
	}

	/* Get the str */
	memset(buf, 0x0, len);
	start += strlen(match);
	end = start;
	while ((*end != '\0') && (*end != ','))
		end++;
	if (end-start >= len) {
		printf("Error: [%s] - buff overrun\n", __func__);
		buf[0] = '\0';
		return;
	}
	memcpy(buf, start, end-start);
}

