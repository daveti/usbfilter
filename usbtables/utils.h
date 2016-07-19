/*
 * utils.h
 * Header file for utils used by usbtables
 * Jul 24, 2015
 * root@davejingtian.org
 * http://davejingtian.org
 */
#include "nlm.h"

#define USBTABLES_SUB_TABLE_LEN		256
#define USBTABLES_PROC_TBL_STR_PID	"pid="
#define USBTABLES_PROC_TBL_STR_PPID	"ppid="
#define USBTABLES_PROC_TBL_STR_PGID	"pgid="
#define USBTABLES_PROC_TBL_STR_UID	"uid="
#define USBTABLES_PROC_TBL_STR_EUID	"euid="
#define USBTABLES_PROC_TBL_STR_GID	"gid="
#define USBTABLES_PROC_TBL_STR_EGID	"egid="
#define USBTABLES_PROC_TBL_STR_COMM	"comm="
#define USBTABLES_DEV_TBL_STR_BUSNUM	"busnum="
#define USBTABLES_DEV_TBL_STR_DEVNUM	"devnum="
#define USBTABLES_DEV_TBL_STR_PORTNUM	"portnum="
#define USBTABLES_DEV_TBL_STR_IFNUM	"ifnum="
#define USBTABLES_DEV_TBL_STR_DEVPATH	"devpath="
#define USBTABLES_DEV_TBL_STR_PRODUCT	"product="
#define USBTABLES_DEV_TBL_STR_MANUFACT	"manufacturer="
#define USBTABLES_DEV_TBL_STR_SERIAL	"serial="
#define USBTABLES_PKT_TBL_STR_TYPE	"type="
#define USBTABLES_PKT_TBL_STR_DIRECTION	"direction="
#define USBTABLES_PKT_TBL_STR_ENDPOINT	"endpoint="
#define USBTABLES_PKT_TBL_STR_ADDRESS	"address="
#define USBTABLES_LUM_TBL_STR_NAME	"name="
#define USBTABLES_MBM_SEC_IN_USEC         1000000         /* usbtables micro benchmark */
#define USBTABLES_MBM_SUB_TV(s, e)                \
	((e.tv_sec*USBTABLES_MBM_SEC_IN_USEC+e.tv_usec) - \
	(s.tv_sec*USBTABLES_MBM_SEC_IN_USEC+s.tv_usec))

void dump_usbfilter_rule(struct usbfilter_rule *rule);
void dump_usbfilter_sim_rule(struct usbfilter_sim_rule *sim);
void dump_rule(nlmsgt *msg);
char *get_rule_name(nlmsgt *msg);
int get_tab_field_num(char *match, char *str);
void get_tab_field_str(char *match, char *str, char *buf, int len);

