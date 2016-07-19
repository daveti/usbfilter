/*
 * Header file for Prolog engine
 * Dec 31, 2015
 * root@davejingtian.org
 * http://davejingtian.org
 */
#include "nlm.h"

#define USBTABLES_LOGIC_VAL_INVALID			(-1)
#define USBTABLES_LOGIC_STR_INVALID			"na"
#define USBTABLES_GPC_FUNC_DYNAMIC_USBFILTER_RULE	"usbfilter_rule"
#define USBTABLES_GPC_FUNC_NO_CONFLICT			"no_conflict"
#define USBTABLES_GPC_FUNC_ASSERTA			"asserta"
#define USBTABLES_GPC_FUNC_RETRACT			"retract"
#define USBTABLES_GPC_SOLUTION_MAX_NUM			20
#define USBTABLES_GPC_ARG_MAX_NUM			12
#define USBTABLES_GCP_LIST_ARG_MAX_NUM			8
#define USBTABLES_GPC_LIST_BUFF_LEN			1024
#define USBTABLES_GPC_FUNC_BUFF_LEN			4096
#define USBTABLES_GPC_TERM_WILDCARD			"_"
#define USBTABLES_LOGIC_ARG_LIST_LEN			11
#define USBTABLES_LOGIC_PRO_LIST_LEN			7
#define USBTABLES_LOGIC_DEV_LIST_LEN			4
#define USBTABLES_LOGIC_PKT_LIST_LEN			4

void init_logic(void);
void exit_logic(void);
int logic_no_conflict(struct usbfilter_rule *rule);
int logic_add_rule(struct usbfilter_rule *rule, int parsed);
int logic_del_rule(struct usbfilter_rule *rule);
