/*
 * Implementation of Prolog engine interface for rule checking
 * Dec 31, 2015
 * root@davejingtian.org
 * http://davejingtian.org
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gprolog.h>
#include "logic.h"
#include "utils.h"

/* Global vars */
static int gpc_func_dynamic_usbfilter_rule_num;
static int gpc_func_no_conflict_num;
static int gpc_func_asserta_num;
static int gpc_func_retract_num;
static int logic_inited;
static PlTerm gpc_args[USBTABLES_GPC_ARG_MAX_NUM];
static PlTerm gpc_list_args[USBTABLES_LOGIC_ARG_LIST_LEN];
static char gpc_list_buff[USBTABLES_GPC_LIST_BUFF_LEN];
static int logic_debug = 1;
static int logic_perf = 1;
static int logic_daemon;

/* Feed the gpc args for rule deletion */
static void logic_parse_rule_for_del(struct usbfilter_rule *rule)
{
	int i;

	/* Defensive checking */
	if (!rule)
		return;

	/* Get the name */
	gpc_args[0] = Pl_Mk_String(rule->name);

	/* Wildcard all the left */
	for (i = 1; i < USBTABLES_LOGIC_ARG_LIST_LEN; i++)
		gpc_args[i] = Pl_Mk_String(USBTABLES_GPC_TERM_WILDCARD);
}

/* Feed the gpc args */
static void logic_parse_rule(struct usbfilter_rule *rule)
{
	int i;

	/* Defensive checking */
	if (!rule)
		return;

	/* Get the name */
	gpc_args[0] = Pl_Mk_String(rule->name);

	/* Get the process value list */
	if (rule->proc.valid) {
		gpc_list_args[0] = Pl_Mk_Integer(rule->proc.pid);
		gpc_list_args[1] = Pl_Mk_Integer(rule->proc.ppid);
		gpc_list_args[2] = Pl_Mk_Integer(rule->proc.pgid);
		gpc_list_args[3] = Pl_Mk_Integer(rule->proc.uid);
		gpc_list_args[4] = Pl_Mk_Integer(rule->proc.euid);
		gpc_list_args[5] = Pl_Mk_Integer(rule->proc.gid);
		gpc_list_args[6] = Pl_Mk_Integer(rule->proc.egid);
	}
	else {
		for (i = 0; i < USBTABLES_LOGIC_PRO_LIST_LEN; i++)
			gpc_list_args[i] = Pl_Mk_Integer(USBTABLES_LOGIC_VAL_INVALID);
	}
	gpc_args[1] = Pl_Mk_Proper_List(USBTABLES_LOGIC_PRO_LIST_LEN, gpc_list_args);

	/* Get the comm name */
	if (rule->proc.comm)
		gpc_args[2] = Pl_Mk_String(rule->proc.comm);
	else
		gpc_args[2] = Pl_Mk_String(USBTABLES_LOGIC_STR_INVALID);

	/* Get the device list value */
	if (rule->dev.valid) {
		gpc_list_args[0] = Pl_Mk_Integer(rule->dev.busnum);
		gpc_list_args[1] = Pl_Mk_Integer(rule->dev.devnum);
		gpc_list_args[2] = Pl_Mk_Integer(rule->dev.portnum);
		gpc_list_args[3] = Pl_Mk_Integer(rule->dev.ifnum);
	}
	else {
		for (i = 0; i < USBTABLES_LOGIC_DEV_LIST_LEN; i++);
			gpc_list_args[i] = Pl_Mk_Integer(USBTABLES_LOGIC_VAL_INVALID);
	}
	gpc_args[3] = Pl_Mk_Proper_List(USBTABLES_LOGIC_DEV_LIST_LEN, gpc_list_args);

	/* Get the device strings */
	if (rule->dev.devpath)
		gpc_args[4] = Pl_Mk_String(rule->dev.devpath);
	else
		gpc_args[4] = Pl_Mk_String(USBTABLES_LOGIC_STR_INVALID);
	if (rule->dev.product)
                gpc_args[5] = Pl_Mk_String(rule->dev.product);
        else
                gpc_args[5] = Pl_Mk_String(USBTABLES_LOGIC_STR_INVALID);
        if (rule->dev.manufacturer)
                gpc_args[6] = Pl_Mk_String(rule->dev.manufacturer);
        else
                gpc_args[6] = Pl_Mk_String(USBTABLES_LOGIC_STR_INVALID);
        if (rule->dev.serial)
                gpc_args[7] = Pl_Mk_String(rule->dev.serial);
        else
                gpc_args[7] = Pl_Mk_String(USBTABLES_LOGIC_STR_INVALID);

	/* Get the packet list values */
	if (rule->pkt.valid) {
		gpc_list_args[0] = Pl_Mk_Integer(rule->pkt.type);
		gpc_list_args[1] = Pl_Mk_Integer(rule->pkt.direction);
		gpc_list_args[2] = Pl_Mk_Integer(rule->pkt.endpoint);
		gpc_list_args[3] = Pl_Mk_Integer(rule->pkt.address);
	}
	else {
		for (i = 0; i < USBTABLES_LOGIC_PKT_LIST_LEN; i++)
			gpc_list_args[i] = Pl_Mk_Integer(USBTABLES_LOGIC_VAL_INVALID);
	}
	gpc_args[8] = Pl_Mk_Proper_List(USBTABLES_LOGIC_PKT_LIST_LEN, gpc_list_args);

	/* Get the LUM name */
	if (rule->lum.valid)
		gpc_args[9] = Pl_Mk_String(rule->lum.name);
	else
		gpc_args[9] = Pl_Mk_String(USBTABLES_LOGIC_STR_INVALID);

	/* Get the action */
	gpc_args[10] = Pl_Mk_Integer(rule->action);
}

/* Add the new rule to the Prolog engine */
int logic_add_rule(struct usbfilter_rule *rule, int parsed)
{
	int rtn;
	PlTerm args[2];

	/* Check if parsing needed */
	if (!parsed)
		logic_parse_rule(rule);

	/* Construct the internal callable */
	args[0] = Pl_Mk_Callable(gpc_func_dynamic_usbfilter_rule_num,
				USBTABLES_LOGIC_ARG_LIST_LEN, gpc_args);

        /* Query the Prolog engine */
	Pl_Query_Begin(PL_TRUE);
	rtn = Pl_Query_Call(gpc_func_asserta_num, 1, args);
	Pl_Query_End(PL_RECOVER);

	/* Check the result */
	if (rtn != PL_SUCCESS) {
		if (logic_debug)
			printf("Logic: %s failed\n", __func__);
		return -1;
	}

	return 0;
}

/* Delelte the rule from the Prolog engine */
int logic_del_rule(struct usbfilter_rule *rule)
{
	int rtn;
	PlTerm args[2];

	/* Parse the rule for deletion */
	logic_parse_rule_for_del(rule);

        /* Construct the internal callable */
        args[0] = Pl_Mk_Callable(gpc_func_dynamic_usbfilter_rule_num,
                                USBTABLES_LOGIC_ARG_LIST_LEN, gpc_args);

        /* Query the Prolog engine */
        Pl_Query_Begin(PL_TRUE);
        rtn = Pl_Query_Call(gpc_func_retract_num, 1, args);
        Pl_Query_End(PL_RECOVER);

        /* Check the result */
        if (rtn != PL_SUCCESS) {
                if (logic_debug)
                        printf("Logic: %s failed\n", __func__);
                return -1;
        }

        return 0;
}

/* Return 1 if no conflict; otherwise 0 */
int logic_no_conflict(struct usbfilter_rule *rule)
{
	int rtn;
	struct timeval start_tv, end_tv;

	/* Start perf */
	if (logic_perf)
		gettimeofday(&start_tv, NULL);

	/* Parse the rule */
	logic_parse_rule(rule);

	/* Query the Prolog engine */
	Pl_Query_Begin(PL_TRUE);
	rtn = Pl_Query_Call(gpc_func_no_conflict_num, USBTABLES_LOGIC_ARG_LIST_LEN, gpc_args);
	Pl_Query_End(PL_RECOVER);

	/* End perf */
	if (logic_perf) {
		gettimeofday(&end_tv, NULL);
		printf("usbtables-perf: Prolog took [%lu] us\n",
			USBTABLES_MBM_SUB_TV(start_tv, end_tv));
	}

	/* Add the rule if no conflict only for daemon mode */
	if ((rtn) && (logic_daemon) && (logic_add_rule(rule, 1)))
		if (logic_debug)
			printf("Logic: logic_add_rule failed in %s\n", __func__);

	return rtn;
}

/* Init the GNU Prolog */
void init_logic(void)
{
	if (logic_inited)
		return;

	printf("Initializing the logic .. \n");
	/* Zero out these before passing to Prolog in case of SegV */
	int argc = 0;
	char *argv[1] = {0};
	Pl_Start_Prolog(argc, argv);

	/* Init the gprolog API */
	gpc_func_dynamic_usbfilter_rule_num = Pl_Find_Atom(USBTABLES_GPC_FUNC_DYNAMIC_USBFILTER_RULE);
	gpc_func_asserta_num = Pl_Find_Atom(USBTABLES_GPC_FUNC_ASSERTA);
	gpc_func_retract_num = Pl_Find_Atom(USBTABLES_GPC_FUNC_RETRACT);
	gpc_func_no_conflict_num = Pl_Find_Atom(USBTABLES_GPC_FUNC_NO_CONFLICT);
	logic_inited = 1;

	printf("Done\n");
	if (logic_debug)
		printf("GPC debug:\n"
			"func(%s) = [%d]\n"
			"func(%s) = [%d]\n"
			"func(%s) = [%d]\n"
			"func(%s) = [%d]\n",
			USBTABLES_GPC_FUNC_DYNAMIC_USBFILTER_RULE, gpc_func_dynamic_usbfilter_rule_num,
			USBTABLES_GPC_FUNC_ASSERTA, gpc_func_asserta_num,
			USBTABLES_GPC_FUNC_RETRACT, gpc_func_retract_num,
			USBTABLES_GPC_FUNC_NO_CONFLICT, gpc_func_no_conflict_num);
}

/* Exit Prolog */
void exit_logic(void)
{
	if (!logic_inited)
		return;

	printf("Stopping the USBTABLES logic ...\n");
	Pl_Stop_Prolog();
	printf("Done\n");
	logic_inited = 0;
}
