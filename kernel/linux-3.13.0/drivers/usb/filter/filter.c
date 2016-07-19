/*
 * usbfilter
 * A USB layer 'netfilter' in the linux kernel
 * Jul 8, 2015
 * Internal debugging
 * Feb 10, 2016
 * root@davejingtian.org
 * http://davejingtian.org
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/usb.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/time.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/net.h>
#include <linux/fs.h>
#include <net/sock.h>
#include "usb_filter.h"

/* Default behavior when no rule matching is found */
static int usbfilter_default_behavior = USBFILTER_RULE_ACTION_ALLOW;
/* Lock for the default behavior */
DEFINE_SPINLOCK(usbfilter_default_behavior_lock);
/* Rule DB */
static struct list_head	usbfilter_rdb;
/* Lock for RDB */
DEFINE_SPINLOCK(usbfilter_rdb_lock);
/* LUM DB */
static struct list_head usbfilter_ldb;
/* Lock for LDB */
DEFINE_MUTEX(usbfilter_ldb_lock);
/* Global switch for usbfilter */
static int usbfilter_on;
/* Lock for the switch */
DEFINE_SPINLOCK(usbfilter_on_lock);
/* Global init flag */
static int usbfilter_inited;
/* Debug */
static int usbfilter_debug = 0;
/* Perf */
static int usbfilter_perf = 0;
/* Netlink socket */
static struct sock *usbfilter_nl_sock;
/* pid for usbtables */
static pid_t usbfilter_usbtables_pid;
/* Lock for the pid */
DEFINE_MUTEX(usbfilter_usbtables_pid_lock);
/* Default rules - always allow */
static pid_t default_pgid_tab[USBFILTER_SIM_RULE_ENTRY_NUM] = {
	0,	/* for all kernel threads */
	1,	/* initd or systemd */
	-1,	/* invalid */
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1};
static char default_comm_tab[USBFILTER_SIM_RULE_ENTRY_NUM][TASK_COMM_LEN] = {
	"init",			/* all */
	"systemd-udevd",	/* all */
	"udisks-part-id",	/* storage */
	"mount",		/* storage */
	"gvfsd-trash",		/* storage */
	"pool",			/* storage */
	"v4l_id",		/* webcam */
	"pulseaudio",		/* webcam, headset */
	"alsa-source-USB",	/* webcam */
	"null",			/* null */
	"null",
	"null",
	"null",
	"null",
	"null",
	"null"};

/* helpers */
static int usbfilter_match_default_pgid_tab(pid_t pgid, struct sim_pgid_tab *tab)
{
	int i;

	for (i = 0; i < USBFILTER_SIM_RULE_ENTRY_NUM; i++) {
		if (tab->pgid[i] == -1)
			break;
		if (tab->pgid[i] == pgid)
			return 1;
	}

	return 0;
}

static int usbfilter_match_default_comm_tab(char *comm, struct sim_comm_tab *tab)
{
	int i;

	for (i = 0; i < USBFILTER_SIM_RULE_ENTRY_NUM; i++) {
		if (!strcasecmp(tab->comm[i], "null"))
			break;
		if (!strcasecmp(tab->comm[i], comm))
			return 1;
	}

	return 0;
}

static int usbfilter_is_started(void)
{
	int on;
	unsigned long flags;

	if (usbfilter_inited) {
		spin_lock_irqsave(&usbfilter_on_lock, flags);
		on = usbfilter_on;
		spin_unlock_irqrestore(&usbfilter_on_lock, flags);
		if (on)
			return 1;
	}
	return 0;
}

static int usbfilter_enable(void)
{
	unsigned long flags;

	if (!usbfilter_inited)
		return -1;

	spin_lock_irqsave(&usbfilter_on_lock, flags);
	usbfilter_on = 1;
	spin_unlock_irqrestore(&usbfilter_on_lock, flags);

	pr_info("usbfilter - Info: usbfilter has been enabled\n");

	return 0;
}

static int usbfilter_disable(void)
{
	unsigned long flags;

	if (!usbfilter_inited)
		return -1;

	spin_lock_irqsave(&usbfilter_on_lock, flags);
	usbfilter_on = 0;
	spin_unlock_irqrestore(&usbfilter_on_lock, flags);

	pr_info("usbfilter - Info: usbfilter has been disabled\n");

	return 0;
}

static int usbfilter_change_default_behav(int behav)
{
	unsigned long flags;

	if (!usbfilter_inited)
		return -1;

	switch (behav) {

	case USBFILTER_RULE_ACTION_ALLOW:
		spin_lock_irqsave(&usbfilter_default_behavior_lock, flags);
		usbfilter_default_behavior = USBFILTER_RULE_ACTION_ALLOW;
		spin_unlock_irqrestore(&usbfilter_default_behavior_lock, flags);
		break;

	case USBFILTER_RULE_ACTION_DROP:
		spin_lock_irqsave(&usbfilter_default_behavior_lock, flags);
		usbfilter_default_behavior = USBFILTER_RULE_ACTION_DROP;
		spin_unlock_irqrestore(&usbfilter_default_behavior_lock, flags);
		break;

	default:
		pr_err("usbfilter - Error: unknown behavior [%d]\n", behav);
		return -1;
	}

	return 0;
}

static char *usbfilter_get_rule_name_ele(struct usbfilter_rdb_ele *ele)
{
	if (!ele)
		return NULL;

	switch (ele->type) {

	case USBFILTER_TYPE_RULE:
		return ele->rule.name;

	case USBFILTER_TYPE_SIM_RULE:
		return ele->sim_rule.name;

	default:
		pr_err("usbfilter - Error: unknown type [%d]\n", ele->type);
	}

	return NULL;
}

static char *usbfilter_get_rule_name_nlmsg(struct usbfilter_nlmsg *msg)
{
	if (!msg)
		return NULL;

	switch (msg->type) {

	case USBFILTER_TYPE_RULE:
		return msg->rule.name;

	case USBFILTER_TYPE_SIM_RULE:
		return msg->sim_rule.name;

	default:
		pr_err("usbfilter - Error: unknown type [%d]\n", msg->type);
	}

	return NULL;
}

static char *usbfilter_get_lum_name_nlmsg(struct usbfilter_nlmsg *msg)
{
	if (!msg)
		return NULL;

	if (msg->type == USBFILTER_TYPE_RULE) {
		if (msg->rule.lum.valid)
			return msg->rule.lum.name;
	}

	return NULL;
}

/* ldb routines */
static struct usbfilter_lum *usbfilter_ldb_find(char *name)
{
	struct usbfilter_ldb_ele *ptr;
	struct usbfilter_lum *lum = NULL;

	mutex_lock(&usbfilter_ldb_lock);
	/* Go thru the list and check the name */
	list_for_each_entry(ptr, &usbfilter_ldb, list) {
		if (!strcasecmp(name, ptr->lum.name)) {
			lum = &ptr->lum;
			break;
		}
	}
	mutex_unlock(&usbfilter_ldb_lock);

	return lum;
}

static void usbfilter_ldb_destroy(void)
{
	struct usbfilter_ldb_ele *ptr, *next;

	mutex_lock(&usbfilter_ldb_lock);
	/* Go thru the list and free the memory */
	list_for_each_entry_safe(ptr, next, &usbfilter_ldb, list) {
		list_del(&ptr->list);
		kfree(ptr);
	}
	mutex_unlock(&usbfilter_ldb_lock);
}

/* rdb routines */
static struct usbfilter_rdb_ele *usbfilter_rdb_find(char *name)
{
	unsigned long flags;
	struct usbfilter_rdb_ele *ptr;
	struct usbfilter_rdb_ele *rtn = NULL;

	spin_lock_irqsave(&usbfilter_rdb_lock, flags);
	/* Go thru the list and check the name */
	list_for_each_entry(ptr, &usbfilter_rdb, list) {
		if (!strcasecmp(name, usbfilter_get_rule_name_ele(ptr))) {
			rtn = ptr;
			break;
		}
	}
	spin_unlock_irqrestore(&usbfilter_rdb_lock, flags);

	return rtn;
}

static int usbfilter_rdb_add(struct usbfilter_rdb_ele *ele)
{
	char *name;
	unsigned long flags;
	struct usbfilter_rdb_ele *rule;

	/* Get the name of the new rule */
	name = usbfilter_get_rule_name_ele(ele);
	if (!name) {
		pr_err("usbfilter - Error: no name in the rule\n");
		return -1;
	}

	/* Check for duplicate */
	rule = usbfilter_rdb_find(name);
	if (rule) {
		pr_err("usbfilter - Error: rule [%s] already exists\n", name);
		return -1;
	}

	/* Add the new rule */
	spin_lock_irqsave(&usbfilter_rdb_lock, flags);
	list_add_tail(&ele->list, &usbfilter_rdb);
	spin_unlock_irqrestore(&usbfilter_rdb_lock, flags);

	if (usbfilter_debug)
		pr_info("usbfilter - Debug: rule [%s] has been added\n", name);

	return 0;
}

static int usbfilter_rdb_del(char *name)
{
	struct usbfilter_rdb_ele *ptr, *next;
	unsigned long flags;

	spin_lock_irqsave(&usbfilter_rdb_lock, flags);
	/* Go thru the list and check the name */
	list_for_each_entry_safe(ptr, next, &usbfilter_rdb, list) {
		if (!strcasecmp(name, usbfilter_get_rule_name_ele(ptr))) {
			list_del(&ptr->list);
			kfree(ptr);
			if (usbfilter_debug)
				pr_info("usbfilter - Debug: rule [%s] is removed\n", name);
			break;
		}
	}
	spin_unlock_irqrestore(&usbfilter_rdb_lock, flags);

	return 0;
}

static int usbfilter_rdb_load_default_rules(void)
{
	struct usbfilter_rdb_ele *ele;
	struct usbfilter_sim_rule *sim;
	unsigned long flags;

	/* Alloc memory */
	ele = kmalloc(sizeof(*ele), GFP_KERNEL);
	if (!ele) {
		pr_err("usbfilter - Error: kmalloc failed in [%s] for simple pgid rule\n",
			__func__);
		return -1;
	}

	/* Init this simple pgid rule */
	memset(ele, 0x0, sizeof(*ele));
	ele->type = USBFILTER_TYPE_SIM_RULE;
	sim = &ele->sim_rule;
	sim->action = USBFILTER_RULE_ACTION_ALLOW;
	sim->type = USBFILTER_SIM_RULE_TYPE_PGID;
	snprintf(sim->name, USBFILTER_RULE_NAME_LEN, "%s", "kernel");
	memcpy(sim->pgid_tab.pgid, default_pgid_tab,
		(USBFILTER_SIM_RULE_ENTRY_NUM*sizeof(pid_t)));

	/* Add it into the rdb */
	spin_lock_irqsave(&usbfilter_rdb_lock, flags);
	list_add_tail(&ele->list, &usbfilter_rdb);
	spin_unlock_irqrestore(&usbfilter_rdb_lock, flags);

	/* Alloc memory (again) */
	ele = kmalloc(sizeof(*ele), GFP_KERNEL);
	if (!ele) {
		pr_err("usbfilter - Error: kmalloc failed in [%s] for simple comm rule\n",
			__func__);
		return -1;
	}

	/* Init this simple comm rule */
	memset(ele, 0x0, sizeof(*ele));
	ele->type = USBFILTER_TYPE_SIM_RULE;
	sim = &ele->sim_rule;
	sim->action = USBFILTER_RULE_ACTION_ALLOW;
	sim->type = USBFILTER_SIM_RULE_TYPE_COMM;
	snprintf(sim->name, USBFILTER_RULE_NAME_LEN, "%s", "system");
	memcpy(sim->comm_tab.comm, default_comm_tab,
		(USBFILTER_SIM_RULE_ENTRY_NUM*TASK_COMM_LEN));

	/* Add it into the rdb */
	spin_lock_irqsave(&usbfilter_rdb_lock, flags);
	list_add_tail(&ele->list, &usbfilter_rdb);
	spin_unlock_irqrestore(&usbfilter_rdb_lock, flags);

	if (usbfilter_debug)
		pr_info("usbfilter - Debug: %s done\n", __func__);

	return 0;
}

static void usbfilter_rdb_destroy(void)
{
	struct usbfilter_rdb_ele *ptr, *next;
	unsigned long flags;

	spin_lock_irqsave(&usbfilter_rdb_lock, flags);
	/* Go thru the list and free the memory */
	list_for_each_entry_safe(ptr, next, &usbfilter_rdb, list) {
		list_del(&ptr->list);
		kfree(ptr);
	}
	spin_unlock_irqrestore(&usbfilter_rdb_lock, flags);
}

/* netlink routines */
static struct usbfilter_nlmsg *usbfilter_nl_build_ack(int result)
{
        struct usbfilter_nlmsg *ack;

        switch (result) {

        case USBFILTER_NETLINK_RES_SUCCESS:
        case USBFILTER_NETLINK_RES_FAILURE:
                break;

        default:
                pr_err("usbfilter - Error: unknown result %d\n", result);
                return NULL;
        }

        ack = kmalloc(sizeof(*ack), GFP_KERNEL);
        if (!ack) {
                pr_err("usbfilter - Error: kmalloc failed in %s\n", __func__);
                return NULL;
        }

        memset(ack, 0x0, sizeof(*ack));
        ack->opcode = USBFILTER_NETLINK_OPC_ACK;
        ack->type = USBFILTER_TYPE_SIM_RULE;
        ack->result = result;

        return ack;
}

static int usbfilter_nl_send(struct usbfilter_nlmsg *msg)
{
        struct nlmsghdr *nlh;
        struct sk_buff *skb_out;
        pid_t usbtables_pid;
        int rtn;

        /* Get the pid */
        mutex_lock(&usbfilter_usbtables_pid_lock);
        usbtables_pid = usbfilter_usbtables_pid;
        mutex_unlock(&usbfilter_usbtables_pid_lock);

        /* Defensive checking */
        if (!usbtables_pid) {
                pr_err("usbfilter - Error: usbtables pid is unknown yet\n");
                return -1;
        }

        /* Alloc new skb */
        skb_out = nlmsg_new(sizeof(*msg), 0);
        if (!skb_out) {
                pr_err("usbfilter - Error: failed to allocate new skb\n");
                return -1;
        }

        /* Construct the nlmsg */
        nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, sizeof(*msg), 0);
        NETLINK_CB(skb_out).dst_group = 0;
        memcpy(nlmsg_data(nlh), msg, sizeof(*msg));

        /* Send it */
        rtn = nlmsg_unicast(usbfilter_nl_sock, skb_out, usbtables_pid);
        if (rtn) {
                pr_err("usbfilter - Error: failed to send nlmsg with rtn %d\n", rtn);
                return -1;
        }

        if (usbfilter_debug)
                pr_info("usbfilter - Debug: %s sent a nlmsg to usbtables\n", __func__);

        return 0;
}

static int usbfilter_nl_build_send_ack(int result)
{
        struct usbfilter_nlmsg *ack;
        int rtn;

        /* Build the ACK */
        ack = usbfilter_nl_build_ack(result);
        if (!ack) {
                pr_err("usbfilter - Error: [%s] usbfilter_nl_build_ack failed\n",
                        __func__);
                return -1;
        }

        /* Send the ACK */
        rtn = usbfilter_nl_send(ack);
        if (rtn)
                pr_err("usbfitler - Error: [%s] usbfilter_nl_send failed\n",
                        __func__);

        /* Free the mem */
        kfree(ack);
        return rtn;
}

static int usbfilter_nl_handle_add(struct usbfilter_nlmsg *msg)
{
	int rtn;
	int res;
	char *name;
	struct usbfilter_rdb_ele *ele;
	struct usbfilter_lum *lum = NULL;

	if (usbfilter_debug)
		pr_info("usbfilter - Debug: into %s\n", __func__);

	/* Init the default result */
	res = USBFILTER_NETLINK_RES_FAILURE;

	/* Check the existence of lum */
	name = usbfilter_get_lum_name_nlmsg(msg);
	if (name) {
		lum = usbfilter_ldb_find(name);
		if (!lum) {
			pr_err("usbfilter - Error: lum [%s] does not exist\n", name);
			goto add_out;
		}
	}

	/* Alloc mem for ele */
	ele = kmalloc(sizeof(*ele), GFP_KERNEL);
	if (!ele) {
		pr_err("usbfilter - Error: kmalloc failed\n");
		goto add_out;
	}

	/* Copy the rule */
	memset(ele, 0x0, sizeof(*ele));
	ele->type = msg->type;
	switch (ele->type) {

	case USBFILTER_TYPE_RULE:
		memcpy(&ele->rule, &msg->rule, sizeof(struct usbfilter_rule));
		ele->rule.mod = lum;
		break;

	case USBFILTER_TYPE_SIM_RULE:
		memcpy(&ele->sim_rule, &msg->sim_rule, sizeof(struct usbfilter_sim_rule));
		break;

	default:
		pr_err("usbfilter - Error: unknown rule type [%d]\n", ele->type);
		kfree(ele);
		goto add_out;
	}

	/* Try to add the rule */
	rtn = usbfilter_rdb_add(ele);
	if (rtn) {
		pr_err("usbfilter - Error: usbfilter_rdb_add failed\n");
		kfree(ele);
		goto add_out;
	}
	res = USBFILTER_NETLINK_RES_SUCCESS;

add_out:
	/* Send Ack and return */
	rtn = usbfilter_nl_build_send_ack(res);
	if (rtn)
		pr_err("usbfilter - Error: usbfilter_nl_build_send_ack failed\n");
	return rtn;
}

static int usbfilter_nl_handle_del(struct usbfilter_nlmsg *msg)
{
	int rtn;
	int res;
	char *name;

	if (usbfilter_debug)
		pr_info("usbfilter - Debug: into %s\n", __func__);

	/* Init the default result */
	res = USBFILTER_NETLINK_RES_FAILURE;

	/* Get the name of the rule */
	name = usbfilter_get_rule_name_nlmsg(msg);
	if (!name) {
		pr_err("usbfilter - Error: usbfilter_get_rule_name_nlmsg failed\n");
		goto del_out;
	}

	/* Try to del the rule */
	rtn = usbfilter_rdb_del(name);
	if (rtn) {
		pr_err("usbfilter - Error: usbfilter_rdb_del failed\n");
		goto del_out;
	}
	res = USBFILTER_NETLINK_RES_SUCCESS;

del_out:
	/* Send Ack and return */
	rtn = usbfilter_nl_build_send_ack(res);
	if (rtn)
		pr_err("usbfilter - Error: usbfilter_nl_build_send_ack failed\n");
	return rtn;
}

static int usbfilter_nl_handle_syn(struct usbfilter_nlmsg *msg)
{
	if (usbfilter_debug)
		pr_info("usbfilter - Debug: into %s\n", __func__);

	/* Reuse Add now */
	return usbfilter_nl_handle_add(msg);
}

static int usbfilter_nl_handle_ena(struct usbfilter_nlmsg *msg)
{
	int rtn;

	if (usbfilter_debug)
		pr_info("usbfilter - Debug: into %s\n", __func__);

	/* Enable the usbfilter */
	rtn = usbfilter_enable();
	if (rtn == 0)
		rtn = usbfilter_nl_build_send_ack(USBFILTER_NETLINK_RES_SUCCESS);
	else
		rtn = usbfilter_nl_build_send_ack(USBFILTER_NETLINK_RES_FAILURE);
	if (rtn)
		pr_err("usbfilter - Error: usbfilter_nl_build_send_ack failed in %s\n",
			__func__);

	return rtn;
}

static int usbfilter_nl_handle_dis(struct usbfilter_nlmsg *msg)
{
	int rtn;

	if (usbfilter_debug)
		pr_info("usbfilter - Debug: into %s\n", __func__);

	/* Disable the usbfilter */
	rtn = usbfilter_disable();
	if (rtn == 0)
		rtn = usbfilter_nl_build_send_ack(USBFILTER_NETLINK_RES_SUCCESS);
	else
		rtn = usbfilter_nl_build_send_ack(USBFILTER_NETLINK_RES_FAILURE);
	if (rtn)
		pr_err("usbfilter - Error: usbfilter_nl_build_send_ack failed in %s\n",
			__func__);

	return rtn;
}

static int usbfilter_nl_handle_chg(struct usbfilter_nlmsg *msg)
{
	int rtn;

	if (usbfilter_debug)
		pr_info("usbfilter - Debug: into %s\n", __func__);

	/* Change the default behav */
	rtn = usbfilter_change_default_behav(msg->behavior);
	if (rtn == 0)
		rtn = usbfilter_nl_build_send_ack(USBFILTER_NETLINK_RES_SUCCESS);
	else
		rtn = usbfilter_nl_build_send_ack(USBFILTER_NETLINK_RES_FAILURE);
	if (rtn)
		pr_err("usbfilter - Error: usbfilter_nl_build_send_ack failed in %s\n",
			__func__);

	return rtn;
}

static int usbfilter_nl_handle_dmp(struct usbfilter_nlmsg *msg)
{
	int rtn;
	unsigned long flags;
	struct usbfilter_nlmsg *ack;
	struct usbfilter_rdb_ele *ptr;

	if (usbfilter_debug)
		pr_info("usbfilter - Debug: into %s\n", __func__);

	/* Build a special Ack */
	ack = usbfilter_nl_build_ack(USBFILTER_NETLINK_RES_SUCCESS);
	if (!ack) {
		pr_err("usbfilter - Error: usbfilter_nl_build_ack failed\n");
		return -1;
	}

	/* Fulfill the usbfilter config */
	ack->type = USBFILTER_TYPE_SIM_RULE;
	spin_lock_irqsave(&usbfilter_on_lock, flags);
	ack->sim_rule.action = usbfilter_on;	/* reuse the field */
	spin_unlock_irqrestore(&usbfilter_on_lock, flags);
	/* NOTE: follow this locking order to avoid deablock */
	spin_lock_irqsave(&usbfilter_default_behavior_lock, flags);
	ack->behavior = usbfilter_default_behavior;
	spin_unlock_irqrestore(&usbfilter_default_behavior_lock, flags);
	snprintf(ack->sim_rule.name, USBFILTER_RULE_NAME_LEN, "%s",
		USBFILTER_CONFIG_DMP_NAME);

        /* Send the first ack */
        rtn = usbfilter_nl_send(ack);
        if (rtn)
                pr_err("usbfilter - Error: 1st usbfilter_nl_send failed\n");

        /* Send all rules in the kernel to the user-space */
        spin_lock_irqsave(&usbfilter_rdb_lock, flags);
        list_for_each_entry(ptr, &usbfilter_rdb, list) {
		memset(ack, 0x0, sizeof(*ack));
		ack->opcode = USBFILTER_NETLINK_OPC_ACK;
		ack->type = ptr->type;
		ack->result = USBFILTER_NETLINK_RES_SUCCESS;
		if (ack->type == USBFILTER_TYPE_RULE)
			memcpy(&ack->rule, &ptr->rule, sizeof(struct usbfilter_rule));
		else
			memcpy(&ack->sim_rule, &ptr->sim_rule, sizeof(struct usbfilter_sim_rule));
		/* Send the ack */
		rtn = usbfilter_nl_send(ack);
		if (rtn)
			pr_err("usbfilter - Error: following usbfilter_nl_send failed\n");
        }
        spin_unlock_irqrestore(&usbfilter_rdb_lock, flags);

	/* Send the last ack to let usbtables know */
	memset(ack, 0x0, sizeof(*ack));
	ack->opcode = USBFILTER_NETLINK_OPC_ACK;
	ack->type = USBFILTER_TYPE_SIM_RULE;
	ack->result = USBFILTER_NETLINK_RES_LAST;
	rtn = usbfilter_nl_send(ack);
	if (rtn)
		pr_err("usbfilter - Error: last usbfilter_nl_send failed\n");


	kfree(ack);
	return rtn;
}

static int usbfilter_nl_handle_init(struct nlmsghdr *nlh)
{
	char *init_msg = "__usbfilter_kernel_ack__";
	struct usbfilter_nlmsg *ack;
	int rtn;

	if (usbfilter_debug)
		pr_info("usbfilter - Debug: into %s\n", __func__);

	if (!nlh) {
		pr_err("usbfilter - Error: null nlmsg header\n");
		return -1;
	}

	/* Retrieve the pid */
	mutex_lock(&usbfilter_usbtables_pid_lock);
	usbfilter_usbtables_pid = nlh->nlmsg_pid;
	mutex_unlock(&usbfilter_usbtables_pid_lock);
	/* Retrieve the hello msg */
	ack = (struct usbfilter_nlmsg *)nlmsg_data(nlh);
	if (usbfilter_debug)
		pr_info("usbfilter - Debug: usbtables pid [%i], msg [%s]\n",
			usbfilter_usbtables_pid, ack->sim_rule.name);

	/* Build a special ACK */
	ack = usbfilter_nl_build_ack(USBFILTER_NETLINK_RES_SUCCESS);
	if (!ack) {
		pr_err("usbfilter - Error: usbfilter_nl_build_ack failed\n");
		return -1;
	}

	/* Reuse the pgid tab */
	memcpy(ack->sim_rule.name, init_msg, strlen(init_msg));

	/* Send it */
	rtn = usbfilter_nl_send(ack);
	if (rtn)
		pr_err("usbfilter - Error: usbfilter_nl_send failed\n");

	kfree(ack);
	return rtn;
}

static void usbfilter_nl_handler(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	struct usbfilter_nlmsg *uf_nlmsg_ptr;
	int opcode;
	int rtn;

	/* Retrieve the opcode */
	nlh = (struct nlmsghdr *)skb->data;
	uf_nlmsg_ptr = (struct usbfilter_nlmsg *)nlmsg_data(nlh);
	opcode = uf_nlmsg_ptr->opcode;
	if (usbfilter_debug)
		pr_info("usbfilter - Debug: %s got a netlink msg with opcode %d\n",
			__func__, opcode);

	switch (opcode) {

	case USBFILTER_NETLINK_OPC_INIT:
		rtn = usbfilter_nl_handle_init(nlh);
		break;

	case USBFILTER_NETLINK_OPC_ADD:
		rtn = usbfilter_nl_handle_add(uf_nlmsg_ptr);
		break;

	case USBFILTER_NETLINK_OPC_DEL:
		rtn = usbfilter_nl_handle_del(uf_nlmsg_ptr);
		break;

	case USBFILTER_NETLINK_OPC_SYN:
		rtn = usbfilter_nl_handle_syn(uf_nlmsg_ptr);
		break;
	
	case USBFILTER_NETLINK_OPC_ENA:
		rtn = usbfilter_nl_handle_ena(uf_nlmsg_ptr);
		break;

	case USBFILTER_NETLINK_OPC_DIS:
		rtn = usbfilter_nl_handle_dis(uf_nlmsg_ptr);
		break;

	case USBFILTER_NETLINK_OPC_CHG:
		rtn = usbfilter_nl_handle_chg(uf_nlmsg_ptr);
		break;

	case USBFILTER_NETLINK_OPC_DMP:
		rtn = usbfilter_nl_handle_dmp(uf_nlmsg_ptr);
		break;

	case USBFILTER_NETLINK_OPC_ACK:
		/* Fall thru */
	default:
		rtn = -1;
		pr_err("usbfilter - Error: unknown opcode %d\n", opcode);
		break;
	}

	if (rtn != 0)
		pr_err("usbfilter - Error: netlink processing failure\n");
}

/* Rule matching cores */
static pid_t usbfilter_get_pgid(struct task_struct *task)
{
	struct pid *uf_grp;
	pid_t uf_pgid;

	/* Get the PGID
	 * NOTE: this is tricky and not trivial!
	 * The safest way to do this is follow sys_getpgid.
	 * Jul 1, 2015
	 * daveti
	 */
	rcu_read_lock();
	uf_grp = task_pgrp(task);
	if (!uf_grp)
		uf_pgid = -1;
	else
		uf_pgid = pid_vnr(uf_grp);
	rcu_read_unlock();

	return uf_pgid;
}

static pid_t usbfilter_get_current_pgid(void)
{
	return usbfilter_get_pgid(current);
}

/* All below are learned from kernel/sys.c */
static uid_t usbfilter_get_uid(struct task_struct *task)
{
	return from_kuid_munged(task_cred_xxx(task, user_ns), task_uid(task));
}

static uid_t usbfilter_get_euid(struct task_struct *task)
{
	return from_kuid_munged(task_cred_xxx(task, user_ns), task_euid(task));
}

static gid_t usbfilter_get_gid(struct task_struct *task)
{
	return from_kgid_munged(task_cred_xxx(task, user_ns),
			task_cred_xxx(task, gid));
}

static gid_t usbfilter_get_egid(struct task_struct *task)
{
	return from_kgid_munged(task_cred_xxx(task, user_ns),
			task_cred_xxx(task, egid));
}

static pid_t usbfilter_get_pid_urb(struct urb *urb)
{
	pid_t pid;

        if ((urb->submit_pid == -1) || (urb->submit_pid == 0)) {
                /* The urb is submitted in IRQ ctx */
                if ((urb->app_pid == -1) || (urb->app_pid == 0)) {
                        /* The urb is NOT from block devices */
			pid = -1;
                } else {
			/* Use the app_pid */
			pid = urb->app_pid;
		}
        } else {
                /* The submit_pid is valid */
                if ((urb->app_pid == -1) || (urb->app_pid == 0)) {
                        /* Use the submit_pid */
                        pid = urb->submit_pid;
                } else {
			/* Use the app_pid when both pids are valid */
			pid = urb->app_pid;
		}
        }

	return pid;
}

static int usbfitler_match_rule_proc(struct urb *urb, struct proc_tab *tab)
{
	pid_t pid;
	struct task_struct *task;
	char comm[TASK_COMM_LEN];

	if (usbfilter_debug)
		pr_info("usbfilter - Debug: into [%s] with urb [%p] proc_tab [%p], "
			"submit_pid [%i] app_pid [%i]\n",
			__func__, urb, tab, urb->submit_pid, urb->app_pid);

	/* NOTE: proc table heavily depends on the submit_pid and app_pid within the urb
	 * submit_pid has the first priority for checking as it works for all subsys;
	 * app_pid currently only works for block devices!
	 */
	pid = usbfilter_get_pid_urb(urb);
	if (pid == -1)
		goto proc_quick_match;

	if (usbfilter_debug)
		pr_info("usbfilter - Debug: use pid [%i]\n", pid);

	/* Go thru each field in the tab */
	if (tab->pid != -1) {
		if (tab->pid != pid)
			goto proc_quick_match;
	}

	/* Get the task before moving forward */
	task = find_task_by_vpid(pid);
	if (!task) {
		pr_err("usbfilter - Error: cannot find task with pid [%i]\n", pid);
		goto proc_quick_match;
	}

	if (tab->ppid != -1) {
		if (tab->ppid != task_pid_vnr(rcu_dereference(task->real_parent)))
			goto proc_quick_match;
	}

	if (tab->pgid != -1) {
		if (tab->pgid != usbfilter_get_pgid(task))
			goto proc_quick_match;
	}

	if (tab->uid != -1) {
		if (tab->uid != usbfilter_get_uid(task))
			goto proc_quick_match;
	}

	if (tab->euid != -1) {
		if (tab->euid != usbfilter_get_euid(task))
			goto proc_quick_match;
	}

	if (tab->gid != -1) {
		if (tab->gid != usbfilter_get_gid(task))
			goto proc_quick_match;
	}

	if (tab->egid != -1) {
		if (tab->egid != usbfilter_get_egid(task))
			goto proc_quick_match;
	}

	if (tab->comm[0] != '\0') {
		memset(comm, 0x0, TASK_COMM_LEN);
		(void)get_task_comm(comm, task);
		if (strcasecmp(tab->comm, comm))
			goto proc_quick_match;
	}

	return 1;

proc_quick_match:
	return 0;
}

static int usbfilter_match_rule_dev(struct urb *urb, struct dev_tab *tab)
{
	struct usb_host_endpoint *ep;

	if (usbfilter_debug)
		pr_info("usbfilter - Debug: into [%s] with urb [%p] dev_tab [%p]\n",
			__func__, urb, tab);

	/* Get ep */
	ep = usb_pipe_endpoint(urb->dev, urb->pipe);

	/* Go thru each field */
	if (tab->busnum != -1) {
		if (tab->busnum != urb->dev->bus->busnum)
			goto dev_quick_match;
	}

	if (tab->devnum != -1) {
		if (tab->devnum != urb->dev->devnum)
			goto dev_quick_match;
	}

	if (tab->portnum != -1) {
		if (tab->portnum != urb->dev->portnum)
			goto dev_quick_match;
	}

	if (tab->ifnum != -1) {
		if (tab->ifnum != ep->if_num)
			goto dev_quick_match;
	}

	if (tab->devpath[0] != '\0') {
		if (!urb->dev->devpath)
			goto dev_quick_match;
		if ((urb->dev->devpath) && (strcasecmp(tab->devpath, urb->dev->devpath)))
			goto dev_quick_match;
	}

	if (tab->product[0] != '\0') {
		if (!urb->dev->product)
			goto dev_quick_match;
		if ((urb->dev->product) && (strcasecmp(tab->product, urb->dev->product)))
			goto dev_quick_match;
	}

	if (tab->manufacturer[0] != '\0') {
		if (!urb->dev->manufacturer)
			goto dev_quick_match;
		if ((urb->dev->manufacturer) && (strcasecmp(tab->manufacturer, urb->dev->manufacturer)))
			goto dev_quick_match;
	}

	if (tab->serial[0] != '\0') {
		if (!urb->dev->serial)
			goto dev_quick_match;
		if ((urb->dev->serial) && (strcasecmp(tab->serial, urb->dev->serial)))
			goto dev_quick_match;
	}

	return 1;

dev_quick_match:
	return 0;
}

static int usbfilter_get_urb_dir(struct urb *urb)
{
	int ret;

	/* Check for IN */
	if (usb_pipein(urb->pipe))
		return USBFILTER_PKT_TAB_DIR_IN;

	/* Then OUT */
	return USBFILTER_PKT_TAB_DIR_OUT;
}

static int usbfilter_match_rule_pkt(struct urb *urb, struct pkt_tab *tab)
{
	if (usbfilter_debug)
		pr_info("usbfilter - Debug: into [%s] with urb [%p] pkt_tab [%p]\n",
			__func__, urb, tab);

	/* Go thru each field */
	if (tab->type != -1) {
		if (tab->type != usb_pipetype(urb->pipe))
			goto pkt_quick_match;
	}

	if (tab->direction != -1) {
		if (tab->direction != usbfilter_get_urb_dir(urb))
			goto pkt_quick_match;
	}

	if (tab->endpoint != -1) {
		if (tab->endpoint != usb_pipeendpoint(urb->pipe))
			goto pkt_quick_match;
	}

	if (tab->address != -1) {
		if (tab->address != usb_pipedevice(urb->pipe))
			goto pkt_quick_match;
	}

	return 1;

pkt_quick_match:
	return 0;
}

static int usbfilter_match_rule(struct urb *urb, struct usbfilter_rule *rule)
{
	int match;

	if (usbfilter_debug)
		pr_info("usbfilter - Debug: into [%s] with urb [%p] rule [%p]\n",
			__func__, urb, rule);

	/* Go thru each sub rule */
	if (rule->proc.valid) {
		match = usbfitler_match_rule_proc(urb, &rule->proc);
		/* Short cut */
		if (!match)
			goto quick_match;
	}

	if (rule->dev.valid) {
		match = usbfilter_match_rule_dev(urb, &rule->dev);
		if (!match)
			goto quick_match;
	}

	if (rule->pkt.valid) {
		match = usbfilter_match_rule_pkt(urb, &rule->pkt);
		if (!match)
			goto quick_match;
	}

	if (rule->lum.valid) {
		match = ((struct usbfilter_lum *)(rule->mod))->lum_filter_urb(urb);
		if (!match)
			goto quick_match;
	}

	return 1;

quick_match:
	return 0;
}

static int usbfilter_match_sim_rule(struct urb *urb, struct usbfilter_sim_rule *sim)
{
	pid_t pid;
	pid_t pgid;
	struct task_struct *task;
	int match = 0;

	if (usbfilter_debug)
		pr_info("usbfilter - Debug: into [%s] with urb [%p] sim [%p]\n",
			__func__, urb, sim);

	/* Retrieve the pid from the urb */
	pid = usbfilter_get_pid_urb(urb);
	if (pid == -1)
		return match;

	/* Get the task struct */
	task = find_task_by_vpid(pid);
	if (!task) {
		pr_err("usbfilter - Error: cannot find task with pid [%i]\n", pid);
		return match;
	}

	/* Match different types */
	switch (sim->type) {

	case USBFILTER_SIM_RULE_TYPE_PGID:
		/* Get the pgid */
		pgid = usbfilter_get_pgid(task);
		if (pgid == -1)
			return match;
		/* Match */
		match = usbfilter_match_default_pgid_tab(pgid, &sim->pgid_tab);
		break;

	case USBFILTER_SIM_RULE_TYPE_COMM:
		/* Match */
		match = usbfilter_match_default_comm_tab(task->comm, &sim->comm_tab);
		break;

	default:
		pr_err("usbfilter - Error: unknow sim rule type [%d]\n",
			sim->type);
		break;
	}

	return match;
}

/* Rule conditions dumping helpers */
static void usbfilter_dump_proc_conditions(struct urb *urb)
{
	pid_t pid;
	struct task_struct *task;
	char comm[TASK_COMM_LEN];

	/* Check the pid of the urb */
	pid = usbfilter_get_pid_urb(urb);
	if (pid == -1) {
		pr_info("process conditions not available\n");
		return;
	}

	/* Get the task of the pid */
	task = find_task_by_vpid(pid);
	if (!task) {
		pr_info("process conditions not available due to missing task for pid [%i]\n", pid);
		return;
	}

	/* Get the task name */
	memset(comm, 0x0, TASK_COMM_LEN);
	(void)get_task_comm(comm, task);

	/* Let's dump */
	pr_info("pid=[%i],ppid=[%i],pgid=[%i],uid=[%i],euid=[%i],gid=[%i],egid[%i],comm=[%s]\n",
		pid,
		task_pid_vnr(rcu_dereference(task->real_parent)),
		usbfilter_get_pgid(task),
		usbfilter_get_uid(task),
		usbfilter_get_euid(task),
		usbfilter_get_gid(task),
		usbfilter_get_egid(task),
		comm);		
}

static void usbfilter_dump_dev_conditions(struct urb *urb)
{
	struct usb_host_endpoint *ep;

	/* Get the ep */
	ep = usb_pipe_endpoint(urb->dev, urb->pipe);

	/* usb_submit_urb() has done all the sanity checking */
	pr_info("busnum=[%d],devnum=[%d],portnum=[%d],ifnum=[%d],"
		"devpath=[%s],product=[%s],manufacturer=[%s],serial=[%s]\n",
		urb->dev->bus->busnum,
		urb->dev->devnum,
		urb->dev->portnum,
		ep->if_num,
		(urb->dev->devpath ? urb->dev->devpath : "null"),
		(urb->dev->product ? urb->dev->product : "null"),
		(urb->dev->manufacturer ? urb->dev->manufacturer : "null"),
		(urb->dev->serial ? urb->dev->serial : "null"));
}

static void usbfilter_dump_pkt_conditions(struct urb *urb)
{
	pr_info("type=[%d],direction=[%d],endpoint=[%d],address=[%d]\n",
		usb_pipetype(urb->pipe),
		usbfilter_get_urb_dir(urb),
		usb_pipeendpoint(urb->pipe),
		usb_pipedevice(urb->pipe));
}

static void usbfilter_dump_conditions(struct urb *urb)
{
	usbfilter_dump_proc_conditions(urb);
	usbfilter_dump_dev_conditions(urb);
	usbfilter_dump_pkt_conditions(urb);
}

/* main interface */
int usbfilter_register_lum(struct usbfilter_lum *lum)
{
	struct usbfilter_ldb_ele *ele;

	/* Defensive checking */
	if (!usbfilter_inited)
		return -1;

	/* Alloc mem for this lum */
	ele = kmalloc(sizeof(*ele), GFP_KERNEL);
	if (!ele) {
		pr_err("usbfilter - Error: kmalloc failed in %s\n", __func__);
		return -1;
	}

	/* Save this lum */
	memset(ele, 0x0, sizeof(*ele));
	memcpy(&ele->lum, lum, sizeof(*lum));

	/* Add this ele into ldb */
	mutex_lock(&usbfilter_ldb_lock);
	list_add_tail(&ele->list, &usbfilter_ldb);
	mutex_unlock(&usbfilter_ldb_lock);

	if (usbfilter_debug)
		pr_info("usbfilter - Debug: lum [%s] has been registered\n", lum->name);

	return 0;
}
EXPORT_SYMBOL_GPL(usbfilter_register_lum);

void usbfilter_deregister_lum(struct usbfilter_lum *lum)
{
	struct usbfilter_ldb_ele *ptr, *next;

	/* Defensive checking */
	if (!usbfilter_inited)
		return;

	/* Go thru the ldb and try to move this lum */
	mutex_lock(&usbfilter_ldb_lock);
	list_for_each_entry_safe(ptr, next, &usbfilter_ldb, list) {
		if (!strcasecmp(lum->name, ptr->lum.name)) {
			list_del(&ptr->list);
			kfree(ptr);
			if (usbfilter_debug)
				pr_info("usbfilter - Debug: lum [%s] has been deregistered\n",
					lum->name);
			break;
		}
	}
	mutex_lock(&usbfilter_ldb_lock);

	return;
}
EXPORT_SYMBOL_GPL(usbfilter_deregister_lum);

int usbfilter_filter_urb(struct urb *urb)
{
	int rtn;
	int action;
	unsigned long flags;
	struct usbfilter_rdb_ele *ptr;
	struct timeval start_tv, end_tv;

	if (usbfilter_debug) {
		pr_info("usbfilter - Debug: into [%s] with urb [%p]\n",
			__func__, urb);
		usbfilter_dump_conditions(urb);
	}

	/* Micro-benchmark */
	if (usbfilter_perf)
		do_gettimeofday(&start_tv);

	/* Get the default action */
	spin_lock_irqsave(&usbfilter_default_behavior_lock, flags);
	action = usbfilter_default_behavior;
	spin_unlock_irqrestore(&usbfilter_default_behavior_lock, flags);

	/* Check if started */
	if (!usbfilter_is_started())
		return USBFILTER_RULE_ACTION_ALLOW;

	spin_lock_irqsave(&usbfilter_rdb_lock, flags);
	/* Go thru each rule */
	list_for_each_entry(ptr, &usbfilter_rdb, list) {
		switch (ptr->type) {

		case USBFILTER_TYPE_RULE:
			rtn = usbfilter_match_rule(urb, &ptr->rule);
			if (rtn)
				action = ptr->rule.action;
			break;

		case USBFILTER_TYPE_SIM_RULE:
			rtn = usbfilter_match_sim_rule(urb, &ptr->sim_rule);
			if (rtn)
				action = ptr->sim_rule.action;
			break;

		default:
			rtn = 0;
			pr_err("usbfilter - Error: unknown rule type [%d]\n",
				ptr->type);
			break;
		}

		/* Found a match */
		if (rtn)
			break;
	}
	spin_unlock_irqrestore(&usbfilter_rdb_lock, flags);

	if (usbfilter_perf) {
		do_gettimeofday(&end_tv);
		pr_info("usbfilter-perf: %s took [%lu] us\n", __func__,
			USBFILTER_MBM_SUB_TV(start_tv, end_tv));
	}

	return action;
}
EXPORT_SYMBOL_GPL(usbfilter_filter_urb);

/* init/exit */
int usbfilter_init(void)
{
	int ret;

	/* Init the socket */
	struct netlink_kernel_cfg cfg = {
		.input = usbfilter_nl_handler,
	};

	usbfilter_nl_sock = netlink_kernel_create(&init_net, USBFILTER_NETLINK, &cfg);
	if (!usbfilter_nl_sock) {
		pr_err("usbfilter - Error: netlink socket creation failure\n");
		return -1;
	}

	/* Init DBs */
	INIT_LIST_HEAD(&usbfilter_rdb);
	INIT_LIST_HEAD(&usbfilter_ldb);

	/* Load default rules */
	ret = usbfilter_rdb_load_default_rules();
	if (ret) {
		pr_err("usbfilter - Error: usbfilter_rdb_load_default_rules failure\n");
		return -1;
	}

	/* Mark the flag */
	usbfilter_inited = 1;
	usbfilter_on = 1;

	if (usbfilter_debug)
		pr_info("usbfilter - Debug: usbfilter inited\n");

	return 0;
}
EXPORT_SYMBOL_GPL(usbfilter_init);

void usbfilter_exit(void)
{
	if (usbfilter_inited) {
		/* Close the netlink */
		netlink_kernel_release(usbfilter_nl_sock);
		/* Destroy the rdb */
		usbfilter_rdb_destroy();
		/* Destroy the ldb */
		usbfilter_ldb_destroy();
		/* FIXME: a better way is to trigger lum unloading before ldb clearance */
	}
}
EXPORT_SYMBOL_GPL(usbfilter_exit);

void usbfilter_get_app_pid_from_skb(struct sk_buff *skb, struct urb *urb)
{
	if (!urb)
		return;

	/* Apparently, not each skb has a pid corelated */
#ifdef DAVETI_INSANE
	if (skb && skb->sk && skb->sk->sk_socket && skb->sk->sk_socket->file
		&& skb->sk->sk_socket->file->f_owner.pid)
		urb->app_pid = pid_vnr(skb->sk->sk_socket->file->f_owner.pid);
	else
		urb->app_pid = -1;
#endif
	/* Use the app pid from skb directly */
	urb->app_pid = skb->app_pid;

}
EXPORT_SYMBOL_GPL(usbfilter_get_app_pid_from_skb);

