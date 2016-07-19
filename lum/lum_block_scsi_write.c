/*
 * lbsw
 * A LUM kernel module
 * used to block SCSI write command within USB packets
 * Feb 13, 2016
 * root@davejingtian.org
 * http://davejingtian.org
 */
#include <linux/module.h>
#include <linux/usbfilter.h>
#include <scsi/scsi.h>

#define LUM_NAME		"block_scsi_write"
#define LUM_SCSI_CMD_IDX	15

static struct usbfilter_lum lbsw;
static int lum_registered;

/*
 * Define the filter function
 * Return 1 if this is the target packet
 * Otherwise 0
 */
int lbsw_filter_urb(struct urb *urb)
{
	char opcode;

	/* Has to be an OUT packet */
	if (usb_pipein(urb->pipe))
		return 0;

	/* Make sure the packet is large enough */
	if (urb->transfer_buffer_length <= LUM_SCSI_CMD_IDX)
		return 0;

	/* Make sure the packet is not empty */
	if (!urb->transfer_buffer)
		return 0;

	/* Get the SCSI cmd opcode */
	opcode = ((char *)urb->transfer_buffer)[LUM_SCSI_CMD_IDX];

	/* Current only handle WRITE_10 for Kingston */
	switch (opcode) {
	case WRITE_10:
		return 1;
	default:
		break;
	}

	return 0;
}

static int __init lbsw_init(void)
{
	pr_info("lbsw: Entering: %s\n", __func__);
	snprintf(lbsw.name, USBFILTER_LUM_NAME_LEN, "%s", LUM_NAME);
	lbsw.lum_filter_urb = lbsw_filter_urb;

	/* Register this lum */
	if (usbfilter_register_lum(&lbsw))
		pr_err("lbsw: registering lum failed\n");
	else
		lum_registered = 1;

	return 0;
}

static void __exit lbsw_exit(void)
{
	pr_info("exiting lbsw module\n");
	if (lum_registered)
		usbfilter_deregister_lum(&lbsw);
}

module_init(lbsw_init);
module_exit(lbsw_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("lbsw module");
MODULE_AUTHOR("daveti");

