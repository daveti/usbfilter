/*
 * usbfilter.h
 * There are 2 parts in this header file:
 * a. APIs visible to call usbfilter
 * b. APIs visible to implement a lum (aka. linux usbfilter module)
 * c. APIs visible to retrieve pid from skb (Jan 7, 2016)
 * Jul 8, 2015
 * root@davejingtian.org
 * https://davejingtian.org
 */
#include <linux/usb.h>
#include <linux/skbuff.h>

#define USBFILTER_LUM_NAME_LEN	32	

struct usbfilter_lum {
	char name[USBFILTER_LUM_NAME_LEN];
	int (*lum_filter_urb)(struct urb *urb);	/* The return value should be 0 or 1 - no others */
};

int usbfilter_init(void);
void usbfilter_exit(void);
int usbfilter_filter_urb(struct urb *urb);

int usbfilter_register_lum(struct usbfilter_lum *lum);
void usbfilter_deregister_lum(struct usbfilter_lum *lum);

void usbfilter_get_app_pid_from_skb(struct sk_buff *skb, struct urb *urb);

