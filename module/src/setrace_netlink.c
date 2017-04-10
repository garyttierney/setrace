#include "setrace.h"

#include <setrace/genl_family.h>

/**
 * Netlink attribute policies for setrace attribute types.
 */
struct nla_policy setrace_genl_attr_policy[SETRACE_ATTR_MAX + 1] = {
	[SETRACE_ATTR_MSG] = { .type = NLA_NUL_STRING },
	[SETRACE_ATTR_ID] = { .type = NLA_U64 }
};

/**
 * Supported operations for the setrace generic netlink family.
 */
const struct genl_ops setrace_genl_ops[] = {
	{
		.cmd = SETRACE_CMD_SUB,
		.doit = setrace_genl_cmd_sub,
		.policy = setrace_genl_attr_policy
	},
	{
		.cmd = SETRACE_CMD_UNSUB,
		.doit = setrace_genl_cmd_unsub,
		.policy = setrace_genl_attr_policy
	}
};

/**
 * Generic netlink socket family for setrace communication between the kernel
 * and userspace.
 */
struct genl_family setrace_genl_family __ro_after_init = {
	.name = SETRACE_GENL_NAME,
	.version = SETRACE_GENL_VERSION_NR,
	.module = THIS_MODULE,
	.maxattr = SETRACE_ATTR_MAX,
	.ops = setrace_genl_ops,
	.n_ops = ARRAY_SIZE(setrace_genl_ops),
	.hdrsize = 0,
};

int setrace_genl_register(void)
{
	int rc = 0;

	rc = genl_register_family(&setrace_genl_family);
	if (rc != 0) {
		pr_info("Failed to register setrace generic netlink family\n");
		rc = -1;
	}

	return rc;
}

void setrace_genl_unregister(void)
{
	genl_unregister_family(&setrace_genl_family);
}

int setrace_genl_cmd_sub(struct sk_buff *skb, struct genl_info *info)
{
	int rc = 0;

	pid_t target_id;
	u32 subscriber_id = info->snd_portid;
	struct nlattr *attr = info->attrs[SETRACE_ATTR_ID];

	if (!attr) {
		rc = -1;
		goto out;
	}

	target_id = (pid_t) nla_get_u64(attr);
	pr_info_ratelimited("Received request from userspace (subscriber_id=%d) to begin tracing pid %d\n",
			    subscriber_id, target_id);

	if (setrace_subscribe(subscriber_id, target_id) < 0) {
		rc = -1;
		goto out;
	}
out:
	return rc;
}

int setrace_genl_cmd_unsub(struct sk_buff *skb, struct genl_info *info)
{
	int rc = 0;

	pid_t target_id;
	u32 subscriber_id = info->snd_portid;
	struct nlattr *attr = info->attrs[SETRACE_ATTR_ID];

	if (!attr) {
		rc = -1;
		goto out;
	}

	target_id = (pid_t) nla_get_u64(attr);
	setrace_unsubscribe(subscriber_id, target_id);
out:
	return rc;
}

int setrace_genl_send_msg(u32 subscriber_id, const char *msg)
{
	static unsigned int notify_event_seq;

	int ret = 0;

	struct sk_buff *skb = NULL;
	void *msg_header = NULL;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	msg_header = genlmsg_put(skb, 0, notify_event_seq++,
				 &setrace_genl_family, 0, SETRACE_CMD_EVENT);
	if (msg_header == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	ret = nla_put_string(skb, SETRACE_ATTR_MSG, msg);
	if (ret != 0) {
		goto err;
	}

	genlmsg_end(skb, msg_header);
	ret = genlmsg_unicast(&init_net, skb, subscriber_id);
	if (ret != 0) {
		goto err;
	}

	return ret;
err:
	kfree(skb);
	kfree(msg_header);
	return ret;
}

