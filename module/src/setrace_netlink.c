#include "setrace.h"

#include <uapi/linux/setrace.h>

/**
 * Netlink attribute policies for setrace attribute types.
 */
struct nla_policy setrace_genl_attr_policy[SETRACE_CMD_ATTR_MAX + 1] = {
	[SETRACE_CMD_ATTR_PID] = { .type = NLA_U32 }
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
	.maxattr = SETRACE_CMD_ATTR_MAX,
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
	struct nlattr *attr = info->attrs[SETRACE_CMD_ATTR_PID];

	if (!attr) {
		rc = -1;
		goto out;
	}

	target_id = (pid_t) nla_get_u64(attr);
	pr_info_ratelimited("setrace: received request from userspace "
			    "(subscriber_id=%u) to begin tracing pid %u\n",
			    subscriber_id, target_id);

	if (setrace_subscribe_to_pid(subscriber_id, target_id) < 0) {
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
	struct nlattr *attr = info->attrs[SETRACE_CMD_ATTR_PID];

	if (!attr) {
		rc = -1;
		goto out;
	}

	target_id = (pid_t) nla_get_u64(attr);
	setrace_unsubscribe(subscriber_id, target_id);
out:
	return rc;
}

#define COPY_AVC_TO_RECORD(avc, record, item) \
	record->item = avc->item

static void copy_avc_to_record(const struct setrace_avc_check *avc,
			       struct setrace_record *record)
{
	memset(record, 0, sizeof(*record));
	memcpy(record->userspace_stacktrace, avc->userspace_stacktrace,
	       sizeof(u64) * avc->userspace_stacktrace_size);
	memcpy(record->kernel_stacktrace, avc->kernel_stacktrace,
	       sizeof(u64) * avc->kernel_stacktrace_size);

	COPY_AVC_TO_RECORD(avc, record, pid);
	COPY_AVC_TO_RECORD(avc, record, userspace_stacktrace_size);
	COPY_AVC_TO_RECORD(avc, record, kernel_stacktrace_size);
	COPY_AVC_TO_RECORD(avc, record, security_class);
	COPY_AVC_TO_RECORD(avc, record, permissions);
}

int setrace_genl_send_record(u32 subscriber_id,
			     const struct setrace_avc_check *avc)
{
	static u32 record_event_seq = 0;

	int ret = 0;

	void *msg_header = NULL;
	struct sk_buff *skb = NULL;
	struct nlattr *attr = NULL;
	struct nlattr *record_attr = NULL;
	struct setrace_record *record = NULL;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	msg_header = genlmsg_put(skb, 0, record_event_seq++,
				 &setrace_genl_family, 0, SETRACE_CMD_NEW);
	if (msg_header == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	attr = nla_nest_start(skb, SETRACE_TYPE_AGGR_RECORD);
	if (!attr) {
		ret = -ENOMEM;
		goto err;
	}

	if (nla_put_string(skb, SETRACE_TYPE_SCONTEXT, avc->scontext) < 0 ||
	    nla_put_string(skb, SETRACE_TYPE_TCONTEXT, avc->tcontext) < 0) {
		ret = -ENOMEM;
		goto err;
	}

	record_attr = nla_reserve_64bit(skb, SETRACE_TYPE_RECORD,
				   sizeof(struct setrace_record),
				   SETRACE_TYPE_NULL);
	nla_nest_end(skb, attr);

	record = nla_data(record_attr);
	record->version = SETRACE_GENL_VERSION_NR;
	copy_avc_to_record(avc, record);

	genlmsg_end(skb, msg_header);

	return genlmsg_unicast(&init_net, skb, subscriber_id);
err:
	if (skb && attr) {
		nla_nest_cancel(skb, attr);
	}
	nlmsg_free(skb);
	return ret;
}
