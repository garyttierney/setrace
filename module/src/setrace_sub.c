#include "setrace.h"
#include "setrace_sel.h"

/**
 * A list of processes (or generic netlink 'portids') which have subscribed
 * to tracing a particular process id.
 */
struct setrace_subscriber {
	struct list_head list;
	struct rcu_head rcu;

	int type;
	u32 subscriber_id;

	union {
		pid_t pid;
		u32 sid;
	};
};

/**
 * Top of the list of setrace subscribers.
 */
static LIST_HEAD(subscribers_head);

/**
 * RCU function to reclaim the memory used by a setrace_subscriber
 * struct.
 */
static void setrace_subscriber_rcu_reclaim(struct rcu_head *rp)
{
	struct setrace_subscriber *sub =
	    container_of(rp, struct setrace_subscriber, rcu);
	kfree(sub);
}

static int setrace_subscriber_listening(const struct setrace_subscriber *sub,
		pid_t pid, u32 ssid, u32 tsid)
{
	switch (sub->type) {
		case SETRACE_SUB_SCONTEXT:
			return sub->sid == ssid;
		case SETRACE_SUB_TCONTEXT:
			return sub->sid == tsid;
		case SETRACE_SUB_PID:
			return sub->pid == pid;
		default:
			BUG();
	}
	
	return 0;
}

int setrace_is_subscribed_to(pid_t pid, u32 ssid, u32 tsid)
{
	struct setrace_subscriber *sub;
	int subscribed_to = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(sub, &subscribers_head, list) {
		if (setrace_subscriber_listening(sub, pid, ssid, tsid)) {
			subscribed_to = 1;
			break;
		}
	}
	rcu_read_unlock();

	return subscribed_to;
}

/**
 * Notify all subscribers which subscribe to the @pid in the trace record.
 *
 * @record The trace record to notify clients of.
 */
int setrace_notify(const struct setrace_avc_check *avc)
{
	int ret = 0;
	struct setrace_subscriber *sub;

	rcu_read_lock();
	list_for_each_entry_rcu(sub, &subscribers_head, list) {
		if (setrace_subscriber_listening(sub, avc->pid, avc->ssid,
						 avc->tsid)) {
			ret = setrace_genl_send_record(sub->subscriber_id, avc);
			if (ret == -ECONNREFUSED) {
				// Unsubscribe any ports which refused
				// a connection when trying to send
				// a message
				setrace_unsubscribe(sub->subscriber_id,
						    SETRACE_UNSUBSCRIBE_ALL);
				continue;
			} else if (ret < 0) {
				break;
			}
		}
	}
	rcu_read_unlock();

	return ret;
}

/**
 * Subscribe a netlink socket opened by @subscriber_id to AVC check events on
 * @target_id.
 */
int setrace_subscribe_to_pid(u32 subscriber_id, pid_t pid)
{
	struct setrace_subscriber *sub = kmalloc(sizeof(*sub), GFP_KERNEL);
	if (sub == NULL) {
		return -ENOMEM;
	}

	sub->subscriber_id = subscriber_id;
	sub->type = SETRACE_SUB_PID;
	sub->pid = pid;
	list_add_rcu(&sub->list, &subscribers_head);

	return 0;
}

int setrace_subscribe_to_context(u32 subscriber_id, int type,
				 const char *context)
{
	u32 sid;
	struct setrace_subscriber *sub;

	if (type != SETRACE_SUB_SCONTEXT && type != SETRACE_SUB_TCONTEXT) {
		return -1;
	}

	if (sel_context_to_sid(context, strlen(context), &sid,
			       GFP_KERNEL) < 0) {
		return -1;
	}

	sub = kmalloc(sizeof(*sub), GFP_KERNEL);
	if (sub == NULL) {
		return -ENOMEM;
	}

	sub->subscriber_id = subscriber_id;
	sub->type = type;
	sub->sid = sid;
	list_add_rcu(&sub->list, &subscribers_head);

	return 0;
}

void setrace_unsubscribe(u32 subscriber_id, pid_t target_id)
{
	struct setrace_subscriber *sub;

	list_for_each_entry(sub, &subscribers_head, list) {
		if (sub->subscriber_id == subscriber_id &&
		    (/*sub->target_id == target_id ||*/
		     target_id == SETRACE_UNSUBSCRIBE_ALL)) {
			list_del_rcu(&sub->list);
			call_rcu(&sub->rcu, setrace_subscriber_rcu_reclaim);
		}
	}

	if (target_id == SETRACE_UNSUBSCRIBE_ALL) {
		pr_info_ratelimited("setrace: unsubscribed %d from all processes\n",
				    subscriber_id);
	} else {
		pr_info_ratelimited("setrace: unsubscribed %d from %d\n",
				    subscriber_id, target_id);
	}
}

void setrace_unsubscribe_all(void)
{
	struct setrace_subscriber *sub;

	list_for_each_entry(sub, &subscribers_head, list) {
		list_del_rcu(&sub->list);
		call_rcu(&sub->rcu, setrace_subscriber_rcu_reclaim);
	}
}
