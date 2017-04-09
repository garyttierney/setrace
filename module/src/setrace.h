#ifndef SETRACE_H
#define SETRACE_H

#include <linux/kernel.h>
#include <linux/stacktrace.h>
#include <linux/types.h>
#include <net/genetlink.h>

#define SETRACE_MAX_STACK_FRAMES 16

/**
 * A trace record containing all information sent to userspace about an AVC
 * check.
 *
 * @pid The pid of the task that the AVC check was for.
 * @scontext A string representation of the source context.
 * @scontext_len The length of the source context string.
 * @tcontext A string representation of the target context.
 * @tcontext_len The length of the target context string.
 * @tclass The security class the AVC check was on.
 * @tperms The access vectors that were checked.
 * @kernel_stacktrace An array containing the instruction pointer of kernel
 * stackframes leading up to this record.
 * @kernel_stacktrace_size The number of frames which could be saved to create
 * a kernel stacktrace.
 * @userspace_stacktrace An array containing the instruction pointers of
 * userspace stackframes leading up to this record.
 * @userspace_stacktrace_size The number of frames which could be saved to
 * create a userspace stacktrace.
 */
struct setrace_record {
	pid_t pid;

	char *scontext;
	u32 scontext_len;

	char *tcontext;
	u32 tcontext_len;

	u16 tclass;
	u32 tperms;

	unsigned long kernel_stacktrace[SETRACE_MAX_STACK_FRAMES];
	unsigned int kernel_stacktrace_size;
	unsigned long userspace_stacktrace[SETRACE_MAX_STACK_FRAMES];
	unsigned int userspace_stacktrace_size;
};

/**
 * Command handler for 'subscribe' commands from userspace netlink sockets.
 */
int setrace_genl_cmd_sub(struct sk_buff *skb, struct genl_info *info);

/**
 * Command handler for 'unsubscribe' commands from userspace netlink sockets.
 */
int setrace_genl_cmd_unsub(struct sk_buff *skb, struct genl_info *info);

/**
 * Send a message event to the netlink client with a port id of @subscriber_id.
 */
int setrace_genl_send_msg(pid_t subscriber_id, const char *msg);

/**
 * Register the setrace generic netlink socket family.
 */
int setrace_genl_register(void);

/**
 * Unregister the setrace generic netlink socket family.
 */
void setrace_genl_unregister(void);

/**
 * Check if any subscriber is subscribed to AVC checks on @target_id.
 *
 * @target_id The pid of the target to check.
 */
int setrace_is_subscribed_to(pid_t target_id);

/**
 * Notifies subscribers of a trace record by sending netlink sockets containing
 * the record as a message.
 *
 * @subscriber_id The port id of the subscribers netlink socket.
 * @trace_record The trace record to send as a message.
 */
int setrace_notify(const struct setrace_record *trace_record);

/**
 * Register @subscriber_id as a subscriber to AVC checks on @target_id.
 *
 * @subscriber_id The port id of the subscribers netlink socket.
 * @target_id The pid of the target process.
 */
int setrace_subscribe(pid_t subscriber_id, pid_t target_id);

/**
 * Unregister @subscriber_id as a subscriber from AVC checks on @target_id.
 *
 * @subscriber_id The port id of the subscribers netlink socket.
 * @target_id The pid of the process that was subscribed to.
 */
void setrace_unsubscribe(pid_t subscriber_id, pid_t target_id);

/**
 * Unsubscribe all AVC trace subscribers.
 */
void setrace_unsubscribe_all(void);

#endif
