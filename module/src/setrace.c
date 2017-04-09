/*
 * A module for tracing access vector checks by the SELinux subsystem and logging
 * them to userspace with kernel and userspace stack trace information.
 *
 * Author: Gary Tierney <gary.tierney@gmx.com>
 */
#include "setrace.h"

#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/lsm_audit.h>
#include <linux/module.h>
#include <linux/stacktrace.h>
#include <linux/types.h>

#define AVC_CHECK_SYM_NAME "avc_has_perm"
#define SID_TO_CONTEXT_SYM_NAME "security_sid_to_context"

/**
 * A pointer to the 'security_sid_to_context' symbol, to map
 * security identifiers to context strings.
 *
 * @sid The security identifier to map to a context.
 * @scontext [out] Address to store the context string in.
 * @scontext_len [out] Address to store the length of the context string in.
 */
static int (*sid_to_context)(u32 sid, char **scontext,
			     u32 *scontext_len) __ro_after_init;

/**
 * A stub for @avc_has_perm that takes the the function arguments
 * and logs a trace record.
 *
 * @ssid The security id of the source.
 * @tsid The security id of the target.
 * @tclass The target security class identifier.
 * @requested A bitmask of requested access vectors.
 */
static int avc_has_perm_stub(u32 ssid, u32 tsid, u16 tclass, u32 requested,
			     struct common_audit_data *data)
{
	int err = 0;

	struct setrace_record record;
	struct stack_trace kernel_stacktrace = {
		.nr_entries = 0,
		.entries = &record.kernel_stacktrace[0],
		.max_entries = SETRACE_MAX_STACK_FRAMES,
		.skip = 0
	};
	
	struct stack_trace userspace_stacktrace = {
		.nr_entries = 0,
		.entries = &record.userspace_stacktrace[0],
		.max_entries = SETRACE_MAX_STACK_FRAMES,
		.skip = 0
	};

	char *scontext = NULL;
	char *tcontext = NULL;
	u32 scontext_len = 0, tcontext_len = 0;

	pid_t task_pid = task_pid_nr(current);

	if (!setrace_is_subscribed_to(task_pid)) {
		jprobe_return();
		return 0;
	}

	err = sid_to_context(ssid, &scontext, &scontext_len);
	if (err < 0) {
		goto out;
	}

	err = sid_to_context(tsid, &tcontext, &tcontext_len);
	if (err < 0) {
		goto out;
	}

	save_stack_trace(&kernel_stacktrace);
	if (IS_ENABLED(CONFIG_USERSPACE_STACKTRACE_SUPPORT)) {
		save_stack_trace_user(&userspace_stacktrace);
	}

	record.pid = task_pid;
	record.scontext = scontext;
	record.scontext_len = scontext_len;
	record.tcontext = tcontext;
	record.tcontext_len = tcontext_len;
	record.tclass = tclass;
	record.tperms = requested;
	record.kernel_stacktrace_size = kernel_stacktrace.nr_entries;
	record.userspace_stacktrace_size = userspace_stacktrace.nr_entries;

	if (setrace_notify(&record) < 0) {
		err = -1;
	}
out:
	kfree(scontext);
	kfree(tcontext);
	jprobe_return();
	return 0;
}

/**
* A jump probe to capture the arguments of the @avc_has_perm function. The
* return code isn't captured since userspace can calculate that using
* the SELinux fs.
*/
static struct jprobe avc_check_probe = {
	.entry = avc_has_perm_stub,
	.kp = {
		.symbol_name = AVC_CHECK_SYM_NAME,
	}
};

static int __init setrace_init(void)
{
	int err = 0;

	unsigned long sid_to_context_addr =
	    kallsyms_lookup_name(SID_TO_CONTEXT_SYM_NAME);

	if (sid_to_context_addr == 0) {
		pr_info("Failed to lookup address of %s\n",
			SID_TO_CONTEXT_SYM_NAME);
		return -1;
	}

	sid_to_context = (void *)sid_to_context_addr;

	err = register_jprobe(&avc_check_probe);
	if (err < 0) {
		pr_info("Failed to register setrace probe for %s, returned %d\n",
			AVC_CHECK_SYM_NAME, err);
		return -1;
	}

	err = setrace_genl_register();
	if (err < 0) {
		unregister_jprobe(&avc_check_probe);
	}

	return err;
}

static void __exit setrace_exit(void)
{
	unregister_jprobe(&avc_check_probe);
	setrace_genl_unregister();
	setrace_unsubscribe_all();
}

module_init(setrace_init);
module_exit(setrace_exit);

MODULE_AUTHOR("Gary Tierney <gary.tierney@gmx.com>");
MODULE_DESCRIPTION("Tracing system for SELinux AVC checks");
MODULE_LICENSE("GPL");
