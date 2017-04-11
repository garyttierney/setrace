#ifndef SETRACE_GENL_FAMILY_H
#define SETRACE_GENL_FAMILY_H

#define SETRACE_GENL_VERSION_NR 1
#define SETRACE_GENL_NAME "SETRACE"
#define SETRACE_MAX_STACK_FRAMES 16

enum {
	SETRACE_CMD_ATTR_UNSPEC = 0,
	SETRACE_CMD_ATTR_PID,
	__SETRACE_ATTR_MAX
};

#define SETRACE_CMD_ATTR_MAX (__SETRACE_ATTR_MAX - 1)

enum {
	SETRACE_CMD_UNSPEC = 0,
	SETRACE_CMD_SUB, /* userspace -> kernel, subscribe to pid */
	SETRACE_CMD_UNSUB, /* userspace -> kernel, unsubscribe from pid */
	SETRACE_CMD_NEW, /* kernel -> userspace, notify of AVC event */
	__SETRACE_CMD_MAX
};

#define SETRACE_CMD_MAX (__SETRACE_CMD_MAX - 1)

enum {
	SETRACE_TYPE_UNSPEC = 0,
	SETRACE_TYPE_AGGR_RECORD,
	SETRACE_TYPE_SCONTEXT,
	SETRACE_TYPE_TCONTEXT,
	SETRACE_TYPE_RECORD,
	SETRACE_TYPE_NULL,
	__SETRACE_TYPE_MAX
};

#define SETRACE_TYPE_MAX (__SETRACE_TYPE_MAX - 1)

struct setrace_record {
	__u16 version;
	__u32 pid __attribute__((aligned(8)));
	__u64 userspace_stacktrace[SETRACE_MAX_STACK_FRAMES];
	__u64 kernel_stacktrace[SETRACE_MAX_STACK_FRAMES];
	__u8 userspace_stacktrace_size __attribute__((aligned(8)));
	__u8 kernel_stacktrace_size;
	__u16 security_class;
	__u32 permissions;

	/* Version 1 ends here */
};

#endif
