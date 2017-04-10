#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <netlink/netlink.h>
#include <netlink/cli/utils.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <setrace/genl_family.h>

int main(int argc, char *argv[])
{
	int got_pid = 0;
	pid_t pid;

	int option;

	while ((option = getopt(argc, argv, "p:")) != -1) {
		switch (option) {
		case 'p':
			pid = (pid_t)atol(optarg);
			got_pid = 1;
			break;
		case '?':
			if (optopt == 'p') {
				printf("Option 'p' expects an argument\n");
			} else if (isprint(optopt)) {
				printf("Unknown option -%c\n", optopt);
			} else {
				printf("Unexpected character\n");
			}

			return -1;
		}
	}

	if (!got_pid) {
		printf("Must specify a process id\n");
		return -1;
	}

	int err = 0;

	struct nl_sock *sock = NULL;
	struct nl_msg *msg = NULL;
	void *msg_hdr = NULL;

	sock = nl_cli_alloc_socket();
	if (sock == NULL) {
		fprintf(stderr, "Failed to allocate netlink socket\n");
		err = -ENOMEM;
		goto error;
	}

	err = genl_connect(sock);
	if (err < 0) {
		fprintf(stderr,
			"Failed to connect to generic netlink socket\n");
		goto error;
	}

	int genl_family = genl_ctrl_resolve(sock, SETRACE_GENL_NAME);
	if (genl_family < 0) {
		fprintf(stderr,
			"Failed to resolve generic netlink family id (is the module loaded?)\n");
		nl_close(sock);
		err = -EAFNOSUPPORT;
		goto error;
	}

	msg = nlmsg_alloc();
	if (msg == NULL) {
		fprintf(stderr, "Failed to allocate netlink message\n");
		nl_close(sock);
		err = -ENOMEM;
		goto error;
	}

	msg_hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, genl_family, 0, 0,
			      SETRACE_CMD_SUB, SETRACE_GENL_VERSION_NR);
	if (msg_hdr == NULL) {
		fprintf(stderr,
			"Failed to allocate generic netlink message header\n");
		nlmsg_free(msg);
		nl_close(sock);
		err = -ENOMEM;
		goto error;
	}

	err = nla_put_u64(msg, SETRACE_ATTR_ID, pid);
	if (err < 0) {
		nl_close(sock);
		nlmsg_free(msg);
		goto error;
	}

	err = nl_send_auto_complete(sock, msg);
	if (err < 0) {
		fprintf(stderr, "Failed to send netlink message to generic "
				"netlink socket\n");
	} else {
		printf("Sent request to setrace-lkm to begin tracing %d\n",
		       pid);
	}

	nlmsg_free(msg);
	nl_close(sock);
error:
	nl_socket_free(sock);
	return err;
}
