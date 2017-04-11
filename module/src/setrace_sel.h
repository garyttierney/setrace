/*
 * Symbol declarations for SELinux utility functions which aren't exported
 * to the rest of the kernel.
 *
 * author: Gary Tierney <gary.tierney@gmx.com>
 */
#ifndef SETRACE_SEL_H
#define SETRACE_SEL_H

extern int (*sel_sid_to_context)(u32 sid, char **scontext,
				 u32 *scontext_len) __ro_after_init;

extern int (*sel_context_to_sid)(const char *context, u32 context_len, u32 *sid,
				 gfp_t gfpflags) __ro_after_init;

#endif
