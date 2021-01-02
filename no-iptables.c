/*
	Prevent libvirtd from adding iptables rules by calling /sbin/iptables or
	/sbin/ip6tables. Let it call "iptables --version" though.
	Compile with: gcc -shared -ldl -fPIC no-iptables.c -o no-iptables.so
	If needed, add -DNOIPTABLES_DEBUG
	Usage: LD_PRELOAD=/path/to/no-iptables.so libvirtd

	(c) 2016-2021 - Xavier G.
	This program is free software. It comes without any warranty, to
	the extent permitted by applicable law. You can redistribute it
	and/or modify it under the terms of the Do What The Fuck You Want
	To Public License, Version 2, as published by Sam Hocevar. See
	http://www.wtfpl.net/ for more details.
*/
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef NOIPTABLES_SO_NAME
#define NOIPTABLES_SO_NAME "no-iptables.so"
#endif

typedef int (*execve_function_type)(const char *, char *const *, char *const *);

/* Pointer to the actual execve symbol. */
execve_function_type actual_execve = NULL;

/* When refusing to run iptables, we simply run "true" instead: */
const char *noexec_filename = "/bin/true";
char *const noexec_argv[] = { "/bin/true", NULL };
char *const noexec_envp[] = { NULL };

/*
	libvirtd is liable to use two functions to execute other programs:
	  - execv()
	  - execve()
*/
int execv(const char *filename, char *const *argv) {
	return execve(filename, argv, __environ);
}

int execve(const char *filename, char *const *argv, char *const *envp) {
	char *error_string;
	unsigned int arg_index;

	/* Ask the linker to provide us with the actual execve symbol: */
	if (!actual_execve) {
		actual_execve = (execve_function_type)dlsym(RTLD_NEXT, "execve");
		if (!actual_execve) {
			error_string = dlerror();
			if (error_string) {
				dprintf(2, "%s: unable to find the actual execve symbol: %s\n", NOIPTABLES_SO_NAME, error_string);
			}
			else {
				dprintf(2, "%s: unable to find the actual execve symbol\n", NOIPTABLES_SO_NAME);
			}
			errno = ENOENT;
			return -1;
		}
	}

	/* Determine whether libvirtd is trying to call iptables: */
	if (!strncmp(filename, "/sbin/iptables", 15) || !strncmp(filename, "/sbin/ip6tables", 16) ||
	    !strncmp(filename, "/usr/sbin/iptables", 19) || !strncmp(filename, "/usr/sbin/ip6tables", 20)) {
#ifdef NOIPTABLES_DEBUG
		dprintf(2, "OMG it's calling %s!\n", filename);
#endif
		/* Do not interfere when libvirtd tries to run iptables --version: */
		for (arg_index = 0; argv[arg_index]; ++ arg_index) {
			if (!strncmp(argv[arg_index], "--version", 10) || !strncmp(argv[arg_index], "-V", 3)) {
#ifdef NOIPTABLES_DEBUG
				dprintf(2, "Oh, it's ok, it's just calling %s --version.\n", filename);
#endif
				goto let_it_go;
			}
		}
		/* Refuse to run the program: */
		return actual_execve(noexec_filename, noexec_argv, noexec_envp);
	}

	let_it_go:
	/* Execute the program pointed to by filename as initially intended: */
	return actual_execve(filename, argv, envp);
}
