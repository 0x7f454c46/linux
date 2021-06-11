// SPDX-License-Identifier: GPL-2.0-only
/*
 * 32/64-bit test to check vDSO munmap.
 *
 * Copyright (c) 2021 Dmitry Safonov
 */
/*
 * Can be built statically:
 * gcc -Os -Wall -static -m32 test_munmap_vdso.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#define PAGE_SIZE	4096

static int try_to_unmap(void *vdso_addr, unsigned long size)
{
	int ret;

	printf("[NOTE]\tunmapping vDSO: [%p, %#lx]\n",
		vdso_addr, (unsigned long)vdso_addr + size);
	fflush(stdout);

#ifdef __i386__
	/* vDSO is a landing for fast syscalls - don't use it for munmap() */
	asm volatile ("int $0x80" : "=a" (ret)
			: "a" (SYS_munmap),
			  "b" (vdso_addr),
			  "c" (size));
	errno = -ret;
#else /* __x86_64__ */
	ret = munmap(vdso_addr, size);
#endif
	if (ret) {
		if (errno == EINVAL) {
			printf("[NOTE]\tvDSO partial move failed, will try with bigger size\n");
			return -1; /* Retry with larger */
		}
		printf("[FAIL]\tmunmap failed (%d): %m\n", errno);
		return 1;
	}

	return 0;
}

int main(int argc, char **argv, char **envp)
{
	pid_t child;

#ifdef __i386__
	enum syscall_type_t {
		INT80, SYSCALL32, SYSENTER
	} syscall_type = INT80;

	if (argc > 1) {
		if (!strcmp(argv[1], "syscall32")) {
			syscall_type = SYSCALL32;
			printf("[NOTE]\tUsing syscall32 after munmap\n");
		} else if (!strcmp(argv[1], "sysenter")) {
			syscall_type = SYSENTER;
			printf("[NOTE]\tUsing sysenter after munmap\n");
		}
	}
#endif

	child = fork();
	if (child == -1) {
		printf("[WARN]\tfailed to fork (%d): %m\n", errno);
		return 1;
	}

	if (child == 0) {
		unsigned long vdso_size = PAGE_SIZE;
		unsigned long auxval;
		int ret = -1;

		auxval = getauxval(AT_SYSINFO_EHDR);
		printf("\tAT_SYSINFO_EHDR is %#lx\n", auxval);
		if (!auxval || auxval == -ENOENT) {
			printf("[WARN]\tgetauxval failed\n");
			return 0;
		}

		/* Simpler than parsing ELF header */
		while (ret < 0) {
			ret = try_to_unmap((void *)auxval, vdso_size);
			vdso_size += PAGE_SIZE;
		}

		/* Glibc is likely to explode now - exit with raw syscall */
#ifdef __i386__
		switch (syscall_type) {
		case SYSCALL32:
			asm volatile ("syscall" : : "a" (__NR_exit), "b" (!!ret));
		case SYSENTER:
			asm volatile ("sysenter" : : "a" (__NR_exit), "b" (!!ret));
		default:
		case INT80:
			asm volatile ("int $0x80" : : "a" (__NR_exit), "b" (!!ret));
		}
#else /* __x86_64__ */
		syscall(SYS_exit, ret);
#endif
	} else {
		int status;

		if (waitpid(child, &status, 0) != child) {
			printf("[FAIL]\tUnexpected child, killing the expected one\n");
			kill(child, SIGKILL);
			return 1;
		}


#ifdef __i386__
		switch (syscall_type) {
		case SYSCALL32:
		case SYSENTER:
			if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) {
				printf("[OK]\t32-bit process gets segfault on fast syscall with unmapped vDSO\n");
				return 0;
			}
		default:
		case INT80:
			/* same as on x86_64 */
		}
#endif

		if (!WIFEXITED(status)) {
			printf("[FAIL]\tmunmap() of the vDSO does not work on this kernel!\n");
			if (WIFSIGNALED(status))
				printf("[FAIL]\tprocess crashed with %s\n",
					strsignal(WTERMSIG(status)));
			return 1;
		} else if (WEXITSTATUS(status) != 0) {
			printf("[FAIL]\tChild failed with %d\n",
					WEXITSTATUS(status));
			return 1;
		}
		printf("[OK]\n");
	}

	return 0;
}
