/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Copyright (C) 2019  Dmitry Safonov, Andrey Vagin
 */

#ifndef _ASM_X86_STATIC_RETCALL_H
#define _ASM_X86_STATIC_RETCALL_H

struct retcall_entry {
	u16 call;
	u16 ret;
	u16 out;
};

#define static_retcall(func, ...)					\
	do {								\
		asm_volatile_goto(					\
			".pushsection __retcall_table, \"aw\" \n\t"	\
			"2: .word %l[l_call] - 2b\n\t"			\
			".word %l[l_return] - 2b\n\t"			\
			".word %l[l_out] - 2b\n\t"			\
			".popsection"					\
			: : : : l_call, l_return, l_out);		\
l_call:									\
		func(__VA_ARGS__);					\
l_return:								\
		return;							\
		annotate_reachable();					\
l_out:									\
		nop();							\
		return;							\
	} while(0)

#define static_retcall_int(ret, func, ...)				\
	do {								\
		asm_volatile_goto(					\
			".pushsection __retcall_table, \"aw\" \n\t"	\
			_ASM_ALIGN "\n\t"				\
			"2: .word %l[l_call] - 2b\n\t"			\
			".word %l[l_return] - 2b\n\t"			\
			".word %l[l_out] - 2b\n\t"			\
			".popsection"					\
			: : : : l_call, l_return, l_out);		\
l_call:									\
		func(__VA_ARGS__);					\
l_return:								\
		return ret;						\
		annotate_reachable();					\
l_out:									\
		nop();							\
		return ret;						\
	} while(0)

#endif
