/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps
                        /* 0      tf_err   */
/*   refer to Trapframe   num  tf_trapno   */

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */

TRAPHANDLER_NOEC(_trap_divid, T_DIVIDE)
TRAPHANDLER_NOEC(_trap_debug, T_DEBUG)
TRAPHANDLER_NOEC(_trap_nmi, T_NMI)
TRAPHANDLER_NOEC(_trap_brkpt, T_BRKPT)
TRAPHANDLER_NOEC(_trap_overflow, T_OFLOW)
TRAPHANDLER_NOEC(_trap_bound, T_BOUND)
TRAPHANDLER_NOEC(_trap_illop, T_ILLOP)
TRAPHANDLER_NOEC(_trap_device, T_DEVICE)
TRAPHANDLER_NOEC(_trap_dblflt, T_DBLFLT)
TRAPHANDLER_NOEC(_trap_tss, T_TSS)
TRAPHANDLER_NOEC(_trap_segnp, T_SEGNP)
TRAPHANDLER_NOEC(_trap_stack, T_STACK)
TRAPHANDLER_NOEC(_trap_gpflt, T_GPFLT)
/* 
TRAPHANDLER_NOEC(_trap_pgflt, T_PGFLT)
*/
TRAPHANDLER(_trap_pgflt, T_PGFLT)  /* notice here */
TRAPHANDLER_NOEC(_trap_fperr, T_FPERR)
TRAPHANDLER_NOEC(_trap_align, T_ALIGN)
TRAPHANDLER_NOEC(_trap_mchk, T_MCHK)
TRAPHANDLER_NOEC(_trap_simd, T_SIMDERR)

TRAPHANDLER_NOEC(_trap_timer, IRQ_OFFSET + IRQ_TIMER)
TRAPHANDLER_NOEC(_trap_syscall, T_SYSCALL)

/*
 * Lab 3: Your code here for _alltraps
 */
_alltraps:
	pushl %ds   /*  refer to Trapframe   ds */
	pushl %es   /*                       es */
	pushal      /*                  tf_regs */
	movl $GD_KD, %eax
	movw %ax, %ds
	movw %ax, %es
	pushl %esp   // current stack pointer, pointer to Trapframe  
	call trap
	addl $4, %esp

