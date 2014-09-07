#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/cpu.h>
#include <kern/spinlock.h>
#include <kern/time.h>

static struct Taskstate ts;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t) idt
};


static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < sizeof(excnames)/sizeof(excnames[0]))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}


void
trap_init(void)
{
	extern struct Segdesc gdt[];

	extern void _trap_divid();
	extern void _trap_debug();
	extern void _trap_nmi();
	extern void _trap_brkpt();
	extern void _trap_overflow();
	extern void _trap_bound();
	extern void _trap_illop();
	extern void _trap_device();
	extern void _trap_dblflt();
	extern void _trap_tss();
	extern void _trap_segnp();
	extern void _trap_stack();
	extern void _trap_gpflt();
	extern void _trap_pgflt();
	extern void _trap_fperr();
	extern void _trap_align();
	extern void _trap_mchk();
	extern void _trap_simd();
	extern void _trap_syscall();
	extern void _trap_default();

// #define SETCALLGATE(gate, sel, off, dpl) 
// #define SETGATE(gate, istrap, sel, off, dpl) 
	// LAB 3: Your code here.
	//SETCALLGATE();	
	SETGATE(idt[T_DIVIDE], 1, GD_KT, _trap_divid, 0);
	SETGATE(idt[T_DEBUG], 1, GD_KT, _trap_debug, 0);
    SETGATE(idt[T_NMI], 0, GD_KT, _trap_nmi, 0);
    SETGATE(idt[T_BRKPT], 1, GD_KT, _trap_brkpt, 3);
    SETGATE(idt[T_OFLOW], 1, GD_KT, _trap_overflow, 0);
    SETGATE(idt[T_BOUND], 1, GD_KT, _trap_bound, 0);
    SETGATE(idt[T_ILLOP], 1, GD_KT, _trap_illop, 0);
    SETGATE(idt[T_DEVICE], 1, GD_KT, _trap_device, 0);
    SETGATE(idt[T_DBLFLT], 1, GD_KT, _trap_dblflt, 0);
    SETGATE(idt[T_TSS], 1, GD_KT, _trap_tss, 0);
    SETGATE(idt[T_SEGNP], 1, GD_KT, _trap_segnp, 0);
    SETGATE(idt[T_STACK], 1, GD_KT, _trap_stack, 0);
    SETGATE(idt[T_GPFLT], 1, GD_KT, _trap_gpflt, 0);
    SETGATE(idt[T_PGFLT], 1, GD_KT, _trap_pgflt, 0);
    SETGATE(idt[T_FPERR], 1, GD_KT, _trap_fperr, 0);
    SETGATE(idt[T_ALIGN], 1, GD_KT, _trap_align, 0);
    SETGATE(idt[T_MCHK], 1, GD_KT, _trap_mchk, 0);
    SETGATE(idt[T_SIMDERR], 1, GD_KT, _trap_simd, 0);

	
	extern void _trap_timer();
	SETGATE(idt[IRQ_OFFSET + IRQ_TIMER], 0, GD_KT, _trap_timer, 0);

	SETGATE(idt[T_SYSCALL], 0, GD_KT, _trap_syscall, 3);

	// from user space to kernel space, dpl from 3 to 0
	// Per-CPU setup 
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// The example code here sets up the Task State Segment (TSS) and
	// the TSS descriptor for CPU 0. But it is incorrect if we are
	// running on other CPUs because each CPU has its own kernel stack.
	// Fix the code so that it works for all CPUs.
	//
	// Hints:
	//   - The macro "thiscpu" always refers to the current CPU's
	//     struct Cpu;
	//   - The ID of the current CPU is given by cpunum() or
	//     thiscpu->cpu_id;
	//   - Use "thiscpu->cpu_ts" as the TSS for the current CPU,
	//     rather than the global "ts" variable;
	//   - Use gdt[(GD_TSS0 >> 3) + i] for CPU i's TSS descriptor;
	//   - You mapped the per-CPU kernel stacks in mem_init_mp()
	//
	// ltr sets a 'busy' flag in the TSS selector, so if you
	// accidentally load the same TSS on more than one CPU, you'll
	// get a triple fault.  If you set up an individual CPU's TSS
	// wrong, you may not get a fault until you try to return from
	// user space on that CPU.
	//
	// LAB 4: Your code here:
	thiscpu->cpu_ts.ts_esp0 = KSTACKTOP - thiscpu->cpu_id * 
							(KSTKSIZE + KSTKGAP);
	thiscpu->cpu_ts.ts_ss0 = GD_KD; 
	gdt[(GD_TSS0 >> 3) + thiscpu->cpu_id]	= SEG16(STS_T32A, 
				(uint32_t)(&(thiscpu->cpu_ts)), sizeof(struct Taskstate), 0);
	gdt[(GD_TSS0 >> 3) + thiscpu->cpu_id].sd_s = 0;
	ltr(GD_TSS0 + ((thiscpu->cpu_id) << 3));

#if 0
	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	ts.ts_esp0 = KSTACKTOP;
	ts.ts_ss0 = GD_KD;

	// Initialize the TSS slot of the gdt.
	gdt[GD_TSS0 >> 3] = SEG16(STS_T32A, (uint32_t) (&ts),
					sizeof(struct Taskstate), 0);
	gdt[GD_TSS0 >> 3].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	ltr(GD_TSS0);
#endif

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p from CPU %d\n", tf, cpunum());
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf("  esp  0x%08x\n", tf->tf_esp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.
	int no = tf->tf_trapno;
	if(no == T_BRKPT) {
		monitor(tf);
		return;
	}
	else if(no == T_PGFLT) {
		page_fault_handler(tf);
	}
	else if(no == T_SYSCALL) {
		uint32_t syscallno = tf->tf_regs.reg_eax;
		uint32_t a1 = tf->tf_regs.reg_edx;
		uint32_t a2 = tf->tf_regs.reg_ecx;
		uint32_t a3 = tf->tf_regs.reg_ebx;
		uint32_t a4 = tf->tf_regs.reg_edi;
		uint32_t a5 = tf->tf_regs.reg_esi;
		uint32_t ret = syscall(syscallno, a1, a2, a3, a4, a5);
		tf->tf_regs.reg_eax = ret;
		return;
#if 0
		int num = tf->tf_regs.reg_eax;
		char *s = (char*)tf->tf_regs.reg_edx;  // problem ??
		int len = tf->tf_regs.reg_ecx;  // problem ??
		if (num == SYS_cputs) {
			s[len] = '\0';
			cprintf("%s", s);
		}
		else if (num == SYS_env_destroy) {
			env_destroy(curenv);
		}
		else if (num == SYS_yield) {
			sched_yield();
		}
		else if (num == SYS_env_set_status) {
			int envid = tf->tf_regs.reg_edx;
			int status = tf->tf_regs.reg_ecx;
			sys_env_set_status(envid, status);
		}
		else {
			cprintf("syscall num %d not implemented yet\n", num);
		}
		return;  // need
#endif
	}
	else if(no >= T_DIVIDE && no <= T_SIMDERR) {
		cprintf("trap %d not implemented yet\n", no);
		//return;
	}

	// Handle spurious interrupts
	// The hardware sometimes raises these because of noise on the
	// IRQ line or other reasons. We don't care.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_SPURIOUS) {
		cprintf("Spurious interrupt on irq 7\n");
		print_trapframe(tf);
		return;
	}

	// Handle clock interrupts. Don't forget to acknowledge the
	// interrupt using lapic_eoi() before calling the scheduler!
	// LAB 4: Your code here.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_TIMER) {
		//cprintf("timer interrupt come\n");
		time_tick();
		lapic_eoi();
		sched_yield();
	}
	// Add time tick increment to clock interrupts.
	// Be careful! In multiprocessors, clock interrupts are
	// triggered on every CPU.
	// LAB 6: Your code here.


	// Unexpected trap: The user process or the kernel has a bug.
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT)
		panic("unhandled trap in kernel");
	else {
		env_destroy(curenv);
		return;
	}
}

void
trap(struct Trapframe *tf)
{
	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc");

	// Halt the CPU if some other CPU has called panic()
	extern char *panicstr;
	if (panicstr)
		asm volatile("hlt");

	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	// assert(!(read_eflags() & FL_IF));

//	cprintf("Incoming TRAP frame at %p\n", tf);
	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		// Acquire the big kernel lock before doing any
		// serious kernel work.
		// LAB 4: Your code here.
		assert(curenv);
		lock_kernel();

		// Garbage collect if current enviroment is a zombie
		if (curenv->env_status == ENV_DYING) {
			env_free(curenv);
			curenv = NULL;
			sched_yield();
		}

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}
	else {
		assert(!(read_eflags() & FL_IF));
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);


	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.

	if (curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
	else
		sched_yield();
}


void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;

	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();

	// Handle kernel-mode page faults.

	// LAB 3: Your code here.
	if ((tf->tf_cs & 0x3) == 0x00) {
	//	print_trapframe(tf);
		panic("Page fault in kernel\n");
	}
	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	//
	// The trap handler needs one word of scratch space at the top of the
	// trap-time stack in order to return.  In the non-recursive case, we
	// don't have to worry about this because the top of the regular user
	// stack is free.  In the recursive case, this means we have to leave
	// an extra word between the current top of the exception stack and
	// the new stack frame because the exception stack _is_ the trap-time
	// stack.
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack or can't write to it, or the exception
	// stack overflows, then destroy the environment that caused the fault.
	// Note that the grade script assumes you will first check for the page
	// fault upcall and print the "user fault va" message below if there is
	// none.  The remaining three checks can be combined into a single test.
	//
	// Hints:
	//   user_mem_assert() and env_run() are useful here.
	//   To change what the user environment runs, modify 'curenv->env_tf'
	//   (the 'tf' variable points at 'curenv->env_tf').

	// LAB 4: Your code here.
	uint32_t* esp = (uint32_t*)UXSTACKTOP;
	if (curenv->env_pgfault_upcall == NULL) {
		cprintf("Do not have env_pgfault_upcall\n");
		goto err;
	}
	// notice, lookat faultbadhandler.c
	// env_pgfault_upcall may be error  
//	cprintf("assert mem(upcall): %p\n", 
//			ROUNDDOWN(curenv->env_pgfault_upcall, PGSIZE));
	user_mem_assert(curenv, ROUNDDOWN(curenv->env_pgfault_upcall, PGSIZE), 
						PGSIZE, PTE_U);
	// check the stack
//	cprintf("assert mem(stack): %p", (void*)(UXSTACKTOP-PGSIZE));
	user_mem_assert(curenv, (void*)(UXSTACKTOP-PGSIZE), PGSIZE, PTE_U | PTE_W);

//	cprintf("to print pgfault handler frame\n");
//	print_trapframe(tf);
	// The first time enter this function from user space
	// tf_esp would be below USTACKTOP 
	// else it is a recursively call and have been set to below UXSTACKTOP
	//  curenv->env_tf.tf_esp = (uintptr_t)esp;
	if (tf->tf_esp >= (UXSTACKTOP - PGSIZE) && tf->tf_esp < UXSTACKTOP) {
		if ((tf->tf_esp - sizeof(struct UTrapframe) -4)  
				< (UXSTACKTOP - PGSIZE)) {
			cprintf("Will overflow");
			goto err;
		}
		esp = (uint32_t*)tf->tf_esp;
		--esp; 
		*esp = 0x0;
	}

	// refer to UTrapframe
	--esp;
	*esp = tf->tf_esp;  // somehow like ebp 
	--esp;
	*esp = tf->tf_eflags; 
	--esp;
	*esp = tf->tf_eip;
	esp -= (sizeof(struct PushRegs) >> 2);  // notice the size here
	*(struct PushRegs*)esp = tf->tf_regs; 
	--esp;
	//*esp = tf->tf_err; 
	*esp = 0x6; 
	--esp;
	*esp = fault_va;
	curenv->env_tf.tf_esp = (uintptr_t)esp;
	curenv->env_tf.tf_eip = (uintptr_t)curenv->env_pgfault_upcall;
	env_run(curenv);  // is it ok

err:
	// Destroy the environment that caused the fault.
	print_trapframe(tf);
	env_destroy(curenv);

}

