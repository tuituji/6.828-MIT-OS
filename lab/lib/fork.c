// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800


extern volatile pte_t vpt[]; 
extern volatile pde_t vpd[];
//  ./lib/entry.S
// For all page table entries vpt[i] to get the page table entry
// Take a look at kern/pmap.c
// 		kern_pgdir[PDX(UVPT)] = PADDR(kern_pgdir) | PTE_U | PTE_P;


// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	envid_t id = sys_getenvid();
//	cprintf("in fork pgfault addr: %p, id : %d\n", addr, id);
	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at vpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	int perm = PTE_U | PTE_COW;

	if ((vpd[PDX(addr)] & (PTE_P | PTE_U)) !=(PTE_U | PTE_P))
		panic("errror pgfault vpd addr: %p\n", addr);
//	printf("pde 0x%x\n", vpt[PGNUM(addr)]);
	if ((vpt[PGNUM(addr)] & perm) != perm)
		panic("error pgfault vpt addr: %p\n", addr);

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.

	// LAB 4: Your code here.
//	envid_t envid = sys_getenvid();
	// 0 is the current env,  see envid2env
	envid_t envid = 0x0; 

	// temporary map to PFTEMP, later in sys_page_map will map to addr
	r = sys_page_alloc(envid, PFTEMP, PTE_U | PTE_W | PTE_P);
	if ( r < 0) panic("error alloc page\n");

	// to copy the data
	memmove((void*)PFTEMP, (void*)ROUNDDOWN(addr, PGSIZE), PGSIZE);

	// to map to the child thread's address space
	r = sys_page_map(envid, (void*)PFTEMP, envid, 
					 (void*)ROUNDDOWN(addr, PGSIZE), PTE_U | PTE_W | PTE_P);
	if (r < 0) panic("error map page\n");

	// undo the temporary map
	r = sys_page_unmap(envid, (void*)PFTEMP); 
	if (r < 0) panic("error unmap\n");

//	panic("pgfault not implemented");
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	// LAB 4: Your code here.
	int ret = 0;
	int id = sys_getenvid();
	id = 0;
	pte_t pte = vpt[pn];
	//int perm = (PGOFF(pte) | PTE_P | PTE_U | PTE_COW) & (~PTE_W);
	int perm = ( PTE_P | PTE_U | PTE_COW) & (~PTE_W);
	
	ret = sys_page_map(id, (void*)(pn * PGSIZE), 
						envid, (void*)(pn * PGSIZE), perm);

	// Important here
	// If do not mark ~PTE_W here
	// Parent thread may change the mem and when chile do map
	// The mem have changed
	ret = sys_page_map(id, (void*)(pn *PGSIZE), 
						id, (void*)(pn * PGSIZE), perm) ;
						//id, (void*)(pn * PGSIZE), PGOFF(pte)) ;
	return ret;
//	panic("duppage not implemented");
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use vpd, vpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	int ret, i;
	envid_t id;
	uintptr_t addr;
	
	// set_pgfault_handler already allocated a page for user exception stack
	set_pgfault_handler(pgfault);
	id = sys_exofork();
	if (id < 0) panic("fork error sys_exofork error\n");
	if (id == 0) {   // the child process
		thisenv = &envs[ENVX(sys_getenvid())];
		set_pgfault_handler(pgfault); // yes need ??
		return 0;	
	}
	
	for (addr = 0, i = 0; addr < UTOP; addr += PGSIZE, ++i) {
		// the exception stack
		if (addr == (UXSTACKTOP - PGSIZE)) { 
			ret = sys_page_alloc(id, (void*)(UXSTACKTOP - PGSIZE), 
						PTE_P | PTE_U | PTE_W);
			if (ret < 0) panic("allocate page for UXSTACKTOP error");
			continue;
		}
		
		uint32_t perm = PTE_U | PTE_P;
		pde_t pde = vpd[(i >> 10)];	// check pde first
		if ((pde & perm) != perm) continue;
		pte_t pte = vpt[i];			// then pte
		if ((pte & perm) != perm) continue;
		
		ret = duppage(id, i);
		if (ret < 0) {
			cprintf("map addr error addr: %p\n", addr);
			return ret;
		}
	}

	extern void _pgfault_upcall(void);
	sys_env_set_pgfault_upcall(id, _pgfault_upcall);

	// Start the child environment running
	if ((ret = sys_env_set_status(id, ENV_RUNNABLE)) < 0)
		panic("sys_env_set_status: %e", ret);
	return id;

//	panic("fork not implemented");
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
