#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "x86.h"
#include "traps.h"
#include "spinlock.h"
//added
#include "wmap.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "stat.h"
#include "fcntl.h"
#define min(a, b) ((a) < (b) ? (a) : (b))

// Interrupt descriptor table (shared by all CPUs).
struct gatedesc idt[256];
extern uint vectors[];  // in vectors.S: array of 256 entry pointers
struct spinlock tickslock;
uint ticks;

void
tvinit(void)
{
  int i;

  for(i = 0; i < 256; i++)
    SETGATE(idt[i], 0, SEG_KCODE<<3, vectors[i], 0);
  SETGATE(idt[T_SYSCALL], 1, SEG_KCODE<<3, vectors[T_SYSCALL], DPL_USER);

  initlock(&tickslock, "time");
}

void
idtinit(void)
{
  lidt(idt, sizeof(idt));
}

//handle page faults for mmap lazily
void handle_page_fault() {
  struct proc *p = myproc();
  uint page_fault_addr = rcr2();

  //go thru memory-mapped regions to find the one we need
  for (int i = 0; i < p->total_mmaps; i++) {
   
    //check if fault addr is in this one
    if (page_fault_addr < p->mmaps[i].virt_addr ||
        page_fault_addr >= p->mmaps[i].virt_addr + p->mmaps[i].size) {
      continue; //move on if not in the range
    }

    //addr in range so do lazy alloc and/or file-backed mapping
    uint faulting_page_start = PGROUNDDOWN(page_fault_addr);
    char *mem = kalloc();
    if (!mem) {
      cprintf("error: no more memory\n");
      kill(p->pid);
      return;
    } else {
      memset(mem, 0, PGSIZE);
    }

    //file-backed mapping
    if (!(p->mmaps[i].flags & MAP_ANONYMOUS)) {
     //struct file *f = p->mmaps[i].f;
      if (!p->mmaps[i].f) {
        cprintf("invalid file\n");
        kill(p->pid);
        return;
      }

      uint file_offset = faulting_page_start - p->mmaps[i].virt_addr;
      if (file_offset >= p->mmaps[i].f->ip->size) {
        cprintf("invalid offset\n");
        kill(p->pid);
        return;
      }

      uint to_read = min(p->mmaps[i].f->ip->size - file_offset, (uint)PGSIZE);
      ilock(p->mmaps[i].f->ip);
      if (readi(p->mmaps[i].f->ip, mem, file_offset, to_read) != to_read) {
        iunlock(p->mmaps[i].f->ip);
        cprintf("error reading file\n");
        kill(p->pid);
        return;
      }
      iunlock(p->mmaps[i].f->ip);
    }

    //map page
    if (mappages(p->pgdir, (char *)faulting_page_start, PGSIZE, V2P(mem), PTE_W | PTE_U) < 0) {
      cprintf("handle_page_fault: mappages failed\n");
      kfree(mem); //free alloc'd mem
      kill(p->pid);
      return;
    }
    return; // handled page fault.
  }

  cprintf("Segmentation Fault\n");
  p->killed = 1;
  }

//PAGEBREAK: 41
void
trap(struct trapframe *tf)
{
  if(tf->trapno == T_SYSCALL){
    if(myproc()->killed)
      exit();
    myproc()->tf = tf;
    syscall();
    if(myproc()->killed)
      exit();
    return;
  }

  switch(tf->trapno){
  case T_IRQ0 + IRQ_TIMER:
    if(cpuid() == 0){
      acquire(&tickslock);
      ticks++;
      wakeup(&ticks);
      release(&tickslock);
    }
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE:
    ideintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE+1:
    // Bochs generates spurious IDE1 interrupts.
    break;
  case T_IRQ0 + IRQ_KBD:
    kbdintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_COM1:
    uartintr();
    lapiceoi();
    break;

  case T_IRQ0 + 7:
  case T_IRQ0 + IRQ_SPURIOUS:
    cprintf("cpu%d: spurious interrupt at %x:%x\n",
            cpuid(), tf->cs, tf->eip);
    lapiceoi();
    break;
  case 14: // Page fault caused by mmap
    if (rcr2() >= MMAPBASE && rcr2() < KERNBASE) {
      handle_page_fault(tf);
      break;
    }
  //PAGEBREAK: 13
  default:
    if(myproc() == 0 || (tf->cs&3) == 0){
      // In kernel, it must be our mistake.
      cprintf("unexpected trap %d from cpu %d eip %x (cr2=0x%x)\n",
              tf->trapno, cpuid(), tf->eip, rcr2());
      panic("trap");
    }
    // In user space, assume process misbehaved.
    cprintf("pid %d %s: trap %d err %d on cpu %d "
            "eip 0x%x addr 0x%x--kill proc\n",
            myproc()->pid, myproc()->name, tf->trapno,
            tf->err, cpuid(), tf->eip, rcr2());
    myproc()->killed = 1;
  }

  // Force process exit if it has been killed and is in user space.
  // (If it is still executing in the kernel, let it keep running
  // until it gets to the regular system call return.)
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();

  // Force process to give up CPU on clock tick.
  // If interrupts were on while locks held, would need to check nlock.
  if(myproc() && myproc()->state == RUNNING &&
     tf->trapno == T_IRQ0+IRQ_TIMER)
    yield();

  // Check if the process has been killed since we yielded
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();
}
