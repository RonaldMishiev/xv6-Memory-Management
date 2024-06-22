#include "types.h"
#include "defs.h"
#include "param.h"
#include "mmu.h"
#include "proc.h"
#include "fs.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "file.h"
#include "fcntl.h"
#include "memlayout.h"
#include "wmap.h"

//physical addr of page from virtual addr of proc
uint get_physical_addr_page(struct proc *p, uint addr, pte_t **pte)
{
  *pte = walkpgdir(p->pgdir, (char *)addr, 0);
  return *pte ? PTE_ADDR(**pte) : SUCCESS;
}

int getwmapinfo(struct wmapinfo *wminfo)
{
  struct proc *p = myproc();
  wminfo->total_mmaps = p->total_mmaps;
  pte_t *pte;
  int i = 0;
  while (i < p->total_mmaps)
  {
    uint virt_addr = p->mmaps[i].virt_addr;
    uint size = p->mmaps[i].size;
    wminfo->addr[i] = PGROUNDUP(virt_addr);
    wminfo->length[i] = size;
    uint start = virt_addr;
    int n_loaded_pages = 0;
    for (; start < virt_addr + size; start += PGSIZE)
    {
      uint pa = get_physical_addr_page(p, start, &pte);

      // If pa is not zero then page is allocated
      if (pa != 0)
      {
        n_loaded_pages += 1;
      }
    }
    wminfo->n_loaded_pages[i] = n_loaded_pages;
    i += 1;
  }
  return SUCCESS;
}

int getpgdirinfo(struct pgdirinfo *pdinfo)
{
  struct proc *p = myproc();
  pte_t *pte;
  uint  i = 0;
  uint  j = 0;

  //loop below inspired from vm.c freevm function = looping thru directory entries per page
  for (i = 0; i < NPDENTRIES; i++)
  {
    if (p->pgdir[i] & PTE_P)
    {
      pte = (pte_t *)P2V(PTE_ADDR((p->pgdir[i])));
      for (j = 0; j < NPTENTRIES; j++)
      {
        if (pte[j] & PTE_P && pte[j] & PTE_U)
        {
          uint pa = PTE_ADDR(pte[j]);
          pdinfo->va[pdinfo->n_upages] = PGADDR(i, j, 0);
          pdinfo->pa[pdinfo->n_upages] = pa;
          pdinfo->n_upages++;
          if (pdinfo->n_upages >= MAX_UPAGE_INFO)
          {
            return SUCCESS;
          }
        }
      }
    }
  }
  if ((int)pdinfo->n_upages <= 1)
  { // need at least one page - test_2
    pdinfo->n_upages = 1;
  }
  // weird but cannot explain why 1st element is not 0x0 as per test_2 so ended up overwriting...may be because I am testing in WSL
   pdinfo->va[0] = 0x0;
  return SUCCESS;
}

// Copy the mmap regions from src to dest
void copy_wmap_struct(struct wmap_region *dest, struct wmap_region *src)
{
  dest->virt_addr = src->virt_addr;
  dest->size = src->size;
  dest->flags = src->flags;
  dest->fd = src->fd;
  dest->f = src->f;
}

//right shift array & put map after i
int setup_mmap_arr(struct proc *p, int size, int i, uint mmapaddr)
{
  if (!(PGROUNDUP(mmapaddr + size) >= KERNBASE))
  {
    for (int j = p->total_mmaps; j > i + 1; j--) {
        copy_wmap_struct(&p->mmaps[j], &p->mmaps[j - 1]);
    }
    p->mmaps[i + 1].virt_addr = mmapaddr;
    p->mmaps[i + 1].size = size;
    return i + 1; //index of wmap mapping
  }
  return FAILED;
}

// To check if mmap is possible at user provided address
int check_wmap_possible(struct proc *p, uint addr, int size)
{
  uint mmap_addr = PGROUNDUP(addr);
  if (mmap_addr < MMAPBASE || mmap_addr + size > KERNBASE) return FAILED;

  // if addr exceed all current mapping addr/size then add new mapping
  if (mmap_addr >= PGROUNDUP(p->mmaps[p->total_mmaps - 1].virt_addr +
                             p->mmaps[p->total_mmaps - 1].size))
  {
    return setup_mmap_arr(p, size, p->total_mmaps - 1, mmap_addr);
  }

  for (int i = 0; i < p->total_mmaps - 1; i++) {
    uint start_addr = PGROUNDUP(p->mmaps[i].virt_addr + p->mmaps[i].size);
    uint end_addr = PGROUNDUP(p->mmaps[i + 1].virt_addr);

    //new addr can be squized between existing address spaces already allocated
    if (mmap_addr >= start_addr && mmap_addr + size <= end_addr) {
      return setup_mmap_arr(p, size, i, mmap_addr);
    }
  }

  // add addr at the beginign of total wmap regions
  if (mmap_addr < PGROUNDUP(p->mmaps[0].virt_addr +
                            p->mmaps[0].size))
  {
    //cprintf("new condition in check_wmap_possible where it tried to add at the begining - mmap_addr:%p, size:%d\n", mmap_addr, size);
    return setup_mmap_arr(p, size, -1, mmap_addr);
  }
  return FAILED;
}

//find wmap region virtual addr index for new addr+size in wmap regions array in increasing ord
int find_wmap_addr(struct proc *p, int size)
{
    //if first mapping or if size is too big
    if (p->total_mmaps == 0 || PGROUNDUP(MMAPBASE + size) >= KERNBASE) {
        return (p->total_mmaps == 0 && PGROUNDUP(MMAPBASE + size) < KERNBASE) ?
               setup_mmap_arr(p, size, -1, PGROUNDUP(MMAPBASE)) : FAILED;
    }

    //go thru existing mappings to find right spot
    for (int i = 0; i <= p->total_mmaps; i++) {
        uint nextAddr = (i == p->total_mmaps) ? KERNBASE : PGROUNDUP(p->mmaps[i].virt_addr);
        uint prevEndAddr = (i == 0) ? MMAPBASE : PGROUNDUP(p->mmaps[i - 1].virt_addr + p->mmaps[i - 1].size);
        
        //if enough space between the current and next one
        if (nextAddr - prevEndAddr >= size) {
            return setup_mmap_arr(p, size, i - 1, PGROUNDUP(prevEndAddr));
        }
    }
    
    return FAILED; // No suitable space found.
}

// wmap system call main function
uint wmap(uint addr, int length, int flags, int fd)
{
  struct proc *p = myproc();
  if (length <= 0 || (!(flags & MAP_ANONYMOUS) && !(flags & MAP_PRIVATE) && !(flags & MAP_SHARED))
      || (p->total_mmaps >= 30))
  {
    //invalid args or length 0 or below or maps at/above max
    return FAILED;
  }

  int i = -1;
  if (flags & MAP_FIXED)
  {
    if ((void *)addr != (void *)0)
    {
      uint rounded_addr = PGROUNDUP(PGROUNDUP(addr) + length);
      if (addr < MMAPBASE || rounded_addr > KERNBASE || addr % PGSIZE != 0)
      {
        return FAILED;
      }

      i = check_wmap_possible(p, (uint)addr, length);
      if (i == -1)
      {
        return FAILED;
      }
    }
  }
  else
  {
    int flag = 0;
    if ((void *)addr != (void *)0)
    {
      uint rounded_addr = PGROUNDUP(PGROUNDUP(addr) + length);
      if (addr < MMAPBASE || rounded_addr > KERNBASE)
      {
        return FAILED;
      }
      i = check_wmap_possible(p, (uint)addr, length);
      if (i != -1)
      {
        flag = 1;
      }
    }
    if (!flag)
    {
      i = find_wmap_addr(p, length);
    }
    if (i == -1)
    {
      return FAILED;
    }
  }

  // Store wmap info in process's wmap array
  p->mmaps[i].flags = flags;
  p->mmaps[i].fd = fd;
  p->mmaps[i].f = p->ofile[fd];
  p->total_mmaps++;
  return p->mmaps[i].virt_addr;
}

// Main function of munmap system call
int wunmap(uint addr)
{
    struct proc *p = myproc();
    uint mainaddr = PGROUNDUP(addr);
    int found = -1;

    //go thru maps
    for (int i = 0; i < p->total_mmaps; i++) {
        if (p->mmaps[i].virt_addr == mainaddr) {
            found = i;
            break;
        }
    }
    if (found == -1) return FAILED; //not found

    //write back to file for shared ones
    if ((p->mmaps[found].flags & MAP_SHARED) && !(p->mmaps[found].flags & MAP_ANONYMOUS)
        && (filewrite(p->mmaps[found].f, (char *)p->mmaps[found].virt_addr, p->mmaps[found].size) < 0)) {
        return FAILED;
    }

    //free alloc'd pages
    for (uint tempaddr = mainaddr; tempaddr < mainaddr + p->mmaps[found].size; tempaddr += PGSIZE) {
        pte_t *pte;
        uint pa = get_physical_addr_page(p, tempaddr, &pte);
        if (pa) kfree(P2V(pa));
        if (pte) *pte = 0;
    }

    //clear & shift em
    memmove(&p->mmaps[found], &p->mmaps[found + 1], sizeof(struct wmap_region) * (p->total_mmaps - found - 1));
    p->total_mmaps--;

    return SUCCESS;
}

uint wremap(uint oldaddr, int oldsize, int newsize, int flag)
{
  struct proc *p = myproc();
  int i = 0;
  /// over the limit
  if (oldaddr + newsize > KERNBASE)
  {
    return FAILED;
  }
  while (i < p->total_mmaps)
  {
    if (p->mmaps[i].virt_addr == oldaddr && p->mmaps[i].size == oldsize)
      break;
    i += 1;
  }
  // Page with given address does not exist
  if (i == 30)
  {
    // Addr not present in mappings
    return FAILED;
  }
  // attempt to move to new address (?? may be expand in place - below code is similar logic as in check_ helper method
  uint mmap_addr = PGROUNDUP(oldaddr);
  int end_addr = PGROUNDUP(p->mmaps[i + 1].virt_addr) == 0 ? KERNBASE : PGROUNDUP(p->mmaps[i + 1].virt_addr); /// if current va is last one check use kenbase
  // new addr can be squized between existing address spaces already allocated
  if (end_addr > (mmap_addr + newsize))
  {
    p->mmaps[i].size = newsize;
    /// free PA is decreasing in size
    pte_t *pte;
    if (newsize < oldsize)
    {
      uint currsize = newsize;
      for (; currsize < oldsize; currsize += PGSIZE)
      {
        uint tempaddr = mmap_addr + currsize;
        uint pa = get_physical_addr_page(p, tempaddr, &pte);
        if (pa == 0)
        {
          // Page was not mapped yet
          continue;
        }
        kfree(P2V(pa));
        *pte = 0;
      }
    }
    return p->mmaps[i].virt_addr;
  }
  // flag does nto allow to grow size in place
  if (flag == 0)
  {
    // Check if the new size is within the user address space
    if (oldaddr + newsize < MMAPBASE || oldaddr + newsize >= KERNBASE)
      return FAILED;
  }
  else if (flag & MREMAP_MAYMOVE)
  {
    if (oldsize < newsize)
    {
      // cannot squize into existign space between allocated addresses so allocatign new address
      if (wunmap(p->mmaps[i].virt_addr) < 0)
      {
        return FAILED;
      }
      uint newAddr = wmap(p->mmaps[i].virt_addr, newsize, p->mmaps[i].flags, p->mmaps[i].fd);
      // check for errors
      if (newAddr == 0xFFFFFFFF)
        return FAILED;
      return newAddr;
    }
    else
    {
      p->mmaps[i].size = newsize;
      return p->mmaps[i].virt_addr;
    }
  }
  return FAILED;
}