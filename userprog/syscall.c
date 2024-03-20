#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "lib/user/syscall.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "kernel/stdio.h"
#include "threads/synch.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_valid_addr(const char *addr);
void halt();
void exit(int status);
bool create(const char *file, unsigned initial_size);
int open(const char *file);
int filesize(int fd);
int write(int fd, const void *buffer, unsigned length);
int read(int fd, void *buffer, unsigned length);
void close(int fd);
tid_t fork(const char *thread_name);
/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	switch (f->R.rax)
	{

	case SYS_HALT: /* Halt the operating system. */
		halt();
		break;

	case SYS_EXIT: /* Terminate this process. */
		exit(f->R.rdi);
		break;

	case SYS_FORK: /* Clone current process. */
		fork((char *)f->R.rdi);
		break;

	case SYS_EXEC:
		break;

	case SYS_WAIT:
		break;

	case SYS_CREATE:
		f->R.rax = create((char *)f->R.rdi, f->R.rsi);
		break;

	case SYS_REMOVE:
		break;

	case SYS_OPEN:
		f->R.rax = open((char *)f->R.rdi);
		break;

	case SYS_FILESIZE:
		break;

	case SYS_READ:
		f->R.rax = read(f->R.rdi, (void *)f->R.rsi, f->R.rdx);
		break;

	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, (void *)f->R.rsi, f->R.rdx);
		break;

	case SYS_SEEK:
		break;

	case SYS_TELL:
		break;

	case SYS_CLOSE:
		close(f->R.rsi);
		break;

	default:
		printf("!!!!!!!ERROR!!!!!!!");
		thread_exit();
	}
}
void check_valid_addr(const char *addr)
{
	if (!is_user_vaddr(addr) || addr == NULL || !pml4_get_page(thread_current()->pml4, addr))
	{
		exit(-1);
	}
}

void halt()
{
	power_off();
}

void exit(int status)
{
	struct thread *curr = thread_current();
	curr->exit_status = status;

	if (curr->fd_idx > 1)
	{
		for (int fd = curr->fd_idx; fd > 1; fd--)
			close(fd);
	}
	printf("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
}

bool create(const char *file, unsigned initial_size)
{
	check_valid_addr(file);
	return filesys_create(file, initial_size);
}
tid_t fork(const char *thread_name)
{
}
int exec(const char *cmd_line)
{
}

int open(const char *file)
{
	check_valid_addr(file);
	struct file *f = filesys_open(file);
	if (f == NULL)
		return -1;

	struct thread *curr = thread_current();
	struct file **fdt = curr->fd_table;

	while (curr->fd_idx < FD_COUNT_LIMIT && fdt[curr->fd_idx])
	{
		curr->fd_idx++;
	}

	if (curr->fd_idx >= FD_COUNT_LIMIT)
	{
		file_close(f);
		return -1;
	}

	fdt[curr->fd_idx] = f;
	curr->runn_file = curr->fd_idx;

	return curr->fd_idx;
}

int filesize(int fd)
{
	int size = -1;

	if (fd <= 1)
		return size;

	struct thread *curr = thread_current();
	struct file *f = curr->fd_table[fd];

	if (f == NULL)
		return size;

	size = file_length(f);
	return size;
}

int read(int fd, void *buffer, unsigned length)
{
	int read_size = -1;

	check_valid_addr(buffer);
	if (fd > FD_COUNT_LIMIT || fd == STDOUT_FILENO || fd < 0)
		return read_size;

	struct thread *curr = thread_current();
	struct file *f = curr->fd_table[fd];

	if (f == NULL)
		return read_size;

	// lock_acquire (&filesys_lock);
	read_size = file_read(f, buffer, length);
	// lock_release (&filesys_lock);

	return read_size;
}

int write(int fd, const void *buffer, unsigned length)
{
	int write_size = -1;

	check_valid_addr(buffer);
	if (fd > FD_COUNT_LIMIT || fd <= 0)
		return write_size;

	if (fd == 1)
	{
		putbuf(buffer, length);
		return 0;
	}
	else
	{
		struct thread *curr = thread_current();
		struct file *f = curr->fd_table[fd];

		if (f == NULL)
			return write_size;

		// lock_acquire (&filesys_lock);
		write_size = file_write(f, buffer, length);
		// lock_release (&filesys_lock);
	}
	return write_size;
}

void close(int fd)
{
	if (fd <= 1)
		return;

	struct thread *curr = thread_current();
	struct file *f = curr->fd_table[fd];

	if (f == NULL)
		return;

	curr->fd_table[fd] = NULL;
	file_close(f);
}