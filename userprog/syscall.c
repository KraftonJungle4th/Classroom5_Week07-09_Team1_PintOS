#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}
bool check_addr(char* addr){
	if(!is_user_vaddr(addr)|| !pml4_get_page(thread_current()->pml4,addr))
		return false;
	return true;
}
/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");
	// printf("%d\n",check_addr(f->R.rsi));
	// printf("%d\n",f->R.rax);
	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi);
		break;
	case SYS_EXEC:  
		f->R.rax = exec(f->R.rdi);
		break;
	case SYS_WAIT:
		wait(f->R.rdi);
		break;
	case SYS_CREATE:
		if(!check_addr(f->R.rdi)){
			exit(-1);
		}
		if(f->R.rdi ==NULL || strcmp(f->R.rdi,"")== 0)
			exit(-1);
		if (!create(f->R.rdi,f->R.rsi))
			f->R.rax = false;
		else 
			f->R.rax = true;
		break;
	case SYS_REMOVE:
		remove(f->R.rdi);
		break;
	case SYS_OPEN:
		if(!check_addr(f->R.rdi))
			exit(-1);
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		if(!check_addr(f->R.rsi))
			exit(-1);
		f->R.rax = read(f->R.rdi,f->R.rsi,f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi,f->R.rsi,f->R.rdx);
		break;
	case SYS_SEEK:
		break;
	case SYS_TELL:
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	default:
		break;
	}
}

void halt (void) //NO_RETURN
{
	power_off();
}

void exit (int status)// NO_RETURN
{
	thread_current()->exit_status = status;
	struct thread *curr = thread_current ();
	printf("%s: exit(%d)\n",curr->name,curr->exit_status);
	thread_exit();
}

pid_t fork (const char *thread_name){
	return process_fork(thread_name,thread_current()->tf);
}

int exec (const char *file){
	return process_exec(file);
}

int wait (pid_t child_tid){
	return process_wait(child_tid);
}

int create_fd(struct file *file){
	struct thread *curr = thread_current();
	if(curr->fd_idx <64){
		int idx = curr->fd_idx;
		curr->files[idx] = file;
		curr->fd_idx ++;
		return idx+2;
	}
	return -1;
}

struct file* find_file_by_fd(int fd){
	fd -=2;
	if(fd >64 || fd <0)
		exit(-1);
	struct thread *curr = thread_current();
	return curr->files[fd];
}

void del_fd(int fd){
	fd -= 2;
	struct thread *curr = thread_current();
	
	if(fd == curr->fd_idx-1)
	{
		curr->files[fd] = NULL;
		curr->fd_idx --;
	}else{
		for(int i = fd; i < curr->fd_idx ; i++){
			curr->files[i] = curr->files[i+1];
		}
		curr->fd_idx --;
	}	 
}

bool create (const char *file, unsigned initial_size){
	if(strlen(file) >= 511)
		return 0;
	return filesys_create(file,initial_size);
}

bool remove (const char *file){
	return filesys_remove(file);
}

int open (const char *file){
	if(file == NULL){
		exit(-1);
	}
	if(strcmp(file,"")== 0 ){
		return -1;
	}
	struct file *open_file = filesys_open(file);

	if(open_file == NULL){
		return -1;
	}else {
		int fd = create_fd(open_file);
		return fd;
	}
}

int filesize (int fd){
	struct file *file = find_file_by_fd(fd);
	if(file == NULL)
		return -1;
	return file_length(file);
}

int read (int fd, void *buffer, unsigned length){
	struct file *file = find_file_by_fd(fd);
	if (file == NULL){
		return -1;
	}
	return file_read(file,buffer,length);
}

int write (int fd, const void *buffer, unsigned length){
	if (fd == 1) 
		putbuf(buffer,length);
	else
	{
		if(check_addr(buffer) == 0)
			exit(-1);
		struct file *file = find_file_by_fd(fd);
		return file_write(file,buffer,length);
	}
}

void seek (int fd, unsigned position);
unsigned tell (int fd);

void close (int fd){
	struct file *file = find_file_by_fd(fd);
	if(file == NULL)
		return;
	file_close(file);
	del_fd(fd);
}

int dup2(int oldfd, int newfd);
