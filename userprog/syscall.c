#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "lib/kernel/stdio.h"
#include "vm/vm.h"

// struct lock filesys_lock;
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

	lock_init(&filesys_lock);
}

// void check_addr(char *addr){
// 	if (addr == NULL || !is_user_vaddr(addr) || !pml4_get_page(thread_current()->pml4,addr)){
// 		exit(-1);
// 	}
// }
bool check_addr(char* addr){
	if(!addr || !is_user_vaddr(addr)|| !pml4_get_page(thread_current()->pml4,addr))
		return false;
	return true;
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	switch(f->R.rax){
		case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi,f);
		break;
	case SYS_EXEC:  
		f->R.rax = exec(f->R.rdi);
		break;
	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);

		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		// if(!check_addr(f->R.rsi))
		// 	exit(-1);
		f->R.rax = read(f->R.rdi,f->R.rsi,f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi,f->R.rsi,f->R.rdx);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	}
}

void halt (void)
{
	power_off();
}

void exit (int status)
{
	struct thread *cur = thread_current (); 
    /* Save exit status at process descriptor */
	cur->exit_status = status;
    printf("%s: exit(%d)\n" , cur -> name , status);
	//printf("syscall_exit\n");
    thread_exit();
}

pid_t fork (const char *thread_name, const struct intr_frame *f){
	struct thread *curr = thread_current ();
	// printf("[DBG] fork() {%s} try to fork {%s}\n", curr->name, thread_name); //
	return process_fork(thread_name, f);
}

/* process_create_initd 과 유사, thread_create은 fork에서 */
int exec (const char *cmd_line){
	// struct file *open_file = filesys_open(cmd_line);
	// if(open_file == NULL){
	// 	return -1;
	// }
	if(!check_addr(cmd_line))
		exit(-1);
	// int size = strlen(cmd_line) + 1;
	char *cmd_line_copy;
	cmd_line_copy = palloc_get_page(0);
	if (cmd_line_copy == NULL)
		exit(-1);
	strlcpy (cmd_line_copy, cmd_line, PGSIZE);
	if (process_exec(cmd_line_copy) == -1)
		exit(-1);
}

int wait (pid_t child_tid){
	return process_wait(child_tid);
}

// int create_fd(struct file *file){
// 	struct thread *curr = thread_current();
// 	if(curr->fd_idx <128){
// 		int idx = curr->fd_idx;
// 		curr->fdt[idx] = file;
// 		curr->fd_idx ++;
// 		return idx;
// 	}
// 	return -1;
// }

int create_fd(struct file *file){
	// struct thread *curr = thread_current();
	// struct file **fdt = curr->fdt;
	// if(curr->fd_idx <128){
	// 	int idx = curr->fd_idx;
	// 	curr->fdt[idx] = file;
	// 	curr->fd_idx ++;
	// 	return idx;
	// }
	// return -1;
	struct thread*curr = thread_current();
	struct file**fdt = curr->fdt;

	while(curr->fd_idx<FDT_COUNT_LIMIT&&fdt[curr->fd_idx])
		curr->fd_idx++;
		if(curr->fd_idx >= FDT_COUNT_LIMIT)
			return -1;
		fdt[curr->fd_idx] =file;

		return curr->fd_idx;
	
	// for (int idx = curr->fd_idx; idx< FDT_COUNT_LIMIT; idx++){
	// 	if (fdt[idx] == NULL){
	// 		fdt[idx] = file;
	// 		curr->fd_idx = idx;
	// 		return curr->fd_idx;
	// 	}
	// }
	// return -1;
}

struct file* find_file_by_fd(int fd){
	// struct thread *curr = thread_current();
	// struct file **fdt = curr->fdt;
	// if(fd >128 || fd <3)
	// 	exit(-1);
	// return curr->fdt[fd];
	struct thread*curr = thread_current();
	struct file**fdt = curr->fdt;
	if(fd < 2 || fd >= FDT_COUNT_LIMIT)
		return NULL;
	
	return fdt[fd];
}

void del_fd(int fd){
	// struct thread *curr = thread_current();
	// struct file **fdt = curr->fdt;

	// if(fd == curr->fd_idx-1)
	// {
	// 	curr->fdt[fd] = NULL;
	// 	curr->fd_idx --;
	// }else{
	// 	for(int i = fd; i < curr->fd_idx ; i++){
	// 		curr->fdt[i] = curr->fdt[i+1];
	// 	}
	// 	curr->fd_idx --;
	// }
	struct thread*curr = thread_current();
	struct file**fdt = curr->fdt;
	if(fd < 2 || fd >= FDT_COUNT_LIMIT)
	{
		return NULL;
	}
	fdt[fd] = NULL;	 
}
bool create (const char *file, unsigned initial_size){
	if(!check_addr(file)){
			exit(-1);
		}
	lock_acquire(&filesys_lock);
	// if(strlen(file) >= 511)
	// 	return 0;
	bool success = filesys_create(file,initial_size);
	lock_release(&filesys_lock);
	return success;
	
}
// bool create (const char *file, unsigned initial_size){
// 	// check_addr(file);
// 	// printf("%d\n",strlen(file));
// 	// if (file==NULL || strlen(file) == 0){
// 	// 	exit(-1);
// 	// }
// 	// if (strlen(file) >= 511){
// 	// 	return 0;
// 	// lock_acquire(&filesys_lock);
// 	check_addr(file);
// 	bool success = filesys_create(file, initial_size);
// 	// lock_release(&filesys_lock);
// 	return success;
// 	}
bool remove (const char *file){
	if(!check_addr(file))
			exit(-1);
	//lock_acquire(&filesys_lock);
	bool success = filesys_remove(file);
	//lock_release(&filesys_lock);
	return success;
}

int open (const char *file){
	if(!check_addr(file))
			exit(-1);
	// // if(file == NULL){
	// // 	exit(-1);
	// // }
	// lock_acquire(&filesys_lock);
	// if(strcmp(file,"")== 0){
	// 	return -1;
	// }
	// struct file *open_file = filesys_open(file);
	// lock_release(&filesys_lock);
	// if(open_file == NULL){
	// 	return -1;
	// }else {
	// 	int fd = create_fd(open_file);
	// 	return fd;
	// }
	struct file *f = filesys_open(file);

	if (f == NULL)
		return -1;

	int fd = create_fd(f);
	if (fd == -1)
		file_close(f);

	return fd;
}
// /* returns fd*/
// int open (const char *file){
// 	check_addr(file);
// 	//lock_acquire(&filesys_lock);
// 	struct file *f= filesys_open(file);
	
// 	if (f == NULL){
// 	   	return -1;
// 	}
	
// 	int fd = create_fd(file);
// 	if (fd == -1)
// 		file_close(f);
// 	//lock_release(&filesys_lock);
// 	return fd;
// }
int filesize (int fd){
	struct file *file = find_file_by_fd(fd);
	if(file == NULL)
		return -1;
	return file_length(file);
}

int read (int fd, void *buffer, unsigned length){
	if(!check_addr(buffer))
			exit(-1);
	char *ptr = (char *)buffer;
	int bytes_read = 0;

	if (fd == 0){
		for (int i = 0; i < length; i++){
			char ch = input_getc();
			if (ch == '\n'){
				break;
			*ptr = ch;
            ptr++;
			bytes_read++;
			}
		}
	}
	else{
		if (fd < 2)
				return -1;
		struct file *file = find_file_by_fd(fd);
		if (file == NULL){
			return -1;
		}
		lock_acquire(&filesys_lock);
		bytes_read = file_read(file,buffer,length);
		lock_release(&filesys_lock);
}
	return bytes_read;
}

// /* STDIN:0 STDOUT:1*/
int write (int fd, const void *buffer, unsigned length){
	if(check_addr(buffer) == 0)
		exit(-1);
	int bytes_written = 0;
	if (fd == 1){
		//lock_acquire(&filesys_lock);
		putbuf(buffer,length);
		//lock_release(&filesys_lock);
		bytes_written = length;
	}
	else
	{
		if (fd < 2)
			return -1;
		struct file *file = find_file_by_fd(fd);
		if (file == NULL)
			return -1;
		lock_acquire(&filesys_lock);
		bytes_written = file_write(file,buffer,length);
		lock_release(&filesys_lock);
	}
	return bytes_written;
}


/*파일 편집 위치 변경*/
void seek (int fd, unsigned position){
	if (fd < 2)
		return -1;
	struct file *file = find_file_by_fd(fd);
	// if(!check_addr(file))
	// 	exit(-1);
	if (file == NULL) {
	 	return;
	}
	file_seek(file, position);
}

/*파일 위치 반환*/
unsigned tell (int fd){
	if (fd < 2)
		return;
	struct file *file = find_file_by_fd(fd);
	// if(!check_addr(file))
	// 	exit(-1);
	if (file == NULL) {
	 	return;
	}
	return file_tell(file);
}


/* set 0 at file descriptor entry at index fd */
void close (int fd){
	if (fd < 2)
		return;
	struct file *file = find_file_by_fd(fd);
	if(file == NULL)
		return;
	file_close(file);
	del_fd(fd);
}


