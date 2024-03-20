#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <debug.h>
#include <stddef.h>
#include "threads/interrupt.h"

struct lock filesys_lock;
bool check_addr(char *addr);
//int create_fd(struct file *f);
void del_fd(int fd);
struct file* find_file_by_fd(int fd);
int create_fd(struct file *file);
typedef int pid_t;
void syscall_init (void);
/* Projects 2 and later. */
void halt (void); //NO_RETURN
void exit (int status);// NO_RETURN
pid_t fork (const char *thread_name, const struct intr_frame *f);
int exec (const char *cmd_line);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

int dup2(int oldfd, int newfd);
#endif /* userprog/syscall.h */
