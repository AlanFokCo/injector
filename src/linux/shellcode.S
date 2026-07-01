#if defined(__x86_64__)
#define handle_offset 0
#define dlopen_addr_offset 8
#define dlerror_addr_offset 16
#define dlflags_offset 24
#define file_path_offset 28
#define page_size 4096
	.text
	.global	injector_shellcode
	.hidden	injector_shellcode
	.type	injector_shellcode, @function
	// void *injector_shellcode(injector_shellcode_arg_t *arg) {
injector_shellcode:
	//   // prolog
	pushq	%rbx
	movq	%rdi, %rbx
	//   int dlflags = arg->dlflags;
	movl	dlflags_offset(%rbx), %esi
	//   const char *file_path = arg->file_path;
	leaq	file_path_offset(%rbx), %rdi
	//   void *handle = dlopen(file_path, dlflags);
	call	*dlopen_addr_offset(%rbx)
	//   arg->handle = handle;
	movq	%rax, handle_offset(%rbx)
	//   arg->file_path[0] = '\0';
	movb	$0, file_path_offset(%rbx)
	//   if (handle != NULL) return;
	test	%rax, %rax
	jnz	.exit
	//   if (arg->dlerror_addr == 0) return;
	cmpq	$0, dlerror_addr_offset(%rbx)
	je	.exit
	//   char *errmsg = dlerror();
	call	*dlerror_addr_offset(%rbx)
	//   if (errmsg == NULL) return;
	test	%rax, %rax
	jz	.exit
	//   char *dest = arg->file_path
	leaq	file_path_offset(%rbx), %rdi
	//   char *end = (char*)arg + page_size;
	leaq	page_size(%rbx), %rcx
.loop:
	//   char c = *(errmsg++);
	movb	(%rax), %dl
	addq	$1, %rax
	//   *(dest++) = c;
	movb	%dl, (%rdi)
	addq	$1, %rdi
	//   if (c == 0) return;
	testb	%dl, %dl
	jz	.exit
	//   if (dest < end) goto loop;
	cmpq	%rdi, %rcx
	ja	.loop
.exit:
	//   // epilog
	popq	%rbx
	ret
	// }
	.size	injector_shellcode, . - injector_shellcode

	.balign  4
	.global	injector_shellcode_size
	.hidden	injector_shellcode_size
	.type	injector_shellcode_size, @object
	.size	injector_shellcode_size, 4
injector_shellcode_size:
	// distance from injector_shellcode to current.
	.int	. - injector_shellcode

// injector_shellcode_invoke_arg_t field offsets
#define inv_retval_offset 0
#define inv_status_offset 8
#define inv_dlopen_addr_offset 16
#define inv_dlsym_addr_offset 24
#define inv_dlerror_addr_offset 32
#define inv_dlflags_offset 40
#define inv_func_name_off_offset 44
#define inv_func_args_offset 48
#define inv_file_path_offset 96

	.balign 16
	.global	injector_shellcode_invoke
	.hidden	injector_shellcode_invoke
	.type	injector_shellcode_invoke, @function
	// void *injector_shellcode_invoke(injector_shellcode_invoke_arg_t *arg) {
injector_shellcode_invoke:
	pushq	%rbx
	pushq	%r12
	movq	%rdi, %rbx

	// 1. handle = dlopen(file_path, dlflags)
	leaq	inv_file_path_offset(%rbx), %rdi
	movl	inv_dlflags_offset(%rbx), %esi
	call	*inv_dlopen_addr_offset(%rbx)
	test	%rax, %rax
	jz	.inv_error
	movq	%rax, %r12

	// 2. func = dlsym(handle, func_name)
	movq	%r12, %rdi
	movslq	inv_func_name_off_offset(%rbx), %rax
	leaq	(%rbx, %rax, 1), %rsi
	call	*inv_dlsym_addr_offset(%rbx)
	test	%rax, %rax
	jz	.inv_error

	// 3. retval = func(args[0..5])
	movq	%rax, %r12
	movq	inv_func_args_offset +  0(%rbx), %rdi
	movq	inv_func_args_offset +  8(%rbx), %rsi
	movq	inv_func_args_offset + 16(%rbx), %rdx
	movq	inv_func_args_offset + 24(%rbx), %rcx
	movq	inv_func_args_offset + 32(%rbx), %r8
	movq	inv_func_args_offset + 40(%rbx), %r9
	call	*%r12
	movq	%rax, inv_retval_offset(%rbx)
	movq	$1, inv_status_offset(%rbx)
	jmp	.inv_exit

.inv_error:
	// copy dlerror() message into file_path area
	movb	$0, inv_file_path_offset(%rbx)
	cmpq	$0, inv_dlerror_addr_offset(%rbx)
	je	.inv_set_err
	call	*inv_dlerror_addr_offset(%rbx)
	test	%rax, %rax
	jz	.inv_set_err
	leaq	inv_file_path_offset(%rbx), %rdi
	leaq	page_size(%rbx), %rcx
.inv_copy:
	movb	(%rax), %dl
	incq	%rax
	movb	%dl, (%rdi)
	incq	%rdi
	testb	%dl, %dl
	jz	.inv_set_err
	cmpq	%rdi, %rcx
	ja	.inv_copy

.inv_set_err:
	movq	$2, inv_status_offset(%rbx)

.inv_exit:
	popq	%r12
	popq	%rbx
	ret
	// }
	.size	injector_shellcode_invoke, . - injector_shellcode_invoke

	.balign  4
	.global	injector_shellcode_invoke_size
	.hidden	injector_shellcode_invoke_size
	.type	injector_shellcode_invoke_size, @object
	.size	injector_shellcode_invoke_size, 4
injector_shellcode_invoke_size:
	.int	. - injector_shellcode_invoke
#endif
