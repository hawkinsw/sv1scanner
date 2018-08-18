	
	.global fail_tests
fail_tests:

 je     1f
 mov    $0x19600,%r12
 movslq %edi,%rax
 mov    %r12,%rbx
 add    -0x7e2cac60(,%rax,8),%rbx
 mov    %gs:0x7ef3c0f6(%rip),%eax        # &0xe01c 
 cmp    %eax,%edi
 je     1f
 add    %gs:0x7ef3f22e(%rip),%r12        # &0x11160 
 mov    %r12,%rdi
 callq  1f
 push   %rbp
 mov    %rsp,%rbp
 push   %r13
 lea    0x10(%rdi),%r13
 push   %r12
 xor    %r12d,%r12d
 push   %rbx

1:	hlt
