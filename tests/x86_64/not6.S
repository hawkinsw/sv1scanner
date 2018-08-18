	
	.global fail_tests
fail_tests:

	jne	1f
	test   	%sil,%sil
	movslq 	%edi,%rdx
	jne    	1f
	mov    	-0x7e2cc540(,%rdx,4),%eax
	jmp    	2f
	nop
	
2:	test   	%eax,%eax
	jne    	1f
	mov    	0xd2eb88(%rip),%rcx        # &0xffffffff81d34f2c 
	lea    	(%rdi,%rdi,1),%eax
	test   	$0x800000,%ecx
	cmove  	%edi,%eax
	test   	%sil,%sil
	je     	1f
	mov    	%eax,-0x7e2cc640(,%rdx,4)

1:	hlt
