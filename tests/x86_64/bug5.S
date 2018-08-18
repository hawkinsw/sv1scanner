	.text
	nop

	.global pass_tests	
pass_tests:

	# First load is second sequentially.
	# Also tests scanner's handling of infinite loops...
	# Also tests having one load before a jump and one after.
	jne     1f
2:	
	mov     0x30(%rax), %rbx
	mov     0xb0(%rdx), %rax
	jmp	2b

1:	hlt
