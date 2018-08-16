	.text
	nop

	.global pass_tests	
pass_tests:

	# Simplest case.
	jne     1f
	mov     0xb0(%rdx), %rax
	mov     0x30(%rax), %rbx

1:	# A non-involved instruction between the two loads.
	jne     1f
	mov     0xb0(%rdi), %rcx
	mov     0xb0(%rsp), %rax
	nop
	mov     0x30(%rcx), %rbx

1:	# Load overwrites destination.
	jne     1f
	mov     0xb0(%r9), %rcx
	mov     0xb0(%rcx), %rcx

1:	# Value moved between registers before being used for the second time.
	jne     1f
	mov     0xb0(%r9), %rcx
	mov     %rcx, %rax
	mov     0x30(%rax), %rsi

1:	# Value pushed onto stack and then poped (into a different register).
	jne     1f
	mov     0xb0(%rdx), %rax
	push	%rax
	pop	%rbx
	mov     0x30(%rbx), %rdx

1:	# First load is second sequentially.
	# Also tests scanner's handling of infinite loops...
	# Also tests having one load before a jump and one after.
	jne     1f
2:	
	mov     0x30(%rax), %rbx
	mov     0xb0(%rdx), %rax
	jmp	2b

1:	# Add:
	#  <more tests>

	.global fail_tests
fail_tests:

	#  Uses lfence
	jne     1f
	mov     0xb0(%r8), %rax
	lfence
	mov     0x30(%rax), %rbx

1:	# Uses RAX - a non-parameter regiser
	jne     1f
	mov     0xb0(%rax), %rax
	mov     0x30(%rax), %rbx

1:	# FIXME: Stack load not considered for attack vector.
	jne     1f
	mov     0xb0(%rsp), %rax
	mov     %rbx, 0x30(%rax)

1:	# Store rather than load.
	jne     1f
	mov     %rax, 0xb0(%rdx)
	mov     0x30(%rax), %rbx
1:	
	# End of tests.
	hlt
