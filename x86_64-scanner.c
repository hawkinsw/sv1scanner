/* x86_64 Spec Load Scanner - a tool for locating vulnerable speculative loads in x86_64 binaries.

   Copyright (c) 2016-2018 Red Hat.

   This is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published
   by the Free Software Foundation; either version 3, or (at your
   option) any later version.

   It is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.  */

#include "scanner.h"

extern int print_insn_i386 (bfd_vma, disassemble_info *);
extern int print_insn_i386_intel (bfd_vma, disassemble_info *);
extern int print_insn_i386_att (bfd_vma, disassemble_info *);

/* Number of bytes on the stack.  */
#define STACK_SIZE     256

/* Values used to initialise registers.  */
#define ATTACKER_REG_VAL	0x06eeeee0UL
#define UNKNOWN_REG_VAL		0x11111100UL
#define ATTACKER_MEM_VAL        0x00e0a0d0UL
#define RANDOM_MEM_VAL          0x12345678

#define ADDRESS_CHAR		'&'

/* For now, we model these registers:
   0-15:  rax - r15 General registers
   16-23: mm0 - mm7 MMX registers
   24-39: xmm0 - xmm15 SSE registers
   40:    CC.  */
#define NUM_REGISTERS	41

#define SP_REGNO        4
#define BP_REGNO        5
#define FIRST_MMX_REGNO 16
#define FIRST_XMM_REGNO 24
#define CC_REGNO        40

enum insn_class
{
  ic_none = 0,
  ic_nop,
  ic_arith,
  ic_call,
  ic_ret,
  ic_condjump,
  ic_jump,
  ic_fault
};

enum insn_subclass
{
  sc_none = 0,
  sc_bin_add,
  sc_bin_and,
  sc_bin_cmp,
  sc_bin_lea,
  sc_bin_or,
  sc_bin_rol,
  sc_bin_ror,
  sc_bin_sar,
  sc_bin_shl,
  sc_bin_shr,
  sc_bin_sub,
  sc_bin_test,
  sc_bin_xor,
  sc_fence,
  sc_flow_call,
  sc_flow_condjmp,
  sc_flow_jmp,
  sc_flow_loop,
  sc_mov_mov,
  sc_mov_sext,
  sc_mov_zext,
  sc_nop,
  sc_stack_enter,
  sc_stack_leave,
  sc_stack_pop,
  sc_stack_pop1,
  sc_stack_push,
  sc_stack_push1,
  sc_stack_ret,
  sc_string_cmps,
  sc_string_lods,
  sc_string_movs,
  sc_string_scas,
  sc_string_stos,
  sc_syscall,
  sc_unop_dec,
  sc_unop_inc,
  sc_unop_neg,
  sc_unop_not,
  sc_xxx
};

typedef enum arg_type
{
  type_unknown = 0,
  type_register,
  type_constant,
  type_address,
} arg_type;

typedef struct arg
{
  enum arg_type      type;
  ulong              value;
} arg;

typedef struct reg_move
{
  uint   tick;
  int    source;
  int    dest;
} reg_move;

typedef struct scan_state
{
  ulong       pc;		// The address of the insn being simulated.
  int         tick;		// Number of instructions simulated from the entry point to here.
  int         conditional_tick; // The instruction number where a conditional branch was encountered.
  ulong *     insns;		// An array insns[max_num_ticks] of addresses of instructions executed.
  uint        num_branches;	// The number of branches taken to reach here.
  ulong       regs [NUM_REGISTERS + 1];  // Values in registers at this point.
  ulong       saved_stack [STACK_SIZE]; // A copy of the stack at the point where a scan_state is clonned.
  reg_move *  moves;
  uint        n_moves;
  int         next_move;
} scan_state;

typedef struct insn_info
{
  const char *        name;		/* The name of the instruction.  */
  const unsigned      len;		/* The length of NAME.  */
  bool                size_suffix;	/* True if the insn accepts a size suffix.  */
  enum insn_class     cl;		/* The class of the instruction.  FIXME: Is this still needed ? */
  enum insn_subclass  type;		/* The subtype of the instruction.  */
  bool (*             handler)		/* Function to emulate the instruction.  */
    (scan_state *, struct insn_info *, const char *);
} insn_info;

typedef struct addr_info
{
  struct insn_info *  insn;		/* Information about the insn starting at this address.  */
  signed int          len;		/* The length of the instruction starting at this address.  */
  ulong               data;		/* Additional information about this instruction.  For absolute
					   jumps, contains the destination address.  */
  const char *        args;		/* The arguments to this particular instruction.  */
  ulong               dup_addr;		/* The address of an identical code sequence, if we found one.  */
  int                 n_arith_insns;	/* The number of instructions starting at this address that can't
					   alter control flow.  */
  hashval_t           seq_hash;		/* The hash value for the sequence of instructions starting here.  */
  bool                ends_in_fault;	/* True if the sequence starting at this address always ends in a fault.  */
  bool                has_pcrel;	/* True if this insn has a pc-relative access.  */
} addr_info;

typedef struct disas_state
{
  char *            buffer;    /* Disassembly printing buffer.  */
  ulong             alloc;     /* Size of the printing buffer.  */
  ulong             pos;       /* Where we are in the printing buffer. */ 
  disassemble_info  info;	// Used by the libopcodes disassembler.
} disas_state;

typedef struct reg_name
{
  const char * name;
  unsigned     len;
  ulong        value;
} reg_name;

typedef struct Emul_info
{
  bfd_byte *  code;	 /* Instruction buffer.  */
  ulong       size;      /* Size of instruction buffer.  */
  ulong       code_base; /* Address of first instruction in the instruction buffer.  */
  bool        status;    /* TRUE as long as the scan is working.  */
  addr_info * scanned;   /* An array of information about each address to be scanned.  */
  ulong       stack[STACK_SIZE];// Contents of the stack.
} Emul_info;

#define UNHANDLED_REG REG_VALUE (64, NUM_REGISTERS)

typedef struct reg_lex_state
{
  /* Indexed by a character passed through char_to_index.
     Zero means no match: entry number zero is reserved for the start of lexing.
     A negative number means the register name ends at the previous character, and
     the negated value (minus one) found here is the index into the reg_names array.
     A positive number indicates we are still on track to find a valid register name,
     it is an index into the lex_data array pointing to the next state.  */
  int nextch_state[37];
} reg_lex_state;

static disassemble_info info = {0};
static Emul_info        emul_info;
static reg_lex_state *  reg_lex_data;
static disas_state      disas;
static htab_t           sequence_htab;
static int              syntax = 0;
static ulong            num_found = 0;
static uint             max_num_branches = 32;
static ulong            start_address = 0;
static int              first_memory_access = -1;
static int              second_memory_access = -1;
static int              attacker_reg_val_set = -1;
static int              attacker_reg_val_used = -1;
static int              attacker_mem_val_used = -1;
static bool             suppress_checks = FALSE;
static uint             max_num_ticks = 1 << 12;
static ulong            first_conditional_seen = 0;

static reg_name reg_names[] =
{
  {STRING_COMMA_LEN ("al"),  0},
  {STRING_COMMA_LEN ("ah"),  0},
  {STRING_COMMA_LEN ("ax"),  0},
  {STRING_COMMA_LEN ("eax"), 0},
  {STRING_COMMA_LEN ("rax"), 0},

  {STRING_COMMA_LEN ("cl"),  1},
  {STRING_COMMA_LEN ("ch"),  1},
  {STRING_COMMA_LEN ("cx"),  1},
  {STRING_COMMA_LEN ("ecx"), 1},
  {STRING_COMMA_LEN ("rcx"), 1},

  {STRING_COMMA_LEN ("dl"),  2},
  {STRING_COMMA_LEN ("dh"),  2},
  {STRING_COMMA_LEN ("dx"),  2},
  {STRING_COMMA_LEN ("edx"), 2},
  {STRING_COMMA_LEN ("rdx"), 2},

  {STRING_COMMA_LEN ("bl"),  3},
  {STRING_COMMA_LEN ("bh"),  3},
  {STRING_COMMA_LEN ("bx"),  3},
  {STRING_COMMA_LEN ("ebx"), 3},
  {STRING_COMMA_LEN ("rbx"), 3},

  {STRING_COMMA_LEN ("spl"), SP_REGNO},
  {STRING_COMMA_LEN ("sp"),  SP_REGNO},
  {STRING_COMMA_LEN ("esp"), SP_REGNO},
  {STRING_COMMA_LEN ("rsp"), SP_REGNO},

  {STRING_COMMA_LEN ("bpl"), 5},
  {STRING_COMMA_LEN ("bp"),  5},
  {STRING_COMMA_LEN ("ebp"), 5},
  {STRING_COMMA_LEN ("rbp"), 5},

  {STRING_COMMA_LEN ("sil"), 6},
  {STRING_COMMA_LEN ("si"),  6},
  {STRING_COMMA_LEN ("esi"), 6},
  {STRING_COMMA_LEN ("rsi"), 6},

  {STRING_COMMA_LEN ("dil"), 7},
  {STRING_COMMA_LEN ("di"),  7},
  {STRING_COMMA_LEN ("edi"), 7},
  {STRING_COMMA_LEN ("rdi"), 7},

  {STRING_COMMA_LEN ("r8b"), 8},
  {STRING_COMMA_LEN ("r8w"), 8},
  {STRING_COMMA_LEN ("r8d"), 8},
  {STRING_COMMA_LEN ("r8"),  8},

  {STRING_COMMA_LEN ("r9b"), 9},
  {STRING_COMMA_LEN ("r9w"), 9},
  {STRING_COMMA_LEN ("r9d"), 9},
  {STRING_COMMA_LEN ("r9"),  9},

  {STRING_COMMA_LEN ("r10b"), 10},
  {STRING_COMMA_LEN ("r10w"), 10},
  {STRING_COMMA_LEN ("r10d"), 10},
  {STRING_COMMA_LEN ("r10"),  10},

  {STRING_COMMA_LEN ("r11b"), 11},
  {STRING_COMMA_LEN ("r11w"), 11},
  {STRING_COMMA_LEN ("r11d"), 11},
  {STRING_COMMA_LEN ("r11"),  11},

  {STRING_COMMA_LEN ("r12b"), 12},
  {STRING_COMMA_LEN ("r12w"), 12},
  {STRING_COMMA_LEN ("r12d"), 12},
  {STRING_COMMA_LEN ("r12"),  12},

  {STRING_COMMA_LEN ("r13b"), 13},
  {STRING_COMMA_LEN ("r13w"), 13},
  {STRING_COMMA_LEN ("r13d"), 13},
  {STRING_COMMA_LEN ("r13"),  13},

  {STRING_COMMA_LEN ("r14b"), 14},
  {STRING_COMMA_LEN ("r14w"), 14},
  {STRING_COMMA_LEN ("r14d"), 14},
  {STRING_COMMA_LEN ("r14"),  14},

  {STRING_COMMA_LEN ("r15b"), 15},
  {STRING_COMMA_LEN ("r15w"), 15},
  {STRING_COMMA_LEN ("r15d"), 15},
  {STRING_COMMA_LEN ("r15"),  15},

  {STRING_COMMA_LEN ("mm0"), 16},
  {STRING_COMMA_LEN ("mm1"), 17},
  {STRING_COMMA_LEN ("mm2"), 18},
  {STRING_COMMA_LEN ("mm3"), 19},
  {STRING_COMMA_LEN ("mm4"), 20},
  {STRING_COMMA_LEN ("mm5"), 21},
  {STRING_COMMA_LEN ("mm6"), 22},
  {STRING_COMMA_LEN ("mm7"), 23},
  {STRING_COMMA_LEN ("xmm0"), 24},
  {STRING_COMMA_LEN ("xmm1"), 25},
  {STRING_COMMA_LEN ("xmm2"), 26},
  {STRING_COMMA_LEN ("xmm3"), 27},
  {STRING_COMMA_LEN ("xmm4"), 28},
  {STRING_COMMA_LEN ("xmm5"), 29},
  {STRING_COMMA_LEN ("xmm6"), 30},
  {STRING_COMMA_LEN ("xmm7"), 31},
  {STRING_COMMA_LEN ("xmm8"), 32},
  {STRING_COMMA_LEN ("xmm9"), 33},
  {STRING_COMMA_LEN ("xmm10"), 34},
  {STRING_COMMA_LEN ("xmm11"), 35},
  {STRING_COMMA_LEN ("xmm12"), 36},
  {STRING_COMMA_LEN ("xmm13"), 37},
  {STRING_COMMA_LEN ("xmm14"), 38},
  {STRING_COMMA_LEN ("xmm15"), 39},

  /* It doesn't occur at assembly level, but the flags register is represented as reg 40.  */

  /* FIXME: Is it safe to ignore these registers ?  */
  {STRING_COMMA_LEN ("ds"),  NUM_REGISTERS},
  {STRING_COMMA_LEN ("es"),  NUM_REGISTERS},
  {STRING_COMMA_LEN ("fs"),  NUM_REGISTERS},
  {STRING_COMMA_LEN ("ss"),  NUM_REGISTERS},
  {STRING_COMMA_LEN ("gs"),  NUM_REGISTERS},
  {STRING_COMMA_LEN ("cs"),  NUM_REGISTERS},
};

/* Convert a character into an index into the lex_state structure's array.  */

static int
char_to_index (int c)
{
  if (c >= '0' && c <= '9')
    return c - '0' + 1;
  if (c >= 'a' && c <= 'z')
    return c - 'a' + 11;
  return 0;
}

/* Convert the reg_names table into a tree structure that can be used to lex register names quickly.  */

static void
build_reg_lex (void)
{
  int i;
  int n = 1;
  int allocated = 40;
  struct reg_lex_state * lx = XNEWVEC (struct reg_lex_state, allocated);

  memset (lx, 0, sizeof (struct reg_lex_state));

  for (i = ARRAY_SIZE (reg_names); i--;)
    {
      int j;
      int state = 0;

      for (j = 0; j < reg_names[i].len + 1; j++)
	{
	  struct reg_lex_state *p = lx + state;
	  int c = char_to_index (reg_names[i].name[j]);

	  if (c == 0)
	    {
	      if (j != reg_names[i].len)
		einfo (FAIL, "reg parse");
	      if (p->nextch_state[c] != 0)
		einfo (FAIL, "reg parse 2");
	      p->nextch_state[c] = -i - 1;
	      break;
	    }

	  int next = p->nextch_state[c];
	  if (next > 0)
	    {
	      state = next;
	      continue;
	    }
	  if (next != 0)
	    einfo (FAIL, "reg parse 3");

	  if (n == allocated)
	    {
	      lx = XRESIZEVEC (struct reg_lex_state, lx, allocated * 2);
	      allocated *= 2;
	    }

	  memset (lx + n, 0, sizeof (struct reg_lex_state));
	  p->nextch_state[c] = n;
	  state = n;
	  n++;
	}
    }
  reg_lex_data = lx;
}

/* Given a string at *PP, look for a valid register name and return the index into the
   reg_names array, or -1 if the name is not a valid register.  */

static int
lex_reg_name (const char **pp)
{
  const char *p = *pp;
  int state = 0;

  for (;;)
    {
      int c = char_to_index (*p);
      int v = reg_lex_data[state].nextch_state[c];

      if (v < 0)
	{
	  *pp = p;
	  return -v - 1;
	}
      if (v == 0)
	return -1;
      state = v;
      p++;
    }
}

static ulong
read_reg (scan_state * ss, int reg)
{
  ulong val;

  if (reg < 0 || reg > NUM_REGISTERS)
    {
      einfo (FAIL, "BAD REG READ %d", reg);
      return 0;
    }
  
  val = ss->regs[reg];
  
  if (! suppress_checks)						
    {
      /* Record when a register containing an				
	 attacker provided value is read.  */				
      if (val == ATTACKER_MEM_VAL)					
	{								
	  attacker_mem_val_used = reg;					
	  einfo (VERBOSE2, "attacker memory value loaded into reg %d has been used", reg); 
	}								
      else if (val == ATTACKER_REG_VAL)					
	{
	  if (attacker_reg_val_used == -1)
	    attacker_reg_val_used = reg;
	  einfo (VERBOSE2, "attacker controlled value in reg %d used", reg); 
	}
    }

  return val;
}

static void
write_reg (scan_state * ss, int reg, ulong val)
{
  if (reg < 0 || reg > NUM_REGISTERS)
    {
      einfo (FAIL, "Bad Reg WRITE %d", reg);
      return;
    }

  if (! suppress_checks)						
    {									
      /* If the attacker value was read during this instruction, then	
	 always set the destination value to ATTACKER, no matter how	
	 it might have been transformed, so that we can track it.  */	
      if (attacker_reg_val_used != -1)					
	{								
	  if (first_memory_access && first_conditional_seen)
	    {								
	      einfo (VERBOSE2, "register %d set based on a value retrieved from an attacker controlled memory address", reg); 
	      attacker_reg_val_set = reg;				
	      val = ATTACKER_MEM_VAL;					
	    }								
	  else
	    {
	      einfo (VERBOSE2, "register %d updated after read from poisoned register", reg);
	      val = ATTACKER_REG_VAL;
	    }
	}
      else if (val != ATTACKER_REG_VAL && val != ATTACKER_MEM_VAL)
	{
	  if (ss->regs[reg] == ATTACKER_REG_VAL)
	    val = ATTACKER_REG_VAL;
	  else if (ss->regs[reg] == ATTACKER_MEM_VAL)
	    val = ATTACKER_MEM_VAL;
	}
    }									

  ss->regs[reg] = val;
}

/* -------------------------------------------------------------------- */

/* Parse a register name and return an index for its name.  Update *PTEXT
   to point past the end of the register name.  */

static unsigned
parse_reg (scan_state * ss, const char ** ptext, bool lval)
{
  const char * text = * ptext;

  if (const_strneq (text, "riz") || const_strneq (text, "eiz"))
    {
      * ptext += 3;
      return -1U;
    }

  int idx = lex_reg_name (& text);
  if (idx >= 0)
    {
      reg_name *r = reg_names + idx;

      *ptext = text;

      if (! lval)
	/* Read the register so that its access will be noted.  */
	(void) read_reg (ss, r->value);
	
      return r->value;
    }

  return -1U;
}

static bool
parse_mem_arg (scan_state * ss, const char * text, const char ** end, arg * arg, bool lval)
{
  const char * orig_text = text;
  bool negated = FALSE;
  ulong addr_off = 0;

  arg->type = type_address;
  arg->value = RANDOM_MEM_VAL;

  /* Try to see if the disassembler has given us an absolute value for
     a %rip-relative address.  */
  if (* text == '-' || * text == '0' || *text == '(')
    {
      const char * p = strstr (text, "# &0x");
      if (p)
	{
	  p += 4;
	  addr_off = strtoul (p, NULL, 16);
	  return TRUE;
	}
    }

  switch (*text++)
    {
    case '*': /* absolute addressing ?  */
      arg->value = strtoul (text, NULL, 16);
      return TRUE;

    case '-':
      negated = TRUE;
      if (*text != '0')
	{
	  einfo (FAIL, "parse mem fail 1");
	  return FALSE;
	}
      text++;
      /* Fall through.  */
    case '0':
      if (*text != 'x')
	{
	  einfo (FAIL, "parse mem fail 2");
	  return FALSE;
	}
      text++;
      addr_off = strtoul (text, (char **) (& text), 16);
      if (negated)
	addr_off = - addr_off;

      if (*text != '(')
	return TRUE;
      /* Register +- offset addressing.  */
      text++;
      /* Fall through.  */
    case '(': /* Register relative addressing ?  */
      if (*text == '%')
	{
	  text++;
	  arg->value = parse_reg (ss, & text, lval);
	}
      if (*text == ',')
	{
	  int scale = 1;

	  text++;
	  if (*text != '%')
	    {
	      einfo (FAIL, "parse mem fail 3");
	      return FALSE;
	    }
	  text++;
	  arg->value = parse_reg (ss, & text, lval);
	  if (*text == ',')
	    {
	      text++;
	      scale = (  *text == '1' ? 1
		       : *text == '2' ? 2
		       : *text == '4' ? 4
		       : *text == '8' ? 8
		       : -1);
	      text++;
	      if (scale == -1)
		{
		  einfo (ERROR, "unknown address scale");
		  scale = 1;
		}
	    }
	}

      if (*text != ')')
	{
	  einfo (FAIL, "parse mem fail 4: %s %s", orig_text, text);
	  return FALSE;
	}
      text++;
      if (end)
	*end = text;
      return TRUE;

    default:
      if (! ISALPHA (text[-1]))
	einfo (ERROR, "unknown type of memory address: %s", text - 1);
      /* Fall through.  */
    case 0:
      if (end)
	*end = NULL;
      arg->type = type_unknown;
      return FALSE;
    }
}

/* Parse an argument at TEXT, updating END to point past the comma
   following it, and store data in ARG.  IS_LEA is true if this is
   for the first operand of a lea instruction;  */

static bool
parse_arg (scan_state * ss, const char * text, const char ** end, arg * arg, bool lval)
{
  bool ret = TRUE;

  if (text == NULL)
    goto unknown_arg;

  while (ISSPACE (* text))
    ++ text;

  switch (* text ++)
    {
    default:
      if (! ISALPHA (text[-1]))
	einfo (ERROR, "Unknown arg prefix: %s", text - 1);
      /* Fall through.  */
    case 0:
    unknown_arg:
      if (end)
	* end = NULL;
      arg->type = type_unknown;
      return FALSE;

    case '%': /* Register.  */
      if (   const_strneq (text, "cs:")
	  || const_strneq (text, "ds:")
	  || const_strneq (text, "es:")
	  || const_strneq (text, "fs:")
	  || const_strneq (text, "gs:")
	  || const_strneq (text, "ss:"))
	{
	  /* FIXME: keep track of segment prefix.  */
	  text += 3;
	  ret = parse_mem_arg (ss, text, & text, arg, lval);
	  break;
	}

      arg->type = type_register;
      arg->value = parse_reg (ss, & text, lval);
      break;

    case '$': /* Constant.  */
      arg->type = type_constant;
      arg->value = strtoul (text, NULL, 0);
      break;

    case '*': /* Register + register + offset addressing ? */
    case '-':
    case '0': /* Register offset addressing ?  */
    case '(': /* Register relative addressing ? */
      ret = parse_mem_arg (ss, text - 1, & text, arg, lval);
      break;

    case '&': /* Absolute address.  */
      arg->type = type_address;
      arg->value = strtoul (text, NULL, 0);
      break;
    }

  if (end)
    {
      text = strchr (text, ',');
      if (text)
	* end = text + 1;
      else
	* end = NULL;
    }

  return ret;
}

static bfd_byte
x86_emul_fetch_byte (ulong addr)
{
  ulong offset = addr - emul_info.code_base;

  if (offset >= emul_info.size)
    {
      if (offset != RANDOM_MEM_VAL)
	{
	  /* FIXME: We should load kernel data sections as well...  */
	  einfo (WARN, "Attempt to read from unmapped memory address: %lx", addr);
	  emul_info.status = FALSE;
	}
      return 0;
    }

  return emul_info.code[offset];
}

static int
x86_read_mem (bfd_vma addr, bfd_byte * buffer, unsigned len, struct disassemble_info * info)
{
  while (len--)
    * buffer ++ = x86_emul_fetch_byte (addr ++);

  return 0;
}

#define GET_REG_FROM_ARG(SS,ARG)       read_reg ((SS), (ARG).value)
#define SET_REG_FROM_ARG(SS,ARG,VAL)  write_reg ((SS), (ARG).value, (VAL))

static ulong
read_mem (scan_state * ss, ulong addr)
{
  ulong * paddr = (ulong *) addr;

  if (! suppress_checks)
    {
      if (attacker_mem_val_used != -1)
	{
	  /* If memory is being accessed after an attacker controlled value
	     was read from a register, then we presume that the attacker
	     is forcing a specific line to loaded into the data cache.  */
	  second_memory_access = attacker_mem_val_used;
	  einfo (VERBOSE2, "second memory access detected (read)");
	}
      else if (attacker_reg_val_used != -1)
	{
	  if (first_conditional_seen)
	    {
	      /* If memory is being accessed after an attacker provided value
		 was read from a register, then we presume that the attacker is
		 controlling this access.  */				
	      first_memory_access = TRUE;
	      einfo (VERBOSE2, "first memory access detected (read)");
	      return (ulong) ATTACKER_MEM_VAL;
	    }
	}								
    }
  
  if (paddr >= emul_info.stack && paddr < emul_info.stack + STACK_SIZE)
    {
      return * paddr;
    }

  if (addr >= emul_info.code_base && addr <= emul_info.code_base + emul_info.size)
    {
      ulong val;

      x86_read_mem (addr, (bfd_byte *) & val, sizeof (val), & info);
      return val;
    }

  return RANDOM_MEM_VAL;
}

static void
write_mem (scan_state * ss, ulong addr, ulong value)
{
  ulong * paddr = (ulong *) addr;

  if (paddr >= emul_info.stack && paddr <= emul_info.stack + STACK_SIZE)
    * paddr = value;
  else
    {
      if (! suppress_checks)
	{
	  if (attacker_mem_val_used != -1
	      || addr == ATTACKER_MEM_VAL)
	    {
	      /* If memory is being written to an attacker controlled value
		 was read from a register, then we presume that the attacker
		 is forcing a specific line to loaded into the data cache.  */
	      second_memory_access = attacker_mem_val_used;
	      einfo (VERBOSE2, "second memory access detected (write)");
	    }
	  else if (addr != RANDOM_MEM_VAL)
	    einfo (WARN, "BAD write to %lx ?", addr);
	}	
    }
}

static bool
handler_error (scan_state * ss, const char * message)
{
  ulong addr = ss->pc;

  disas.pos = 0;
  disas.buffer[0] = 0;
  emul_info.status = TRUE;
  (void) print_insn_i386 (addr, & disas.info);
  emul_info.status = FALSE;

  einfo (FAIL, "%s: %lx: %s", message, addr, disas.buffer);
  exit (-1);
  return FALSE;
}

static arg arg1;
static arg arg2;

static bool
handle_one_op (scan_state * ss, insn_info * info, const char * args)
{
  if (! parse_arg (ss, args, NULL, & arg1, TRUE))
    return handler_error (ss, "Failed to parse arg of unary type insn");

  if (arg1.type != type_register)
    return TRUE;

  switch (info->type)
    {
    case sc_unop_dec:
      SET_REG_FROM_ARG (ss, arg1, GET_REG_FROM_ARG (ss, arg1) - 1);
      break;

    case sc_unop_inc:
      SET_REG_FROM_ARG (ss, arg1, GET_REG_FROM_ARG (ss, arg1) + 1);
      break;

    case sc_unop_not:
      SET_REG_FROM_ARG (ss, arg1, ~ GET_REG_FROM_ARG (ss, arg1));
      break;

    case sc_unop_neg:
      SET_REG_FROM_ARG (ss, arg1, - GET_REG_FROM_ARG (ss, arg1));
      break;

    default:
      return handler_error (ss, "unexpected unary op");
    }

  return TRUE;
}

static int
reg_from_arg (arg * regarg)
{
  if (regarg == NULL)
    return -1;
  if (regarg->type == type_register)
    return regarg->value;
  if (regarg->type != type_address)
    return -1;
  if (regarg->value >= 0 && regarg->value <= NUM_REGISTERS)
    return regarg->value;
  return -1;
}

/* Record a move from INPUT to OUTPUT.  */
static void
add_reg_move (scan_state * ss, int in_reg, int out_reg)
{
  if (in_reg == -1 || out_reg == -1)
    return;
     
  if (ss->n_moves == ss->next_move)
    {
      ss->n_moves += 20;
      ss->moves = xrealloc (ss->moves, ss->n_moves * sizeof (* ss->moves));
    }

  ss->moves[ss->next_move].tick   = ss->tick;
  ss->moves[ss->next_move].source = in_reg;
  ss->moves[ss->next_move].dest   = out_reg;
  ss->next_move ++;
}

static void
add_move (scan_state * ss, arg * input, arg * output)
{
  int in_reg = reg_from_arg (input);
  int out_reg = reg_from_arg (output);

  add_reg_move (ss, in_reg, out_reg);
}

static bool
handle_mov (scan_state * ss, insn_info * info, const char * args)
{
  if (   ! parse_arg (ss, args, & args, & arg1, FALSE)
      || ! parse_arg (ss, args, NULL,   & arg2, TRUE))
    return handler_error (ss, "Failed to parse arg of move type insn");

  add_move (ss, & arg1, & arg2);

  switch (info->type)
    {
    case sc_mov_zext:
    case sc_mov_sext:
    case sc_mov_mov:
      if (arg2.type == type_register)
	{
	  switch (arg1.type)
	    {
	    case type_register:
	      SET_REG_FROM_ARG (ss, arg2, GET_REG_FROM_ARG (ss, arg1));
	      break;
	    case type_address:
	      SET_REG_FROM_ARG (ss, arg2, read_mem (ss, arg1.value));
	      break;
	    case type_constant:
	      SET_REG_FROM_ARG (ss, arg2, arg1.value);
	      break;
	    default:
	      return handler_error (ss, "unhandled MOV");
	    }
	}
      break;

    default:
      return handler_error (ss, "unknown MOV type");
    }

  return TRUE;
}

static bool
handle_string (scan_state * ss, insn_info * info, const char * args)
{
  /* The disassembler seems to always print args for these even if implicit.  */
  if (   ! parse_arg (ss, args, & args, & arg1, FALSE)
      || ! parse_arg (ss, args, NULL,   & arg2, TRUE))
    return handler_error (ss, "Failed to parse arg of string type insn");

  /* FIXME: implement.  */
  return TRUE;
}

static bool
handle_nop (scan_state * ss, insn_info * info, const char * args)
{
  return TRUE;
}

static bool
handle_sys (scan_state * ss, insn_info * info, const char * args)
{
  /* Syscalls.  FIXME: implement.  */
  return TRUE;
}

static bool
handle_xchg (scan_state * ss, insn_info * info, const char * args)
{
  ulong tmp;

  if (   ! parse_arg (ss, args, & args, & arg1, FALSE)
      || ! parse_arg (ss, args, NULL,   & arg2, FALSE))
    return handler_error (ss, "Failed to parse arg of xchg type insn");

  if (info->type != sc_mov_mov)
    einfo (FAIL, "unexpected class in xchg");

  if (arg1.type == type_register)
    {
      tmp = GET_REG_FROM_ARG (ss, arg1);

      if (arg2.type == type_register)
	{
	  SET_REG_FROM_ARG (ss, arg1, GET_REG_FROM_ARG (ss, arg2));
	  SET_REG_FROM_ARG (ss, arg2, tmp);
	}
      else if (arg2.type == type_address)
	{
	  SET_REG_FROM_ARG (ss, arg1, read_mem (ss, arg2.value));
	  write_mem (ss, arg2.value, tmp);
	}
      else
	return handler_error (ss, "unexpected type of 2nd arg of xchg");
    }
  else if (arg1.type == type_address)
    {
      tmp = read_mem (ss, arg1.value);

      if (arg2.type == type_register)
	{
	  write_mem (ss, arg1.value, GET_REG_FROM_ARG (ss, arg2));
	  SET_REG_FROM_ARG (ss, arg2, tmp);
	}
      else if (arg2.type == type_address)
	{
	  write_mem (ss, arg1.value, read_mem (ss, arg2.value));
	  write_mem (ss, arg2.value, tmp);
	}
      else
	return handler_error (ss, "unexpected type of 2nd arg of xchg");
    }
  else
    return handler_error (ss, "unexpected type of 1st arg of xchg");

  return TRUE;
}

static bool
handle_cmpxchg (scan_state * ss, insn_info * info, const char * args)
{
  ulong tmp2 = 0, tmp1 = 0;

  if (   ! parse_arg (ss, args, & args, & arg1, FALSE)
      || ! parse_arg (ss, args, NULL,   & arg2, FALSE))
    return handler_error (ss, "Failed to parse args of cmpxchg type insn");

  if (info->type != sc_mov_mov)
    einfo (FAIL, "unexpected class in cmpxchg");

  switch (arg1.type)
    {
    case type_register: tmp1 = GET_REG_FROM_ARG (ss, arg1); break;
    case type_constant: tmp1 = arg1.value; break;
    case type_address:  tmp1 = read_mem (ss, arg1.value); break;
    default:
      return handler_error (ss, "cmpxchg with unexpected 1st arg");
      break;
    }

  switch (arg2.type)
    {
    case type_register: tmp2 = GET_REG_FROM_ARG (ss, arg2); break;
    case type_constant: tmp2 = arg2.value; break;
    case type_address:  tmp2 = read_mem (ss, arg2.value); break;
    default:
      return handler_error (ss, "cmpxchg with unexpected 2nd arg");
    }

  if (read_reg (ss, 0/*ax*/) == tmp1)
    {
      write_reg (ss, 0, tmp2);
      add_reg_move (ss, 0, reg_from_arg (& arg2));
    }
  else
    {
      write_reg (ss, 0, tmp1);
      add_reg_move (ss, 0, reg_from_arg (& arg1));
    }

  /* FIXME: Update other register ?  */
  return TRUE;
}

#define DO_BINOP(SS,NAME,OP)					\
  do								\
    {								\
      if (arg2.type == type_register)				\
	{							\
	  switch (arg1.type)					\
	    {							\
	    case type_unknown:					\
	      einfo (VERBOSE2, "uknown " #NAME " operation");	\
	      break;						\
	    case type_register:					\
	      SET_REG_FROM_ARG (SS, arg2, GET_REG_FROM_ARG (SS, arg2) OP GET_REG_FROM_ARG (SS, arg1)); \
	      break;						\
	    case type_address:					\
	      SET_REG_FROM_ARG (SS, arg2, GET_REG_FROM_ARG (SS, arg2) OP read_mem (SS, arg1.value)); \
	      break;						\
	    case type_constant:					\
	      SET_REG_FROM_ARG (SS, arg2, GET_REG_FROM_ARG (SS, arg2) OP arg1.value); \
	      break;						\
	    default:						\
	      /* FIXME */					\
	      return handler_error (SS, "Bad argument type in " #NAME);	\
	    }							\
	}							\
    }								\
  while (0)

static bool
handle_two_op (scan_state * ss, insn_info * info, const char * args)
{
  if (   ! parse_arg (ss, args, & args, & arg1, FALSE)
      || ! parse_arg (ss, args, NULL,   & arg2, TRUE))
    return handler_error (ss, "Failed to parse arg of binary type insn");

  switch (info->type)
    {
    case sc_bin_add: /* Addition - we ignore the carry flag...  */
      add_move (ss, & arg1, & arg2);
      DO_BINOP (ss, PLUS, +);
      break;

    case sc_bin_and:
      add_move (ss, & arg1, & arg2);
      DO_BINOP (ss, AND, &);
      break;

    case sc_bin_cmp:
      /* We don't model effects on condition codes just yet.  */
      break;

    case sc_bin_test:
      /* We don't model effects on condition codes just yet.  */
      break;

    case sc_bin_or:
      add_move (ss, & arg1, & arg2);
      DO_BINOP (ss, IOR, |);
      break;

    case sc_bin_xor:
      add_move (ss, & arg1, & arg2);
      DO_BINOP (ss, XOR, ^);
      break;

    case sc_bin_sub:  /* We ignore the carry flag...  */
      add_move (ss, & arg1, & arg2);
      DO_BINOP (ss, MINUS, -);
      break;

    case sc_bin_lea:
      if (arg2.type != type_register)
	return handler_error (ss, "backwards lea ?");
      if (arg1.type != type_address)
	return handler_error (ss, "lea not address type");
      add_move (ss, & arg1, & arg2);
      if (arg2.value != SP_REGNO)
	{
	  suppress_checks = TRUE;
	  SET_REG_FROM_ARG (ss, arg2, arg1.value);
	  suppress_checks = FALSE;
	}
      break;

    default:
      return handler_error (ss, "Unrecognized BINOP type");
    }

  return TRUE;
}

static bool
handle_shift (scan_state * ss, insn_info * info, const char * args)
{
  if (! parse_arg (ss, args, & args, & arg1, FALSE))
    return handler_error (ss, "Failed to parse first arg of binary type insn");

  if (! parse_arg (ss, args, NULL, & arg2, TRUE))
    {
      /* There can be an implied shift count argument of 1.  */
      arg2 = arg1;
      arg1.type = type_constant;
      arg1.value = 1;
    }

  add_move (ss, & arg1, & arg2);

  switch (info->type)
    {
    case sc_bin_rol:
      DO_BINOP (ss, ROTATE, <<);
      break;

    case sc_bin_ror:
      DO_BINOP (ss, ROTATERT, >>);
      break;

    case sc_bin_sar:
      DO_BINOP (ss, ASHIFTRT, >>);
      break;

    case sc_bin_shr:
      DO_BINOP (ss, LSHIFTRT, >>);
      break;

    case sc_bin_shl:
      DO_BINOP (ss, LSHIFT, >>);
      break;

    default:
      return handler_error (ss, "Unrecognized SHIFT type");
    }

  return TRUE;
}

static bool
handle_flow (scan_state * ss, insn_info * info, const char * args)
{
  if (! parse_arg (ss, args, NULL, & arg1, TRUE))
    return handler_error (ss, "Failed to parse arg of flow constrol type insn");

  switch (info->type)
    {
    case sc_flow_call:
      write_reg (ss, SP_REGNO, read_reg (ss, SP_REGNO) - sizeof (emul_info.stack[0]));
      write_mem (ss, read_reg (ss, SP_REGNO), ss->pc);
      /* Fall through.  */
    case sc_flow_loop: /* FIXME: assume always true for now.  */
    case sc_flow_condjmp: /* Conditional jumps - FIXME: assume always true for now.  */
      /* Fall through.  */
    case sc_flow_jmp:
      switch (arg1.type)
	{
	case type_register:
	  ss->pc = GET_REG_FROM_ARG (ss, arg1);
	  break;
	case type_constant:
	  ss->pc += info->len + arg1.value;
	  break;
	case type_address:
	  ss->pc = arg1.value;
	  break;
	default:
	  return handler_error (ss, "Unhandled flow argument");
	}
      break;
    default:
      return handler_error (ss, "Unexpected flow instruction type");
    }

  return TRUE;
}

static bool
handle_stack (scan_state * ss, insn_info * info, const char * args)
{
  switch (info->type)
    {
    case sc_stack_ret:
      ss->pc = read_mem (ss, read_reg (ss, SP_REGNO));
      if (ss->pc < emul_info.code_base || ss->pc >= (emul_info.code_base + emul_info.size))
	{
	  einfo (FAIL, "POP BAD PC %#lx", ss->pc);
	  emul_info.status = FALSE;
	}
      write_reg (ss, SP_REGNO, read_reg (ss, SP_REGNO) + sizeof (emul_info.stack[0]));
      if (parse_arg (ss, args, NULL, & arg1, TRUE))
	{
	  if (arg1.type == type_constant)
	    write_reg (ss, SP_REGNO, read_reg (ss, SP_REGNO) + arg1.value);
	}
      return TRUE;

    case sc_stack_leave:
      write_reg (ss, SP_REGNO, read_reg (ss, BP_REGNO));
      write_reg (ss, BP_REGNO, read_mem (ss, read_reg (ss, SP_REGNO)));
      write_reg (ss, SP_REGNO, read_reg (ss, SP_REGNO) + sizeof (emul_info.stack[0]));
      break;

    case sc_stack_enter:
      if (   ! parse_arg (ss, args, & args, & arg1, TRUE)
	  || ! parse_arg (ss, args, NULL,   & arg2, TRUE))
	return handler_error (ss, "Failed to parse arg of enter type insn");

      write_reg (ss, SP_REGNO, read_reg (ss, SP_REGNO) - sizeof (emul_info.stack[0]));
      write_mem (ss, SP_REGNO, read_reg (ss, BP_REGNO));
      write_reg (ss, BP_REGNO, read_reg (ss, SP_REGNO));
      write_reg (ss, SP_REGNO, read_reg (ss, SP_REGNO) - arg1.value);
      /* Ignore arg2.  */
      break;

    default:
      return handler_error (ss, "unrecognized STACK-OP type");
    }

  return TRUE;
}

static bool
handle_pop (scan_state * ss, insn_info * info, const char * args)
{
  switch (info->type)
    {
    case sc_stack_pop:
      if (! parse_arg (ss, args, & args, & arg1, TRUE))
	return handler_error (ss, "Failed to parse arg of pop type insn");

      if (arg1.type == type_register)
	{
	  SET_REG_FROM_ARG (ss, arg1, read_mem (ss, read_reg (ss, SP_REGNO)));
	  add_move (ss, NULL, & arg1);
	}

      /* Fall through.  */
    case sc_stack_pop1:
      /* FIXME: Model size of stack operations.  */
      write_reg (ss, SP_REGNO, read_reg (ss, SP_REGNO) + sizeof (emul_info.stack[0]));
      break;

    default:
      return handler_error (ss, "unrecognized STACK-OP type");
    }

  return TRUE;
}

static bool
handle_push (scan_state * ss, insn_info * info, const char * args)
{
  switch (info->type)
    {
    case sc_stack_push:
      if (! parse_arg (ss, args, & args, & arg1, TRUE))
	return handler_error (ss, "Failed to parse arg of push type insn");

      /* FIXME: Model size of stack operations.  */
      write_reg (ss, SP_REGNO, read_reg (ss, SP_REGNO) - sizeof (emul_info.stack[0]));
      switch (arg1.type)
	{
	default:
	case type_unknown:
	  return handler_error (ss, "unknown PUSH type");

	case type_address:
	  write_mem (ss, read_reg (ss, SP_REGNO), read_mem (ss, arg1.value));
	  break;

	case type_constant:
	  write_mem (ss, read_reg (ss, SP_REGNO), arg1.value);
	  break;

	case type_register:
	  write_mem (ss, read_reg (ss, SP_REGNO), GET_REG_FROM_ARG (ss, arg1));
	  break;
	}
      break;

    case sc_stack_push1:
      /* FIXME: Model size of stack operations.  */
      write_reg (ss, SP_REGNO, read_reg (ss, SP_REGNO) - sizeof (emul_info.stack[0]));
      break;

    default:
      return handler_error (ss, "unrecognized STACK-OP type");
    }

  return TRUE;
}

static bool
handle_fail (scan_state * ss,
	     insn_info * info ATTRIBUTE_UNUSED,
	     const char * t ATTRIBUTE_UNUSED)
{
  einfo (WARN, "Fault");
  ss->pc = emul_info.code_base;
  emul_info.status = FALSE;
  return FALSE;
}

#define ARITH_OP(NAME,SIZE,SC)   { STRING_COMMA_LEN (NAME), (SIZE), ic_arith,    (SC),       handle_two_op  }
#define CMPXCHG_OP(NAME)         { STRING_COMMA_LEN (NAME), TRUE,   ic_arith,    sc_mov_mov, handle_cmpxchg }
#define CONDJ_OP(NAME,SIZE,SC)   { STRING_COMMA_LEN (NAME), (SIZE), ic_condjump, (SC),       handle_flow    }
#define EXTMOV_OP(NAME,SC)       { STRING_COMMA_LEN (NAME), FALSE,  ic_arith,    (SC),       handle_mov     }
#define FAULT_OP(NAME)           { STRING_COMMA_LEN (NAME), FALSE,  ic_fault,    sc_none,    handle_fail    }
#define FLOW_OP(NAME,SIZE,SC)    { STRING_COMMA_LEN (NAME), (SIZE), ic_call,     (SC),       handle_flow    }
#define IGNORE_OP(NAME)          { STRING_COMMA_LEN (NAME), FALSE,  ic_nop,      sc_none,    handle_nop     }
#define JUMP_OP(NAME,SIZE,SC)    { STRING_COMMA_LEN (NAME), (SIZE), ic_jump,     (SC),       handle_flow    }
#define MOV_OP(NAME)             { STRING_COMMA_LEN (NAME), TRUE,   ic_arith,    sc_mov_mov, handle_mov     }
#define NOP_OP(NAME, SC)         { STRING_COMMA_LEN (NAME), FALSE,  ic_nop,      (SC),       handle_nop     }
#define ONE_OP(NAME,SIZE,SC)     { STRING_COMMA_LEN (NAME), (SIZE), ic_arith,    (SC),       handle_one_op  }
#define POP_OP(NAME,SIZE,SC)     { STRING_COMMA_LEN (NAME), (SIZE), ic_arith,    (SC),       handle_pop     }
#define PUSH_OP(NAME,SIZE,SC)    { STRING_COMMA_LEN (NAME), (SIZE), ic_arith,    (SC),       handle_push    }
#define RET_OP(NAME,SIZE,SC)     { STRING_COMMA_LEN (NAME), (SIZE), ic_ret,      (SC),       handle_stack   }
#define SHIFT_OP(NAME,SIZE,SC)   { STRING_COMMA_LEN (NAME), (SIZE), ic_arith,    (SC),       handle_shift  }
#define STACK_OP(NAME,SIZE,SC)   { STRING_COMMA_LEN (NAME), (SIZE), ic_arith,    (SC),       handle_stack   }
#define STRING_OP(NAME,SC)       { STRING_COMMA_LEN (NAME), TRUE,   ic_arith,    (SC),       handle_string  }
#define SYS_OP(NAME)             { STRING_COMMA_LEN (NAME), TRUE,   ic_call,     sc_syscall, handle_sys     }
#define XCHG_OP(NAME)            { STRING_COMMA_LEN (NAME), TRUE,   ic_arith,    sc_mov_mov, handle_xchg    }
#define END_OF_LIST              { NULL, 0,                 FALSE,  ic_none,     sc_none,    NULL           }

static insn_info a_insns[] =
{
  ARITH_OP ("adc",  TRUE,  sc_bin_add),
  ARITH_OP ("adc1", FALSE, sc_bin_add),
  ARITH_OP ("add",  TRUE,  sc_bin_add),
  ARITH_OP ("and",  TRUE,  sc_bin_and),
  END_OF_LIST
};
static insn_info c_insns [] = 
{
  FLOW_OP ("callq", FALSE, sc_flow_call),
  FLOW_OP ("callw", FALSE, sc_flow_call),
  FAULT_OP ("cld"), 		/* FIXME: Implement.  */
  FAULT_OP ("cli"),
  /* FIXME: We currently assume that conditional moves always takes place.  */
  MOV_OP ("cmova"),
  MOV_OP ("cmovae"),
  MOV_OP ("cmovb"),
  MOV_OP ("cmovbe"),
  MOV_OP ("cmovc"),
  MOV_OP ("cmove"),
  MOV_OP ("cmovg"),
  MOV_OP ("cmovge"),
  MOV_OP ("cmovl"),
  MOV_OP ("cmovle"),
  MOV_OP ("cmovna"),
  MOV_OP ("cmovnae"),
  MOV_OP ("cmovnb"),
  MOV_OP ("cmovnbe"),
  MOV_OP ("cmovnc"),
  MOV_OP ("cmovne"),
  MOV_OP ("cmovng"),
  MOV_OP ("cmovnge"),
  MOV_OP ("cmovnl"),
  MOV_OP ("cmovnle"),
  MOV_OP ("cmovno"),
  MOV_OP ("cmovnp"),
  MOV_OP ("cmovns"),
  MOV_OP ("cmovnz"),
  MOV_OP ("cmovo"),
  MOV_OP ("cmovp"),
  MOV_OP ("cmovpe"),
  MOV_OP ("cmovpo"),
  MOV_OP ("cmovz"),
  ARITH_OP ("cmp", TRUE, sc_bin_cmp),
  STRING_OP ("cmps", sc_string_cmps),
  CMPXCHG_OP ("cmpxchg"),
  IGNORE_OP ("cpuid"),
  END_OF_LIST
};
static insn_info d_insns [] = 
{
  ONE_OP ("dec", TRUE, sc_unop_dec),
  END_OF_LIST
};
static insn_info e_insns [] = 
{
  STACK_OP ("enter", TRUE, sc_stack_enter),
  END_OF_LIST
};
static insn_info h_insns [] = 
{
  FAULT_OP ("hlt"),
  END_OF_LIST
};
static insn_info i_insns [] = 
{
  IGNORE_OP ("in"),
  ONE_OP    ("inc", TRUE, sc_unop_inc),
  FAULT_OP  ("int"),
  FAULT_OP  ("int3"),
  FAULT_OP  ("iret"),
  END_OF_LIST
};
static insn_info j_insns [] = 
{
  CONDJ_OP ("ja",   FALSE, sc_flow_condjmp),
  CONDJ_OP ("jae",  FALSE, sc_flow_condjmp),
  CONDJ_OP ("jb",   FALSE, sc_flow_condjmp),
  CONDJ_OP ("jbe",  FALSE, sc_flow_condjmp),
  CONDJ_OP ("jc",   FALSE, sc_flow_condjmp),
  CONDJ_OP ("jcxz", FALSE, sc_flow_condjmp),
  CONDJ_OP ("je",   FALSE, sc_flow_condjmp),
  CONDJ_OP ("jecxz",FALSE, sc_flow_condjmp),
  CONDJ_OP ("jg",   FALSE, sc_flow_condjmp),
  CONDJ_OP ("jge",  FALSE, sc_flow_condjmp),
  CONDJ_OP ("jl",   FALSE, sc_flow_condjmp),
  CONDJ_OP ("jle",  FALSE, sc_flow_condjmp),
  JUMP_OP ("jmp",   FALSE, sc_flow_jmp),
  JUMP_OP ("jmpq",  FALSE, sc_flow_jmp),
  CONDJ_OP ("jna",  FALSE, sc_flow_condjmp),
  CONDJ_OP ("jnae", FALSE, sc_flow_condjmp),
  CONDJ_OP ("jnb",  FALSE, sc_flow_condjmp),
  CONDJ_OP ("jnbe", FALSE, sc_flow_condjmp),
  CONDJ_OP ("jnc",  FALSE, sc_flow_condjmp),
  CONDJ_OP ("jne",  FALSE, sc_flow_condjmp),
  CONDJ_OP ("jng",  FALSE, sc_flow_condjmp),
  CONDJ_OP ("jnge", FALSE, sc_flow_condjmp),
  CONDJ_OP ("jnl",  FALSE, sc_flow_condjmp),
  CONDJ_OP ("jnle", FALSE, sc_flow_condjmp),
  CONDJ_OP ("jno",  FALSE, sc_flow_condjmp),
  CONDJ_OP ("jnp",  FALSE, sc_flow_condjmp),
  CONDJ_OP ("jns",  FALSE, sc_flow_condjmp),
  CONDJ_OP ("jnz",  FALSE, sc_flow_condjmp),
  CONDJ_OP ("jo",   FALSE, sc_flow_condjmp),
  CONDJ_OP ("jp",   FALSE, sc_flow_condjmp),
  CONDJ_OP ("jpe",  FALSE, sc_flow_condjmp),
  CONDJ_OP ("jpo",  FALSE, sc_flow_condjmp),
  CONDJ_OP ("js",   FALSE, sc_flow_condjmp),
  CONDJ_OP ("js",   FALSE, sc_flow_condjmp),
  CONDJ_OP ("jz",   FALSE, sc_flow_condjmp),
  END_OF_LIST
};
static insn_info l_insns [] = 
{
  FLOW_OP ("lcall",   FALSE, sc_flow_call),
  ARITH_OP ("lea",    FALSE, sc_bin_lea),
  STACK_OP ("leave",  FALSE, sc_stack_leave),
  STACK_OP ("leaveq", FALSE, sc_stack_leave),
  NOP_OP ("lfence",   sc_fence),
  JUMP_OP ("ljmp",    FALSE, sc_flow_jmp),
  STRING_OP ("lods",  sc_string_lods),
  CONDJ_OP ("loop",   FALSE, sc_flow_loop),/* FIXME: Currently treated as condjumps.  */
  CONDJ_OP ("loope",  FALSE, sc_flow_loop),
  CONDJ_OP ("loopne", FALSE, sc_flow_loop),
  CONDJ_OP ("loopnz", FALSE, sc_flow_loop),
  CONDJ_OP ("loopz",  FALSE, sc_flow_loop),
  STACK_OP ("lret",   FALSE, sc_stack_ret),
  END_OF_LIST
};
static insn_info m_insns [] = 
{
  MOV_OP ("mov"),
  MOV_OP ("movabs"),
  MOV_OP ("movaps"),
  MOV_OP ("movdqa"),
  STRING_OP ("movs", sc_string_movs),
  EXTMOV_OP ("movsbl", sc_mov_sext),
  EXTMOV_OP ("movslq", sc_mov_sext),
  EXTMOV_OP ("movswl", sc_mov_sext),
  EXTMOV_OP ("movswq", sc_mov_sext),
  MOV_OP ("movw"),
  EXTMOV_OP ("movzbl", sc_mov_zext),
  EXTMOV_OP ("movzlq", sc_mov_zext),
  EXTMOV_OP ("movzwl", sc_mov_zext),
  EXTMOV_OP ("movzwq", sc_mov_zext),
  END_OF_LIST
};
static insn_info n_insns [] = 
{
  ONE_OP ("neg", TRUE, sc_unop_neg),
  NOP_OP ("nop", sc_nop),
  NOP_OP ("nopl", sc_nop),
  NOP_OP ("nopw", sc_nop),
  ONE_OP ("not", TRUE, sc_unop_not),
  END_OF_LIST
};
static insn_info o_insns [] = 
{
  ARITH_OP ("or",  TRUE, sc_bin_or),
  END_OF_LIST
};
static insn_info p_insns [] = 
{
  NOP_OP ("pause", sc_fence),
  POP_OP ("pop", TRUE, sc_stack_pop),
  POP_OP ("popf", TRUE, sc_stack_pop1),
  PUSH_OP ("push", TRUE, sc_stack_push),
  PUSH_OP ("pushf", TRUE, sc_stack_push1),
  END_OF_LIST
};
static insn_info r_insns [] = 
{
  IGNORE_OP ("rdmsr"),
  RET_OP   ("retf", FALSE, sc_stack_ret),
  RET_OP   ("retq", FALSE, sc_stack_ret),
  SHIFT_OP ("rol",  TRUE, sc_bin_rol),
  SHIFT_OP ("ror",  TRUE, sc_bin_ror),
  END_OF_LIST
};
static insn_info s_insns [] = 
{
  SHIFT_OP ("sar",  TRUE, sc_bin_sar),
  ARITH_OP ("sbb",  TRUE, sc_bin_sub),
  STRING_OP ("scas", sc_string_scas),
  SHIFT_OP ("shl",  TRUE, sc_bin_shl),
  SHIFT_OP ("shr",  TRUE, sc_bin_shr),
  FAULT_OP ("std"), 		/* FIXME: Implement.  */
  FAULT_OP ("sti"),
  STRING_OP ("stos", sc_string_stos),
  ARITH_OP ("sub",  TRUE, sc_bin_sub),
  SYS_OP ("syscall"),
  END_OF_LIST
};
static insn_info t_insns [] = 
{
  ARITH_OP ("test",  TRUE, sc_bin_test),
  END_OF_LIST
};
static insn_info x_insns [] = 
{
  XCHG_OP  ("xchg"),
  ARITH_OP ("xor",  TRUE, sc_bin_xor),
  END_OF_LIST
};

static insn_info * insn_lists[26] =
{
  a_insns,
  NULL,
  c_insns,
  d_insns,
  e_insns,
  NULL,
  NULL,
  h_insns,
  i_insns,
  j_insns,
  NULL,
  l_insns,
  m_insns,
  n_insns,
  o_insns,
  p_insns,
  NULL,
  r_insns,
  s_insns,
  t_insns,
  NULL,
  NULL,
  NULL,
  x_insns,
  NULL,
  NULL
};

#define PREFIX_OP(NAME) { STRING_COMMA_LEN (NAME), FALSE, ic_none, sc_none, NULL }

static struct insn_info prefixes[] =
{
  PREFIX_OP ("bnd"),
  PREFIX_OP ("cs"),
  PREFIX_OP ("data16"),
  PREFIX_OP ("ds"),
  PREFIX_OP ("es"),
  PREFIX_OP ("fs"),
  PREFIX_OP ("gs"),
  PREFIX_OP ("lock"),
  PREFIX_OP ("rep"),
  PREFIX_OP ("repnz"),
  PREFIX_OP ("repz"),
  PREFIX_OP ("rex"),
  PREFIX_OP ("rex.B"),
  PREFIX_OP ("rex.R"),
  PREFIX_OP ("rex.RB"),
  PREFIX_OP ("rex.RX"),
  PREFIX_OP ("rex.RXB"),
  PREFIX_OP ("rex.W"),
  PREFIX_OP ("rex.WB"),
  PREFIX_OP ("rex.WR"),
  PREFIX_OP ("rex.WRB"),
  PREFIX_OP ("rex.WRX"),
  PREFIX_OP ("rex.WRXB"),
  PREFIX_OP ("rex.WX"),
  PREFIX_OP ("rex.WXB"),
  PREFIX_OP ("rex.X"),
  PREFIX_OP ("rex.XB"),
  PREFIX_OP ("ss"),
  PREFIX_OP ("xrelease"),
};

static bool
handler_name_matches (struct insn_info *   handler,
		      const char **        pt)
{
  const char * t = * pt;
  size_t       len = handler->len;
  char         m;

  if (! strneq (t, handler->name, len))
    return FALSE;

  t += len;
  m = *t;

  if (ISSPACE (m) || m == 0)
    {
      *pt = t;
      return TRUE;
    }

  if (!handler->size_suffix)
    return FALSE;

  if (m != 'b' && m != 'w' && m != 'l' && m != 'q')
    return FALSE;

  ++ t;
  if (ISSPACE (*t) || *t == 0)
    {
      *pt = t;
      return TRUE;
    }

  return FALSE;
}

static int
x86_classify_insn (ulong pc, addr_info * info)
{
  insn_info *   insns;
  const char *  t;
  int           i;

  /* Initialise the info structure with default values.  */
  info->insn   = NULL;
  info->args   = NULL;

  /* Use the libopcodes library to disassemble the next insn and put it into a buffer.  */
  disas.pos = 0;
  disas.buffer[0] = 0;
  emul_info.status = TRUE;
  info->len = print_insn_i386 (pc, & disas.info);
  if (info->len < 1)
    return 1;

  /* Scan the disassembled instruction for opcodes that we recognise and parse them
     again.  Yes, this is crazy, but it is safer to use a known good disassembler like
     libopcodes than to write a new one from scratch, and we are only looking for
     certain particular instructions that can be used as rop/jopb operators.  */
  t = disas.buffer;

  /* First off, check to see if the instruction is invalid.  This can easily happen
     since we are trying execution at arbitrary addresses, not just known instruction
     start addresses.  */
  if (*t == 0
      /* Note: This is actually testing for ".byte" and "(bad)" but we know that
	 no valid instruction will ever start with either of these characters.  */
      || *t == '('
      || *t == '.')
    return info->len;

  /* Next skip any prefixes on the insn.  */
  for (i = ARRAY_SIZE (prefixes); i--;)
    {
      struct insn_info * pref = prefixes + i;
      unsigned len = pref->len;

      if (pref->size_suffix)
	einfo (FAIL, "unexpecetd insn suffix");
      if (strneq (t, pref->name, len))
	{
	  t += len;
	  while (ISSPACE (*t))
	    t++;

	  if (*t == 0)
	    /* All prefix, no insn ?  */
	    return info->len;

	  /* There may be more than one prefix.  */
	  i = ARRAY_SIZE (prefixes);
	}
    }

  /* Now see if the instruction is one that we care about.  */
  if (! ISALPHA (*t))
    {
      einfo (VERBOSE2, "bad insn: %s", disas.buffer);
      return info->len;
    }

  insns = insn_lists[TOLOWER (*t) - 'a'];
  if (insns != NULL)
    {
      for (i = 0; insns[i].name; i++)
	{
	  struct insn_info * insn = insns + i;
	  if (handler_name_matches (insn, &t))
	    {
	      /* We identified the instruction, but there may still be
		 reasons why it is invalid: bad segment registers
		 (printed as %? by the disassembler), or registers
		 that fault when accessed in user space.  */
	      const char *scan = t;
	      for (;;)
		{
		  scan = strchr (scan, '%');
		  if (!scan)
		    break;
		  scan++;
		  if (const_strneq (scan, "?")
		      || const_strneq (scan, "cr")
		      || const_strneq (scan, "db")
		      || const_strneq (scan, "tr"))
		    return info->len;
		}
	      info->insn = insn;
	      info->args = xstrdup (t);
	      return info->len;
	    }
	}
    }

  /* Unhandled insns are presumed to be uninteresting to a gadget.  */
  /* FIXME: Have we missed any insns that do have interesting effects ?  */
  einfo (VERBOSE2, "unhandled insn: %s", disas.buffer);
  return info->len;
}

static int ATTRIBUTE_PRINTF_2
x86_printf (void * stream, const char * format, ...) 
{
  size_t n;
  va_list args;

  while (1)
    {
      size_t space = disas.alloc - disas.pos;

      va_start (args, format);
      n = vsnprintf (disas.buffer + disas.pos, space, format, args);
      va_end (args);

      if (space > n)
	break;

      disas.alloc = (disas.alloc + n) * 2;
      disas.buffer = (char *) xrealloc (disas.buffer, disas.alloc);
    }
  disas.pos += n;

  return n;
}

static void
x86_mem_err (int status, bfd_vma addr, struct disassemble_info * info)
{
  einfo (ERROR, "x86 disasembler: memory err %d for addr %lx base %lx",
	 status, addr, emul_info.code_base);
}

static void
x86_addr (bfd_vma addr, struct disassemble_info * info)
{
  size_t space = disas.alloc - disas.pos;

  if (space < 16)
    {
      disas.alloc  = disas.alloc * 2;
      disas.buffer = (char *) xrealloc (disas.buffer, disas.alloc);
    }

  sprintf (disas.buffer + disas.pos, "%c0x%lx ", ADDRESS_CHAR, addr);
  disas.pos += strlen (disas.buffer + disas.pos);
  return;
}

static bool
scan_init (scan_state * ss, bfd_byte *code, ulong size, ulong start, ulong pc)
{
  int reg;

  suppress_checks = TRUE;
  for (reg = 0; reg <= NUM_REGISTERS; reg++)
    write_reg (ss, reg, UNKNOWN_REG_VAL);

  /* Poison the parameter passing registers.  */
  static int param_regs [6] = { 7 /* rdi */, 6 /* rsi */, 2 /* rdx */, 1 /* rcx */, 8 /* r8 */, 9 /* r9 */ };
  int i;
  for (i = 0; i < ARRAY_SIZE (param_regs); i++)
    write_reg (ss, param_regs[i], ATTACKER_REG_VAL);

  emul_info.status = TRUE;
  ss->pc = pc;
  write_reg (ss, SP_REGNO, (ulong)(emul_info.stack + (STACK_SIZE - 1)));

  suppress_checks = FALSE;
  return TRUE;
}

static bool
x86_init (bfd_byte * code, ulong size, ulong start, const char * filename, ulong entry, bool little)
{
  static bool once = FALSE;

  einfo (VERBOSE2, "Scan init: start addr = %#lx size = %#lx", start, size);

  if (!once)
    {
      once = TRUE;

      disas.alloc  = 128;
      disas.pos    = 0;
      disas.buffer = xmalloc (disas.alloc);

      /* Initialise the non-NULL fields in the disassembler info structure.  */
      init_disassemble_info (& disas.info, stdout, x86_printf);
      disas.info.application_data   = & emul_info;
      disas.info.stream             = & emul_info;
      disas.info.endian_code        = BFD_ENDIAN_LITTLE;
      disas.info.read_memory_func   = x86_read_mem;
      disas.info.memory_error_func  = x86_mem_err;
      disas.info.arch               = bfd_arch_i386;
      disas.info.mach               = bfd_mach_x86_64;
      disas.info.print_address_func = x86_addr;
      disassemble_init_for_target (& disas.info);

      build_reg_lex ();
    }

  memset (& emul_info, 0, sizeof emul_info);

  emul_info.code = code;
  emul_info.size = size;
  emul_info.code_base = start;
  emul_info.status = TRUE;
  emul_info.scanned = xmalloc (size * sizeof * emul_info.scanned);
  return TRUE;
}

static int
display_insn (enum einfo_type type, ulong addr, const char * prefix)
{
  int len;

  disas.pos = 0;
  disas.buffer[0] = 0;
  emul_info.status = TRUE;
  switch (syntax)
    {
    case 1:  len = print_insn_i386_att (addr, & disas.info); break;
    case -1: len = print_insn_i386_intel (addr, & disas.info); break;
    default: len = print_insn_i386 (addr, & disas.info); break;
    }
  einfo (type, "%s %.6lx: %s", prefix, addr, disas.buffer);
  return len;
}

static void
dump_tick (scan_state * ss, uint tick, uint move, int reg)
{
  const char * prefix = "        ";

  if (tick == ss->conditional_tick)
    {
      display_insn (INFO, ss->insns[tick], " COND:  ");
      return;
    }
    
  assert (tick > ss->conditional_tick);

  if (move != -1 && ss->moves[move].tick == tick)
    {
      if (reg == ss->moves[move].dest)
	{
	  reg = ss->moves[move].source;      
	  prefix = " MOVE:  ";
	}

      move --;
    }

  dump_tick (ss, tick - 1, move, reg);
  display_insn (INFO, ss->insns[tick], prefix);
}

static void
dump_sequence (scan_state * ss, ulong second_load)
{
  int tick;

  einfo (INFO, "Possible sequence found, based on a starting address of %#lx:", start_address);

  if (BE_VERBOSE)
    for (tick = 0; tick < ss->conditional_tick; tick ++)
      display_insn (INFO, ss->insns[tick], "        ");

  dump_tick (ss, second_load, ss->next_move - 1, ss->moves[ss->next_move - 1].dest);
}

static hashval_t
hash_one_insn (addr_info *info, ulong addr, hashval_t init)
{
  if (info->insn->cl == ic_jump)
    return info->data;

  if (info->insn->cl == ic_ret || info->insn->cl == ic_arith)
    {
      void *p = emul_info.code + (addr - emul_info.code_base);
      return iterative_hash (p, info->len, init);
    }
  return 0;
}

static hashval_t
sequence_hash (const void *seq)
{
  ulong addr = (ulong) seq;

  addr_info *info = emul_info.scanned + (addr - emul_info.code_base);
  return info->seq_hash;
}

/* The function tests automaton declarations on equality of their
   keys.  The function is used by abstract data `hashtab'.  The
   function returns 1 if the declarations have the same key, 0
   otherwise.  */

static int
sequence_eq_p (const void *s1, const void *s2)
{
  ulong addr1 = (ulong) s1;
  ulong addr2 = (ulong) s2;

  addr_info *info1 = emul_info.scanned + (addr1 - emul_info.code_base);
  addr_info *info2 = emul_info.scanned + (addr2 - emul_info.code_base);

  if (info1->seq_hash == 0)
    einfo (FAIL, "bad hash");

  if (info1->seq_hash != info2->seq_hash)
    return FALSE;
  if (info1->n_arith_insns != info2->n_arith_insns)
    return FALSE;

  int n_insns = info1->n_arith_insns;
  int i;
  int len = 0;

  for (i = 0; i < n_insns; i++)
    {
      if (info1->has_pcrel || info2->has_pcrel)
	return FALSE;
      if (info1->len != info2->len)
	return FALSE;
      int this_len = info1->len;
      len += this_len;
      info1 += this_len;
      info2 += this_len;
    }
  /* Compare the last insn - a ret or a jump.  */
  if (info1->insn != info2->insn || info1->len != info2->len)
    return FALSE;
  if (info1->insn->cl == ic_ret)
    len += info1->len;
  else if (info1->insn->cl == ic_jump)
    {
      if (info1->data != info2->data || info1->data == 0)
	return FALSE;
    }
  void *p1 = emul_info.code + (addr1 - emul_info.code_base);
  void *p2 = emul_info.code + (addr1 - emul_info.code_base);
  if (memcmp (p1, p2, len) != 0)
    return FALSE;
  return TRUE;
}

/* Run over the address space, classifying every insn there and computing certain
   other information such as sequence hash values.  */

static void
x86_preevaluate (ulong start, ulong end)
{
  ulong addr;
  int len;

  einfo (VERBOSE, "Classifying insns...");
  suppress_checks = TRUE;
  for (addr = start; addr < end ; addr += len)
    {
      addr_info *start_info = emul_info.scanned + (addr - start);

      len = x86_classify_insn (addr, start_info);

      start_info->n_arith_insns = 0;
      if (start_info->insn == NULL
	  || start_info->insn->cl == ic_fault)
	{
	  start_info->ends_in_fault = TRUE;
	  continue;
	}

      if (start_info->insn->cl == ic_ret
	  || start_info->insn->cl == ic_jump)
	start_info->seq_hash = hash_one_insn (start_info, addr, 0);

      /* If this is a plain arith instruction, look up the information about
	 the sequence following it.  */
      if (start_info->insn->cl != ic_arith)
	continue;

      ulong next = addr + start_info->len;
      if (next >= end)
	{
	  start_info->ends_in_fault = TRUE;
	  continue;
	}

      addr_info *next_info = emul_info.scanned + (next - start);
      start_info->n_arith_insns = next_info->n_arith_insns + 1;
      start_info->ends_in_fault = next_info->ends_in_fault;
      if (strstr (start_info->args, "#  &0x"))
	{
	  /* Can't hash it meaninfully (yet?).  */
	  start_info->has_pcrel = TRUE;
	  continue;
	}
      if (next_info->seq_hash != 0)
	start_info->seq_hash = hash_one_insn (start_info, addr, next_info->seq_hash);
    }
  suppress_checks = FALSE;
  einfo (VERBOSE, "Classified");
}

/* Statistics counters, to be reported in the final_report hook.  */

static bool
is_speculation_barrier (insn_info * info)
{
  return info->type == sc_fence;
}

static bool
is_conditional_branch (insn_info * info)
{
  return info->type == sc_flow_condjmp;
}

static bool
is_breakpoint (insn_info * info)
{
  /* FIXME: Add a subclass for the HLT insn...  */
  return info->cl == ic_fault && streq (info->name, "hlt");
}

static bool
is_undefined (insn_info * info)
{
  return info->cl == ic_fault;

}

static void
reset_probes (void)
{
  first_memory_access = -1;
  second_memory_access = -1;
  attacker_reg_val_set = -1;
  attacker_reg_val_used = -1;
  attacker_mem_val_used = -1;
}

static ulong
get_branch_dest (ulong addr)
{
  const char * dest;

  if ((dest = strchr (disas.buffer, ADDRESS_CHAR)) != NULL)
    {
      ulong pc;

      pc = strtoul (dest + 1, NULL, 0);
      if (pc == addr)
	/* The disassembler could not work out the dest.
	   FIXME: Try parsing the insn ?  */
	einfo (VERBOSE, "UNABLE TO EXTRACT DESTINATION OF BRANCH INSN: %s", disas.buffer);

      return pc;
    }

  /* FIXME: Try harder ?  Is dest in a register ?  */
  einfo (FAIL, "UNABLE TO EXTRACT DESTINATION OF BRANCH INSN: %s", disas.buffer);
  return -1UL;
}

static scan_state *
clone_state (scan_state * old_state, ulong new_pc)
{
  scan_state * new_state = xmalloc (sizeof * new_state);

  if (old_state)
    memcpy (new_state, old_state, sizeof (* old_state));
  else
    {
      memset (new_state, 0, sizeof (* new_state));
      new_state->conditional_tick = -1;
    }
  
  new_state->insns = xmalloc (max_num_ticks * sizeof (* new_state->insns));

  if (old_state)
    {
      memcpy (new_state->insns, old_state->insns, max_num_ticks * sizeof (* new_state->insns));
      new_state->moves = xmalloc (old_state->n_moves * sizeof (* new_state->moves));
      memcpy (new_state->moves, old_state->moves, old_state->next_move * sizeof (* old_state->moves));
    }
  else
    {
      new_state->n_moves   = 20;
      new_state->next_move = 0;
      new_state->moves     = xmalloc (20 * sizeof (* new_state->moves));
    }

  new_state->pc = new_pc;

  return new_state;
}

static void
release_state (scan_state * ss)
{
  free (ss->insns);
  free (ss);
}

static void
save_stack (scan_state * ss)
{
  memcpy (ss->saved_stack, emul_info.stack, STACK_SIZE * (sizeof ss->saved_stack[0]));
}

static void
restore_stack (scan_state * ss)
{
  memcpy (emul_info.stack, ss->saved_stack, STACK_SIZE * (sizeof ss->saved_stack[0]));
}

static void
run_scan (scan_state * ss, ulong start, ulong end)
{
  ulong start_pc = ss->pc;

  for (;ss->tick < max_num_ticks; ss->tick++)
    {
      ulong       next;
      addr_info * this_addr;
      ulong       this_pc;

      this_pc = ss->pc;

      display_insn (VERBOSE2, this_pc, "");

      if (this_pc < start || this_pc >= end)
	{
	  /* This can happen with an out of section call instruction.  */
	  einfo (VERBOSE2, "RESET: PC out of range: %lx", this_pc);
	  break;
	}

      this_addr = emul_info.scanned + (this_pc - start);
      ss->insns [ss->tick] = this_pc;

      /* Stop on bad instructions.  */
      if (this_addr == NULL
	  || this_addr->insn == NULL)
	break;
      
      if (is_breakpoint (this_addr->insn))
	{
	  einfo (VERBOSE2, "RESET: we have already scanned from this point");
	  break;
	}

      if (is_undefined (this_addr->insn))
	{
	  einfo (VERBOSE2, "RESET: unhandled isntruction");
	  break;
	}

      /* Check to see if the instruction is a conditional branch.
	 If so we need to simulate *both* possibilties as this is
	 what speculation does.  */
      if (is_conditional_branch (this_addr->insn))
	{
	  if (first_conditional_seen == 0)
	    {
	      einfo (VERBOSE2, "First conditional instruction seen at %#lx", this_pc);
	      first_conditional_seen = ss->tick;
	    }

	  if (ss->num_branches ++ >= max_num_branches)
	    {
	      einfo (VERBOSE2, "RESET: maximum number of branches reached");
	      break;
	    }

	  if (ss->conditional_tick == -1)
	    {
	      display_insn (VERBOSE2, this_pc, "START: conditional branch");

	      ss->conditional_tick = ss->tick;
	    }

	  next = get_branch_dest (this_pc);

	  if (next >= start && next < end)
	    {
	      scan_state * new_state;

	      einfo (VERBOSE2, "assume branch from %lx to %lx", this_pc, next);
	      new_state = clone_state (ss, next);
	      if (new_state == NULL)
		einfo (FAIL, "failed to create new state");
	      save_stack (ss);
	      new_state->tick ++;
	      run_scan (new_state, start, end);

	      einfo (VERBOSE2, "restoring state to cond branch at %lx", this_pc);
	      release_state (new_state);
	      restore_stack (ss);
	    }
	  else if (next == -1UL)
	    einfo (VERBOSE2, "assume branch not taken");
	  else
	    einfo (VERBOSE, "branch out of range ? (dest = %lx)", next);

	  ss->pc += this_addr->len;
	  einfo (VERBOSE2, "assuming branch not followed, so next pc is %lx", ss->pc);
	  if (ss->pc >= end)
	    break;

	  continue;
	}

      if (ss->conditional_tick != -1 && is_speculation_barrier (this_addr->insn))
	{
	  display_insn (VERBOSE2, this_pc, "RESET: speculation barrier");
	  /* Reset the search.  FIXME: Some barriers are only effective if used
	     between the first and second loads...  */
	  ss->conditional_tick = -1;
	}

      reset_probes ();

      /* Simulate the instruction.  */
      if (this_addr->insn->handler == NULL)
	einfo (FAIL, "no handler for insn");
      if (! this_addr->insn->handler (ss, this_addr->insn, this_addr->args))
	{
	  einfo (WARN, "RESET: instruction simulation failed");
	  break;
	}

      if (emul_info.status == FALSE)
	{
	  einfo (WARN, "RESET: emulation stopped");
	  break;
	}

      if (ss->conditional_tick >= 0)
	{
	  if (second_memory_access != -1)
	    {
	      display_insn (VERBOSE2, this_pc, "2nd speculative load");
	      /* We have found a sequence.  Tell the user.  */
	      dump_sequence (ss, ss->tick);
	      ++ num_found;
	      ss->conditional_tick = -1;
	      break;
	    }
	  else if (first_memory_access != -1)
	    {
	      /* The attacker has now been able to load a register
		 with a value from an address that they control.
		 Record the address where this happened.  */
	      display_insn (VERBOSE2, this_pc, "1st speculative load");
	    }
	}

      /* Advance to the next instruction, unless it has already been done for us.  */
      if (ss->pc == this_pc)
	{
	  if (this_addr->len == 0)
	    einfo (FAIL, "zero length instruction");
	  ss->pc += this_addr->len;
	}
    }

  if (ss->tick >= max_num_ticks)
    einfo (VERBOSE2, "RESET: Maximum number of instructions simulated (%d)", max_num_ticks);

  /* We have now probed from this address onwards, so record
     the fact so that we do not need to test it again.  */
  /* FIXME: We should seeach for the hlt insn structure by name...  */
  emul_info.scanned [start_pc - start].insn = h_insns + 0; /* hlt */
}

/* Entry point for the x86_64 scanner.
   Scans CODE for gadgets.
   ADDR is the starting address of the CODE.
   Code buffer is SIZE bytes long.
   ENTRY is the start address of the file being scanned.
   Returns TRUE if the scan went OK, even if no gadgets were found, and FALSE if something went wrong.
   FILENAME is the name of the associated file, for use in messages.  */

bool
x86_scan (bfd_byte * code, ulong size, ulong start, const char * filename, ulong entry)
{
  ulong end = start + size;

  /* If the user did not give us a start address then default to the beginning of the binary.  */
  if (start_address == 0 && start_address < start)
    start_address = start;

  if (start_address < start || start_address >= end)
    {
      einfo (VERBOSE, "Start address (%lx) not in simulated address range (%lx - %lx)",
	     start_address, start, end);
      return TRUE;
    }

  sequence_htab = htab_create (80000, sequence_hash, sequence_eq_p, (htab_del) 0);

  einfo (VERBOSE2, "Classifying instructions");
  x86_preevaluate (start, end);

  einfo (VERBOSE2, "Creating state");
  struct scan_state * ss = clone_state (NULL, start_address);

  einfo (VERBOSE2, "Initialising scan");
  if (! scan_init (ss, code, size, start, start_address))
    return FALSE;

  num_found = 0;

  einfo (VERBOSE2, "Running scan");
  run_scan (ss, start, end);

  if (num_found == 0)
    einfo (INFO, "No sequences found");

  release_state (ss);
  htab_delete (sequence_htab);

  einfo (VERBOSE2, "x86 Scanner: scan finished");

  return TRUE;
}

static bool
x86_options (const char * arg, const char ** argv, unsigned argc)
{
  if (const_strneq (arg, "--num-branches="))
    {
      max_num_branches = strtoul (arg + 15, NULL, 0);
      return TRUE;
    }

  if (const_strneq (arg, "--start-address="))
    {
      start_address = strtoul (arg + 16, NULL, 0);
      return TRUE;
    }

  if (strneq (arg, "--syntax=", 9))
    {
      arg += 9;
      if (streq (arg, "att"))
	syntax = 1;
      else if (streq (arg, "intel"))
	syntax = -1;
      else
	{
	  einfo (WARN, "unrecognised --syntax value %s", arg);
	  return FALSE;
	}
      return TRUE;
    }

  return FALSE;
}

static void
x86_usage (void)
{
  einfo (INFO, "    --num-branches=<n>  [Set the maximum number of branches to follow]");
  einfo (INFO, "    --start-address=<n> [Set the entry point of the scan]");
  einfo (INFO, "    --syntax=[att|intel][Set the desired disassembly syntax]");
}

struct callbacks target =
{
  EM_X86_64,
  0,
  "X86 Scanner",
  x86_init,
  NULL,		/* x86_finish */
  x86_scan,
  NULL,		/* x86_final_report */
  x86_options,
  x86_usage
};
