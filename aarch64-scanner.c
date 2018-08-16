/* AArch64 Sim Spec Scanner - a tool for locating vulnerable speculative loads in AArch64 binaries.
   Copyright (c) 2016, 2017 Red Hat.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  You should have received a copy of the GNU General Public
  License along with this program; see the file COPYING3. If not,
  see <http://www.gnu.org/licenses/>.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#include "scanner.h"
#include "gdb/callback.h"
#include "gdb/remote-sim.h"
#define WITH_PROFILE 0
#include "sim-main.h"
#include "memory.h"

#define NUM_REGISTERS	32

/* Values used to initialise registers.  */
#define ATTACKER_REG_VAL	0x06eeeee0UL
#define UNKNOWN_REG_VAL		0x11111100UL
#define ATTACKER_MEM_VAL        0x00e0a0d0UL

#define BREAKPOINT		0xd42000c0 	/* brk	#0x6 */

#define ADDRESS_CHAR		'&'

typedef struct reg_move
{
  uint   tick;
  int    source;
  int    dest;
} reg_move;

typedef struct scan_state
{
  ulong       pc;
  int         tick;
  int         conditional_tick;
  ulong *     insns;
  uint        num_branches;
  uint64_t    regs [NUM_REGISTERS];
  reg_move *  moves;
  uint        n_moves;
  int         next_move;
} scan_state;

extern int print_insn_aarch64 (bfd_vma, struct disassemble_info *);

static scan_state *     current_ss = NULL;
static uint             num_found = 0;
static ulong            num_insns = 0;
static uint             max_num_branches = 32;
static char             print_buffer[256];
static disassemble_info info = {0};
static SIM_DESC         sd;
static ulong            start_address = 0;
static bool             first_memory_access = FALSE;
static int              second_memory_access = -1;
static int              attacker_reg_val_set = -1;
static bool             attacker_reg_val_used = FALSE;
static int              attacker_mem_val_used = -1;
static bool             suppress_checks = FALSE;
static int              reg_read = -1;
static const char *     trace_arg = NULL;
static int              poison_reg = -1;
static uint             max_num_ticks = 1 << 12;

/* --------Simulator Interceptor Functions ------------------------------------ */

static void
reset_probes (void)
{
  attacker_reg_val_used = FALSE;
  attacker_mem_val_used = -1;
  attacker_reg_val_set = -1;
  first_memory_access = FALSE;
  second_memory_access = -1;
  reg_read = -1;
}

static void
add_reg_move (scan_state * ss, int from, int to)
{
  if (ss->n_moves == ss->next_move)
    {
      ss->n_moves += 20;
      ss->moves = xrealloc (ss->moves, ss->n_moves * sizeof (* ss->moves));
    }

  ss->moves[ss->next_move].tick   = ss->tick;
  ss->moves[ss->next_move].source = from;
  ss->moves[ss->next_move].dest   = to;
  ss->next_move ++;
}

#define WRAP_REG_GET_FUNC(NAME,TYPE)					\
TYPE									\
__wrap_aarch64_get_reg_##NAME (sim_cpu * cpu, GReg reg, int r31_is_sp)	\
{									\
  extern TYPE __real_aarch64_get_reg_##NAME (sim_cpu *, GReg, int);	\
  TYPE val;								\
									\
  val = __real_aarch64_get_reg_##NAME (cpu, reg, r31_is_sp);		\
  if (! suppress_checks)						\
    {									\
      /* Record when a register containing an				\
	 attacker provided value is read.  */				\
      if (val == ATTACKER_MEM_VAL)					\
	{								\
	  attacker_mem_val_used = reg;					\
	  einfo (VERBOSE2, "attacker memory value loaded into reg %d has been used", reg); \
	}								\
      else if (val == ATTACKER_REG_VAL)					\
	{								\
	  attacker_reg_val_used = TRUE;					\
	  einfo (VERBOSE2, "attacker controlled value in reg %d used", reg); \
	}								\
      reg_read = reg;							\
    }									\
  return val;								\
}

WRAP_REG_GET_FUNC (u64, uint64_t)
WRAP_REG_GET_FUNC (s64, int64_t)
WRAP_REG_GET_FUNC (u32, uint32_t)
WRAP_REG_GET_FUNC (s32, int32_t)
WRAP_REG_GET_FUNC (u16, uint16_t)
WRAP_REG_GET_FUNC (s16, int16_t)
WRAP_REG_GET_FUNC (u8,  uint8_t)
WRAP_REG_GET_FUNC (s8,  int8_t)

#define WRAP_REG_SET_FUNC(NAME,TYPE)					\
void									\
__wrap_aarch64_set_reg_##NAME (sim_cpu * cpu, GReg reg, int r31_is_sp, TYPE val) \
{									\
  extern void __real_aarch64_set_reg_##NAME (sim_cpu *, GReg, int, TYPE); \
									\
  if (! suppress_checks)						\
    {									\
      /* If the attacker value was read during this instruction, then	\
	 always set the destination value to ATTACKER, no matter how	\
	 it might have been transformed, so that we can track it.  */	\
      if (attacker_reg_val_used)					\
	{								\
	  if (first_memory_access)					\
	    {								\
	      einfo (VERBOSE2, "register %d set based on a value retrieved from an attacker controlled memory address", reg); \
	      attacker_reg_val_set = reg;				\
	      val = ATTACKER_MEM_VAL;					\
	    }								\
	  else								\
	    val = ATTACKER_REG_VAL;					\
	}								\
      if (reg_read != -1)						\
	add_reg_move (current_ss, reg_read, reg);			\
    }									\
  									\
  __real_aarch64_set_reg_##NAME (cpu, reg, r31_is_sp, val);		\
}

WRAP_REG_SET_FUNC (u64, uint64_t)
WRAP_REG_SET_FUNC (s64, int64_t)
WRAP_REG_SET_FUNC (u32, uint32_t)
WRAP_REG_SET_FUNC (s32, int32_t)
/* There are no 16-bit or 8-bit register set functions.  */

static ulong BEGIN;
static ulong END;

#define WRAP_MEM_GET_FUNC(NAME,TYPE)					\
TYPE									\
__wrap_aarch64_get_mem_##NAME (sim_cpu * cpu, uint64_t address)		\
{									\
  extern TYPE __real_aarch64_get_mem_##NAME (sim_cpu *, uint64_t);	\
									\
  if (! suppress_checks)						\
    {									\
      if (attacker_mem_val_used != -1)					\
	{								\
	  /* If memory was accessed after an attacker controlled values \
	     was read from a register, then we presume that the attacker\
	     is forcing a specific line to loaded into the data cache.  */	\
	  second_memory_access = attacker_mem_val_used;			\
	  einfo (VERBOSE2, "second memory access detected");		\
	}								\
      else if (attacker_reg_val_used)					\
	{								\
	  /* If memory was accessed after an attacker provide value was	\
	     read from a register, then we presume that the attacker is	\
	     controlling this access.  */				\
	  first_memory_access = TRUE;					\
	  einfo (VERBOSE2, "first memory access detected");		\
	  return (TYPE) ATTACKER_MEM_VAL;				\
	}								\
    } 									\
									\
  if (address >= BEGIN && address < END)				\
    return __real_aarch64_get_mem_##NAME (cpu, address);		\
  									\
  if (address < aarch64_get_stack_start (cpu)				\
      && address >= aarch64_get_reg_u64 (cpu, 31, TRUE))		\
    return __real_aarch64_get_mem_##NAME (cpu, address);		\
      									\
  if (! suppress_checks)						\
    einfo (VERBOSE2, "Treating memory read from unmapped address %#lx as a read of zero", address); \
  return 0;								\
}

WRAP_MEM_GET_FUNC (u64, uint64_t)
WRAP_MEM_GET_FUNC (s64, int64_t)
WRAP_MEM_GET_FUNC (u32, uint32_t)
WRAP_MEM_GET_FUNC (s32, int32_t)
WRAP_MEM_GET_FUNC (u16, uint16_t)
WRAP_MEM_GET_FUNC (s16, int16_t)
WRAP_MEM_GET_FUNC (u8,  uint8_t)
WRAP_MEM_GET_FUNC (s8,  int8_t)

#define WRAP_MEM_SET_FUNC(NAME,TYPE)					\
void									\
__wrap_aarch64_set_mem_##NAME (sim_cpu * cpu, uint64_t address, TYPE val)	\
{									\
  extern void __real_aarch64_set_mem_##NAME (sim_cpu *, uint64_t, TYPE);\
									\
  if (address >= BEGIN || address < END)				\
    return __real_aarch64_set_mem_##NAME (cpu, address, val);		\
									\
  if (address < aarch64_get_stack_start (cpu)				\
      && address >= aarch64_get_reg_u64 (cpu, 31, TRUE))		\
    return __real_aarch64_set_mem_##NAME (cpu, address, val);		\
      									\
  if (! suppress_checks)						\
    einfo (VERBOSE2, "Treating memory write to unmapped address %#lx as OK", address); \
}

WRAP_MEM_SET_FUNC (u64, uint64_t)
WRAP_MEM_SET_FUNC (s64, int64_t)
WRAP_MEM_SET_FUNC (u32, uint32_t)
WRAP_MEM_SET_FUNC (s32, int32_t)
WRAP_MEM_SET_FUNC (u16, uint16_t)
WRAP_MEM_SET_FUNC (s16, int16_t)
WRAP_MEM_SET_FUNC (u8,  uint8_t)
WRAP_MEM_SET_FUNC (s8,  int8_t)

/* -------------------------------------------------------- */

static int ATTRIBUTE_PRINTF_2
aarch64_printf (void * stream, const char * format, ...) 
{
  int      n;
  va_list  args;

  va_start (args, format);
  n = vsprintf (print_buffer + strlen (print_buffer), format, args);
  va_end (args);

  return n;
}

static int
aarch64_read_mem (bfd_vma                     memaddr,
		  bfd_byte *                  ptr,
		  unsigned int                length,
		  struct disassemble_info *   info)
{
  sim_cpu *  cpu = STATE_CPU (sd, 0);

  suppress_checks = TRUE;
  unsigned int val = aarch64_get_mem_u32 (cpu, memaddr);
  switch (length)
    {
    case 4: 
      ptr[3] = val >> 24;
      ptr[2] = val >> 16;
    case 2:
      ptr[1] = val >> 8;
    case 1:
      * ptr = val;
      suppress_checks = FALSE;
      return 0;

    default:
      einfo (INFO, "UNEXPECTED read mem from addr %lx of %u bytes", memaddr, length);
      return -1;
    }
}

static void
aarch64_addr (bfd_vma addr, struct disassemble_info * info)
{
  sprintf (print_buffer + strlen (print_buffer), " %c0x%lx", ADDRESS_CHAR, addr);
}

static void
aarch64_mem_err (int status, bfd_vma addr, struct disassemble_info * info ATTRIBUTE_UNUSED)
{
  einfo (ERROR, "mem err %x for addr %lx \n", status, addr);
}

/* Initialise the simulated registers and stack.  */

static bool
scan_init (ulong pc)
{
  sim_cpu *  cpu;
  unsigned   reg;

  if (sd == NULL)
    return FALSE;

  cpu = STATE_CPU (sd, 0);
  suppress_checks = TRUE;
  /* We set registers x0..x7 and v0..v7 to ATTACKER since these are the
     parameter registers used when making function calls.  We set the
     other registers to UNKNOWN since we assume that the attacker cannot
     use them to pass values into the kernel.  */
  for (reg = 0; reg < NUM_REGISTERS; reg++)
    {
      uint64_t val = reg < 8 ? ATTACKER_REG_VAL : UNKNOWN_REG_VAL;

      /* Allow the user to specify a poisoned register on the command line.  */
      if (reg == poison_reg)
	val = ATTACKER_REG_VAL;

      aarch64_set_reg_u64 (cpu, reg, 0, val);
      aarch64_set_vec_u64 (cpu, reg, 0, val);
      aarch64_set_vec_u64 (cpu, reg, 1, val);
    }

  aarch64_init (cpu, pc);

  suppress_checks = FALSE;

  /* FIXME: Should we reload the executable image as well ?  */
  /* FIXME: Should we load the static and/or dynamic data ?  */
  return TRUE;
}

static bool
string_match (const char ** array, unsigned array_len)
{
  const char * buffer = print_buffer;
  unsigned int i;

  for (i = array_len; i--;)
    {
      unsigned len = strlen (array[i]);

      if (strneq (array[i], buffer, len) && ISSPACE (buffer[len]))
	return TRUE;
    }

  return FALSE;
}

/* Returns TRUE if the buffer contains a conditional branch instruction.  */

static bool
is_conditional_branch (void)
{
  static const char * branch_insns[] =
    {
      "b.eq", "b.ne", "b.cs", "b.cc", "b.mi", "b.pl", "b.vs", "b.vc", "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le", "b.any",
      "cbz", "cbnz", 
      "tbz", "tbnz"
    };

  return string_match (branch_insns, ARRAY_SIZE (branch_insns));
}

static bool
is_speculation_barrier (void)
{
  static const char * barrier_insns[] =
    {
      "hint"
    };

  /* The CSDB instruction has no parameters, so it will not match
     the ISSPACE check in string_match().  */
  if (streq (print_buffer, "csdb"))
    return TRUE;
  
  /* FIXME: We should check the immediate value of any HINT instruction
     The value needed is 0x14....  */
  return string_match (barrier_insns, ARRAY_SIZE (barrier_insns));
}

static bool
is_breakpoint (void)
{
  static const char * break_insns[] =
    {
      "brk"
    };

  return string_match (break_insns, ARRAY_SIZE (break_insns));
}

static bool
is_control_flow (void)
{
  static const char * flow_insns[] =
    {
      "b"
    };

  return string_match (flow_insns, ARRAY_SIZE (flow_insns));
}

static bool
is_undefined (void)
{
  static const char * undefined_insns[] =
    {
      ".inst"
    };

  return string_match (undefined_insns, ARRAY_SIZE (undefined_insns));
}

static void
display_insn (enum einfo_type type, ulong addr, const char * prefix)
{
  print_buffer[0] = 0;
  print_insn_aarch64 (addr, & info);
  einfo (type, "%s %.6lx: %s", prefix, addr, print_buffer);
}

/* Recurse backwards through the instruction stream, looking for
   places where a register value was moved.  If the move matches
   our destination register, update it with the source register.

   Display the instructions as the recursion unwinds.  */

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
	  prefix = " LOAD:  ";
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


static scan_state *
clone_state (ulong new_pc, scan_state * old_state)
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
save_reg_state (scan_state * ss)
{
  sim_cpu *  cpu = STATE_CPU (sd, 0);
  int reg;

  suppress_checks = TRUE;
  for (reg = 0; reg < NUM_REGISTERS; reg++)
    ss->regs[reg] = aarch64_get_reg_u64 (cpu, reg, 0);
  /* FIXME: Save vector registers as well.  */
  suppress_checks = FALSE;
}

static void
restore_reg_state (scan_state * ss)
{
  sim_cpu *  cpu = STATE_CPU (sd, 0);
  int reg;

  suppress_checks = TRUE;
  for (reg = 0; reg < NUM_REGISTERS; reg++)
    aarch64_set_reg_u64 (cpu, reg, 0, ss->regs[reg]);
  /* FIXME: Restore vector registers as well.  */
  suppress_checks = FALSE;
}

static ulong
get_branch_dest (ulong addr)
{
  const char * dest;

  if ((dest = strchr (print_buffer, ADDRESS_CHAR)) != NULL)
    {
      ulong pc;

      pc = strtoul (dest + 1, NULL, 0);
      if (pc == addr)
	/* The disassembler could not work out the dest.
	   FIXME: Try parsing the insn ?  */
	einfo (VERBOSE, "UNABLE TO EXTRACT DESTINATION OF BRANCH INSN: %s", print_buffer);
      return pc;
    }

  /* FIXME: Try harder ?  Is dest in a register ?  */
  einfo (VERBOSE, "UNABLE TO EXTRACT DESTINATION OF BRANCH INSN: %s", print_buffer);
  return -1UL;
}

static void
run_scan (scan_state * ss, ulong start, ulong end)
{
  ulong      start_pc = ss->pc;
  jmp_buf    jumpbuf;
  sim_cpu *  cpu = STATE_CPU (sd, 0);

  current_ss = ss;
  
  STATE_ENGINE (sd)->jmpbuf = & jumpbuf;

  for (;ss->tick < num_insns; ss->tick++)
    {
      ulong next;

      aarch64_set_next_PC (cpu, ss->pc);
      aarch64_update_PC (cpu);
      /* FIXME: We need to detect loops!  */
      ss->insns [ss->tick] = ss->pc;

      print_buffer[0] = 0;
      print_insn_aarch64 (ss->pc, & info);
      
      if (is_breakpoint ())
	/* We have already scanned forwards from this point.
	   No need to continue.  */
	break;

      display_insn (VERBOSE2, ss->pc, "");

      if (is_undefined ())
	{
	  einfo (INFO, "%lx: Scan stopped by unrecognised instruction: %s", ss->pc, print_buffer);
	  break;
	}

      /* Check to see if the instruction is a conditional branch.
	 If so we need to simulate *both* possibilties as this is
	 what speculation does.  */
      if (is_conditional_branch ())
	{
	  if (ss->num_branches ++ >= max_num_branches)
	    {
	      einfo (VERBOSE2, "RESET: maximum number of branches reached");
	      break;
	    }

	  if (ss->conditional_tick == -1)
	    {
	      display_insn (VERBOSE2, ss->pc, "START: condtional branch");

	      ss->conditional_tick = ss->tick;
	    }

	  next = get_branch_dest (ss->pc);

	  if (next >= start && next < end)
	    {
	      scan_state * new_state;

	      einfo (VERBOSE2, "assume branch from %lx to %lx", ss->pc, next);
	      new_state = clone_state (next, ss);
	      new_state->tick ++;
	      save_reg_state (ss);	      
	      run_scan (new_state, start, end);
	      einfo (VERBOSE2, "restoring state to cond branch at %lx", ss->pc);
	      release_state (new_state);
	      restore_reg_state (ss);
	      current_ss = ss;
	    }
	  else if (next == -1UL)
	    einfo (VERBOSE2, "assume branch not taken");
	  else
	    einfo (VERBOSE, "branch out of range ? (dest = %lx)", next);

	  einfo (VERBOSE2, "assuming branch not followed...");
	  ss->pc += 4;
	  if (ss->pc >= end)
	    break;

	  continue;
	}

      if (ss->conditional_tick != -1 && is_speculation_barrier ())
	{
	  display_insn (VERBOSE2, ss->pc, "RESET: speculation barrier");
	  /* Reset the search.  FIXME: Some barriers are only effective if used
	     between the first and second loads...  */
	  ss->conditional_tick = -1;
	}

      reset_probes ();

      /* Simulate the instruction.  */
      if (setjmp (jumpbuf))
	{
	  if (STATE_ENGINE (sd)->reason != sim_stopped
	      || STATE_ENGINE (sd)->sigrc != 5 /* SIGTRAP */)
	    {
	      display_insn (INFO, ss->pc, "Simulation failed");
	      break;
	    }
	  display_insn (VERBOSE, ss->pc, "SIM STOPPED ?!");
	}
      else
	{
	  sim_resume (sd, TRUE, 0);
	}

      if (ss->conditional_tick >= 0)
	{
	  if (second_memory_access != -1)
	    {
	      display_insn (VERBOSE2, ss->pc, "2nd speculative load");
	      /* We have found a sequence.  Tell the user.  */
	      dump_sequence (ss, ss->tick);
	      ++ num_found;
	      ss->conditional_tick = -1;
	      break;
	    }
	  else if (first_memory_access)
	    {
	      /* The attacker has now been able to load a register
		 with a value from an address that they control.
		 Record the address where this happened.  */
	      display_insn (VERBOSE2, ss->pc, "1st speculative load");
	    }
	}

      /* Get the address of the next instruction.  */
      next = aarch64_get_next_PC (cpu);
      if (next < start || next >= end)
	break;

      if (next == ss->pc)
	{
	  display_insn (WARN, next, "unable to simulate insn - ignoring");
	  next += 4;
	}
      else if (next != ss->pc + 4)
	{
	  print_buffer[0] = 0;
	  print_insn_aarch64 (ss->pc, & info);
      
	  if (! is_control_flow ())
	    {
	      if (STATE_ENGINE (sd)->reason == sim_stopped)
		{
		  switch (STATE_ENGINE (sd)->sigrc)
		    {
		    case SIM_SIGBUS:
		    case SIM_SIGSEGV:
		      /* An illegal memory access.  This does not matter for simulation
			 but it does mean that the pc will be redirected to the fault
			 vector (address 0) which mucks up our instruction tracing.  */
		    case SIM_SIGTRAP:
		      /* This is the normal way for the sim to stop.  */
		    case SIM_SIGNONE:
		      break;
		    default:
		      einfo (WARN, "%lx: Unhandled signal (%d)", ss->pc, STATE_ENGINE (sd)->sigrc);
		      break;
		    }
		}
	      if (next == 0)
		next = ss->pc + 4;
	    }
	}

      ss->pc = next;
    }

  /* We have now probed from this address onwards, so record
     the fact so that we do not need to test it again.  */
  suppress_checks = TRUE;
  aarch64_set_mem_u32 (cpu, start_pc, BREAKPOINT);
  suppress_checks = FALSE;
}

static void
set_sim_memory (ulong start, ulong size, bool add)
{
  char buf[256];

  size = (size + 2047) & ~2047;
  if (start + size < 0x8000000)
    {
      einfo (VERBOSE2, "Skip setting memory region %#lx,%#lx as it is already set by the simulator",
	     start, start + size);
      return;
    }

  sprintf (buf, "%s %#lx,%#lx", add ? "memory-region" : "delete-memory", start, size);

  einfo (VERBOSE2, "Run sim command: %s", buf);
  sim_do_commandf (sd, buf);
}

/* Entry point for the AArch64 speculative load simulator.
   Scans CODE for gadgets.
   Code buffer is SIZE bytes long.
   ADDR is the starting address of the CODE in simulated memory.
   FILENAME is the name of the associated file, for use in messages.
   ENTRY is the starting address of the simulated application, which may or may not be inside ADDR..ADDR+SIZE.
   Returns TRUE if the scan went OK, even if nothing was found, and FALSE if something went wrong.  */
   
bool
aarch64_scan (bfd_byte *   code,
	      ulong        size,
	      ulong        start,
	      const char * filename ATTRIBUTE_UNUSED,
	      ulong        entry ATTRIBUTE_UNUSED)
{
  scan_state * ss;
  ulong end = start + size;

  /* If the user did not give us a start address then default to the beginning of the binary.  */
  if (start_address == 0 && start_address < start)
    start_address = start;

  if (start_address < start || start_address >= end)
    return TRUE;

  num_insns = size / 4;
  num_found = 0;

  einfo (VERBOSE, "Scan for speculative loads starting from %lx", start_address);

  if (! scan_init (start_address))
    return FALSE;

  ss = clone_state (start_address, NULL);
  
  run_scan (ss, start, end);

  if (num_found == 0)
    einfo (INFO, "No sequences found starting from %#lx", start_address);

  release_state (ss);

  return TRUE;
}

/* Printer function to catch messages from the common sim framework.  */

static void
aarch64_printf_filtered (host_callback * p ATTRIBUTE_UNUSED, const char * format, va_list args)
{
  static char buffer[256];

  vsnprintf (buffer, 256, format, args);
  if (BE_VERY_VERBOSE)
    einfo (PARTIAL, "%s", buffer);
}

static bool
aarch64_scan_init (bfd_byte * code, ulong size, ulong start, const char * filename, ulong entry, bool little)
{
  static char *  initialised_for = NULL;
  sim_cpu *      cpu;
  uint64_t       addr;
  ulong          end = start + size;

  if (start_address < start || start_address >= end)
    {
      einfo (VERBOSE, "Starting address (%lx) not in address range (%lx - %lx)",
	     start_address, start, end);
      return TRUE;
    }

  /* FIXME: We should include any data sections in our memory map.  */
  BEGIN = start;
  if (end < 0x8000000)
    END = 0x8000000;
  else
    END = end;

  einfo (VERBOSE, "Initialising scan of %s in the address range %#lx..%#lx", filename, start, end);

  if (initialised_for == NULL || ! streq (filename, initialised_for))
    {
      extern host_callback default_callback;

      char * argv[4];
      int dummy;

      argv[0] = "AArch64_scanner";
      if (trace_arg)
	{
	  argv[1] = (char *) trace_arg;
	  argv[2] = (char *) filename;
	  argv[3] = NULL;
	}
      else
	{
	  argv[1] = (char *) filename;
	  argv[2] = NULL;
	}

      if (sd)
	sim_close (sd, 0);

      default_callback.init (& default_callback);

      sd = sim_open (SIM_OPEN_STANDALONE, & default_callback, NULL, argv);
      if (sd == NULL)
	{
	  einfo (FAIL, "sim_open() could not load file");
	  return FALSE;
	}

      default_callback.target_endian = BFD_ENDIAN_LITTLE; /* Aarch64 insns are always little endian.  */
      default_callback.evprintf_filtered = aarch64_printf_filtered;

      /* Initialise the disassembler info structure.  */
      init_disassemble_info (& info, stdout, aarch64_printf);
      info.arch               = bfd_arch_aarch64;
      info.mach               = bfd_mach_aarch64;
      info.endian_code        = default_callback.target_endian;
      info.application_data   = & dummy;
      info.read_memory_func   = aarch64_read_mem;
      info.memory_error_func  = aarch64_mem_err;
      info.print_address_func = aarch64_addr;
      disassemble_init_for_target (& info);

      if (sim_create_inferior (sd, NULL, argv, NULL) != SIM_RC_OK)
	{
	  einfo (FAIL, "sim_create_inferior file %s", filename);
	  return FALSE;
	}

      STATE_PROG_BFD (sd) = NULL;
      CPU_TRACE_DATA (STATE_CPU (sd, 0))->dis_bfd = NULL;
      CPU_TRACE_DATA (STATE_CPU (sd, 0))->disassembler = print_insn_aarch64;
      CPU_TRACE_DATA (STATE_CPU (sd, 0))->dis_info = info;
      
      free (initialised_for);
      initialised_for = xstrdup (filename);
    }

  /* Make sure that memory is mapped.  */
  set_sim_memory (start, size, TRUE);
      
  cpu = STATE_CPU (sd, 0);

  einfo (VERBOSE2, "Loading code into simulated memory");
  suppress_checks = TRUE;
  /* Copy code into simulated memory.  */
  for (addr = start;
       addr < start + size;
       addr += 4, code += 4)
    aarch64_set_mem_u32 (cpu, addr, * (uint32_t *) code);
  suppress_checks = FALSE;
  einfo (VERBOSE2, "Code Loaded");


  return TRUE;
}

static bool
aarch64_options (const char * arg, const char ** argv, unsigned argc)
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

  if (const_strneq (arg, "--trace"))
    {
      /* Pass --trace options on to the simulator.  */
      trace_arg = arg;
      return TRUE;
    }

  if (const_strneq (arg, "--poison-reg="))
    {
      poison_reg = strtoul (arg + 13, NULL, 0);
      return TRUE;
    }

  return FALSE;
}

static void
aarch64_usage (void)
{
  einfo (INFO, "    --num-branches=<n>  [Set the maximum number of branches to follow]");
  einfo (INFO, "    --poison-reg=<n>    [Poison the contents of register <N>]");
  einfo (INFO, "    --start-address=<n> [Set the entry point of the scan]");
}

struct callbacks target = 
{
  EM_AARCH64,
  0,
  "AARCH64 Scanner",
  aarch64_scan_init,
  NULL,			/* aarch64_finish */
  aarch64_scan,
  NULL,			/* aarch64_final */
  aarch64_options,
  aarch64_usage
};
