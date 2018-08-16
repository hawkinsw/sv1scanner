/* Scanner - a tool for locating SPECTRE vulnerabilities in binaries.

   Copyright (c) 2016 - 2018 Red Hat.
   Version 1.1
   Created by Nick Clifton.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#include "scanner.h"

static char * version = "1.1";

/* Structure to hold information about an archive file.  */

struct archive_info
{
  char *  filename;               /* Archive file name.  */
  FILE *  file;                   /* Open file descriptor.  */
  ulong   index_num;              /* Number of symbols in table.  */
  ulong * index_array;            /* The array of member offsets.  */
  char *  sym_table;              /* The symbol table.  */
  ulong   sym_size;               /* Size of the symbol table.  */
  char *  longnames;              /* The long file names table.  */
  ulong   longnames_size;         /* Size of the long file names table.  */
  ulong   nested_member_origin;   /* Origin in the nested archive of the current member.  */
  ulong   next_arhdr_offset;      /* Offset of the next archive header.  */
  bool    is_thin_archive;        /* TRUE if this is a thin archive.  */
  bool    uses_64bit_indicies;    /* TRUE if the index table uses 64bit entries.  */
  arhdr   arhdr;                  /* Current archive header.  */
};

static ulong  archive_file_size;
static long   archive_file_offset;

static Elf_Internal_Ehdr    elf_header;
static Elf32_External_Ehdr  ehdr32;
static Elf64_External_Ehdr  ehdr64;
static ulong (*             byte_get) (const uchar *, uint);
static bool                 is_32bit;

#define BYTE_GET(field)	    byte_get (field, sizeof (field))

/* Maximum number of input files.  FIXME: Use a linked list instead.  */
#define MAX_NUM_FILES 256

#ifndef ARMAGT
#define ARMAGT "!<thin>\012"	/* For thin archives.  */
#endif

/* Variables set by command line options.  */
ulong                verbosity = 0;
static ulong         num_files = 0;
static const char *  files[MAX_NUM_FILES];
static bool          binary_blob = FALSE;

/* -------------------------------------------------------------------- */
/* Print a message on stdout or stderr.  Returns FALSE (for error
   messages) so that it can be used as a terminator in boolean functions.  */

bool
einfo (einfo_type type, const char * format, ...)
{
  FILE *        file;
  const char *  do_newline = "";
  const char *  prefix = NULL;
  va_list       args;
  bool          res = FALSE;

  switch (type)
    {
    case WARN:
    case SYS_WARN:
      prefix = "Warning";
      file   = stderr;
      break;
    case ERROR:
    case SYS_ERROR:
      prefix = "Error";
      file   = stderr;
      break;
    case FAIL:
      prefix = "Internal Failure";
      file   = stderr;
      break;
    case VERBOSE2:
    case VERBOSE:
      //prefix = "Verbose";
      file   = stdout;
      res    = TRUE;
      break;
    case INFO:
      //prefix = "Info";
      file   = stdout;
      res    = TRUE;
      break;
    case PARTIAL:
      // prefix = "";
      file   = stdout;
      res    = TRUE;
      break;
    default:
      fprintf (stderr, "ICE: Unknown einfo type %x\n", type);
      exit (-1);
    }
  
  if (verbosity == -1UL
      || (type == VERBOSE && verbosity < 1)
      || (type == VERBOSE2 && verbosity < 2))
    return res;

  fflush (stderr);
  fflush (stdout);
  if (target.scanner_name && type != PARTIAL)
    fprintf (file, "%s: ", target.scanner_name);

  if (format[strlen (format) - 1] != '\n')
    do_newline = ".\n";

  if (prefix)
    fprintf (file, "%s: ", prefix);

  va_start (args, format);
  vfprintf (file, format, args);
  va_end (args);

  if (type == SYS_WARN || type == SYS_ERROR)
    fprintf (file, ": system error: %s", strerror (errno));

  if (type != PARTIAL)
    fprintf (file, "%s", do_newline);
  return res;
}
  
/* -------------------------------------------------------------------- */

static void
add_file (const char * filename)
{
  if (num_files == MAX_NUM_FILES)
    return;

  files[num_files ++] = filename;
}

static void
print_version (void)
{
  einfo (INFO, "Version: %s", version);
}

static void
usage (void)
{
  einfo (INFO, "Useage: %s [options] <file(s)>", target.scanner_name);
  einfo (INFO, " options:");
  einfo (INFO, "          --binary      [Treat file(s) as binary blobs]");
  einfo (INFO, "          --help        [Display this message]");
  einfo (INFO, "          --quiet       [Do not print anything, just return a count of the number of problems found]");
  einfo (INFO, "          --verbose     [Produce informational messages whilst working.  Repeat for more information]");
  einfo (INFO, "          --version     [Report the verion of the tool]");

  if (target.usage)
    target.usage ();
}

/* Handle command line options.  Returns to caller if there is
   something to do.  */

static void
process_command_line (uint argc, const char * argv[])
{
  while (argc > 1)
    {
      const char * arg = argv[--argc];

      if (target.process_arg != NULL
	  && target.process_arg (arg, argv, argc))
	continue;

      if (arg[0] == '-')
        {
	  arg += (arg[1] == '-' ? 2 : 1);
	  switch (*arg)
	    {
	    case 'b':
	      binary_blob = TRUE;
	      break;

	    case 'h':
	      usage ();
	      exit (EXIT_SUCCESS);

	    case 'q':
	      verbosity = -1UL;
	      break;

	    case 'v':
	      if (const_strneq (arg, "version"))
		{
		  print_version ();
		  exit (EXIT_SUCCESS);
		}
	      else if (const_strneq (arg, "verbose")
		       /* Allow -v as an alias for --verbose.  */
		       || arg[1] == 0)
		{
		  verbosity ++;
		  break;
		}
	      /* else Fall through.  */

	    default:
	      einfo (WARN, "Unrecognised command line option: %s ", argv[argc]);
	      usage ();
	      exit (EXIT_FAILURE);
	    }
	}
      else
	add_file (arg);
    }

  if (num_files == 0)
    {
      einfo (WARN, "No input files specified");
      exit (EXIT_FAILURE);
    }
}

static ulong
byte_get_little_endian (const uchar * field, uint size)
{
  switch (size)
    {
    case 1:
      return *field;

    case 2:
      return  ((uint) (field[0]))
	|    (((uint) (field[1])) << 8);

    case 3:
      return  ((ulong) (field[0]))
	|    (((ulong) (field[1])) << 8)
	|    (((ulong) (field[2])) << 16);

    case 4:
      return  ((ulong) (field[0]))
	|    (((ulong) (field[1])) << 8)
	|    (((ulong) (field[2])) << 16)
	|    (((ulong) (field[3])) << 24);

    case 5:
      if (sizeof (ulong) == 8)
	return  ((ulong) (field[0]))
	  |    (((ulong) (field[1])) << 8)
	  |    (((ulong) (field[2])) << 16)
	  |    (((ulong) (field[3])) << 24)
	  |    (((ulong) (field[4])) << 32);
      else if (sizeof (ulong) == 4)
	/* We want to extract data from an 8 byte wide field and
	   place it into a 4 byte wide field.  Since this is a little
	   endian source we can just use the 4 byte extraction code.  */
	return  ((ulong) (field[0]))
	  |    (((ulong) (field[1])) << 8)
	  |    (((ulong) (field[2])) << 16)
	  |    (((ulong) (field[3])) << 24);

    case 6:
      if (sizeof (ulong) == 8)
	return  ((ulong) (field[0]))
	  |    (((ulong) (field[1])) << 8)
	  |    (((ulong) (field[2])) << 16)
	  |    (((ulong) (field[3])) << 24)
	  |    (((ulong) (field[4])) << 32)
	  |    (((ulong) (field[5])) << 40);
      else if (sizeof (ulong) == 4)
	/* We want to extract data from an 8 byte wide field and
	   place it into a 4 byte wide field.  Since this is a little
	   endian source we can just use the 4 byte extraction code.  */
	return  ((ulong) (field[0]))
	  |    (((ulong) (field[1])) << 8)
	  |    (((ulong) (field[2])) << 16)
	  |    (((ulong) (field[3])) << 24);

    case 7:
      if (sizeof (ulong) == 8)
	return  ((ulong) (field[0]))
	  |    (((ulong) (field[1])) << 8)
	  |    (((ulong) (field[2])) << 16)
	  |    (((ulong) (field[3])) << 24)
	  |    (((ulong) (field[4])) << 32)
	  |    (((ulong) (field[5])) << 40)
	  |    (((ulong) (field[6])) << 48);
      else if (sizeof (ulong) == 4)
	/* We want to extract data from an 8 byte wide field and
	   place it into a 4 byte wide field.  Since this is a little
	   endian source we can just use the 4 byte extraction code.  */
	return  ((ulong) (field[0]))
	  |    (((ulong) (field[1])) << 8)
	  |    (((ulong) (field[2])) << 16)
	  |    (((ulong) (field[3])) << 24);

    case 8:
      if (sizeof (ulong) == 8)
	return  ((ulong) (field[0]))
	  |    (((ulong) (field[1])) << 8)
	  |    (((ulong) (field[2])) << 16)
	  |    (((ulong) (field[3])) << 24)
	  |    (((ulong) (field[4])) << 32)
	  |    (((ulong) (field[5])) << 40)
	  |    (((ulong) (field[6])) << 48)
	  |    (((ulong) (field[7])) << 56);
      else if (sizeof (ulong) == 4)
	/* We want to extract data from an 8 byte wide field and
	   place it into a 4 byte wide field.  Since this is a little
	   endian source we can just use the 4 byte extraction code.  */
	return  ((ulong) (field[0]))
	  |    (((ulong) (field[1])) << 8)
	  |    (((ulong) (field[2])) << 16)
	  |    (((ulong) (field[3])) << 24);

    default:
      return einfo (FAIL, "Unhandled data length: %u", size);
    }
}

static ulong
byte_get_big_endian (const uchar * field, uint size)
{
  switch (size)
    {
    case 1:
      return *field;

    case 2:
      return ((uint) (field[1])) | (((int) (field[0])) << 8);

    case 3:
      return ((ulong) (field[2]))
	|   (((ulong) (field[1])) << 8)
	|   (((ulong) (field[0])) << 16);

    case 4:
      return ((ulong) (field[3]))
	|   (((ulong) (field[2])) << 8)
	|   (((ulong) (field[1])) << 16)
	|   (((ulong) (field[0])) << 24);

    case 5:
      if (sizeof (ulong) == 8)
	return ((ulong) (field[4]))
	  |   (((ulong) (field[3])) << 8)
	  |   (((ulong) (field[2])) << 16)
	  |   (((ulong) (field[1])) << 24)
	  |   (((ulong) (field[0])) << 32);
      else if (sizeof (ulong) == 4)
	{
	  /* Although we are extracting data from an 8 byte wide field,
	     we are returning only 4 bytes of data.  */
	  field += 1;
	  return ((ulong) (field[3]))
	    |   (((ulong) (field[2])) << 8)
	    |   (((ulong) (field[1])) << 16)
	    |   (((ulong) (field[0])) << 24);
	}

    case 6:
      if (sizeof (ulong) == 8)
	return ((ulong) (field[5]))
	  |   (((ulong) (field[4])) << 8)
	  |   (((ulong) (field[3])) << 16)
	  |   (((ulong) (field[2])) << 24)
	  |   (((ulong) (field[1])) << 32)
	  |   (((ulong) (field[0])) << 40);
      else if (sizeof (ulong) == 4)
	{
	  /* Although we are extracting data from an 8 byte wide field,
	     we are returning only 4 bytes of data.  */
	  field += 2;
	  return ((ulong) (field[3]))
	    |   (((ulong) (field[2])) << 8)
	    |   (((ulong) (field[1])) << 16)
	    |   (((ulong) (field[0])) << 24);
	}

    case 7:
      if (sizeof (ulong) == 8)
	return ((ulong) (field[6]))
	  |   (((ulong) (field[5])) << 8)
	  |   (((ulong) (field[4])) << 16)
	  |   (((ulong) (field[3])) << 24)
	  |   (((ulong) (field[2])) << 32)
	  |   (((ulong) (field[1])) << 40)
	  |   (((ulong) (field[0])) << 48);
      else if (sizeof (ulong) == 4)
	{
	  /* Although we are extracting data from an 8 byte wide field,
	     we are returning only 4 bytes of data.  */
	  field += 3;
	  return ((ulong) (field[3]))
	    |   (((ulong) (field[2])) << 8)
	    |   (((ulong) (field[1])) << 16)
	    |   (((ulong) (field[0])) << 24);
	}

    case 8:
      if (sizeof (ulong) == 8)
	return ((ulong) (field[7]))
	  |   (((ulong) (field[6])) << 8)
	  |   (((ulong) (field[5])) << 16)
	  |   (((ulong) (field[4])) << 24)
	  |   (((ulong) (field[3])) << 32)
	  |   (((ulong) (field[2])) << 40)
	  |   (((ulong) (field[1])) << 48)
	  |   (((ulong) (field[0])) << 56);
      else if (sizeof (ulong) == 4)
	{
	  /* Although we are extracting data from an 8 byte wide field,
	     we are returning only 4 bytes of data.  */
	  field += 4;
	  return ((ulong) (field[3]))
	    |   (((ulong) (field[2])) << 8)
	    |   (((ulong) (field[1])) << 16)
	    |   (((ulong) (field[0])) << 24);
	}

    default:
      return einfo (FAIL, "Unhandled data length: %u", size);
    }
}

static bool
get_file_header (FILE * file, const char * filename)
{
  /* Read in the identity array.  */
  if (fread (elf_header.e_ident, EI_NIDENT, 1, file) != 1)
    return FALSE;

  /* Determine how to read the rest of the header.  */
  switch (elf_header.e_ident[EI_DATA])
    {
    default:
    case ELFDATANONE:
    case ELFDATA2LSB:
      byte_get = byte_get_little_endian;
      break;
    case ELFDATA2MSB:
      byte_get = byte_get_big_endian;
      break;
    }

  /* Read in the rest of the header.
     We only support 32 bit and 64 bit ELF files.  */
  switch (elf_header.e_ident[EI_CLASS])
    {
    default:
      einfo (VERBOSE2, "%s: Unsupported EI_CLASS: %d", filename, elf_header.e_ident[EI_CLASS]);
      return FALSE;

    case ELFCLASS32:
      if (fread (ehdr32.e_type, sizeof (ehdr32) - EI_NIDENT, 1, file) != 1)
	return FALSE;

      elf_header.e_type      = BYTE_GET (ehdr32.e_type);
      elf_header.e_machine   = BYTE_GET (ehdr32.e_machine);
      elf_header.e_version   = BYTE_GET (ehdr32.e_version);
      elf_header.e_entry     = BYTE_GET (ehdr32.e_entry);
      elf_header.e_phoff     = BYTE_GET (ehdr32.e_phoff);
      elf_header.e_shoff     = BYTE_GET (ehdr32.e_shoff);
      elf_header.e_flags     = BYTE_GET (ehdr32.e_flags);
      elf_header.e_ehsize    = BYTE_GET (ehdr32.e_ehsize);
      elf_header.e_phentsize = BYTE_GET (ehdr32.e_phentsize);
      elf_header.e_phnum     = BYTE_GET (ehdr32.e_phnum);
      elf_header.e_shentsize = BYTE_GET (ehdr32.e_shentsize);
      elf_header.e_shnum     = BYTE_GET (ehdr32.e_shnum);
      elf_header.e_shstrndx  = BYTE_GET (ehdr32.e_shstrndx);

      memcpy (&ehdr32, &elf_header, EI_NIDENT);
      is_32bit = TRUE;
      break;

    case ELFCLASS64:
      /* If we have been compiled with sizeof (bfd_vma) == 4, then
	 we will not be able to cope with the 64bit data found in
	 64 ELF files.  Detect this now and abort before we start
	 overwriting things.  */
      if (sizeof (bfd_vma) < 8)
	return einfo (ERROR, "This executable has been built without support for a\n\
64 bit data type and so it cannot process 64 bit ELF files");

      if (fread (ehdr64.e_type, sizeof (ehdr64) - EI_NIDENT, 1, file) != 1)
	return FALSE;

      elf_header.e_type      = BYTE_GET (ehdr64.e_type);
      elf_header.e_machine   = BYTE_GET (ehdr64.e_machine);
      elf_header.e_version   = BYTE_GET (ehdr64.e_version);
      elf_header.e_entry     = BYTE_GET (ehdr64.e_entry);
      elf_header.e_phoff     = BYTE_GET (ehdr64.e_phoff);
      elf_header.e_shoff     = BYTE_GET (ehdr64.e_shoff);
      elf_header.e_flags     = BYTE_GET (ehdr64.e_flags);
      elf_header.e_ehsize    = BYTE_GET (ehdr64.e_ehsize);
      elf_header.e_phentsize = BYTE_GET (ehdr64.e_phentsize);
      elf_header.e_phnum     = BYTE_GET (ehdr64.e_phnum);
      elf_header.e_shentsize = BYTE_GET (ehdr64.e_shentsize);
      elf_header.e_shnum     = BYTE_GET (ehdr64.e_shnum);
      elf_header.e_shstrndx  = BYTE_GET (ehdr64.e_shstrndx);

      memcpy (&ehdr64, &elf_header, EI_NIDENT);
      is_32bit = FALSE;
      break;
    }

  return TRUE;
}

/* Retrieve NMEMB structures, each SIZE bytes long from FILE starting at OFFSET.
   Put the retrieved data into VAR, if it is not NULL.  Otherwise allocate a buffer
   using malloc and fill that.  In either case return the pointer to the start of
   the retrieved data or NULL if something went wrong.  If something does go wrong
   and REASON is not NULL then emit an error message using REASON as part of the
   context.  */

static void *
get_data (void * var,
	  FILE * file,
	  ulong  offset,
	  ulong  size,
	  ulong  nmemb,
	  const char * reason)
{
  void * mvar;
  ulong  amt = size * nmemb;

  if (amt == 0)
    return NULL;

  /* Check for size overflow.  */
  if (amt < nmemb)
    {
      if (reason)
	einfo (ERROR, "Size overflow prevents reading %#lx elements of size %#lx for %s",
	       nmemb, size, reason);
      return NULL;
    }

  if (fseek (file, offset, SEEK_SET))
    {
      if (reason)
	einfo (SYS_ERROR, "Unable to seek to 0x%lx for %s", offset, reason);
      return NULL;
    }

  if (var == NULL)
    {
      mvar = xmalloc (amt + 1);
      ((char *) mvar)[amt] = '\0';
    }
  else
    mvar = var;

  if (fread (mvar, (size_t) size, (size_t) nmemb, file) != nmemb)
    {
      if (reason)
	einfo (SYS_ERROR, "Unable to read in %#lx bytes of %s", amt, reason);
      if (mvar != var)
	free (mvar);
      return NULL;
    }

  return mvar;
}

static bool
process_blob (const char * filename, FILE * file, off_t len)
{
  bfd_byte *  contents;
  
  if (fseek (file, 0, SEEK_SET) != 0)
    {
      einfo (SYS_ERROR, "%s: Failed to seek to the start", filename);
      return FALSE;
    }
  
  contents = XCNEWVEC (bfd_byte, len);
  if (fread (contents, len, 1, file) != 1)
    {
      einfo (SYS_ERROR, "%s: Failed to read in contents", filename);
      XDELETEVEC (contents);
      return FALSE;
    }

  einfo (VERBOSE, "Processing contents of %s", filename);
  if (target.init (contents, len, 0, filename, 0, TRUE))
    {
      (void) target.scanner (contents, len, 0, filename, 0);
    }

  if (target.finish)
    target.finish ();

  XDELETEVEC (contents);

  if (target.final_report)
    target.final_report ();

  return TRUE;
}


#define GET_PROGRAM_HEADERS_FUNC(NAME, ETYPE)				\
/* Read in the program headers from FILE starting at OFFSET.		\
   Returns a pointer to the allocated memory containing the		\
   headers or NULL if there was a problem.  */				\
									\
static Elf_Internal_Phdr *						\
 NAME (FILE * file, ulong offset)					\
{									\
  const ETYPE          phdrs;						\
  const ETYPE          external;					\
  Elf_Internal_Phdr *  headers;						\
  Elf_Internal_Phdr *  internal;					\
  const uint           size = elf_header.e_phentsize;			\
  const uint           num  = elf_header.e_phnum;			\
  uint                 i;						\
									\
  if (size == 0 || num == 0)						\
    return NULL;							\
  if (size < sizeof * phdrs)						\
    {									\
      einfo (ERROR, "The e_phentsize field in the ELF header is less than the size of an ELF program header");	\
      return NULL;							\
    }									\
  if (size > sizeof * phdrs)						\
    einfo (WARN, "The e_phentsize field in the ELF header is larger than the size of an ELF program header"); \
									\
  phdrs = (ETYPE) get_data (NULL, file, offset + elf_header.e_phoff,	\
			    size, num, #NAME);				\
  if (phdrs == NULL)							\
    return NULL;							\
									\
  headers = XCNEWVEC (Elf_Internal_Phdr, num);				\
									\
  for (i = 0, internal = headers, external = phdrs;			\
       i < num;								\
       i++, internal++, external++)					\
    {									\
      internal->p_type   = BYTE_GET (external->p_type);			\
      internal->p_offset = BYTE_GET (external->p_offset);		\
      internal->p_vaddr  = BYTE_GET (external->p_vaddr);		\
      internal->p_paddr  = BYTE_GET (external->p_paddr);		\
      internal->p_filesz = BYTE_GET (external->p_filesz);		\
      internal->p_memsz  = BYTE_GET (external->p_memsz);		\
      internal->p_flags  = BYTE_GET (external->p_flags);		\
      internal->p_align  = BYTE_GET (external->p_align);		\
    }									\
									\
  XDELETEVEC (phdrs);							\
  return headers;							\
}

GET_PROGRAM_HEADERS_FUNC (get_32bit_program_headers, Elf32_External_Phdr *)
GET_PROGRAM_HEADERS_FUNC (get_64bit_program_headers, Elf64_External_Phdr *)

#define GET_SECTION_HEADER_FUNC(NAME, ETYPE)				\
/* Allocate memory and load the sections headers from FILE at OFFSET.	\
   Returns a pointer to the allocated memory or NULL upon failure.  */	\
									\
static Elf_Internal_Shdr *						\
 NAME (FILE * file, ulong offset)					\
{									\
  const ETYPE          shdrs;						\
  Elf_Internal_Shdr *  headers;						\
  Elf_Internal_Shdr *  internal;					\
  const uint           size = elf_header.e_shentsize;			\
  const uint           num  = elf_header.e_shnum;			\
  uint                 i;						\
									\
  if (size == 0 || num == 0)						\
    return NULL;							\
  if (size < sizeof * shdrs)						\
    {									\
      einfo (ERROR, "The e_shentsize field in the ELF header is less than the size of an ELF section header");	\
      return NULL;							\
    }									\
  if (size > sizeof * shdrs)						\
    einfo (WARN, "The e_shentsize field in the ELF header is larger than the size of an ELF section header"); \
									\
  shdrs = (ETYPE) get_data (NULL, file, offset + elf_header.e_shoff,	\
			    size, num, #NAME);				\
  if (shdrs == NULL)							\
    return NULL;							\
									\
  headers = XCNEWVEC (Elf_Internal_Shdr, num);				\
									\
  for (i = 0, internal = headers;					\
       i < num;								\
       i++, internal++)							\
    {									\
      internal->sh_name      = BYTE_GET (shdrs[i].sh_name);		\
      internal->sh_type      = BYTE_GET (shdrs[i].sh_type);		\
      internal->sh_flags     = BYTE_GET (shdrs[i].sh_flags);		\
      internal->sh_addr      = BYTE_GET (shdrs[i].sh_addr);		\
      internal->sh_offset    = BYTE_GET (shdrs[i].sh_offset);		\
      internal->sh_size      = BYTE_GET (shdrs[i].sh_size);		\
      internal->sh_link      = BYTE_GET (shdrs[i].sh_link);		\
      internal->sh_info      = BYTE_GET (shdrs[i].sh_info);		\
      internal->sh_addralign = BYTE_GET (shdrs[i].sh_addralign);	\
      internal->sh_entsize   = BYTE_GET (shdrs[i].sh_entsize);		\
      if (internal->sh_link > num)					\
	einfo (WARN, "Section %u has an out of range sh_link value of %u", i, internal->sh_link); \
      if ((internal->sh_flags & SHF_INFO_LINK) && internal->sh_info > num) \
	einfo (WARN, "Section %u has an out of range sh_info value of %u", i, internal->sh_info); \
    }									\
									\
  XDELETEVEC (shdrs);							\
  return headers;							\
}

GET_SECTION_HEADER_FUNC (get_32bit_section_headers, Elf32_External_Shdr *)
GET_SECTION_HEADER_FUNC (get_64bit_section_headers, Elf64_External_Shdr *)


static bool
process_object (const char * filename, FILE * file, bool user_specified_file)
{
  uint i;
  /* Rememeber where we are.  */
  ulong offset = ftell (file);
  /* For archives we only report problems if we are in verbose mode.
     For user specified files, we report problems as errors.  */
  einfo_type problem_type = user_specified_file ? ERROR : VERBOSE;

  if (! get_file_header (file, filename))
    return einfo (problem_type, "%s: Not an ELF format file", filename);

  /* Make sure that the scanner matches the file type.  */
  if (elf_header.e_machine != target.em_type
      && elf_header.e_machine != target.em_type2)
    return einfo (problem_type, "%s: Unsupported ELF machine type %d", filename, elf_header.e_machine);

  /* FIXME: If the file contains relocation sections (.rel, .rela) then
     we may need to process these first...  */

  /* If there is a section header then use that.  Program headers (aka
     segments) can include a lot of padding that is uninteresting.  */
  if (elf_header.e_shoff)
    {
      Elf_Internal_Shdr * headers;
      bool found = FALSE;
      bool ret = TRUE;

      /* Go to the section headers.  */
      if (fseek (file, offset + elf_header.e_shoff, SEEK_SET) != 0)
	return einfo (SYS_ERROR, "%s: Failed to seek to section headers", filename);

      if (is_32bit)
	headers = get_32bit_section_headers (file, offset);
      else
	headers = get_64bit_section_headers (file, offset);

      if (headers == NULL)
	return FALSE;

      for (i = 0; i < elf_header.e_shnum; i++)
	{
	  if (headers[i].sh_type == SHT_PROGBITS
	      && headers[i].sh_flags & SHF_EXECINSTR
	      && headers[i].sh_size > 0)
	    {
	      bfd_byte *  section;
	      ulong       len = headers[i].sh_size;

	      if (fseek (file, offset + headers[i].sh_offset, SEEK_SET) != 0)
		{
		  einfo (SYS_ERROR, "%s: Failed to seek to the start of section %d", filename, i);
		  continue;
		}

	      section = XCNEWVEC (bfd_byte, len);
	      if (fread (section, len, 1, file) != 1)
		{
		  einfo (SYS_ERROR, "%s: Failed to read in section %d", filename, i);
		  XDELETEVEC (section);
		  continue;
		}

	      einfo (VERBOSE, "Processing section %d of %s", i, filename);

	      if (! target.init (section, headers[i].sh_size, headers[i].sh_addr, filename, elf_header.e_entry,
				 byte_get == byte_get_little_endian))
		{
		  ret = FALSE;
		}
	      else
		{
		  ret &= target.scanner (section, headers[i].sh_size, headers[i].sh_addr, filename, elf_header.e_entry);
		}

	      if (target.finish)
		target.finish ();

	      XDELETEVEC (section);
	      found = TRUE;
	    }
	}

      einfo (VERBOSE2, "Tidy up");

      if (target.final_report)
	target.final_report ();

      free (headers);
      if (found)
	return ret;

      return einfo (problem_type, "%s: No executable sections found", filename);
    }

  /* If there are no section headers, try the program headers instead.  */
  if (elf_header.e_phoff)
    {
      Elf_Internal_Phdr *  headers;
      bool found = FALSE;
      bool ret = TRUE;

      /* Go to the program headers.  */
      if (fseek (file, offset + elf_header.e_phoff, SEEK_SET) != 0)
	return einfo (SYS_ERROR, "%s: Failed to seek to program headers", filename);

      if (is_32bit)
	headers = get_32bit_program_headers (file, offset);
      else
	headers = get_64bit_program_headers (file, offset);

      if (headers == NULL)
	return FALSE;

      for (i = 0; i < elf_header.e_phnum; i++)
	{
	  if (headers[i].p_type == PT_LOAD
	      && headers[i].p_flags & PF_X
	      && headers[i].p_memsz > 0
	      && headers[i].p_memsz >= headers[i].p_filesz)
	    {
	      bfd_byte * segment;

	      if (fseek (file, offset + headers[i].p_offset, SEEK_SET) != 0)
		{
		  einfo (SYS_ERROR, "%s: Failed to seek to the start of segment %d", filename, i);
		  continue;
		}

	      segment = XCNEWVEC (bfd_byte, headers[i].p_memsz);
	      if (fread (segment, headers[i].p_filesz, 1, file) != 1)
		{
		  einfo (SYS_ERROR, "%s: Failed to read in segment %d", filename, i);
		  XDELETEVEC (segment);
		  continue;
		}

	      einfo (VERBOSE, "Processing segment %d of %s", i, filename);

	      if (! target.init (segment, headers[i].p_memsz, headers[i].p_vaddr, filename, elf_header.e_entry,
				 byte_get == byte_get_little_endian))
		ret = FALSE;
	      else
		{
		  ret &= target.scanner (segment, headers[i].p_memsz, headers[i].p_vaddr, filename, elf_header.e_entry);
		}

	      if (target.finish)
		target.finish ();

	      XDELETEVEC (segment);
	      found = TRUE;
	    }
	}

      if (target.final_report)
	target.final_report ();

      free (headers);
      if (found)
	return ret;

      return einfo (problem_type, "%s: No executable program headers found", filename);
    }

  return einfo (problem_type, "%s: No section or program headers found", filename);
}

/* Processes the archive index table and symbol table in ARCH.
   Entries in the index table are SIZEOF_AR_INDEX bytes long.
   Fills in ARCH->next_arhdr_offset and ARCH->arhdr.
   It is the caller's responsibility to free ARCH->index_array and
    ARCH->sym_table.
   Returns TRUE upon success, FALSE otherwise.
   If failure occurs an error message is printed.  */

static bool
process_archive_index_and_symbols (struct archive_info *  arch,
				   uint                   sizeof_ar_index)
{
  size_t  got;
  ulong   size;

  size = strtoul (arch->arhdr.ar_size, NULL, 10);
  if ((signed long) size < 0)
    return einfo (ERROR, "%s: Invalid archive header size: %ld", arch->filename, size);

  size = size + (size & 1);

  arch->next_arhdr_offset += sizeof arch->arhdr + size;

  if (fseek (arch->file, size, SEEK_CUR) != 0)
    return einfo (SYS_ERROR, "%s: Failed to skip archive symbol table", arch->filename);

  /* Read the next archive header.  */
  got = fread (&arch->arhdr, 1, sizeof arch->arhdr, arch->file);
  if (got != sizeof arch->arhdr && got != 0)
    return einfo (SYS_ERROR, "%s: Failed to read archive header following archive index", arch->filename);

  return TRUE;
}

/* Read the symbol table and long-name table from an archive.  */

static bool
setup_archive (struct archive_info * arch,
	       const char *          filename,
	       FILE *                file,
	       bool                  is_thin_archive)
{
  size_t got;

  arch->filename = strdup (filename);
  arch->file = file;
  arch->index_num = 0;
  arch->index_array = NULL;
  arch->sym_table = NULL;
  arch->sym_size = 0;
  arch->longnames = NULL;
  arch->longnames_size = 0;
  arch->nested_member_origin = 0;
  arch->is_thin_archive = is_thin_archive;
  arch->uses_64bit_indicies = FALSE;
  arch->next_arhdr_offset = SARMAG;

  /* Read the first archive member header.  */
  if (fseek (file, SARMAG, SEEK_SET) != 0)
    return einfo (SYS_WARN, "%s: Failed to seek to first archive header", filename);

  got = fread (&arch->arhdr, 1, sizeof arch->arhdr, file);
  if (got != sizeof arch->arhdr)
    {
      if (got == 0)
	return TRUE;

      return einfo (SYS_ERROR, "%s: Failed to read archive header", filename);
    }

  /* See if this is the archive symbol table.  */
  if (const_strneq (arch->arhdr.ar_name, "/               "))
    {
      if (! process_archive_index_and_symbols (arch, 4))
	return FALSE;
    }
  else if (const_strneq (arch->arhdr.ar_name, "/SYM64/         "))
    {
      arch->uses_64bit_indicies = TRUE;
      if (! process_archive_index_and_symbols (arch, 8))
	return FALSE;
    }

  if (const_strneq (arch->arhdr.ar_name, "//              "))
    {
      /* This is the archive string table holding long member names.  */
      arch->longnames_size = strtoul (arch->arhdr.ar_size, NULL, 10);
      if (arch->longnames_size < 8)
	return einfo (ERROR, "%s: Long name table is too small, (size = %ld)",
		      filename, arch->longnames_size);

      if ((signed long) arch->longnames_size < 0)
	return einfo (ERROR, "%s: Long name table is too big, (size = 0x%lx)",
		      filename, arch->longnames_size);

      arch->next_arhdr_offset += sizeof arch->arhdr + arch->longnames_size;

      /* Plus one to allow for a string terminator.  */
      arch->longnames = XNEWVAR (char, arch->longnames_size + 1);

      if (fread (arch->longnames, arch->longnames_size, 1, file) != 1)
	{
	  XDELETE (arch->longnames);
	  arch->longnames = NULL;
	  return einfo (SYS_ERROR, "%s: Failed to read long symbol name string table", filename);
	}

      if ((arch->longnames_size & 1) != 0)
	getc (file);

      arch->longnames[arch->longnames_size] = 0;
    }

  return TRUE;
}

/* Construct a string showing the name of the archive member, qualified
   with the name of the containing archive file.  For thin archives, we
   use square brackets to denote the indirection.  For nested archives,
   we show the qualified name of the external member inside the square
   brackets (e.g., "thin.a[normal.a(foo.o)]").  */

static char *
make_qualified_name (struct archive_info * arch,
		     struct archive_info * nested_arch,
		     const char *          member_name)
{
  const char * error_name = "<corrupt>";
  size_t len;
  char * name;

  len = strlen (arch->filename) + strlen (member_name) + 3;
  if (arch->is_thin_archive
      && arch->nested_member_origin != 0)
    {
      if (nested_arch->filename)
	len += strlen (nested_arch->filename) + 2;
      else
	len += strlen (error_name) + 2;
    }

  name = XNEWVAR (char, len);

  if (arch->is_thin_archive
      && arch->nested_member_origin != 0)
    {
      if (nested_arch->filename)
	snprintf (name, len, "%s[%s(%s)]", arch->filename,
		  nested_arch->filename, member_name);
      else
	snprintf (name, len, "%s[%s(%s)]", arch->filename,
		  error_name, member_name);
    }
  else if (arch->is_thin_archive)
    snprintf (name, len, "%s[%s]", arch->filename, member_name);
  else
    snprintf (name, len, "%s(%s)", arch->filename, member_name);

  return name;
}

/* Return the path name for a proxy entry in a thin archive, adjusted
   relative to the path name of the thin archive itself if necessary.
   Returns a pointer to allocated memory or NULL upon failure.  */

static char *
adjust_relative_path (const char *  filename,
		      const char *  name,
		      ulong         name_len)
{
  char *        member_filename;
  const char *  base_name = lbasename (filename);
  size_t        amt;

  /* This is a proxy entry for a thin archive member.
     If the extended name table contains an absolute path
     name, or if the archive is in the current directory,
     use the path name as given.  Otherwise, we need to
     find the member relative to the directory where the
     archive is located.  */
  if (IS_ABSOLUTE_PATH (name) || base_name == filename)
    {
      amt = name_len + 1;
      if (amt == 0)
	return NULL;
      member_filename = XNEWVAR (char, amt);
      memcpy (member_filename, name, name_len);
      member_filename[name_len] = '\0';
    }
  else
    {
      /* Concatenate the path components of the archive file name
         to the relative path name from the extended name table.  */
      size_t prefix_len = base_name - filename;

      amt = prefix_len + name_len + 1;
      /* Catch wraparound.  */
      if (amt < prefix_len || amt < name_len)
	{
	  einfo (ERROR, "Abnormal length of thin archive member name: %lx", name_len);
	  return NULL;
	}

      member_filename = XNEWVAR (char, amt);
      memcpy (member_filename, filename, prefix_len);
      memcpy (member_filename + prefix_len, name, name_len);
      member_filename[prefix_len + name_len] = '\0';
    }

  return member_filename;
}

/* Release the memory used for the archive information.  */

static void
release_archive (struct archive_info * arch)
{
  if (arch->filename != NULL)
    free (arch->filename);
  if (arch->index_array != NULL)
    free (arch->index_array);
  if (arch->sym_table != NULL)
    free (arch->sym_table);
  if (arch->longnames != NULL)
    free (arch->longnames);
}

/* Open and setup a nested archive, if not already open.  */

static bool
setup_nested_archive (struct archive_info *  nested_arch,
		      const char *           member_filename)
{
  FILE * member_file;

  /* Have we already setup this archive?  */
  if (nested_arch->filename != NULL
      && streq (nested_arch->filename, member_filename))
    return TRUE;

  /* Close previous file and discard cached information.  */
  if (nested_arch->file != NULL)
    fclose (nested_arch->file);
  release_archive (nested_arch);

  member_file = fopen (member_filename, "rb");
  if (member_file == NULL)
    return FALSE;

  return setup_archive (nested_arch, member_filename, member_file, FALSE);
}

static char * get_archive_member_name (struct archive_info *, struct archive_info *);

/* Get the name of an archive member at a given OFFSET within an archive
   ARCH.  */

static char *
get_archive_member_name_at (struct archive_info * arch,
                            ulong                 offset,
			    struct archive_info * nested_arch)
{
  size_t got;

  if (fseek (arch->file, offset, SEEK_SET) != 0)
    {
      einfo (SYS_ERROR, "%s: Failed to seek to next file name", arch->filename);
      return NULL;
    }
  got = fread (&arch->arhdr, 1, sizeof arch->arhdr, arch->file);
  if (got != sizeof arch->arhdr)
    {
      einfo (SYS_ERROR, "%s: Failed to read archive header", arch->filename);
      return NULL;
    }
  if (memcmp (arch->arhdr.ar_fmag, ARFMAG, 2) != 0)
    {
      einfo (ERROR, "%s: Did not find a valid archive header", arch->filename);
      return NULL;
    }

  return get_archive_member_name (arch, nested_arch);
}

/* Get the name of an archive member from the current archive header.
   For simple names, this will modify the ar_name field of the current
   archive header.  For long names, it will return a pointer to the
   longnames table.  For nested archives, it will open the nested archive
   and get the name recursively.  NESTED_ARCH is a single-entry cache so
   we don't keep rereading the same information from a nested archive.  */

static char *
get_archive_member_name (struct archive_info *  arch,
                         struct archive_info *  nested_arch)
{
  ulong j, k;

  if (arch->arhdr.ar_name[0] == '/')
    {
      /* We have a long name.  */
      char * endp;
      char * member_filename;
      char * member_name;

      if (arch->longnames == NULL || arch->longnames_size == 0)
	{
	  einfo (ERROR, "Archive member uses long names, but no longname table found");
	  return NULL;
	}

      arch->nested_member_origin = 0;
      k = j = strtoul (arch->arhdr.ar_name + 1, &endp, 10);
      if (arch->is_thin_archive && endp != NULL && * endp == ':')
        arch->nested_member_origin = strtoul (endp + 1, NULL, 10);

      if (j > arch->longnames_size)
	{
	  einfo (ERROR, "Found long name index (%ld) beyond end of long name table", j);
	  return NULL;
	}

      while ((j < arch->longnames_size)
             && (arch->longnames[j] != '\n')
             && (arch->longnames[j] != '\0'))
        j++;
      if (j > 0 && arch->longnames[j-1] == '/')
        j--;
      if (j > arch->longnames_size)
	j = arch->longnames_size;
      arch->longnames[j] = '\0';

      if (!arch->is_thin_archive || arch->nested_member_origin == 0)
        return arch->longnames + k;

      if (k >= j)
	{
	  einfo (ERROR, "Invalid Thin archive member name");
	  return NULL;
	}

      /* This is a proxy for a member of a nested archive.
         Find the name of the member in that archive.  */
      member_filename = adjust_relative_path (arch->filename,
					       arch->longnames + k, j - k);
      if (member_filename != NULL
          && setup_nested_archive (nested_arch, member_filename) == 0)
	{
          member_name = get_archive_member_name_at (nested_arch,
						    arch->nested_member_origin,
						    NULL);
	  if (member_name != NULL)
	    {
	      free (member_filename);
	      return member_name;
	    }
	}
      free (member_filename);

      /* Last resort: just return the name of the nested archive.  */
      return arch->longnames + k;
    }

  /* We have a normal (short) name.  */
  for (j = 0; j < sizeof (arch->arhdr.ar_name); j++)
    if (arch->arhdr.ar_name[j] == '/')
      {
	arch->arhdr.ar_name[j] = '\0';
	return arch->arhdr.ar_name;
      }

  /* The full ar_name field is used.  Don't rely on ar_date starting
     with a zero byte.  */
  {
    char * name = XNEWVAR (char, sizeof (arch->arhdr.ar_name) + 1);

    memcpy (name, arch->arhdr.ar_name, sizeof (arch->arhdr.ar_name));
    name[sizeof (arch->arhdr.ar_name)] = '\0';
    return name;
  }
}

static bool
process_archive (const char * filename, FILE * file, bool is_thin)
{
  struct archive_info arch;
  struct archive_info nested_arch;
  size_t got;
  bool ret = TRUE;

  /* The ARCH structure is used to hold information about this archive.  */
  arch.filename = NULL;
  arch.file = NULL;
  arch.index_array = NULL;
  arch.sym_table = NULL;
  arch.longnames = NULL;

  /* The NESTED_ARCH structure is used as a single-item cache of information
     about a nested archive (when members of a thin archive reside within
     another regular archive file).  */
  nested_arch.filename = NULL;
  nested_arch.file = NULL;
  nested_arch.index_array = NULL;
  nested_arch.sym_table = NULL;
  nested_arch.longnames = NULL;

  if (! setup_archive (&arch, filename, file, is_thin))
    {
      ret = FALSE;
      goto out;
    }

  while (1)
    {
      char * name;
      size_t namelen;
      char * qualified_name;

      /* Read the next archive header.  */
      if (fseek (file, arch.next_arhdr_offset, SEEK_SET) != 0)
	return einfo (SYS_ERROR, "%s: Failed to seek to next archive header", filename);

      got = fread (&arch.arhdr, 1, sizeof arch.arhdr, file);
      if (got != sizeof arch.arhdr)
        {
          if (got == 0)
	    break;
          ret = einfo (SYS_ERROR, "%s: Failed to read archive header", filename);
          break;
        }

      if (memcmp (arch.arhdr.ar_fmag, ARFMAG, 2) != 0)
        {
          ret = einfo (ERROR, "%s: Did not find a valid archive header", arch.filename);
          break;
        }

      arch.next_arhdr_offset += sizeof arch.arhdr;

      archive_file_size = strtoul (arch.arhdr.ar_size, NULL, 10);
      if (archive_file_size & 01)
        ++archive_file_size;

      name = get_archive_member_name (&arch, &nested_arch);
      if (name == NULL)
	{
	  ret = einfo (ERROR, "%s: Bad archive file name", filename);
	  break;
	}
      namelen = strlen (name);

      qualified_name = make_qualified_name (&arch, &nested_arch, name);
      if (qualified_name == NULL)
	{
	  ret = einfo (ERROR, "%s: Bad archive file name", filename);
	  break;
	}

      if (is_thin && arch.nested_member_origin == 0)
        {
          /* This is a proxy for an external member of a thin archive.  */
          FILE * member_file;
          char * member_filename = adjust_relative_path (filename,
							 name, namelen);
          if (member_filename == NULL)
            {
              ret = FALSE;
              break;
            }

          member_file = fopen (member_filename, "rb");
          if (member_file == NULL)
            {
              ret = einfo (SYS_ERROR, "Input file '%s' is not readable", member_filename);
              free (member_filename);
              break;
            }

          archive_file_offset = arch.nested_member_origin;

          ret &= process_object (qualified_name, member_file, FALSE);

          fclose (member_file);
          free (member_filename);
        }
      else if (is_thin)
        {
          /* This is a proxy for a member of a nested archive.  */
          archive_file_offset = arch.nested_member_origin + sizeof arch.arhdr;

          /* The nested archive file will have been opened and setup by
             get_archive_member_name.  */
          if (fseek (nested_arch.file, archive_file_offset, SEEK_SET) != 0)
            {
              ret = einfo (SYS_ERROR, "%s: Failed to seek to archive member", nested_arch.filename);
              break;
            }

          ret &= process_object (qualified_name, nested_arch.file, FALSE);
        }
      else
        {
          archive_file_offset = arch.next_arhdr_offset;
          arch.next_arhdr_offset += archive_file_size;

          ret &= process_object (qualified_name, file, FALSE);
        }

      free (qualified_name);
    }

 out:
  if (nested_arch.file != NULL)
    fclose (nested_arch.file);
  release_archive (& nested_arch);
  release_archive (& arch);

  return ret;
}

static bool
process_file (const char * filename)
{
  struct stat  statbuf;
  FILE *       file = NULL;
  char         armag[SARMAG];
  bool         ret = FALSE;

  if (stat (filename, &statbuf) < 0)
    {
      if (errno == ENOENT)
	return einfo (WARN, "'%s': No such file", filename);
      else
	return einfo (SYS_WARN, "Could not locate '%s'", filename);
    }

  if (! S_ISREG (statbuf.st_mode))
    return einfo (WARN, "'%s' is not an ordinary file", filename);

  if (statbuf.st_size < 0)
    return einfo (WARN, "'%s' has negative size, probably it is too large", filename);

  if (S_ISDIR (statbuf.st_mode))
    {
      /* FIXME: recurse  */
      return einfo (WARN, "%s is a directory - ignoring", filename);
    }

  if ((file = fopen (filename, "rb")) == NULL)
    return einfo (WARN, "Input file '%s' is not readable", filename);

  if (fread (armag, SARMAG, 1, file) != 1)
    ret = einfo (SYS_WARN, "%s: Failed to read file's magic number", filename);
  else if (binary_blob)
    ret = process_blob (filename, file, statbuf.st_size);
  else if (memcmp (armag, ARMAG, SARMAG) == 0)
    ret = process_archive (filename, file, FALSE);
  else if (memcmp (armag, ARMAGT, SARMAG) == 0)
    ret = process_archive (filename, file, TRUE);
  else
    {
      rewind (file);
      ret = process_object (filename, file, TRUE);
    }

  if (file)
    fclose (file);
  return ret;
}

static bool
process_files (void)
{
  bool result = TRUE;

  while (num_files)
    {
      bool res;

      res = process_file (files [-- num_files]);

      result &= res;
    }
  return result;
}

int
main (int argc, const char * argv[])
{
  // mcheck (NULL);
  
  if (target.init == NULL || target.scanner == NULL)
    {
      einfo (FAIL, "Target init function/scanner not defined.");
      exit (EXIT_FAILURE);
    }

  process_command_line (argc, argv);

  if (!process_files ())
    return EXIT_FAILURE;

  return EXIT_SUCCESS;
}
