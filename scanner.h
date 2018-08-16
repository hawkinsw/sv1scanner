/* Scanner - a tool for locating SPECTRE vulnerabilities in binaries.

   Copyright (c) 2016 - 2018 Red Hat.

  This is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  It is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.  */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#define PACKAGE "scanner"

/* These header files are found in the binutils sources.  */
#include <ar.h>
#include <libiberty.h>
#include <bfd.h>
#include <filenames.h>
#include <dis-asm.h>
#include <safe-ctype.h>
#include <hashtab.h>
#include <elf/common.h>
#include <elf/external.h>
#include <elf/internal.h>

#define streq(a,b)	  (strcmp ((a), (b)) == 0)
#define strneq(a,b,n)	  (strncmp ((a), (b), (n)) == 0)
#define const_strneq(a,b) (strncmp ((a), (b), sizeof (b) - 1) == 0)

typedef unsigned char  uchar;
typedef unsigned int   uint;
typedef unsigned long  ulong;
typedef bfd_boolean    bool;
typedef struct ar_hdr  arhdr;

/* An enum controlling the behaviour of the einfo function:  */
typedef enum einfo_type
{
  WARN,		/* Issues a warning message.  */
  SYS_WARN,     /* Like WARN but also prints out errno.  */
  ERROR,        /* Issues an error message.  */
  SYS_ERROR,    /* Like ERROR but also prints out errno.  */
  FAIL,         /* Like ERROR but also calls abort().  */
  INFO,         /* Prints an informative message (on stdout).  */
  VERBOSE,      /* Like INFO but only generates the message if verbose is set.  */
  VERBOSE2,     /* Like VERBOSE but only generates the message if verbose was set twice.  */
  PARTIAL       /* Like INFO but no EOL required.  */
} einfo_type;

typedef struct callbacks
{
  unsigned int  em_type;
  unsigned int  em_type2;

  const char *  scanner_name;
  /* Called before scanning a segment or section.  */
  bool (* init) (bfd_byte *, ulong, ulong, const char *, ulong, bool);
  /* Called after scanning and reporting on a segment or section.
     Can be NULL.  */
  void (* finish) (void);
  /* Called to scan a segment or section.
     Must not be NULL.  */
  bool (* scanner) (bfd_byte *, ulong, ulong, const char *, ulong);
  /* Called once after everything has been processed to report statistics and such.
     Can be NULL.  */
  void (* final_report) (void);
  /* Called to allow the target a chance to handle its own command line arguments.
     Can be NULL.  */
  bool (* process_arg) (const char *, const char **, uint);
  /* Called to add additional text to the --help output.
     Can be NULL.  */
  void (* usage) (void);
} callbacks;

extern bool  einfo (einfo_type, const char *, ...) ATTRIBUTE_PRINTF(2, 3);

extern ulong             verbosity;           /* How informative we should be.  */
#define BE_VERY_VERBOSE (verbosity > 1)
#define BE_VERBOSE      (verbosity > 0)
#define BE_QUIET        (verbosity == -1UL)

extern callbacks  target;          /* Target specific data structure. */

