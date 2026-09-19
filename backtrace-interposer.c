#define _GNU_SOURCE

// SPDX-License-Identifier: GPL-3.0-or-later
/* Let libbacktrace inspect external ET_DYN files. */
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stddef.h>
#include <string.h>

typedef int (*dl_phdr_callback) (struct dl_phdr_info *, size_t, void *);

static __thread const char *active_filename;

extern int __real_dl_iterate_phdr (dl_phdr_callback, void *);

void
backtrace_interposer_set_filename (const char *filename)
{
  active_filename = filename;
}

const char *
backtrace_interposer_get_filename (void)
{
  return active_filename;
}

/* Make an external ET_DYN file look like the current executable to
   libbacktrace's normal dl_iterate_phdr callback.  The callback consumes
   the descriptor supplied to backtrace_initialize when dlpi_name is empty,
   then parses it with the synthetic zero load address.  */
static int
emit_external_phdr (dl_phdr_callback callback, void *data)
{
  int fd = -1;
  struct stat st;
  void *mapping = MAP_FAILED;
  const ElfW(Ehdr) *ehdr;
  const ElfW(Phdr) *phdr;
  struct dl_phdr_info info;
  int result;

  if (active_filename == NULL)
    return 0;

  fd = open (active_filename, O_RDONLY | O_CLOEXEC);
  if (fd < 0 || fstat (fd, &st) < 0 || st.st_size < (off_t) sizeof (*ehdr))
    goto done;

  mapping = mmap (NULL, (size_t) st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (mapping == MAP_FAILED)
    goto done;

  ehdr = (const ElfW(Ehdr) *) mapping;
  if (memcmp (ehdr->e_ident, ELFMAG, SELFMAG) != 0
      || ehdr->e_ident[EI_CLASS]
           != (sizeof (ElfW(Addr)) == 8 ? ELFCLASS64 : ELFCLASS32)
      || ehdr->e_ident[EI_DATA] != (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
                                    ? ELFDATA2LSB : ELFDATA2MSB)
      || ehdr->e_type != ET_DYN
      || ehdr->e_phentsize != sizeof (ElfW(Phdr))
      || ehdr->e_phnum == 0
      || ehdr->e_phoff > (ElfW(Off)) st.st_size
      || ehdr->e_phnum
           > ((ElfW(Off)) st.st_size - ehdr->e_phoff) / ehdr->e_phentsize)
    goto done;

  phdr = (const ElfW(Phdr) *) ((const char *) mapping + ehdr->e_phoff);
  memset (&info, 0, sizeof info);
  info.dlpi_addr = 0;
  info.dlpi_name = "";
  info.dlpi_phdr = phdr;
  info.dlpi_phnum = ehdr->e_phnum;
  result = callback (&info, sizeof info, data);

  if (munmap (mapping, (size_t) st.st_size) < 0)
    result = 0;
  close (fd);
  return result;

done:
  if (mapping != MAP_FAILED)
    munmap (mapping, (size_t) st.st_size);
  if (fd >= 0)
    close (fd);
  return 0;
}

/* Link this wrapper with -Wl,--wrap=dl_iterate_phdr.  Inject the target
   file before the real process modules so it consumes the executable
   descriptor reserved by libbacktrace for an ET_DYN filename.  */
int
__wrap_dl_iterate_phdr (dl_phdr_callback callback, void *data)
{
  int result = emit_external_phdr (callback, data);
  if (result != 0)
    return result;
  return __real_dl_iterate_phdr (callback, data);
}
