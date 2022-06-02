#include "TranslateVirtual.h"

int translate_self_virt(uint64_t virtaddr, size_t size, uint64_t *buffer) {
  int mapfd, pagesize;
  ssize_t fileoffset, ret;
  size_t pagecnt, buffersize;

  mapfd = open("/dev/virtmmu", O_RDONLY);
  if (mapfd < 0)
    return -1;

  pagesize = getpagesize();
  pagecnt = size / (size_t)pagesize;

  fileoffset = (ssize_t)virtaddr / pagesize * ENTRY_SIZE;

  buffersize = ENTRY_SIZE * pagecnt;
  if (!buffer)
    return -1;

  ret = pread(mapfd, buffer, buffersize, fileoffset);
  if (ret == -1 || ret != (ssize_t)buffersize) 
    return -1;

  return 0;
}

int map_self_virt(uint64_t virtaddr, size_t size, uint64_t *buffer) {
  int mapfd, pagesize;
  ssize_t fileoffset, ret;
  size_t pagecnt, buffersize;

  mapfd = open("/dev/virtmmu", O_WRONLY);
  if (mapfd < 0)
    return -1;

  pagesize = getpagesize();
  pagecnt = size / (size_t)pagesize;

  fileoffset = (ssize_t)virtaddr / pagesize * ENTRY_SIZE;

  buffersize = ENTRY_SIZE * pagecnt;
  if (!buffer)
    return -1;

  ret = pwrite(mapfd, buffer, buffersize, fileoffset);
  if (ret == -1 || ret != (ssize_t)buffersize) 
    return -1;

  return 0;
}
