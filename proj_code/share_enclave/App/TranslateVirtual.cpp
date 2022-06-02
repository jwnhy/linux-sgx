#include "TranslateVirtual.h"
#include <errno.h>
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

bool PTE_WRITE(uint64_t pte) { return 0x2 & pte; }
bool PTE_EXEC(uint64_t pte) { return !((0x1UL << 63) & pte); }
// TODO: update this to use '/dev/sgx/enclave'
int map_self_virt(int sgx_fd, uint64_t virtaddr, size_t size, uint64_t *buffer) {
  size_t i, pagecnt, pagesize;
  uint64_t pte;

  pagesize = getpagesize();
  pagecnt = size / (size_t)pagesize;

  for (i = 0; i < pagecnt; i++) {
    int prot = PROT_READ; // always readble in x86
    pte = buffer[i]; 
    if (PTE_WRITE(pte)) prot |= PROT_WRITE;
    if (PTE_EXEC(pte)) prot |= PROT_EXEC;
    if (mmap((void*)virtaddr, pagesize, prot, MAP_PRIVATE, sgx_fd, 0) != (void*)virtaddr) {
      printf("FUCK %s\n", strerror(errno));
      return -1;
    }
    virtaddr += pagesize;
  } 

  return 0;
}

int send_fd(int socket, int fd) {
  struct msghdr msg = {0};
  char buf[CMSG_SPACE(sizeof(fd))];
  memset(buf, '\0', sizeof(buf));
  // we don't care iovec but the cmsg comes with it
  struct iovec io = { .iov_base = (void*)"ABC", .iov_len = 3 };

  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(struct cmsghdr) + sizeof(fd);

  struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

  *((int*)CMSG_DATA(cmsg)) = fd;

  msg.msg_controllen = CMSG_SPACE(sizeof(fd));
  if (sendmsg(socket, &msg, 0) < 0)
    return -1;

  return 0;
}

int recv_fd(int socket) {
  struct msghdr msg = {0};

  char m_buffer[256];
  struct iovec io = {.iov_base = m_buffer, .iov_len = sizeof(m_buffer)};
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;

  char c_buffer[256];
  msg.msg_control = c_buffer;
  msg.msg_controllen = sizeof(c_buffer);

  if (recvmsg(socket, &msg, 0) < 0)
    return -1;

  struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);

  unsigned char * data = CMSG_DATA(cmsg);
  int fd = *((int*)data);
  return fd;
}
