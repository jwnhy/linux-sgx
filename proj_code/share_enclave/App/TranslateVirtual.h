#ifndef TRANSLATE_VIRTUAL_H__
#define TRANSLATE_VIRTUAL_H__

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <stdlib.h>
const int ENTRY_SIZE=8;
int translate_self_virt(uint64_t virt_addr, size_t size, uint64_t *buffer); 
int map_self_virt(uint64_t virtaddr, size_t size, uint64_t *buffer) ;
#endif
