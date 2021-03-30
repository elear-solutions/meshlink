#ifndef EC_MESH_H
#define EC_MESH_H


#include "elearcommon/allocate.h"

extern const char *meshlinkStr;

#define malloc(bytes) ec_allocate_mem(bytes, EC_TTL_INFINITY, __func__)
#define calloc(mem, bytes) ec_allocate_mem_and_set(bytes, EC_TTL_INFINITY, __func__, 0)
#define realloc(ptr, bytes) ( ptr ? ec_reallocate_mem(ptr, bytes, EC_TTL_INFINITY, __func__) : ec_allocate_mem(bytes, EC_TTL_INFINITY, __func__))
#define free(ptr) ec_deallocate(ptr)

#endif
