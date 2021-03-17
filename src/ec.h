#ifndef EC_H
#define EC_H


#include "elearcommon/allocate.h"

#define malloc(bytes) ec_allocate_ttl(bytes, EC_TTL_INFINITY)

#endif
