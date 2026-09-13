#ifndef MESHLINK_PATH_POLICY_DEVTOOL_H
#define MESHLINK_PATH_POLICY_DEVTOOL_H

#include <stdbool.h>

struct meshlink_handle;
struct node_t;

bool path_policy_cover_unit(struct meshlink_handle *mesh, struct node_t *live);

#endif
