/*
    splay_tree.c -- splay tree and linked list convenience
    Copyright (C) 2014-2017 Guus Sliepen <guus@meshlink.io>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "system.h"

#include "splay_tree.h"
#include "xalloc.h"
#include "logger.h"

/* Splay operation */

static splay_node_t *splay_top_down(splay_tree_t *tree, const void *data, int *result) {
	splay_node_t left, right;
	splay_node_t *leftbottom = &left, *rightbottom = &right, *child, *grandchild;
	splay_node_t *root = tree->root;
	int c;

	memset(&left, 0, sizeof(left));
	memset(&right, 0, sizeof(right));

	if(!root) {
		if(result) {
			*result = 0;
		}

		return NULL;
	}

	while((c = tree->compare(data, root->data))) {
		if(c < 0 && (child = root->left)) {
			c = tree->compare(data, child->data);

			if(c < 0 && (grandchild = child->left)) {
				rightbottom->left = child;
				child->parent = rightbottom;
				rightbottom = child;

				if((root->left = child->right)) {
					child->right->parent = root;
				}

				child->right = root;
				root->parent = child;

				child->left = NULL;
				grandchild->parent = NULL;

				root = grandchild;
			} else if(c > 0 && (grandchild = child->right)) {
				leftbottom->right = child;
				child->parent = leftbottom;
				leftbottom = child;

				child->right = NULL;
				grandchild->parent = NULL;

				rightbottom->left = root;
				root->parent = rightbottom;
				rightbottom = root;

				root->left = NULL;

				root = grandchild;
			} else {
				rightbottom->left = root;
				root->parent = rightbottom;
				rightbottom = root;

				root->left = NULL;
				child->parent = NULL;

				root = child;
				break;
			}
		} else if(c > 0 && (child = root->right)) {
			c = tree->compare(data, child->data);

			if(c > 0 && (grandchild = child->right)) {
				leftbottom->right = child;
				child->parent = leftbottom;
				leftbottom = child;

				if((root->right = child->left)) {
					child->left->parent = root;
				}

				child->left = root;
				root->parent = child;

				child->right = NULL;
				grandchild->parent = NULL;

				root = grandchild;
			} else if(c < 0 && (grandchild = child->left)) {
				rightbottom->left = child;
				child->parent = rightbottom;
				rightbottom = child;

				child->left = NULL;
				grandchild->parent = NULL;

				leftbottom->right = root;
				root->parent = leftbottom;
				leftbottom = root;

				root->right = NULL;

				root = grandchild;
			} else {
				leftbottom->right = root;
				root->parent = leftbottom;
				leftbottom = root;

				root->right = NULL;
				child->parent = NULL;

				root = child;
				break;
			}
		} else {
			break;
		}
	}

	/* Merge trees */

	if(left.right) {
		if(root->left) {
			leftbottom->right = root->left;
			root->left->parent = leftbottom;
		}

		root->left = left.right;
		left.right->parent = root;
	}

	if(right.left) {
		if(root->right) {
			rightbottom->left = root->right;
			root->right->parent = rightbottom;
		}

		root->right = right.left;
		right.left->parent = root;
	}

	/* Return result */

	tree->root = root;

	if(result) {
		*result = c;
	}

	return tree->root;
}

static void splay_bottom_up(splay_tree_t *tree, splay_node_t *node) {
	logger(NULL, MESHLINK_INFO, "%s.%d splay_bottom_up started\n", __func__, __LINE__);
	splay_node_t *parent, *grandparent, *greatgrandparent;

	logger(NULL, MESHLINK_INFO, "%s.%d while parent = node->parent\n", __func__, __LINE__);
	while((parent = node->parent)) {
	logger(NULL, MESHLINK_INFO, "%s.%d in WHILE\n", __func__, __LINE__);
	logger(NULL, MESHLINK_INFO, "%s.%d if grandparent = parent->parent\n", __func__, __LINE__);
		if(!(grandparent = parent->parent)) { /* zig */
	logger(NULL, MESHLINK_INFO, "%s.%d if node == parent->left", __func__, __LINE__);
			if(node == parent->left) {
	logger(NULL, MESHLINK_INFO, "%s.%d if parent->left = node->right\n", __func__, __LINE__);
				if((parent->left = node->right)) {
	logger(NULL, MESHLINK_INFO, "%s.%d if parent->left->parent = parent\n", __func__, __LINE__);
					parent->left->parent = parent;
	logger(NULL, MESHLINK_INFO, "%s.%d if parent->left->parent = parent set\n", __func__, __LINE__);
				}

	logger(NULL, MESHLINK_INFO, "%s.%d node->right = parent\n", __func__, __LINE__);
				node->right = parent;
	logger(NULL, MESHLINK_INFO, "%s.%d node->right = parent set\n", __func__, __LINE__);
			} else {
	logger(NULL, MESHLINK_INFO, "%s.%d else if parent->right = node->left\n", __func__, __LINE__);
				if((parent->right = node->left)) {
	logger(NULL, MESHLINK_INFO, "%s.%d parent->right->parent = parent\n", __func__, __LINE__);
					parent->right->parent = parent;
	logger(NULL, MESHLINK_INFO, "%s.%d parent->right->parent = parent set\n", __func__, __LINE__);
				}

	logger(NULL, MESHLINK_INFO, "%s.%d node->left = parent\n", __func__, __LINE__);
				node->left = parent;
	logger(NULL, MESHLINK_INFO, "%s.%d node->left = parent set\n", __func__, __LINE__);
			}

	logger(NULL, MESHLINK_INFO, "%s.%d parent->parent = node\n", __func__, __LINE__);
			parent->parent = node;
	logger(NULL, MESHLINK_INFO, "%s.%d node->parent = NULL\n", __func__, __LINE__);
			node->parent = NULL;
	logger(NULL, MESHLINK_INFO, "%s.%d node->parent = NULL set\n", __func__, __LINE__);
		} else {
	logger(NULL, MESHLINK_INFO, "%s.%d else greatgrandparent = grandparent->parent\n", __func__, __LINE__);
			greatgrandparent = grandparent->parent;

	logger(NULL, MESHLINK_INFO, "%s.%d node == parent->left", __func__, __LINE__);
			if(node == parent->left && parent == grandparent->left) { /* left zig-zig */
	logger(NULL, MESHLINK_INFO, "%s.%d grandparent->left = parent->right\n", __func__, __LINE__);
				if((grandparent->left = parent->right)) {
	logger(NULL, MESHLINK_INFO, "%s.%d grandparent->left->parent = grandparent\n", __func__, __LINE__);
					grandparent->left->parent = grandparent;
	logger(NULL, MESHLINK_INFO, "%s.%d grandparent->left->parent = grandparent set\n", __func__, __LINE__);
				}

	logger(NULL, MESHLINK_INFO, "%s.%d parent->right = grandparent\n", __func__, __LINE__);
				parent->right = grandparent;
	logger(NULL, MESHLINK_INFO, "%s.%d grandparent->parent = parent\n", __func__, __LINE__);
				grandparent->parent = parent;

	logger(NULL, MESHLINK_INFO, "%s.%d if parent->left = node->right\n", __func__, __LINE__);
				if((parent->left = node->right)) {
	logger(NULL, MESHLINK_INFO, "%s.%d parent->left->parent = parent\n", __func__, __LINE__);
					parent->left->parent = parent;
	logger(NULL, MESHLINK_INFO, "%s.%d parent->left->parent = parent set\n", __func__, __LINE__);
				}

	logger(NULL, MESHLINK_INFO, "%s.%d node->right = parent\n", __func__, __LINE__);
				node->right = parent;
	logger(NULL, MESHLINK_INFO, "%s.%d parentparent\n", __func__, __LINE__);
				parent->parent = node;
	logger(NULL, MESHLINK_INFO, "%s.%d parentparent set\n", __func__, __LINE__);
			} else if(node == parent->right && parent == grandparent->right) { /* right zig-zig */
	logger(NULL, MESHLINK_INFO, "%s.%d in else grandparent->right = parent->left\n", __func__, __LINE__);
				if((grandparent->right = parent->left)) {
	logger(NULL, MESHLINK_INFO, "%s.%d grandparent->right->parent = grandparent\n", __func__, __LINE__);
					grandparent->right->parent = grandparent;
	logger(NULL, MESHLINK_INFO, "%s.%d grandparent->right->parent = grandparent set\n", __func__, __LINE__);
				}

	logger(NULL, MESHLINK_INFO, "%s.%d parent->left = grandparent\n", __func__, __LINE__);
				parent->left = grandparent;
	logger(NULL, MESHLINK_INFO, "%s.%d grandparent->parent = parent\n", __func__, __LINE__);
				grandparent->parent = parent;

	logger(NULL, MESHLINK_INFO, "%s.%d parent->right = node->left\n", __func__, __LINE__);
				if((parent->right = node->left)) {
	logger(NULL, MESHLINK_INFO, "%s.%d parent->right->parent = parent\n", __func__, __LINE__);
					parent->right->parent = parent;
	logger(NULL, MESHLINK_INFO, "%s.%d parent->right->parent = parent set\n", __func__, __LINE__);
				}

	logger(NULL, MESHLINK_INFO, "%s.%d node->left = parent\n", __func__, __LINE__);
				node->left = parent;
	logger(NULL, MESHLINK_INFO, "%s.%d node->parent = node\n", __func__, __LINE__);
				parent->parent = node;
	logger(NULL, MESHLINK_INFO, "%s.%d node->parent = node set\n", __func__, __LINE__);
			} else if(node == parent->right && parent == grandparent->left) { /* left-right zig-zag */
	logger(NULL, MESHLINK_INFO, "%s.%d if parent->right = node->left\n", __func__, __LINE__);
				if((parent->right = node->left)) {
	logger(NULL, MESHLINK_INFO, "%s.%d parent->right = parnt\n", __func__, __LINE__);
					parent->right->parent = parent;
	logger(NULL, MESHLINK_INFO, "%s.%d parent->right = parnt set\n", __func__, __LINE__);
				}

	logger(NULL, MESHLINK_INFO, "%s.%d node->left = parent\n", __func__, __LINE__);
				node->left = parent;
	logger(NULL, MESHLINK_INFO, "%s.%d  parentparentparent = node\n", __func__, __LINE__);
				parent->parent = node;

	logger(NULL, MESHLINK_INFO, "%s.%d  grandparent->left = node->right\n", __func__, __LINE__);
				if((grandparent->left = node->right)) {
	logger(NULL, MESHLINK_INFO, "%s.%d  grandparent->left->parent = grandparent\n", __func__, __LINE__);
					grandparent->left->parent = grandparent;
	logger(NULL, MESHLINK_INFO, "%s.%d  grandparent->left->parent = grandparent set\n", __func__, __LINE__);
				}

	logger(NULL, MESHLINK_INFO, "%s.%d  node->right = grandparent\n", __func__, __LINE__);
				node->right = grandparent;
	logger(NULL, MESHLINK_INFO, "%s.%d grandparent->parent = node\n", __func__, __LINE__);
				grandparent->parent = node;
	logger(NULL, MESHLINK_INFO, "%s.%d grandparent->parent = node set\n", __func__, __LINE__);
			} else { /* right-left zig-zag */
	logger(NULL, MESHLINK_INFO, "%s.%d if parent->left = node->right\n", __func__, __LINE__);
				if((parent->left = node->right)) {
	logger(NULL, MESHLINK_INFO, "%s.%d if parent->left->parent = parent\n", __func__, __LINE__);
					parent->left->parent = parent;
	logger(NULL, MESHLINK_INFO, "%s.%d if parent->left->parent = parent set\n", __func__, __LINE__);
				}

	logger(NULL, MESHLINK_INFO, "%s.%d node->right = parent\n", __func__, __LINE__);
				node->right = parent;
	logger(NULL, MESHLINK_INFO, "%s.%d parentparent\n", __func__, __LINE__);
				parent->parent = node;

	logger(NULL, MESHLINK_INFO, "%s.%d grandparent->right = node->left\n", __func__, __LINE__);
				if((grandparent->right = node->left)) {
	logger(NULL, MESHLINK_INFO, "%s.%d grandparent->right->parent = grandparent\n", __func__, __LINE__);
					grandparent->right->parent = grandparent;
	logger(NULL, MESHLINK_INFO, "%s.%d grandparent->right->parent = grandparent sey\n", __func__, __LINE__);
				}

	logger(NULL, MESHLINK_INFO, "%s.%d node->left = grandparent\n", __func__, __LINE__);
				node->left = grandparent;
	logger(NULL, MESHLINK_INFO, "%s.%d grandparent->parent = node\n", __func__, __LINE__);
				grandparent->parent = node;
	logger(NULL, MESHLINK_INFO, "%s.%d grandparent->parent = node set\n", __func__, __LINE__);
			}

	logger(NULL, MESHLINK_INFO, "%s.%d if node->parent = greatgrandparent\n", __func__, __LINE__);
			if((node->parent = greatgrandparent)) {
	logger(NULL, MESHLINK_INFO, "%s.%d grandparent == greatgrandparent->left\n", __func__, __LINE__);
				if(grandparent == greatgrandparent->left) {
	logger(NULL, MESHLINK_INFO, "%s.%d greatgrandparent->left = node\n", __func__, __LINE__);
					greatgrandparent->left = node;
	logger(NULL, MESHLINK_INFO, "%s.%d greatgrandparent->left = node set\n", __func__, __LINE__);
				} else {
	logger(NULL, MESHLINK_INFO, "%s.%d  else greatgrandparent->right = node\n", __func__, __LINE__);
					greatgrandparent->right = node;
				}
	logger(NULL, MESHLINK_INFO, "%s.%d  brace 1\n", __func__, __LINE__);
			}
	logger(NULL, MESHLINK_INFO, "%s.%d  brace 2\n", __func__, __LINE__);
		}
	logger(NULL, MESHLINK_INFO, "%s.%d  brace 3\n", __func__, __LINE__);
	}
	logger(NULL, MESHLINK_INFO, "%s.%d out of WHILE\n", __func__, __LINE__);

	tree->root = node;
	logger(NULL, MESHLINK_INFO, "%s.%d done\n", __func__, __LINE__);
}

/* (De)constructors */

splay_tree_t *splay_alloc_tree(splay_compare_t compare, splay_action_t delete) {
	splay_tree_t *tree;

	tree = xzalloc(sizeof(splay_tree_t));
	tree->compare = compare;
	tree->delete = delete;

	return tree;
}

splay_node_t *splay_alloc_node(void) {
	return xzalloc(sizeof(splay_node_t));
}

void splay_free_node(splay_tree_t *tree, splay_node_t *node) {
	if(node->data && tree->delete) {
		tree->delete(node->data);
	}

	free(node);
}

/* Searching */

void *splay_search(splay_tree_t *tree, const void *data) {
	splay_node_t *node;

	node = splay_search_node(tree, data);

	return node ? node->data : NULL;
}

void *splay_search_closest(splay_tree_t *tree, const void *data, int *result) {
	splay_node_t *node;

	node = splay_search_closest_node(tree, data, result);

	return node ? node->data : NULL;
}

void *splay_search_closest_smaller(splay_tree_t *tree, const void *data) {
	splay_node_t *node;

	node = splay_search_closest_smaller_node(tree, data);

	return node ? node->data : NULL;
}

void *splay_search_closest_greater(splay_tree_t *tree, const void *data) {
	splay_node_t *node;

	node = splay_search_closest_greater_node(tree, data);

	return node ? node->data : NULL;
}

splay_node_t *splay_search_node(splay_tree_t *tree, const void *data) {
	splay_node_t *node;
	int result;

	node = splay_search_closest_node(tree, data, &result);

	return result ? NULL : node;
}

splay_node_t *splay_search_closest_node_nosplay(const splay_tree_t *tree, const void *data, int *result) {
	splay_node_t *node;
	int c;

	node = tree->root;

	if(!node) {
		if(result) {
			*result = 0;
		}

		return NULL;
	}

	for(;;) {
		c = tree->compare(data, node->data);

		if(c < 0) {
			if(node->left) {
				node = node->left;
			} else {
				break;
			}
		} else if(c > 0) {
			if(node->right) {
				node = node->right;
			} else {
				break;
			}
		} else {
			break;
		}
	}

	if(result) {
		*result = c;
	}

	return node;
}

splay_node_t *splay_search_closest_node(splay_tree_t *tree, const void *data, int *result) {
	return splay_top_down(tree, data, result);
}

splay_node_t *splay_search_closest_smaller_node(splay_tree_t *tree, const void *data) {
	splay_node_t *node;
	int result;

	node = splay_search_closest_node(tree, data, &result);

	if(result < 0) {
		node = node->prev;
	}

	return node;
}

splay_node_t *splay_search_closest_greater_node(splay_tree_t *tree, const void *data) {
	splay_node_t *node;
	int result;

	node = splay_search_closest_node(tree, data, &result);

	if(result > 0) {
		node = node->next;
	}

	return node;
}

/* Insertion and deletion */

static void splay_insert_top(splay_tree_t *tree, splay_node_t *node) {
	logger(NULL, MESHLINK_INFO, "%s.%d Inside splay_insert_top\n", __func__, __LINE__);
	node->prev = node->next = node->left = node->right = node->parent = NULL;
	logger(NULL, MESHLINK_INFO, "%s.%d tree->head = tree->tail = tree->root = node\n", __func__, __LINE__);
	tree->head = tree->tail = tree->root = node;
	logger(NULL, MESHLINK_INFO, "%s.%d tree->count++\n", __func__, __LINE__);
	tree->count++;
	logger(NULL, MESHLINK_INFO, "%s.%d DONE\n", __func__, __LINE__);
}

static void splay_insert_after(splay_tree_t *tree, splay_node_t *after, splay_node_t *node);

static void splay_insert_before(splay_tree_t *tree, splay_node_t *before, splay_node_t *node) {
	if(!before) {
		if(tree->tail) {
			splay_insert_after(tree, tree->tail, node);
		} else {
			splay_insert_top(tree, node);
		}

		return;
	}

	node->next = before;

	if((node->prev = before->prev)) {
		before->prev->next = node;
	} else {
		tree->head = node;
	}

	before->prev = node;

	splay_bottom_up(tree, before);

	node->right = before;
	before->parent = node;

	if((node->left = before->left)) {
		before->left->parent = node;
	}

	before->left = NULL;

	node->parent = NULL;
	tree->root = node;
	tree->count++;
}

static void splay_insert_after(splay_tree_t *tree, splay_node_t *after, splay_node_t *node) {
	if(!after) {
		if(tree->head) {
			splay_insert_before(tree, tree->head, node);
		} else {
			splay_insert_top(tree, node);
		}

		return;
	}

	node->prev = after;

	if((node->next = after->next)) {
		after->next->prev = node;
	} else {
		tree->tail = node;
	}

	after->next = node;

	splay_bottom_up(tree, after);

	node->left = after;
	after->parent = node;

	if((node->right = after->right)) {
		after->right->parent = node;
	}

	after->right = NULL;

	node->parent = NULL;
	tree->root = node;
	tree->count++;
}

splay_node_t *splay_insert(splay_tree_t *tree, void *data) {
	splay_node_t *closest, *new;
	int result;

	if(!tree->root) {
		new = splay_alloc_node();
		new->data = data;
		splay_insert_top(tree, new);
	} else {
		closest = splay_search_closest_node(tree, data, &result);

		if(!result) {
			return NULL;
		}

		new = splay_alloc_node();
		new->data = data;

		if(result < 0) {
			splay_insert_before(tree, closest, new);
		} else {
			splay_insert_after(tree, closest, new);
		}
	}

	return new;
}

splay_node_t *splay_insert_node(splay_tree_t *tree, splay_node_t *node) {
	logger(NULL, MESHLINK_INFO, "%s.%d Inside splay_insert_node\n", __func__, __LINE__);
	splay_node_t *closest;
	int result;

	logger(NULL, MESHLINK_INFO, "%s.%d node->left = node->right = node->parent = node->next = node->prev = NULL\n", __func__, __LINE__);
	node->left = node->right = node->parent = node->next = node->prev = NULL;

	logger(NULL, MESHLINK_INFO, "%s.%d if tree->root\n", __func__, __LINE__);
	if(!tree->root) {
	logger(NULL, MESHLINK_INFO, "%s.%d beforesplay_insert_top\n", __func__, __LINE__);
		splay_insert_top(tree, node);
	logger(NULL, MESHLINK_INFO, "%s.%d aftersplay_insert_top\n", __func__, __LINE__);
	} else {
	logger(NULL, MESHLINK_INFO, "%s.%d before splay_search_closest_node\n", __func__, __LINE__);
		closest = splay_search_closest_node(tree, node->data, &result);
	logger(NULL, MESHLINK_INFO, "%s.%d after splay_search_closest_node\n", __func__, __LINE__);

		if(!result) {
	logger(NULL, MESHLINK_INFO, "%s.%d return NULL\n", __func__, __LINE__);
			return NULL;
		}

	logger(NULL, MESHLINK_INFO, "%s.%d result < 0\n", __func__, __LINE__);
		if(result < 0) {
	logger(NULL, MESHLINK_INFO, "%s.%d before splay_insert_before\n", __func__, __LINE__);
			splay_insert_before(tree, closest, node);
	logger(NULL, MESHLINK_INFO, "%s.%d after splay_insert_before\n", __func__, __LINE__);
		} else {
	logger(NULL, MESHLINK_INFO, "%s.%d before splay_insert_after\n", __func__, __LINE__);
			splay_insert_after(tree, closest, node);
	logger(NULL, MESHLINK_INFO, "%s.%d after splay_insert_after\n", __func__, __LINE__);
		}
	logger(NULL, MESHLINK_INFO, "%s.%d brace 1\n", __func__, __LINE__);
	}

	logger(NULL, MESHLINK_INFO, "%s.%d DONE \n", __func__, __LINE__);
	return node;
}

splay_node_t *splay_unlink(splay_tree_t *tree, void *data) {
	splay_node_t *node;

	node = splay_search_node(tree, data);

	if(node) {
		splay_unlink_node(tree, node);
	}

	return node;
}

void splay_unlink_node(splay_tree_t *tree, splay_node_t *node) {
	logger(NULL, MESHLINK_INFO, "%s.%d In splay unlink node\n", __func__, __LINE__);
	logger(NULL, MESHLINK_INFO, "%s.%d assert tree->count\n", __func__, __LINE__);
	assert(tree->count);
	logger(NULL, MESHLINK_INFO, "%s.%d assert node->prev\n", __func__, __LINE__);
	assert(node->prev || tree->head == node);
	logger(NULL, MESHLINK_INFO, "%s.%d assert node->next\n", __func__, __LINE__);
	assert(node->next || tree->tail == node);

	logger(NULL, MESHLINK_INFO, "%s.%d if node->prev\n", __func__, __LINE__);
	if(node->prev) {
	logger(NULL, MESHLINK_INFO, "%s.%d node->prev->next = node->next\n", __func__, __LINE__);
		node->prev->next = node->next;
	logger(NULL, MESHLINK_INFO, "%s.%d node->prev->next = node->next set\n", __func__, __LINE__);
	} else {
	logger(NULL, MESHLINK_INFO, "%s.%d else tree->head = node->next\n", __func__, __LINE__);
		tree->head = node->next;
	logger(NULL, MESHLINK_INFO, "%s.%d else tree->head = node->next set\n", __func__, __LINE__);
	}

	logger(NULL, MESHLINK_INFO, "%s.%d if node->next\n", __func__, __LINE__);
	if(node->next) {
	logger(NULL, MESHLINK_INFO, "%s.%d node->next->prev = node->prev\n", __func__, __LINE__);
		node->next->prev = node->prev;
	} else {
	logger(NULL, MESHLINK_INFO, "%s.%d else tree->tail = node->prev\n", __func__, __LINE__);
		tree->tail = node->prev;
	}

	logger(NULL, MESHLINK_INFO, "%s.%d splay_bottom_up\n", __func__, __LINE__);
	splay_bottom_up(tree, node);

	logger(NULL, MESHLINK_INFO, "%s.%d if node->prev\n", __func__, __LINE__);
	if(node->prev) {
	logger(NULL, MESHLINK_INFO, "%s.%d node->left->parent = NULL\n", __func__, __LINE__);
		node->left->parent = NULL;
	logger(NULL, MESHLINK_INFO, "%s.%d tree->root = node->left\n", __func__, __LINE__);
		tree->root = node->left;

	logger(NULL, MESHLINK_INFO, "%s.%d if node->prev->right = node->right\n", __func__, __LINE__);
		if((node->prev->right = node->right)) {
	logger(NULL, MESHLINK_INFO, "%s.%d node->right->parent = node->prev\n", __func__, __LINE__);
			node->right->parent = node->prev;
		}
	logger(NULL, MESHLINK_INFO, "%s.%d if node->right->parent = node->prev then set\n", __func__, __LINE__);
	} else if(node->next) {
	logger(NULL, MESHLINK_INFO, "%s.%d else tree->root = node->right\n", __func__, __LINE__);
		tree->root = node->right;
	logger(NULL, MESHLINK_INFO, "%s.%d node->right->parent = NULL\n", __func__, __LINE__);
		node->right->parent = NULL;
	logger(NULL, MESHLINK_INFO, "%s.%d node->right->parent = NULL set\n", __func__, __LINE__);
	} else {
	logger(NULL, MESHLINK_INFO, "%s.%d else tree->root = NULL\n", __func__, __LINE__);
		tree->root = NULL;
	logger(NULL, MESHLINK_INFO, "%s.%d else tree->root = NULL set\n", __func__, __LINE__);
	}

	logger(NULL, MESHLINK_INFO, "%s.%d tree->count--\n", __func__, __LINE__);
	tree->count--;
	logger(NULL, MESHLINK_INFO, "%s.%d splay_unlink_node done\n", __func__, __LINE__);
}

void splay_delete_node(splay_tree_t *tree, splay_node_t *node) {
	splay_unlink_node(tree, node);
	splay_free_node(tree, node);
}

void splay_delete(splay_tree_t *tree, void *data) {
	splay_node_t *node;

	node = splay_search_node(tree, data);

	if(node) {
		splay_delete_node(tree, node);
	}
}

/* Fast tree cleanup */

void splay_delete_tree(splay_tree_t *tree) {
	for(splay_node_t *node = tree->head, *next; node; node = next) {
		next = node->next;
		splay_free_node(tree, node);
		tree->count--;
	}

	assert(!tree->count);
	free(tree);
}

/* Tree walking */

void splay_foreach(const splay_tree_t *tree, splay_action_t action) {
	for(splay_node_t *node = tree->head, *next; node; node = next) {
		next = node->next;
		action(node->data);
	}
}

void splay_foreach_node(const splay_tree_t *tree, splay_action_t action) {
	for(splay_node_t *node = tree->head, *next; node; node = next) {
		next = node->next;
		action(node);
	}
}
