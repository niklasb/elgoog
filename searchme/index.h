#pragma once

#include "common.h"

#define TOK_LEN 16
#define INITIAL_PL_CAPACITY 4
#define INITIAL_II_CAPACITY 4

#pragma warning(push)
#pragma warning(disable : 4200)

#define POSTING_LIST_SIZE(x) (sizeof(ii_posting_list)+x*sizeof(uint32_t))
typedef struct _ii_posting_list {
	char token[16];
	size_t size, capacity;
	uint32_t data[0];
} ii_posting_list;

#define TOKEN_TABLE_SIZE(x) (sizeof(ii_token_table)+x*sizeof(ii_posting_list*))
typedef struct _ii_token_table {
	size_t size, capacity;
	ii_posting_list* slots[0];
} ii_token_table;

#pragma warning(pop)


typedef struct _inverted_index {
	int compressed;
	ii_token_table* table;
} inverted_index;

int add(inverted_index* idx, uint32_t doc_id, const char* doc, size_t doc_size);
inverted_index* empty_index();
int query(inverted_index* idx, const char* query, uint32_t* results, size_t results_size);
inverted_index* build(inverted_index* idx);

#ifdef DEBUG
void debug(inverted_index* idx);
#endif