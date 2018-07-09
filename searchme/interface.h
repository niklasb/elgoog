#pragma once

#include "common.h"

typedef PVOID IDXHANDLE;
#define INVALID_IDXHANDLE 0

IDXHANDLE searchme_create_index();
void searchme_close_index(IDXHANDLE handle);
int searchme_add_to_index(IDXHANDLE handle, uint32_t doc_id, char* doc, size_t doc_size);
int searchme_query(IDXHANDLE handle, char* query, size_t query_len);
IDXHANDLE searchme_compress_index(IDXHANDLE handle);