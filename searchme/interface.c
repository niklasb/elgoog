#include "common.h"
#include "index.h"
#include "alloc.h"
#include "interface.h"

#define NUM_IDXHANDLES 2048


static PVOID handle_table[NUM_IDXHANDLES] = { 0 };

static int find_handle(IDXHANDLE handle) {
	for (int i = 0; i < NUM_IDXHANDLES; ++i) {
		if (handle == handle_table[i] && handle_table[i]) {
			return i;
		}
	}
	return -1;
}

static inverted_index* resolve_handle(IDXHANDLE handle) {
	int offset = find_handle(handle);
	if (offset < 0)
		return 0;
	return handle_table[offset];
}

IDXHANDLE insert_handle(inverted_index* idx) {
	for (int i = 0; i < NUM_IDXHANDLES; ++i) {
		if (!handle_table[i]) {
			handle_table[i] = idx;
			return idx;
		}
	}
	return INVALID_IDXHANDLE;
}

IDXHANDLE searchme_create_index() {
	inverted_index* idx = empty_index();
	if (!idx)
		return INVALID_IDXHANDLE;
	return insert_handle(idx);
}

void searchme_close_index(IDXHANDLE handle) {
	int offset = find_handle(handle);
	if (offset < 0)
		return;
	kfree(handle_table[offset]);
	handle_table[offset] = 0;
}

int searchme_add_to_index(IDXHANDLE handle, uint32_t doc_id, char* doc, size_t doc_size) {
	inverted_index* idx = resolve_handle(handle);
	if (!idx)
		return 1;
	if (add(idx, doc_id, doc, doc_size)) {
		searchme_close_index(handle);
		return 1;
	}
	return 0;
}

int searchme_query(IDXHANDLE handle, char* query, size_t query_len) {
	(void)handle;
	(void)query;
	(void)query_len;
	return 1;
}

IDXHANDLE searchme_compress_index(IDXHANDLE handle) {
	inverted_index* idx = resolve_handle(handle);
	if (!idx)
		return INVALID_IDXHANDLE;
	idx = build(idx);
	if (!idx)
		return INVALID_IDXHANDLE;
	return insert_handle(idx);
}