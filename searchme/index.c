#include <ctype.h>
#include <string.h>

#include "index.h"
#include "alloc.h"

int is_word(int c) {
	return 'a' <= c && c <= 'z';
}

uint32_t hash(const char* tok) {
	uint32_t res = 16777259;
	for (unsigned char* c = (unsigned char*)tok; *c; ++c)
		res = (res * 2147483659 + *c);
	res *= 2147483659;
	return res;
}

ii_posting_list* empty_pl(const char* tok) {
	ii_posting_list* res = kalloc(POSTING_LIST_SIZE(INITIAL_PL_CAPACITY));
	if (!res)
		return 0;
	res->size = 0;
	res->capacity = INITIAL_PL_CAPACITY;
	strcpy(res->token, tok);
	return res;
}

inverted_index* empty_index() {
	ii_token_table* table = kalloc(TOKEN_TABLE_SIZE(INITIAL_II_CAPACITY));
	if (!table)
		return 0;
	table->size = 0;
	table->capacity = INITIAL_II_CAPACITY;
	inverted_index* idx = kalloc(sizeof(inverted_index));
	if (!idx)
		return 0;
	idx->compressed = 0;
	idx->table = table;
	return idx;
}

int grow_index(inverted_index* idx) {
	// allocate bigger table
	size_t new_cap = idx->table->capacity * 2;
	ii_token_table* tab = kalloc(TOKEN_TABLE_SIZE(new_cap));
	if (!tab)
		return 1;
	tab->capacity = new_cap;
	tab->size = idx->table->size;

	// rehash
	for (size_t i = 0; i < idx->table->capacity; ++i) {
		ii_posting_list* pl = idx->table->slots[i];
		if (!pl)
			continue;
		uint32_t h = hash(pl->token);
		size_t slot = h % tab->capacity;
		while (tab->slots[slot])
			slot = (slot + 1) % tab->capacity;
		tab->slots[slot] = pl;
	}
	idx->table = tab;
	return 0;
}

ii_posting_list** find_posting_list(inverted_index* idx, const char *tok, int create) {
	ii_token_table* tab = idx->table;
	uint32_t h = hash(tok);
	size_t slot = h % tab->capacity;
	while (tab->slots[slot]) {
		if (!strcmp(tab->slots[slot]->token, tok))
			return &tab->slots[slot];
		slot = (slot + 1) % tab->capacity;
	}
	if (!create)
		return 0;
	if (2 * tab->size + 1 > tab->capacity) {
		if (grow_index(idx))
			return 0;
		tab = idx->table;
		slot = h % tab->capacity;
		while (tab->slots[slot])
			slot = (slot + 1) % tab->capacity;
	}
	tab->size++;
	tab->slots[slot] = empty_pl(tok);
	return &tab->slots[slot];
}

int append_posting_list(ii_posting_list** pl, uint32_t doc_id) {
	if ((*pl)->size + 1 >= (*pl)->capacity) {
		ii_posting_list* old = *pl;
		size_t new_cap = old->capacity * 2;
		ii_posting_list* new = krealloc(*pl, POSTING_LIST_SIZE(old->capacity), POSTING_LIST_SIZE(new_cap));
		if (!new)
			return 1;
		*pl = new;
		if (!*pl)
			return 1;
		(*pl)->capacity = new_cap;
	}
	(*pl)->data[(*pl)->size++] = doc_id;
	return 0;
}

int add(inverted_index* idx, uint32_t doc_id, const char* doc, size_t doc_size) {
	if (idx->compressed)
		return 1;

	char token[TOK_LEN];
	int tok_len = 0;
	for (size_t i = 0; i <= doc_size; ++i) {
		if (i == doc_size || !is_word(tolower(doc[i]))) {
			if (tok_len == 0)
				continue;
			token[tok_len] = 0;

			// process token
			ii_posting_list** pl = find_posting_list(idx, token, 1);
			if (!pl) {
				goto fail;
			}
			if ((*pl)->size == 0 || (*pl)->data[(*pl)->size - 1] != doc_id)
				if (append_posting_list(pl, doc_id)) {
					goto fail;
				}

			tok_len = 0;
			continue;
		}
		if (tok_len + 2 <= TOK_LEN) {    // space for null termination
			token[tok_len++] = (char)tolower(doc[i]);
		}
	}
	return 0;
fail:
	return 1;
}

void sort_uint32(uint32_t* a, size_t size) {
	for (size_t i = 1; i < size; ++i) {
		size_t j = i;
		while (j && a[j - 1] > a[j]) {
			uint32_t tmp = a[j - 1];
			a[j - 1] = a[j];
			a[j] = tmp;
			j--;
		}
	}
}

void sort_pls(ii_posting_list** a, size_t size) {
	for (size_t i = 1; i < size; ++i) {
		size_t j = i;
		while (j && a[j] && (!a[j - 1] || strcmp(a[j - 1]->token, a[j]->token) > 0)) {
			ii_posting_list* tmp = a[j - 1];
			a[j - 1] = a[j];
			a[j] = tmp;
			j--;
		}
	}
}

size_t ceillog2(size_t x) {
	size_t i = 0;
	while (x > (1ull << i))
		++i;
	return i;
}

size_t interpolative_size(uint32_t* data, uint32_t l, uint32_t r) {
	if (l >= r)
		return 0;
	uint32_t m = l + (r - l) / 2;
	uint32_t lo = data[l - 1] + m - l + 1;  // min possible value
	uint32_t hi = data[r] - r + m;      // max possible value
	return ceillog2(hi - lo + 1)
		+ interpolative_size(data, l, m)
		+ interpolative_size(data, m + 1, r);
}

int write_u32(char** buf, char* end, uint32_t x) {
	if (*buf + 4 > end)
		return 1;
	*((uint32_t*)*buf) = x;
	*buf += 4;
	return 0;
}

int write_str(char** buf, char* end, char* str) {
	if (*buf + strlen(str) + 1 > end)
		return 1;
	strcpy(*buf, str);
	*buf += strlen(str) + 1;
	return 0;
}

int write_bit(char** buf, size_t* bitoffset, char* end, int bit) {
	if (*buf > end) {
		return 1;
	}
	**buf &= ~(1 << *bitoffset);  // clear bit
	**buf |= bit << (*bitoffset);   // set it
	(*bitoffset)++;
	if (*bitoffset == 8) {
		*bitoffset = 0;
		(*buf)++;
	}
	return 0;
}

int write_interpolative_bits(char** buf, size_t* bitoffset, char* end, uint32_t* data, uint32_t l, uint32_t r)
{
	if (l == r)
		return 0;
	uint32_t m = l + (r - l) / 2;
	uint32_t lo = data[l - 1] + m - l + 1; // min possible value
	uint32_t range = data[r] - r + m - lo;
	uint32_t value = data[m] - lo;
	while (value) {
		if (write_bit(buf, bitoffset, end, value & 1))
			return 1;
		value >>= 1;
		range >>= 1;
	}
	while (range) {
		if (write_bit(buf, bitoffset, end, 0))
			return 1;
		range >>= 1;
	}
	if (write_interpolative_bits(buf, bitoffset, end, data, l, m)) return 1;
	if (write_interpolative_bits(buf, bitoffset, end, data, m + 1, r)) return 1;
	return 0;
}

int write_interpolative(char** buf, char* end, uint32_t* data, uint32_t l, uint32_t r)
{
	size_t bitoffset = 0;
	if (write_interpolative_bits(buf, &bitoffset, end, data, l, r))
		return 1;
	if (bitoffset)
		(*buf)++;
	return 0;
}

inverted_index* build(inverted_index* idx) {
	if (idx->compressed)
		return 0;
	sort_pls(idx->table->slots, idx->table->capacity);

	size_t offset = 8 + 4 * (size_t)idx->table->size;
	size_t needed = offset;

	for (size_t i = 0; i < idx->table->size; ++i) {
		ii_posting_list* pl = idx->table->slots[i];
		sort_uint32(pl->data, pl->size);
		//LOG("i=%lu expected offset=%lu\n", i, needed);
		needed += strlen(pl->token) + 1 + 2 * 4;

		if (pl->size > 0x1000000)
			return 0;

		if (pl->size > 1)
			needed += 4;
		if (pl->size > 2) {
			// TODO remove +1 (also below in call to write_interpolative)
			needed += (interpolative_size(pl->data, 1, (uint32_t)pl->size - 1) + 7) / 8;
		}
	}
	if (needed > 0x10000)
		return 0;
	char* compressed_index = kalloc(needed);
	if (!compressed_index)
		return 0;

	((uint32_t*)compressed_index)[0] = 1;
	// TODO truncation bad?
	((uint32_t*)compressed_index)[1] = (uint32_t)idx->table->size;

	char* p = compressed_index + offset;
	char* end = compressed_index + needed;

	for (size_t i = 0; i < idx->table->size; ++i) {
		//LOG("i=%lu offset=%lu\n", i, p - compressed_index);

		ii_posting_list* pl = idx->table->slots[i];

		if (p > compressed_index + 0x10000)
			return 0;
		((uint32_t*)compressed_index)[i + 2] = (uint32_t)(p - compressed_index);

		if (write_str(&p, end, pl->token)) {
			//kfree(compressed_index);
			return 0;
		}
		if (write_u32(&p, end,(uint32_t)pl->size)) {
			//kfree(compressed_index);
			return 0;
		}
		if (write_u32(&p, end, pl->data[0])) {
			//kfree(compressed_index);
			return 0;
		}
		if (pl->size > 1)
			if (write_u32(&p, end, pl->data[pl->size - 1])) {
				//kfree(compressed_index);
				return 0;
			}
		if (pl->size > 2)
			if (write_interpolative(&p, end, pl->data, 1, (uint32_t)pl->size - 1)) {
				//kfree(compressed_index);
				return 0;
			}
	}
	return (inverted_index*)compressed_index;
}