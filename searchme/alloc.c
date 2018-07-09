#include "alloc.h"

void* kalloc(size_t sz) {
	void * res = ExAllocatePoolWithTag(PagedPool, sz, TAG);
	if (!res)
		return 0;
	memset(res, 0, sz);
	//LOG("allocated %llx bytes at %p\n", sz, res);
	return res;
}

void kfree(void* ptr) {
	if (!ptr)
		return;
	//LOG("free %p\n", ptr);
	ExFreePool(ptr);
}

void* krealloc(void* old, size_t old_sz, size_t new_sz) {
	if (new_sz <= old_sz)
		return old;
	void* new = kalloc(new_sz);
	if (!new)
		return 0;
	memcpy(new, old, old_sz);
	//kfree(old);
	return new;
}