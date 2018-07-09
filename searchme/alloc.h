#pragma once

#include "common.h"
void* kalloc(size_t sz);
void kfree(void* ptr);
void* krealloc(void* old, size_t old_sz, size_t new_sz);