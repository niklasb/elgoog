#pragma once

#include <wdm.h>

typedef FAST_MUTEX mutex;
void mutex_init(mutex* mx);
void mutex_acquire(mutex* mx);
void mutex_release(mutex* mx);