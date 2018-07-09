#include "mutex.h"

void mutex_init(mutex* mx) {
	ExInitializeFastMutex(mx);
}
void mutex_acquire(mutex* mx) {
	ExAcquireFastMutex(mx);
}
void mutex_release(mutex* mx) {
	ExReleaseFastMutex(mx);
}