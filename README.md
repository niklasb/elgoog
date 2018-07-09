# elgoog / searchme

This is a kernel pwnable for Windows 10. Exploit works on RS4 with medium integrity. In RS3 low integrity was enough, because HMValidateHandle could be used to leak palette object addresses.

It was called "elgoog2" at 34C3 CTF, but had an unintended bug. Brought back for WCTF 2018, as "searchme".

We have a vulnerable kernel driver that deals with document indexing. It lets
you build an inverted index by adding documents incrementally to an index, and
then compressing the posting lists using an [binary interpolative code][1],
of course all in kernel land, via driver IOCTLs. Data structures are stored on
the paged kernel pool.


## Bug

While adding documents to an inverted list, the code [tries to keep the list
unique][2] but clearly this is broken because we can just add the same document
twice with one other document in between.

Then we can trigger an awkward mismatch between the [size computation][3] and
[actual implementation][4] of the interpolative encoding, which allows us to
write more than the size that was computed. So we can make almost all of the
`write_XXX` functions receive an out-of-bounds `*buf` pointer. For `write_bit`,
this is a problem, because the bounds check is incorrect, and hence we can
overflow by one byte.

The primitive we can obtain from this bug is an arbitrary off-by-one overflow
in the paged kernel pool, where some NT data structures but also all of the
elgoog-specific data structures reside.


## Intended solution

The intended solution was to corrupt the `PrevSize` field of a `_POOL_HEADER` and
trigger a backward consolidation, leading to overlapping pool chunks. With that
we can corrupt elgoog's own data structures that contain pointers, and achieve
an arbitrary write. Refer to the [exploit code][5] for details.

We then use that to overwrite our own `SEP_TOKEN_RPIVLEGES` and give us debug
privileges, which allows us to inject code into `winlogon.exe`.


[1]: https://link.springer.com/article/10.1023/A:1013002601898
[2]: https://github.com/niklasb/elgoog/blob/master/searchme/index.c#L124
[3]: https://github.com/niklasb/elgoog/blob/master/searchme/index.c#L172
[4]: https://github.com/niklasb/elgoog/blob/master/searchme/index.c#L213
[5]: https://github.com/niklasb/elgoog/blob/master/searchme_pwn/pwn.cpp#L193
