# libxmp-lite-ps2-mread-stack-buffer-overflow-poc
Overview

This repository contains a minimal proof of concept (PoC) demonstrating a stack-buffer overflow in a reproduction of the mread() implementation from tatokis/libxmp-lite-ps2.
vulnerable code is at:
https://github.com/tatokis/libxmp-lite-ps2/blob/master/src/memio.c

vulnerable code snippet:
size_t mread(void *buf, size_t size, size_t num, MFILE *m)
{
    size_t should_read = size * num;
    ptrdiff_t can_read = CAN_READ(m);

    if (!size || !num || can_read <= 0) {
        return 0;
    }

    if (should_read > can_read) {
        should_read = can_read;
    }

    /* Vulnerable: destination buffer capacity is not validated */
    memcpy(buf, m->start + m->pos, should_read);
    m->pos += should_read;

    return should_read / size;
}

The issue occurs when the number of bytes copied by mread() exceeds the capacity of the destination buffer. The function limits the copy length according to the remaining input size but does not receive or validate the destination buffer's capacity.

Affected component under investigation: src/memio.c, function mread().

Vulnerability type: Stack-based Buffer Overflow (CWE-121).

Root Cause

The relevant operation is:

size_t should_read = size * num;
ptrdiff_t can_read = CAN_READ(m);

if (should_read > can_read) {
    should_read = can_read;
}

memcpy(buf, m->start + m->pos, should_read);

The copy length is bounded by the remaining source data, but not by the actual capacity of buf.

Consequently, if the destination buffer is smaller than the final value of should_read, memcpy() writes beyond the destination buffer's bounds.

The multiplication size * num should also be checked for overflow. However, the parameters used in this PoC do not cause integer overflow; the demonstrated failure is a destination-buffer bounds violation.

Proof of Concept

The file overflow1.c contains a standalone reproducer based on the relevant mread() logic.

The PoC creates:

A 256-byte source buffer.

A 128-byte stack destination buffer.

Read parameters that result in a 256-byte copy after the source-length limit is applied.

The resulting copy exceeds the destination buffer by 128 bytes.

Reproduction

Requirements

GCC or a compatible C compiler

AddressSanitizer support

Build

gcc -O0 -g \
    -fsanitize=address \
    -fno-omit-frame-pointer \
    overflow1.c -o overflow_poc

Run

./overflow_poc

Expected result

AddressSanitizer should report a stack-buffer overflow similar to:

ERROR: AddressSanitizer: stack-buffer-overflow

WRITE of size 256

... in mread .../overflow1.c:34
... in main .../overflow1.c:67

'out' ... [16, 144)
Memory access at offset 144 overflows this variable

Exact addresses, line numbers, and diagnostic formatting may differ between builds and environments.

Impact

A stack-buffer overflow can corrupt adjacent stack memory and may cause program termination, memory corruption, or potentially more serious consequences depending on the execution context and platform.

The practical impact on the upstream project depends on whether an affected call path allows input data to influence the read parameters while providing a destination buffer that is smaller than the number of bytes copied.

This standalone PoC demonstrates the memory-safety failure under the supplied conditions. It does not, by itself, establish remote exploitability or prove that an ordinary module file can trigger the issue through the upstream application's normal parsing path.

Suggested Remediation

Validate multiplication before calculating size * num, for example by checking num > SIZE_MAX / size when size is nonzero.

Ensure the requested copy length never exceeds the destination buffer's actual capacity.

Update the API or its callers to provide and validate the destination buffer size.

Add regression tests for oversized read requests and insufficient destination capacity.

Checking multiplication overflow alone is insufficient to prevent this PoC's demonstrated out-of-bounds write.

Environment

Record the environment used for verification:

Operating system: [Specify OS and version]

Architecture: [Specify 32-bit or 64-bit]

Compiler: [Specify compiler and version]

Sanitizer: AddressSanitizer

Tested upstream commit: [Insert exact commit hash]

Scope and Disclosure

This repository is intended to support vulnerability analysis and responsible disclosure.

The upstream affected revision and the reachability of the vulnerable condition through normal application inputs should be verified separately before drawing conclusions about the impact on the original project.

No CVE identifier is claimed or implied by this repository unless one is subsequently assigned.
