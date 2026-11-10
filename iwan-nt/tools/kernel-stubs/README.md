# Local kernel-header stubs

These headers are **not** a WDK replacement. They declare only the kernel and
WSK surface that the iWAN NT driver currently uses, so that a plain Linux host
can run a parser (`gcc -fsyntax-only`) over the driver sources before the real
WDK build runs in CI.

What this catches: syntax errors, undeclared identifiers, wrong argument counts
and types for the declared surface, declaration-after-statement, shadowing, and
obvious unused variables.

What this cannot catch: real WDK signatures, WSK/NDIS semantics, SAL/annotation
correctness, IRQL rules, PREfast/SDV findings, and INF/INF verification.

Never rely on a passing stub check as evidence that the driver compiles or is
correct. It is a fast pre-filter only.

Usage:

    bash tools/check-syntax.sh

The stub headers must grow with the driver. If a stub signature disagrees with
the WDK, fix the stub to match the WDK, not the driver.
