# Third-party notices

The credential serialization implementation in `src/provider.cpp` follows and adapts the packing and password-protection approach in Microsoft's V2 Credential Provider sample:

https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/CredentialProvider

Copyright (c) Microsoft Corporation. Licensed under MIT; the text is included in `LICENSE-Microsoft.txt`. The implementation has been changed to use scheduled, expiring, single-use requests and a single existing local console user.

The included Windows binaries were built with LLVM-MinGW 20261006 and statically link LLVM libc++, libc++abi, libunwind and the MinGW-w64 runtime. LLVM's Apache 2.0 license with LLVM exceptions is included in `LICENSE-LLVM.txt`; the MinGW-w64 notices are included in `LICENSE-MinGW.txt`.

LLVM-MinGW: https://github.com/mstorsjo/llvm-mingw

MinGW-w64: https://www.mingw-w64.org/
