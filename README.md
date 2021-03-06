# BogoTrace
An non-optimized tracer that works everywhere Pin can go. Based on the itrace.cpp manual example.

## How to get schwifty

- Download Pin on Intel's website
- Put the `itrace.cpp` file in pin-3.0-76991-gcc-linux/source/tools/ManualExamples/ to replace the default itrace.cpp
- run `make PIN_ROOT=../../.. CXX="g++ -std=c++0x"` from the ManualExamples directory.
- Run `<path to pin>/pin -t <path to ManualExamples>/obj-intel64/itrace.so -- <binary to trace>`
- Output is in itrace.out

## Output


### Disassembled instruction and its context

```
rdi : 0
rsi : 0
rbp : 0
rsp : 7ffc3f8b2af0
rbx : 0
rdx : 0
rcx : 0
rax : 0
rip : 7f52d3a87cc0
==========================================================
7f52d3a87cc0 : mov rdi, rsp
==========================================================
```

### Call args

```
==========================================================
7f52d3a87cc3 : call 0x7f52d3a8bc00
==========================================================
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ARG_0: 0x00007ffc3f8b2af0
ARG_1: 0x0000000000000000
ARG_2: 0x0000000000000000
ARG_3: 0x0000000000000000
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### Memory writes

```
==========================================================
7f52d3a8bc48 : mov qword ptr [rip+0x221d89], r14
==========================================================
**********************************************************
Writes 0x7f52d3a87000 to 0x00007f52d3cad9d8
Wrote 8 bytes
**********************************************************
```

### Memory reads

```
==========================================================
7f52d3a8bca7 : mov rax, qword ptr [rdx]
==========================================================
**********************************************************
Reads 0x4 from 0x00007f52d3cace80
Read 8 bytes
**********************************************************
```

### Return value

```
==========================================================
7f52d3a928dd : ret·
==========================================================
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Returns 0xd3a8731c
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
```
