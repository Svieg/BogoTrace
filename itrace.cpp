/*BEGIN_LEGAL
Intel Open Source License

Copyright (c) 2002-2016 Intel Corporation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
#include <stdio.h>
#include <ctype.h>
#include <iostream>
#include <fstream>
#include <vector>
#include "pin.H"

std::ofstream TRACE_FILE;

std::vector<string> REG_VECTOR;


// Print disas'ed instruction and context.
VOID print_context_instruction(const CONTEXT* ctxt, std::string disassembled_instr, UINT64 ip) {
        for (int i = 3; i < 11; i++) {
            REG reg = REG(i);
            TRACE_FILE << REG_StringShort(reg) << " : " << std::hex << PIN_GetContextReg(ctxt, reg) << std::endl;
        }
        TRACE_FILE << REG_StringShort(REG_INST_PTR) << " : " << std::hex << PIN_GetContextReg(ctxt, REG_INST_PTR) << std::endl;
        TRACE_FILE << "==========================================================" << std::endl;
        TRACE_FILE << ip << " : " <<disassembled_instr << std::endl;
        TRACE_FILE << "==========================================================" << std::endl;
}


// Prints eax value on ret.
VOID print_ret(INT32 eax) {

    TRACE_FILE << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
    TRACE_FILE << "Returns 0x" << eax << std::endl;
    TRACE_FILE << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;

}

// Prints value, address and length of memory writes.
VOID print_mem_write(UINT64* write_addr, UINT32 write_len) {

    TRACE_FILE << "**********************************************************" << std::endl;
    TRACE_FILE << "Writes 0x" << std::hex << *write_addr << " to " << std::hex << write_addr << std::endl;
    TRACE_FILE << "Wrote " << write_len << " bytes" << std::endl;
    TRACE_FILE << "**********************************************************" << std::endl;

}

// Prints value, address and length of memory reads.
VOID print_mem_read(UINT64* read_addr, UINT32 read_len) {

    TRACE_FILE << "**********************************************************" << std::endl;
    TRACE_FILE << "Reads 0x" << std::hex << *read_addr << " from " << std::hex << read_addr << std::endl;
    TRACE_FILE << "Read " << read_len << " bytes" << std::endl;
    TRACE_FILE << "**********************************************************" << std::endl;

}

// Prints the value of the first four call args.
VOID print_call_args(UINT64* arg_0, UINT64* arg_1, UINT64* arg_2, UINT64* arg_3) {
    //int i = 0;
    TRACE_FILE << "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" << std::endl;
    TRACE_FILE << "ARG_0: " << arg_0 << std::endl;
    TRACE_FILE << "ARG_1: " << arg_1 << std::endl;
    TRACE_FILE << "ARG_2: " << arg_2 << std::endl;
    TRACE_FILE << "ARG_3: " << arg_3 << std::endl;
    TRACE_FILE << "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" << std::endl;

}

VOID print_jmp_eflags(UINT64 rflags) {

    TRACE_FILE << "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" << std::endl;
    TRACE_FILE << "RFLAGS: " << rflags << std::endl;
    TRACE_FILE << "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" << std::endl;

}


// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
    // Insert a call to printip before every instruction, and pass it the IP
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)print_context_instruction,
                    IARG_CONST_CONTEXT,
                    IARG_PTR, new string(INS_Disassemble(ins)),
                    IARG_REG_VALUE, REG_INST_PTR,
                    IARG_END);

    if (INS_IsMemoryRead(ins) and !INS_IsStackRead(ins)) {
        UINT32 mem_op_count = INS_MemoryOperandCount(ins);
        UINT32 read_len = INS_MemoryReadSize(ins);
        for (UINT32 i = 0; i < mem_op_count; i++) {
            if (INS_MemoryOperandIsRead(ins, i)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)print_mem_read,
                                IARG_MEMORYOP_EA, i,                            // read address
                                IARG_UINT32, read_len,                         // Length of the read
                                IARG_END);
            }
        }
    }

    else if (INS_IsMemoryWrite(ins) and !INS_IsStackWrite(ins)) {
        UINT32 mem_op_count = INS_MemoryOperandCount(ins);
        UINT32 write_len = INS_MemoryWriteSize(ins);
        for (UINT32 i = 0; i < mem_op_count; i++) {
            if (INS_MemoryOperandIsWritten(ins, i)) {
                INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)print_mem_write,
                                IARG_MEMORYOP_EA, i,                            // Write address
                                IARG_UINT32, write_len,                         // Length of the write
                                IARG_END);
            }
        }
    }

    else if (INS_IsRet(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)print_ret,
                        IARG_REG_VALUE, REG_EAX,                                // Value of the eax register
                        IARG_END);
    }

    else if (INS_IsCall(ins)) {

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)print_call_args,
                        IARG_FUNCARG_CALLSITE_VALUE, 0,
                        IARG_FUNCARG_CALLSITE_VALUE, 1,
                        IARG_FUNCARG_CALLSITE_VALUE, 2,
                        IARG_FUNCARG_CALLSITE_VALUE, 3,
                        IARG_END);

    }

    else if (INS_IsBranch(ins)) {
        PREDICATE pred = INS_GetPredicate(ins);
        if (pred == PREDICATE_ALWAYS_TRUE)
            std::cout << INS_Disassemble(ins) << std::endl;
        if (INS_BranchTakenPrefix(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)print_jmp_eflags,
                            IARG_REG_VALUE, REG_RFLAGS,
                            IARG_END);
        }

    }

}

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    TRACE_FILE.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    PIN_ERROR("This Pintool prints the IPs of every instruction executed\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    TRACE_FILE.open("itrace.out");

    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();


    return 0;
}
