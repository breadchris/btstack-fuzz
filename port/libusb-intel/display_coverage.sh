#!/bin/bash
LLVM_PROFILE_FILE="gap_inquiry.profraw" sudo -E bash -c './gap_inquiry'
llvm-profdata merge -sparse gap_inquiry.profraw -o gap_inquiry.profdata
llvm-cov show btstack_util.o -instr-profile=gap_inquiry.profdata
