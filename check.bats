#!/usr/bin/env bats

load test_helper

@test "base-minimal-ok" {
    run gcc tests/nostart.c -nostdlib -static -e debut -o tests/nostart
    run ./alcatraz $(./ask-gcc read) tests/nostart    
    checki 0 <<FIN
Hello, World!
0
FIN
}

@test "base-minimal-not-ok" {
    run ./alcatraz $(./ask-gcc exit) tests/nostart
    checki 1 <<FIN
Hello, World!
31
FIN
}

@test "base-minimal-not-not-ok" {
    run ./alcatraz $(./ask-gcc write) tests/nostart
    check 1 "31"
}

@test "base-fork" {
    run ./alcatraz $(./ask-gcc fork) tests/nostart    
    checki 0 <<FIN
Hello, World!
0
FIN
}

@test "base-execve" {
    run ./alcatraz $(./ask-gcc execve) tests/nostart
    check 1 "31"
}

@test "inter-syscall-1" {
    run ./alcatraz $(./ask-gcc fork) /bin/sh -c "echo azul ; echo azul | wc -c"
    checki 0 <<FIN
azul
5
0
FIN
}

@test "inter-syscall-2" {
    run ./alcatraz $(./ask-gcc fork),$(./ask-gcc clone) /bin/sh -c "echo azul ; echo azul | wc -c"
    checki 1 <<FIN
azul
31
FIN
}

@test "inter-syscall-3" {
    run ./alcatraz $(./ask-gcc fork),$(./ask-gcc clone),$(./ask-gcc brk) /bin/sh -c "echo azul ; echo azul | wc -c"
    check 1 "31"
}
