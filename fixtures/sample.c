#include <stdio.h>
__attribute__((noinline)) int calculate_score(int value) { return value * 7 + 3; }
int main(int argc, char **argv) { printf("Ghidra Web static analysis fixture: %d\n", calculate_score(argc)); return 0; }
