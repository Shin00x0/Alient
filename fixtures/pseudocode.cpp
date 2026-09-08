namespace ghidra_web_fixture {
__attribute__((noinline)) int score(int value) {
    if (value < 0) return -1;
    return value * 7 + 3;
}
}
int main(int argc, char **) { return ghidra_web_fixture::score(argc); }
