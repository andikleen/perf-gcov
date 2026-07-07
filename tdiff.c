/* Test program for gcov-diff: two code paths based on argv.
   Compile with -g -O2, run with perf record -b, then gcov.py to profile. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    int fast = (argc > 1 && strcmp(argv[1], "fast") == 0);
    volatile long sum = 0;
    for (int i = 0; i < 1000000; i++) {
        if (fast) {
            sum += i;
        } else {
            sum += i * i;
        }
    }
    printf("sum = %ld\n", sum);
    return 0;
}
