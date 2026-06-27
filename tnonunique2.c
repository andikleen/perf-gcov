/*
 * Test binary with non-unique static symbols (part 2)
 * Shares static symbol names with tnonunique1.c, compiled WITHOUT LTO.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

__attribute__((noinline, noipa)) static int compute(int n) {
	int prod = 1;
	for (int i = 1; i < n; i++)
		prod *= 2;
	return prod;
}

__attribute__((noinline, noipa)) static void helper(int *p) {
	*p = compute(50);
}

int entry_b(void) {
	int x = 1;
	helper(&x);
	return x;
}
