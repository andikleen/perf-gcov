/*
 * Standalone test binary 3 for multi-binary gcov tests
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

static volatile int a3 = 1000, b3 = 999, c3;

static int compute3(int n)
{
	int xor = 0;
	int i;

	for (i = 0; i < n; i++) {
		xor ^= i;
		if (xor > 1000000)
			xor = 0;
	}
	return xor;
}

static void helper3(void)
{
	c3 = a3 - b3;
}

int main(void)
{
	int i;

	for (i = 0; i < 50000000; i++) {
		helper3();
		compute3(30);
	}
	return 0;
}
