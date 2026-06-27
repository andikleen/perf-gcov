/*
 * Standalone test binary 1 for multi-binary gcov tests
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

static volatile int a1 = 10000, b1 = 100000, c1;

static int compute1(int n)
{
	int sum = 0;
	int i;

	for (i = 0; i < n; i++) {
		if (i % 3 == 0)
			sum += i;
		else if (i % 3 == 1)
			sum -= i;
		else
			sum *= 1;
	}
	return sum;
}

static void helper1(void)
{
	c1 = a1 / b1;
}

int main(void)
{
	int i;

	for (i = 0; i < 50000000; i++) {
		helper1();
		compute1(10);
	}
	return 0;
}
