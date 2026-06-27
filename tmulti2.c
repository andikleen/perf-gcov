/*
 * Standalone test binary 2 for multi-binary gcov tests
 */

static volatile int a2 = 50000, b2 = 200000, c2;

static int compute2(int n)
{
	int prod = 1;
	int i;

	for (i = 1; i < n; i++) {
		if (i % 2 == 0)
			prod += i;
		else
			prod -= 1;
	}
	return prod;
}

static void helper2(void)
{
	c2 = a2 * b2;
}

int main(void)
{
	int i;

	for (i = 0; i < 50000000; i++) {
		helper2();
		compute2(20);
	}
	return 0;
}
