/*
 * Shared library for multi-binary gcov tests
 */

int tlib_compute(int n)
{
	int sum = 0;
	int i;

	for (i = 0; i < n; i++) {
		if (i % 2 == 0)
			sum += i;
		else
			sum -= i;
	}
	return sum;
}
