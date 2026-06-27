/*
 * Test binary with non-unique static symbols (part 1)
 * Shares static symbol names with tnonunique2.c, compiled WITHOUT LTO.
 */

__attribute__((noinline, noipa)) static int compute(int n)
{
	int sum = 0;
	for (int i = 0; i < n; i++)
		sum += i;
	return sum;
}

extern int entry_b(void);

__attribute__((noinline, noipa)) static void helper(int *p)
{
	*p = compute(100);
}

int entry_a(void)
{
	int x = 0;
	helper(&x);
	return x;
}

volatile int val;

int main(void)
{
	volatile int r = 0;
	for (int i = 0; i < 50000; i++)
		r += entry_a() + entry_b();
	val = r;
	return 0;
}
