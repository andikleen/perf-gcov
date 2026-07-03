
volatile int x, y, z;

__attribute__((noinline, noipa)) int target1(int arg)
{
	return x += arg;
}

__attribute__((noinline, noipa)) int target2(int arg)
{
	return y += arg;
}

__attribute__((noinline, noipa)) int target3(int arg)
{
	return z += arg;
}

typedef int (*tptr_t)(int);

tptr_t tptr[] = {
	target1,
	target2,
	target3,
};

volatile int w;

int main()
{
	int i;

	for (i = 0; i < 100000; i++) {
		w += (tptr[i % 3])(i % 10);
	}
	return 0;
}
