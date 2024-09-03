
volatile int a = 10000, b = 100000, c;

__attribute__((noinline)) void f2(void)
{
	c = a / b;
}

__attribute__((noinline)) void f1(void)
{
	f2();
	f2();
}

__attribute__((noinline)) void f3(void)
{
	f2();
	f2();
}

static void f3wrap(void) { f3(); } 
static void f1wrap(void) { f1(); }

int main(void)
{
	int i;
	for (i = 0; i < 50000000; i++) {
		f1wrap();
		f3wrap();
	}
	return 0;
}
