#define TRIP 100000000

__attribute__((noinline, noipa))
static void effect_1()
{
}

__attribute__((noinline, noipa))
static void effect_2()
{
}

__attribute__((noinline, noipa))
static int foo()
{
	return 5;
}

__attribute__((noinline, noipa))
int use(int x)
{
	volatile int y = x;
	return x;
}

extern void global();

int main()
{
	for (int i = 0; i < TRIP; i++) {
		if (use(i) < TRIP / 2) {
			global();
		}
		if (foo() < 5) {
			effect_1();
		} else {
			effect_2();
		}
	}
	return 0;
}
