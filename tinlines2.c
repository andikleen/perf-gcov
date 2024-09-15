
volatile int a = 10000, b = 100000, c;

static void f2(void)
{








	c = a / b;
}

static void f1(void)
{
	f2();
	f2();
}

void f3(void)
{
	f2();
	f2();
}

static void f3wrap(void) { f3(); } 
static void f1wrap(void) { f1(); }

int main(void)
{
	int i;
	for (i = 0; i < 90000000; i++) {
		f1wrap();
		f3wrap();
	}
	return 0;
}
