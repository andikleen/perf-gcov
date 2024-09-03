int a, b, c;

int main(void)
{
	int i, j;

	void *targets[] = { &&l1, &&l2, &&l3 };

	for (j = 0; j < 10000000; j++) 
		for (i = 0; i < 20; i++) {
			goto *targets[i % 3];
			l1:
				a++;
				continue;
			l2:
				b++;
				continue;
			l3:
				c++;
				continue;
		}
	return 0;
}

