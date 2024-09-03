volatile int a, b, c;

int main(void)
{
	int i, j;

	for (j = 0; j < 10000000; j++) 
		for (i = 0; i < 20; i++)
			switch (i % 3) {
			case 0:
				a++;
				break;
			case 1:
				b++;
				break;
			case 2:
				c++;
				break;
			}
	return 0;
}

