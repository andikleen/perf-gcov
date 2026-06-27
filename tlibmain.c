/*
 * Main program that links against tlib for multi-binary gcov tests
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>

extern int tlib_compute(int n);

int main(int argc, char **argv)
{
	int n = argc > 1 ? atoi(argv[1]) : 100;
	int result = 0;
	int i;

	for (i = 0; i < n; i++)
		result += tlib_compute(i);
	printf("result=%d\n", result);
	return 0;
}
