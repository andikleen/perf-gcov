volatile int x,y,a,b,c,d,e,z;
int main(void)
{
	long i;
        for (i = 0; i < 8000000; i++) {
		x*=23; y*=23; z*=23; a*=23; b*=23; c*=23; d*=23; e*=23;
	}

}
