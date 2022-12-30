#include <math.h>

double calc_std_dev(double x, double x2, int n) {
	double mean = x / n;
	double variance = x2 / n - pow(mean, 2);
	double std_dev = sqrt(variance);
	return std_dev;
}