#include "math_utils.h"

bool mutils_is_prime(size_t num)
{
    size_t i = 0;

	for (i = 2; i <= (size_t)sqrt(num); i ++) {
		if (0 == (num % i)) {
            return false;
        }
	}

	return true;
}

size_t mutils_gcd(size_t m, size_t n)
{
#define METHOD_N 1
#if METHOD_N
    size_t r = 0;

    while (n > 0) {
        r = m % n;
        m = n;
        n = r;
    }
    return n;
#else  /* METHOD_N */
	if(!n)
	    return m;
	else
	    return mutils_gcd(n, m % n);
#endif /* METHOD_N */
}

size_t mutils_ex_gcd(size_t a, size_t b, size_t *x, size_t *y)
{
    size_t d = 0, t = 0;

    if (b == 0) {
        x = 1, y = 0;
        return a;
    }
    d = mutils_ex_gcd(b, a % b, x, y), t = x;
    *x = *y;
    *y = t - a / b * (*x);
    return d;
}

size_t mutils_ex_gcd_inv(size_t a, size_t b)
{
    size_t x = 0, y = 0;
    mutils_ex_gcd(a, b, &x, &y);
    return x;
}

size_t mutils_pow_mod(size_t a, size_t n, size_t mod)
{
    size_t ret = 1;
    while (n) {
        if(n & 1) ret = ret * a % mod;
        a = a * a % mod;
        n >>= 1;
    }
    return ret;
}

size_t mutils_fermat_inv(size_t a, size_t b)
{
    return mutils_pow_mod(a, b - 2, b);
}