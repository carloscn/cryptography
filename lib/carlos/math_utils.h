#ifndef _MATH_UTILS_H
#define _MATH_UTILS_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>

bool mutils_is_prime(size_t num);
size_t mutils_gcd(size_t m, size_t n);
size_t mutils_ex_gcd(size_t a, size_t b, size_t *x, size_t *y);
size_t mutils_ex_gcd_inv(size_t a, size_t b);

#endif /* _MATH_UTILS_H */