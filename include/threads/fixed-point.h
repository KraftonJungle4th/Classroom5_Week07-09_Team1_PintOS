#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

/* 17.14 고정소수점 표현에서 사용하는 기본값 f */
#define F (1 << 14)

/* 정수를 고정소수점으로 변환 */
#define int_to_fp(n) ((n) * F)

/* 고정소수점을 정수로 변환 (0으로 반올림) */
#define fp_to_int_zero(x) ((x) / F)

/* 고정소수점을 정수로 변환 (가장 가까운 정수로 반올림) */
#define fp_to_int_nearest(x) ((x) >= 0 ? ((x) + F / 2) / F : ((x) - F / 2) / F)

/* 두 고정소수점 수의 합 */
#define add_fp(x, y) ((x) + (y))

/* 두 고정소수점 수의 차 */
#define sub_fp(x, y) ((x) - (y))

/* 고정소수점 수와 정수의 합 */
#define add_fp_int(x, n) ((x) + (n) * F)

/* 고정소수점 수에서 정수를 뺌 */
#define sub_fp_int(x, n) ((x) - (n) * F)

/* 고정소수점 수와 다른 고정소수점 수의 곱셈 */
#define mul_fp(x, y) ((int64_t)(x) * (y) / F)

/* 고정소수점 수와 정수의 곱셈 */
#define mul_fp_int(x, n) ((x) * (n))

/* 고정소수점 수를 다른 고정소수점 수로 나눔 */
#define div_fp(x, y) ((int64_t)(x) * F / (y))

/* 고정소수점 수를 정수로 나눔 */
#define div_fp_int(x, n) ((x) / (n))

#endif /* threads/fixed-point.h */
