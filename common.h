#ifndef COMMON
#define COMMON
#include <stdint.h>
#include <string.h>
#include <stdbool.h>


#define galua_mul(x,y)      gmul_table[x*256+y]

typedef enum
{
    K_64  = 64,
    K_128 = 128,
    K_256 = 256,
    K_384 = 384,
    K_512 = 512
}tkalina_block_len_bits;

#define _rotate_func(i,o,n,l) \
    memcpy(o, i+n, l-n);\
    memcpy(o+(l-n), i, n);

const unsigned kalina_tables_num=4;
const unsigned kalina_V_num=8;
const unsigned kalina_table_chars_num=256;


#define bits_to_bytes(b) (b>>3)
#define kalina_kd_init_val(l,k) (((l+k)/64)+1)

typedef uint16_t tkalina_128_kb ;

const unsigned kalina_128_key_len_bytes=bits_to_bytes(128);
const unsigned kalina_256_key_len_bytes=bits_to_bytes(256);
const unsigned kalina_512_key_len_bytes=bits_to_bytes(512);

#define kalina_128_block_len_bytes kalina_128_key_len_bytes

const unsigned kalina_128_key_len_bytes_div_2=bits_to_bytes(128)/2;
const unsigned kalina_128_64_key_len=bits_to_bytes(128)/8;


void kalina_s_block(void *buf, void *s_blocks, const unsigned size);
void kalina_add_mod64(void *a, void *b, const uint8_t c);
void kalina_ksi(void *in, void *out, const uint8_t c);
void kalina_lsh_64(void *b, unsigned num_8b_blocks, uint8_t n);
void kalina_xor(void *a, void *b, const uint8_t c);
void kalina_rol_64(void *b, unsigned num_8b_blocks, uint8_t n);


/**
 * Виконує множення двох чисел над полем Галуа вектору 0x11d
 * @param a  перший аргумент
 * @param b  другий аргумент
 * @return результат множення a*b над полем Галуа
 */
uint8_t galua_mul_forw(const uint8_t a, const uint8_t b);

#define ksitau(tb, x1,z1,x2,z2, t1,t2,t3,t4,t5,t6,t7,t8)    (uint64_t)((((uint64_t)tb[t1*256+( (x1>>(z1*8) ) & 0xFF)])<<(0*8)) | (((uint64_t)tb[t2*256+((x1>>(z1*8)) & 0xFF)])<<(1*8)) | (((uint64_t)tb[t3*256+((x1>>(z1*8) ) & 0xFF)])<<(2*8)) | (((uint64_t)tb[t4*256+((x1>>(z1*8)) & 0xFF)])<<(3*8)) |\
                                                                      (((uint64_t)tb[t5*256+( (x2>>(z2*8) ) & 0xFF)])<<(4*8)) | (((uint64_t)tb[t6*256+((x2>>(z2*8)) & 0xFF)])<<(5*8)) | (((uint64_t)tb[t7*256+((x2>>(z2*8) ) & 0xFF)])<<(6*8)) | (((uint64_t)tb[t8*256+((x2>>(z2*8)) & 0xFF)])<<(7*8)))
#define kpi(tb, x1)    (uint64_t)((((uint64_t)tb[0*256+( (x1>>(0*8) ) & 0xFF)])<<(0*8)) | (((uint64_t)tb[1*256+((x1>>(1*8)) & 0xFF)])<<(1*8)) | (((uint64_t)tb[2*256+((x1>>(2*8) ) & 0xFF)])<<(2*8)) | (((uint64_t)tb[3*256+((x1>>(3*8)) & 0xFF)])<<(3*8)) |\
                                  (((uint64_t)tb[0*256+( (x1>>(4*8) ) & 0xFF)])<<(4*8)) | (((uint64_t)tb[1*256+((x1>>(5*8)) & 0xFF)])<<(5*8)) | (((uint64_t)tb[2*256+((x1>>(6*8) ) & 0xFF)])<<(6*8)) | (((uint64_t)tb[3*256+((x1>>(7*8)) & 0xFF)])<<(7*8)))


/**
 * Виконує генерування таблиці з перемноженим на s-блоки вектором з функції ксі,
 * що прискорює шифрування в 10 разів
 * @param out       Вихідний буфер(16384 байт)
 * @param s_blocks  Вхідна таблиця s-блоків
 */
void kalina_make_awesome_table(void *out, void *s_blocks);

/**
 * Виконує генерування зворотної таблиці s-блоків,
 * @param rev_s_blocks   Вихідний буфер(1024 байт)
 * @param forw_s_blocks  Вхідна таблиця s-блоків
 */
void kalina_generate_reverse_table(void *rev_s_blocks, const void *forw_s_blocks);

/**
 * Виконує інкремент числа будь-якого розміру кратного 8-байтам
 * @param buf   Вхідний-Вихідний
 * @param s_64  Розмір числа в 8-байтних блоках
 */
void kalina_inc_one(uint64_t *buf, const unsigned s_64);


#endif // COMMON

