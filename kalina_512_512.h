#ifndef KALINA_512_512_H
#define KALINA_512_512_H
#include "common.h"
const unsigned kalina_512_64_key_len=kalina_512_key_len_bytes>>3;

typedef struct {
    uint8_t   v[kalina_512_key_len_bytes];
    uint64_t  s[kalina_512_64_key_len];
    unsigned index;
    void *round_keys;
    void *big_table;
}tkalina_512;

/**
 * Функція генерування раундових ключів для розміру блоку 512 біт, при розмірі ключа 512 біт
 * @param out       Вихідний буфер під ключі(19*64 байт)
 * @param key_0     Ключ розшифрування
 * @param awesome_table   Вказівник на велику таблицю, що згенерована функцією kalina_make_awesome_table
 */
void kalina_512_512_generate_round_keys(void *out, const void *key_0, const void *awesome_table);

/**
 * Виконує базове шифрування(проста заміна)
 * @param kalina Вказівник на базову структуру шифрування
 * @param out   Вихідний буфер
 * @param in    Вхідний буфер
 * @param round_keys  Вказівник на масив раундовими ключами
 * згенерований функцією kalina_512_512_generate_round_keys
 * @param awesome_table   Вказівник на велику таблицю, що згенерована функцією kalina_make_awesome_table
 */
void kalina_512_512_encrypt_block( void *out, const void *in, const void *roundkeys, const void *awesome_table);



/**
 * Виконує початкову ініціалізацію шифратора в режимах CTR CFB
 * @param kalina Вказівник на базову структуру шифрування
 * @param iv Синхропосилка
 * @param round_keys  Вказівник на масив раундовими ключами
 * згенерований функцією kalina_512_512_generate_round_keys
 * @param big_table   Вказівник на велику таблицю, що згенерована функцією kalina_make_awesome_table
 */
void kalina_512_512_prepare(tkalina_512 *kalina, void *iv,void *round_keys, void *big_table);

/**
 * Виконує шифрування в режимі гамування
 * @param kalina Вказівник на базову структуру шифрування
 * @param out_buf Вихідний буфер
 * @param in_buf  Вхідний буфер
 * @param size    Розмір буферу в байтах
 * @param n       Кількість біт, що не кратні розміру байта, має бути 0(Воно вам не знадобиться).
 */
void kalina_512_512_CTR(tkalina_512 *kalina, void *out_buf, void *in_buf, uint32_t size, uint32_t n);

/**
 * Виконує шифрування в режимі гамування з зворотним зв'язком за шифротекстом
 * @param kalina Вказівник на базову структуру шифрування
 * @param out_buf Вихідний буфер
 * @param in_buf  Вхідний буфер
 * @param size    Розмір буферу в байтах
 * @param n       Кількість біт, що не кратні розміру байта, має бути 0(Воно вам не знадобиться).
 * @param last    Чи це останній буфер данних?
 */
void kalina_512_512_CFB_E(tkalina_512 *kalina, void *out_buf, void *in_buf, uint32_t size, uint32_t n, bool last);

/**
 * Виконує розшифрування в режимі гамування з зворотним зв'язком за шифротекстом
 * @param kalina Вказівник на базову структуру шифрування
 * @param out_buf Вихідний буфер
 * @param in_buf  Вхідний буфер
 * @param size    Розмір буферу в байтах
 * @param n       Кількість біт, що не кратні розміру байта, має бути 0(Воно вам не знадобиться).
 * @param last    Чи це останній буфер данних?
 */
void kalina_512_512_CFB_D(tkalina_512 *kalina, void *out_buf, void *in_buf, uint32_t size, uint32_t n, bool last);


#endif // KALINA_512_512_H

