#ifndef KALINA_128_H
#define KALINA_128_H

#include <stdint.h>
#include "common.h"


typedef struct {
    uint8_t   v[kalina_128_key_len_bytes];
    uint64_t  s[kalina_128_64_key_len];
    unsigned index;
    void *round_keys;
    void *big_table;
}tkalina_128;

/**
 * Функція генерування раундових ключів для розміру блоку 128 біт, при розмірі ключа 128 біт
 * @param out       Вихідний буфер під ключі(11*16 байт)
 * @param key_0     Ключ розшифрування
 * @param awesome_table   Вказівник на велику таблицю, що згенерована функцією kalina_make_awesome_table
 */
void kalina_128_128_generate_round_keys(void *round_key_buf, void *key_0, void *big_table);

/**
 * Виконує базове шифрування(проста заміна)
 * @param kalina Вказівник на базову структуру шифрування
 * @param out   Вихідний буфер
 * @param in    Вхідний буфер
 * @param round_keys  Вказівник на масив раундовими ключами
 * згенерований функцією kalina_128_128_generate_round_keys
 * @param awesome_table   Вказівник на велику таблицю, що згенерована функцією kalina_make_awesome_table
 */
void kalina_128_128_encrypt_block(void *out_block, void *in_block,void *round_keys, void *big_table);

/**
 * Виконує початкову ініціалізацію шифратора в режимах CTR CFB
 * @param kalina Вказівник на базову структуру шифрування
 * @param iv Синхропосилка
 * @param round_keys  Вказівник на масив раундовими ключами
 * згенерований функцією kalina_128_128_generate_round_keys
 * @param big_table   Вказівник на велику таблицю, що згенерована функцією kalina_make_awesome_table
 */
void kalina_128_128_prepare (tkalina_128 *kalina, void *iv,void *round_keys, void *big_table);


/**
 * Виконує шифрування в режимі гамування
 * @param kalina Вказівник на базову структуру шифрування
 * @param out_buf Вихідний буфер
 * @param in_buf  Вхідний буфер
 * @param size    Розмір буферу в байтах
 * @param n       Кількість біт, що не кратні розміру байта, має бути 0(Воно вам не знадобиться).
 */
void kalina_128_128_CTR     (tkalina_128 *kalina, void *out_buf, void *in_buf, uint32_t size, uint32_t n);



/**
 * Виконує шифрування в режимі гамування з зворотним зв'язком за шифротекстом
 * @param kalina Вказівник на базову структуру шифрування
 * @param out_buf Вихідний буфер
 * @param in_buf  Вхідний буфер
 * @param size    Розмір буферу в байтах
 * @param n       Кількість біт, що не кратні розміру байта, має бути 0(Воно вам не знадобиться).
 * @param last    Чи це останній буфер данних?
 */
void kalina_128_128_CFB_E(tkalina_128 *kalina, void *out_buf, void *in_buf, uint32_t size, uint32_t n, bool last);

/**
 * Виконує розшифрування в режимі гамування з зворотним зв'язком за шифротекстом
 * @param kalina Вказівник на базову структуру шифрування
 * @param out_buf Вихідний буфер
 * @param in_buf  Вхідний буфер
 * @param size    Розмір буферу в байтах
 * @param n       Кількість біт, що не кратні розміру байта, має бути 0(Воно вам не знадобиться).
 * @param last    Чи це останній буфер данних?
 */
void kalina_128_128_CFB_D(tkalina_128 *kalina, void *out_buf, void *in_buf, uint32_t size, uint32_t n, bool last);


#endif // KALINA_128_H

