#ifndef KALINA_256_256_H
#define KALINA_256_256_H
#include "common.h"
const unsigned kalina_256_64_key_len=kalina_256_key_len_bytes>>3;

typedef struct {
  uint8_t   v[kalina_256_key_len_bytes];
  uint64_t  s[kalina_256_64_key_len];
  unsigned index;
  void *round_keys;
  void *big_table;

}tkalina_256;


/**
 * Функція генерування раундових ключів для розміру блоку 256 біт, при розмірі ключа 256 біт
 * @param out       Вихідний буфер під ключі(14*32 байт)
 * @param key_0     Ключ розшифрування
 * @param awesome_table   Вказівник на велику таблицю, що згенерована функцією kalina_make_awesome_table
 */
void kalina_256_256_generate_round_keys(void *out, const void *key_0, const void *awesome_table);

/**
 * Виконує базове шифрування(проста заміна)
 * @param kalina Вказівник на базову структуру шифрування
 * @param out   Вихідний буфер
 * @param in    Вхідний буфер
 * @param round_keys  Вказівник на масив раундовими ключами
 * згенерований функцією kalina_256_256_generate_round_keys
 * @param awesome_table   Вказівник на велику таблицю, що згенерована функцією kalina_make_awesome_table
 */
void kalina_256_256_encrypt_block( void *out, void *in, const void *roundkey, const void *awesome_table);

/**
 * Виконує початкову ініціалізацію шифратора в режимах CTR CFB
 * @param kalina Вказівник на базову структуру шифрування
 * @param iv Синхропосилка
 * @param round_keys  Вказівник на масив раундовими ключами
 * згенерований функцією kalina_256_256_generate_round_keys
 * @param big_table   Вказівник на велику таблицю, що згенерована функцією kalina_make_awesome_table
 */
void kalina_256_256_prepare(tkalina_256 *kalina, void *iv,void *round_keys, void *big_table);


/**
 * Виконує шифрування в режимі гамування
 * @param kalina Вказівник на базову структуру шифрування
 * @param out_buf Вихідний буфер
 * @param in_buf  Вхідний буфер
 * @param size    Розмір буферу в байтах
 * @param n       Кількість біт, що не кратні розміру байта, має бути 0(Воно вам не знадобиться).
 */
void kalina_256_256_CTR(tkalina_256 *kalina, void *out_buf, void *in_buf, uint32_t size, uint32_t n);


/**
 * Виконує шифрування в режимі гамування з зворотним зв'язком за шифротекстом
 * @param kalina Вказівник на базову структуру шифрування
 * @param out_buf Вихідний буфер
 * @param in_buf  Вхідний буфер
 * @param size    Розмір буферу в байтах
 * @param n       Кількість біт, що не кратні розміру байта, має бути 0(Воно вам не знадобиться).
 * @param last    Чи це останній буфер данних?
 */
void kalina_256_256_CFB_E(tkalina_256 *kalina, void *out_buf, void *in_buf, uint32_t size, uint32_t n, bool last);

/**
 * Виконує розшифрування в режимі гамування з зворотним зв'язком за шифротекстом
 * @param kalina Вказівник на базову структуру шифрування
 * @param out_buf Вихідний буфер
 * @param in_buf  Вхідний буфер
 * @param size    Розмір буферу в байтах
 * @param n       Кількість біт, що не кратні розміру байта, має бути 0(Воно вам не знадобиться).
 * @param last    Чи це останній буфер данних?
 */
void kalina_256_256_CFB_D(tkalina_256 *kalina, void *out_buf, void *in_buf, uint32_t size, uint32_t n, bool last);

#endif // KALINA_256_256_H

