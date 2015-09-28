#include "common.h"
#include "kalina_tables.h"
#include "galua_table.h"
#include "kalina_128_table.h"
#include "kalina_128.h"
#include <string.h>

#define kalina128_c 2

const uint64_t kalina_128_epsilon[12]={ 0x0001000100010001, 0x0001000100010001,
                                        0x0002000200020002, 0x0002000200020002,
                                        0x0004000400040004, 0x0004000400040004,
                                        0x0008000800080008, 0x0008000800080008,
                                        0x0010001000100010, 0x0010001000100010,
                                        0x0020002000200020, 0x0020002000200020};


void kalina_128_shift_rows(void *b){
    uint32_t *block=(uint32_t *)b;
    uint32_t tmp;

    tmp=block[3];
    block[3]=block[1];
    block[1]=tmp;

}


void  kalina_128_form_kt(void *key_0, void *key_d, void *s_blocks  )
{

     tkalina_128_kb *key_b0=(tkalina_128_kb *)key_0;
     tkalina_128_kb *key_bd=(tkalina_128_kb *)key_d;
     uint8_t key_bd_tmp[kalina_128_key_len_bytes];

     memset(key_bd, 0x00, kalina_128_key_len_bytes);
     key_bd[0] = kalina_kd_init_val(K_128, K_128);

     kalina_add_mod64(key_bd, key_b0, kalina128_c);
     kalina_s_block(key_bd,s_blocks,kalina_128_key_len_bytes);
     kalina_128_shift_rows(key_bd);
     kalina_ksi(key_bd, key_bd_tmp, kalina128_c);

     kalina_xor(key_bd_tmp, key_b0, kalina128_c);
     kalina_s_block(key_bd_tmp,s_blocks, kalina_128_key_len_bytes);
     kalina_128_shift_rows(key_bd_tmp);
     kalina_ksi(key_bd_tmp, key_bd, kalina128_c);

     kalina_add_mod64(key_bd, key_b0, kalina128_c);
     kalina_s_block(key_bd,s_blocks,kalina_128_key_len_bytes);
     kalina_128_shift_rows(key_bd);
     memcpy(key_bd_tmp, key_bd, kalina_128_key_len_bytes);
     kalina_ksi(key_bd_tmp, key_bd, kalina128_c);


}

void kalina_128_rotate_left_key(void *out, void *in){
    uint64_t *key_i=(uint64_t *)in;
    uint64_t *key_o=(uint64_t *)out;

    key_o[0]=key_i[1];
    key_o[1]=key_i[0];
}


inline void kalina_128_rotate_left_7(void *out, void *in){
    _rotate_func((uint8_t *)in,(uint8_t *)out,7,16)
}



void kalina_128_form_round_key_pair(void *key_buf, void *key_0, void *s_blocks, void *key_kd,  unsigned n){

    uint8_t tmp[kalina_128_key_len_bytes];
    uint8_t key_buf_tmp[kalina_128_key_len_bytes];


    memcpy(key_buf, &kalina_128_epsilon_table[(n>>1)*kalina_128_key_len_bytes],kalina_128_key_len_bytes);
    kalina_add_mod64(key_buf, key_kd, kalina128_c);
    memcpy(tmp, key_buf, kalina_128_key_len_bytes);

    kalina_add_mod64(key_buf, key_0,  kalina128_c);
    kalina_s_block(key_buf, s_blocks, kalina_128_key_len_bytes);
    kalina_128_shift_rows(key_buf);
    kalina_ksi(key_buf, key_buf_tmp, kalina128_c);

    kalina_xor(key_buf_tmp, tmp, kalina128_c);
    kalina_s_block(key_buf_tmp, s_blocks, kalina_128_key_len_bytes);
    kalina_128_shift_rows(key_buf_tmp);
    kalina_ksi(key_buf_tmp, key_buf, kalina128_c);

    kalina_add_mod64(key_buf, tmp,  kalina128_c);
}

void kalina_128_generate_round_keys(void *round_key_buf, void *key_0, void *s_blocks){

    uint8_t key_d[kalina_128_key_len_bytes];
    uint8_t key_0_s[kalina_128_key_len_bytes];
    uint8_t *key_buf=(uint8_t *)round_key_buf;

    kalina_128_form_kt(key_0, key_d, s_blocks);
    kalina_128_rotate_left_key(key_0_s,key_0);

    kalina_128_form_round_key_pair(&key_buf[0],                           key_0,    s_blocks, key_d, 0  );
    kalina_128_form_round_key_pair(&key_buf[kalina_128_key_len_bytes*4],  key_0,    s_blocks, key_d, 4  );
    kalina_128_form_round_key_pair(&key_buf[kalina_128_key_len_bytes*8],  key_0,    s_blocks, key_d, 8  );

    kalina_128_form_round_key_pair(&key_buf[kalina_128_key_len_bytes*2],  key_0_s,  s_blocks, key_d, 2  );
    kalina_128_form_round_key_pair(&key_buf[kalina_128_key_len_bytes*6],  key_0_s,  s_blocks, key_d, 6  );
    kalina_128_form_round_key_pair(&key_buf[kalina_128_key_len_bytes*10], key_0_s,  s_blocks, key_d, 10 );

    kalina_128_rotate_left_7(&key_buf[kalina_128_key_len_bytes],    &key_buf[0]);
    kalina_128_rotate_left_7(&key_buf[kalina_128_key_len_bytes*3],  &key_buf[kalina_128_key_len_bytes*2]);
    kalina_128_rotate_left_7(&key_buf[kalina_128_key_len_bytes*5],  &key_buf[kalina_128_key_len_bytes*4]);
    kalina_128_rotate_left_7(&key_buf[kalina_128_key_len_bytes*7],  &key_buf[kalina_128_key_len_bytes*6]);
    kalina_128_rotate_left_7(&key_buf[kalina_128_key_len_bytes*9],  &key_buf[kalina_128_key_len_bytes*8]);

}

void kalina_128_crypt_block(void *block, void *round_keys, void *s_blocks){
    uint8_t *key_buf=(uint8_t *)round_keys;

    uint64_t *key_buf_64=(uint64_t *)round_keys;
    uint64_t *block_64=(uint64_t *)block;
    uint8_t tmp[kalina_128_block_len_bytes];

    //0
    //kalina_add_mod64(block, &key_buf[0], kalina128_c);
    block_64[0]=block_64[0]+key_buf_64[0];
    block_64[1]=block_64[1]+key_buf_64[1];
    //1
    kalina_s_block(block, s_blocks, kalina_128_block_len_bytes);
    kalina_128_shift_rows(block);
    kalina_ksi(block,tmp,kalina128_c);
    kalina_xor(tmp, &key_buf[kalina_128_key_len_bytes], kalina128_c);

    //2
    kalina_s_block(tmp, s_blocks, kalina_128_block_len_bytes);
    kalina_128_shift_rows(tmp);
    kalina_ksi(tmp,block,kalina128_c);
    kalina_xor(block, &key_buf[kalina_128_key_len_bytes*2], kalina128_c);

    //3
    kalina_s_block(block, s_blocks, kalina_128_block_len_bytes);
    kalina_128_shift_rows(block);
    kalina_ksi(block,tmp,kalina128_c);
    kalina_xor(tmp, &key_buf[kalina_128_key_len_bytes*3], kalina128_c);

    //4
    kalina_s_block(tmp, s_blocks, kalina_128_block_len_bytes);
    kalina_128_shift_rows(tmp);
    kalina_ksi(tmp,block,kalina128_c);
    kalina_xor(block, &key_buf[kalina_128_key_len_bytes*4], kalina128_c);

    //5
    kalina_s_block(block, s_blocks, kalina_128_block_len_bytes);
    kalina_128_shift_rows(block);
    kalina_ksi(block,tmp,kalina128_c);
    kalina_xor(tmp, &key_buf[kalina_128_key_len_bytes*5], kalina128_c);

    //6
    kalina_s_block(tmp, s_blocks, kalina_128_block_len_bytes);
    kalina_128_shift_rows(tmp);
    kalina_ksi(tmp,block,kalina128_c);
    kalina_xor(block, &key_buf[kalina_128_key_len_bytes*6], kalina128_c);

    //7
    kalina_s_block(block, s_blocks, kalina_128_block_len_bytes);
    kalina_128_shift_rows(block);
    kalina_ksi(block,tmp,kalina128_c);
    kalina_xor(tmp, &key_buf[kalina_128_key_len_bytes*7], kalina128_c);

    //8
    kalina_s_block(tmp, s_blocks, kalina_128_block_len_bytes);
    kalina_128_shift_rows(tmp);
    kalina_ksi(tmp,block,kalina128_c);
    kalina_xor(block, &key_buf[kalina_128_key_len_bytes*8], kalina128_c);

    //9
    kalina_s_block(block, s_blocks, kalina_128_block_len_bytes);
    kalina_128_shift_rows(block);
    kalina_ksi(block,tmp,kalina128_c);
    kalina_xor(tmp, &key_buf[kalina_128_key_len_bytes*9], kalina128_c);

    //10
    kalina_s_block(tmp, s_blocks, kalina_128_block_len_bytes);
    kalina_128_shift_rows(tmp);
    kalina_ksi(tmp,block,kalina128_c);
    kalina_add_mod64(block, &key_buf[kalina_128_key_len_bytes*10], kalina128_c);

}




void kalina_128_form_kt_f(void *key_0, void *key_d, void *big_table  ){
    uint64_t *key       =   (uint64_t *)key_0;
    uint64_t *o         =   (uint64_t *)key_d;
    uint64_t *table     =   (uint64_t *)big_table;
    uint64_t i[2];


    i[0] = kalina_kd_init_val(K_128, K_128)+key[0];
    i[1] = key[1];


    o[0] =  table[ 0 * kalina_table_chars_num + ( ( i[0] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( i[0] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( i[0] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( i[0] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( i[1] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( i[1] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( i[1] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( i[1] >> (7 * 8) ) & 0xFF) ] ^ key[0];

    o[1] =  table[ 0 * kalina_table_chars_num + ( ( i[1] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( i[1] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( i[1] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( i[1] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( i[0] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( i[0] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( i[0] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( i[0] >> (7 * 8) ) & 0xFF) ] ^ key[1];

    i[0] = (table[ 0 * kalina_table_chars_num + ( ( o[0] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( o[0] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( o[0] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( o[0] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( o[1] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( o[1] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( o[1] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( o[1] >> (7 * 8) ) & 0xFF) ]) + key[0];

    i[1] = (table[ 0 * kalina_table_chars_num + ( ( o[1] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( o[1] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( o[1] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( o[1] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( o[0] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( o[0] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( o[0] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( o[0] >> (7 * 8) ) & 0xFF) ]) + key[1];


    o[0] =  table[ 0 * kalina_table_chars_num + ( ( i[0] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( i[0] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( i[0] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( i[0] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( i[1] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( i[1] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( i[1] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( i[1] >> (7 * 8) ) & 0xFF) ];

    o[1] =  table[ 0 * kalina_table_chars_num + ( ( i[1] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( i[1] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( i[1] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( i[1] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( i[0] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( i[0] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( i[0] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( i[0] >> (7 * 8) ) & 0xFF) ];



}


void kalina_128_form_round_key_pair_f(void *key_buf, void *key_0, void *key_kd, void *big_table, unsigned n){

    uint64_t *i       = (uint64_t *)key_buf;
    uint64_t *key     = (uint64_t *)key_0;
    uint64_t *table   = (uint64_t *)big_table;
    uint64_t *kd      = (uint64_t *)key_kd;
    uint64_t o[kalina_128_64_key_len];
    uint64_t k[kalina_128_64_key_len];


    k[0]=kd[0]+kalina_128_epsilon[n+0];
    k[1]=kd[1]+kalina_128_epsilon[n+1];

    i[0]=k[0]+key[0];
    i[1]=k[1]+key[1];

    o[0] =  table[ 0 * kalina_table_chars_num + ( ( i[0] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( i[0] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( i[0] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( i[0] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( i[1] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( i[1] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( i[1] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( i[1] >> (7 * 8) ) & 0xFF) ] ^ k[0];

    o[1] =  table[ 0 * kalina_table_chars_num + ( ( i[1] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( i[1] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( i[1] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( i[1] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( i[0] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( i[0] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( i[0] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( i[0] >> (7 * 8) ) & 0xFF) ] ^ k[1];

    i[0] = (table[ 0 * kalina_table_chars_num + ( ( o[0] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( o[0] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( o[0] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( o[0] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( o[1] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( o[1] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( o[1] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( o[1] >> (7 * 8) ) & 0xFF) ]) + k[0];

    i[1] = (table[ 0 * kalina_table_chars_num + ( ( o[1] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( o[1] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( o[1] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( o[1] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( o[0] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( o[0] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( o[0] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( o[0] >> (7 * 8) ) & 0xFF) ]) + k[1];
}


void kalina_128_128_generate_round_keys(void *round_key_buf, void *key_0, void *big_table){
   uint64_t *key_buf   =   (uint64_t *)round_key_buf;
   uint64_t *key       =   (uint64_t *)key_0;
   uint64_t kd[kalina_128_64_key_len];
   uint64_t rot_key[kalina_128_64_key_len];

   kalina_128_form_kt_f(key,kd,big_table);

   rot_key[0]=key[1];
   rot_key[1]=key[0];

   kalina_128_form_round_key_pair_f(&key_buf[0*kalina_128_64_key_len],key,kd,big_table,0);
   kalina_128_form_round_key_pair_f(&key_buf[4*kalina_128_64_key_len],key,kd,big_table,4);
   kalina_128_form_round_key_pair_f(&key_buf[8*kalina_128_64_key_len],key,kd,big_table,8);

   kalina_128_form_round_key_pair_f(&key_buf[2*kalina_128_64_key_len],rot_key,kd,big_table,2);
   kalina_128_form_round_key_pair_f(&key_buf[6*kalina_128_64_key_len],rot_key,kd,big_table,6);
   kalina_128_form_round_key_pair_f(&key_buf[10*kalina_128_64_key_len],rot_key,kd,big_table,10);


   kalina_128_rotate_left_7(&key_buf[1*kalina_128_64_key_len],  &key_buf[0]);
   kalina_128_rotate_left_7(&key_buf[3*kalina_128_64_key_len],  &key_buf[2*kalina_128_64_key_len]);
   kalina_128_rotate_left_7(&key_buf[5*kalina_128_64_key_len],  &key_buf[4*kalina_128_64_key_len]);
   kalina_128_rotate_left_7(&key_buf[7*kalina_128_64_key_len],  &key_buf[6*kalina_128_64_key_len]);
   kalina_128_rotate_left_7(&key_buf[9*kalina_128_64_key_len],  &key_buf[8*kalina_128_64_key_len]);
}


void kalina_128_128_encrypt_block(void *out_block, void *in_block,void *round_keys, void *big_table){

    uint64_t    *round_k    =   (uint64_t *)round_keys;
    uint64_t    *table      =   (uint64_t *)big_table;
    uint64_t    *in         =   (uint64_t *)in_block;
    uint64_t    *i          =   (uint64_t *)out_block;
    uint64_t    o[kalina_128_64_key_len];


    i[0] = in[0]+round_k[0*kalina_128_64_key_len+0];
    i[1] = in[1]+round_k[0*kalina_128_64_key_len+1];

    o[0] =  table[ 0 * kalina_table_chars_num + ( ( i[0] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( i[0] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( i[0] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( i[0] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( i[1] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( i[1] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( i[1] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( i[1] >> (7 * 8) ) & 0xFF) ] ^ round_k[1*kalina_128_64_key_len+0];

    o[1] =  table[ 0 * kalina_table_chars_num + ( ( i[1] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( i[1] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( i[1] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( i[1] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( i[0] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( i[0] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( i[0] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( i[0] >> (7 * 8) ) & 0xFF) ] ^ round_k[1*kalina_128_64_key_len+1];


    i[0] =  table[ 0 * kalina_table_chars_num + ( ( o[0] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( o[0] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( o[0] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( o[0] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( o[1] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( o[1] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( o[1] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( o[1] >> (7 * 8) ) & 0xFF) ] ^ round_k[2*kalina_128_64_key_len+0];

    i[1] =  table[ 0 * kalina_table_chars_num + ( ( o[1] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( o[1] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( o[1] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( o[1] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( o[0] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( o[0] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( o[0] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( o[0] >> (7 * 8) ) & 0xFF) ] ^ round_k[2*kalina_128_64_key_len+1];


    o[0] =  table[ 0 * kalina_table_chars_num + ( ( i[0] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( i[0] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( i[0] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( i[0] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( i[1] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( i[1] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( i[1] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( i[1] >> (7 * 8) ) & 0xFF) ] ^ round_k[3*kalina_128_64_key_len+0];

    o[1] =  table[ 0 * kalina_table_chars_num + ( ( i[1] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( i[1] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( i[1] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( i[1] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( i[0] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( i[0] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( i[0] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( i[0] >> (7 * 8) ) & 0xFF) ] ^ round_k[3*kalina_128_64_key_len+1];


    i[0] =  table[ 0 * kalina_table_chars_num + ( ( o[0] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( o[0] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( o[0] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( o[0] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( o[1] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( o[1] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( o[1] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( o[1] >> (7 * 8) ) & 0xFF) ] ^ round_k[4*kalina_128_64_key_len+0];

    i[1] =  table[ 0 * kalina_table_chars_num + ( ( o[1] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( o[1] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( o[1] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( o[1] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( o[0] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( o[0] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( o[0] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( o[0] >> (7 * 8) ) & 0xFF) ] ^ round_k[4*kalina_128_64_key_len+1];


    o[0] =  table[ 0 * kalina_table_chars_num + ( ( i[0] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( i[0] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( i[0] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( i[0] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( i[1] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( i[1] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( i[1] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( i[1] >> (7 * 8) ) & 0xFF) ] ^ round_k[5*kalina_128_64_key_len+0];

    o[1] =  table[ 0 * kalina_table_chars_num + ( ( i[1] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( i[1] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( i[1] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( i[1] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( i[0] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( i[0] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( i[0] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( i[0] >> (7 * 8) ) & 0xFF) ] ^ round_k[5*kalina_128_64_key_len+1];


    i[0] =  table[ 0 * kalina_table_chars_num + ( ( o[0] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( o[0] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( o[0] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( o[0] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( o[1] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( o[1] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( o[1] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( o[1] >> (7 * 8) ) & 0xFF) ] ^ round_k[6*kalina_128_64_key_len+0];

    i[1] =  table[ 0 * kalina_table_chars_num + ( ( o[1] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( o[1] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( o[1] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( o[1] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( o[0] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( o[0] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( o[0] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( o[0] >> (7 * 8) ) & 0xFF) ] ^ round_k[6*kalina_128_64_key_len+1];


    o[0] =  table[ 0 * kalina_table_chars_num + ( ( i[0] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( i[0] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( i[0] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( i[0] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( i[1] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( i[1] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( i[1] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( i[1] >> (7 * 8) ) & 0xFF) ] ^ round_k[7*kalina_128_64_key_len+0];

    o[1] =  table[ 0 * kalina_table_chars_num + ( ( i[1] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( i[1] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( i[1] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( i[1] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( i[0] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( i[0] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( i[0] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( i[0] >> (7 * 8) ) & 0xFF) ] ^ round_k[7*kalina_128_64_key_len+1];


    i[0] =  table[ 0 * kalina_table_chars_num + ( ( o[0] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( o[0] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( o[0] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( o[0] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( o[1] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( o[1] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( o[1] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( o[1] >> (7 * 8) ) & 0xFF) ] ^ round_k[8*kalina_128_64_key_len+0];

    i[1] =  table[ 0 * kalina_table_chars_num + ( ( o[1] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( o[1] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( o[1] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( o[1] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( o[0] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( o[0] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( o[0] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( o[0] >> (7 * 8) ) & 0xFF) ] ^ round_k[8*kalina_128_64_key_len+1];


    o[0] =  table[ 0 * kalina_table_chars_num + ( ( i[0] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( i[0] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( i[0] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( i[0] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( i[1] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( i[1] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( i[1] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( i[1] >> (7 * 8) ) & 0xFF) ] ^ round_k[9*kalina_128_64_key_len+0];

    o[1] =  table[ 0 * kalina_table_chars_num + ( ( i[1] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( i[1] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( i[1] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( i[1] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( i[0] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( i[0] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( i[0] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( i[0] >> (7 * 8) ) & 0xFF) ] ^ round_k[9*kalina_128_64_key_len+1];

    i[0] = (table[ 0 * kalina_table_chars_num + ( ( o[0] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( o[0] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( o[0] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( o[0] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( o[1] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( o[1] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( o[1] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( o[1] >> (7 * 8) ) & 0xFF) ] )+ round_k[10*kalina_128_64_key_len+0];

    i[1] = (table[ 0 * kalina_table_chars_num + ( ( o[1] >> (0 * 8) ) & 0xFF) ] ^
            table[ 1 * kalina_table_chars_num + ( ( o[1] >> (1 * 8) ) & 0xFF) ] ^
            table[ 2 * kalina_table_chars_num + ( ( o[1] >> (2 * 8) ) & 0xFF) ] ^
            table[ 3 * kalina_table_chars_num + ( ( o[1] >> (3 * 8) ) & 0xFF) ] ^
            table[ 4 * kalina_table_chars_num + ( ( o[0] >> (4 * 8) ) & 0xFF) ] ^
            table[ 5 * kalina_table_chars_num + ( ( o[0] >> (5 * 8) ) & 0xFF) ] ^
            table[ 6 * kalina_table_chars_num + ( ( o[0] >> (6 * 8) ) & 0xFF) ] ^
            table[ 7 * kalina_table_chars_num + ( ( o[0] >> (7 * 8) ) & 0xFF) ] )+ round_k[10*kalina_128_64_key_len+1];
}


void kalina_128_128_decrypt_block_f(void *out_block, void *in_block,void *round_keys, void *r_big_table){



    uint64_t    *round_k    =   (uint64_t *)round_keys;
    uint8_t     *s_table    =   (uint8_t *)r_big_table;
    uint64_t    *in         =   (uint64_t *)in_block;
    uint64_t    o[2];
    uint64_t    *i=(uint64_t *)out_block;


    i[0] = in[0]-round_k[10*kalina_128_64_key_len+0];
    i[1] = in[1]-round_k[10*kalina_128_64_key_len+1];

    o[0]=  ksitau(gmul_table_RV, i[0],0, i[1],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[0],1, i[1],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[0],2, i[1],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[0],3, i[1],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[0],4, i[1],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[0],5, i[1],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[0],6, i[1],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[0],7, i[1],7, 7,6,5,4,3,2,1,0);

    o[1]=  ksitau(gmul_table_RV, i[1],0, i[0],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[1],1, i[0],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[1],2, i[0],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[1],3, i[0],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[1],4, i[0],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[1],5, i[0],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[1],6, i[0],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[1],7, i[0],7, 7,6,5,4,3,2,1,0);

    i[0]=  kpi(s_table,o[0])^round_k[9*kalina_128_64_key_len+0];
    i[1]=  kpi(s_table,o[1])^round_k[9*kalina_128_64_key_len+1];


    o[0]=  ksitau(gmul_table_RV, i[0],0, i[1],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[0],1, i[1],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[0],2, i[1],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[0],3, i[1],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[0],4, i[1],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[0],5, i[1],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[0],6, i[1],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[0],7, i[1],7, 7,6,5,4,3,2,1,0);

    o[1]=  ksitau(gmul_table_RV, i[1],0, i[0],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[1],1, i[0],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[1],2, i[0],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[1],3, i[0],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[1],4, i[0],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[1],5, i[0],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[1],6, i[0],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[1],7, i[0],7, 7,6,5,4,3,2,1,0);

    i[0]=  kpi(s_table,o[0])^round_k[8*kalina_128_64_key_len+0];
    i[1]=  kpi(s_table,o[1])^round_k[8*kalina_128_64_key_len+1];


    o[0]=  ksitau(gmul_table_RV, i[0],0, i[1],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[0],1, i[1],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[0],2, i[1],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[0],3, i[1],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[0],4, i[1],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[0],5, i[1],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[0],6, i[1],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[0],7, i[1],7, 7,6,5,4,3,2,1,0);

    o[1]=  ksitau(gmul_table_RV, i[1],0, i[0],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[1],1, i[0],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[1],2, i[0],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[1],3, i[0],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[1],4, i[0],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[1],5, i[0],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[1],6, i[0],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[1],7, i[0],7, 7,6,5,4,3,2,1,0);

    i[0]=  kpi(s_table,o[0])^round_k[7*kalina_128_64_key_len+0];
    i[1]=  kpi(s_table,o[1])^round_k[7*kalina_128_64_key_len+1];


    o[0]=  ksitau(gmul_table_RV, i[0],0, i[1],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[0],1, i[1],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[0],2, i[1],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[0],3, i[1],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[0],4, i[1],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[0],5, i[1],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[0],6, i[1],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[0],7, i[1],7, 7,6,5,4,3,2,1,0);

    o[1]=  ksitau(gmul_table_RV, i[1],0, i[0],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[1],1, i[0],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[1],2, i[0],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[1],3, i[0],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[1],4, i[0],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[1],5, i[0],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[1],6, i[0],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[1],7, i[0],7, 7,6,5,4,3,2,1,0);

    i[0]=  kpi(s_table,o[0])^round_k[6*kalina_128_64_key_len+0];
    i[1]=  kpi(s_table,o[1])^round_k[6*kalina_128_64_key_len+1];


    o[0]=  ksitau(gmul_table_RV, i[0],0, i[1],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[0],1, i[1],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[0],2, i[1],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[0],3, i[1],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[0],4, i[1],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[0],5, i[1],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[0],6, i[1],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[0],7, i[1],7, 7,6,5,4,3,2,1,0);

    o[1]=  ksitau(gmul_table_RV, i[1],0, i[0],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[1],1, i[0],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[1],2, i[0],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[1],3, i[0],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[1],4, i[0],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[1],5, i[0],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[1],6, i[0],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[1],7, i[0],7, 7,6,5,4,3,2,1,0);

    i[0]=  kpi(s_table,o[0])^round_k[5*kalina_128_64_key_len+0];
    i[1]=  kpi(s_table,o[1])^round_k[5*kalina_128_64_key_len+1];


    o[0]=  ksitau(gmul_table_RV, i[0],0, i[1],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[0],1, i[1],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[0],2, i[1],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[0],3, i[1],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[0],4, i[1],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[0],5, i[1],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[0],6, i[1],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[0],7, i[1],7, 7,6,5,4,3,2,1,0);

    o[1]=  ksitau(gmul_table_RV, i[1],0, i[0],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[1],1, i[0],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[1],2, i[0],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[1],3, i[0],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[1],4, i[0],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[1],5, i[0],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[1],6, i[0],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[1],7, i[0],7, 7,6,5,4,3,2,1,0);

    i[0]=  kpi(s_table,o[0])^round_k[4*kalina_128_64_key_len+0];
    i[1]=  kpi(s_table,o[1])^round_k[4*kalina_128_64_key_len+1];


    o[0]=  ksitau(gmul_table_RV, i[0],0, i[1],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[0],1, i[1],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[0],2, i[1],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[0],3, i[1],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[0],4, i[1],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[0],5, i[1],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[0],6, i[1],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[0],7, i[1],7, 7,6,5,4,3,2,1,0);

    o[1]=  ksitau(gmul_table_RV, i[1],0, i[0],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[1],1, i[0],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[1],2, i[0],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[1],3, i[0],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[1],4, i[0],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[1],5, i[0],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[1],6, i[0],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[1],7, i[0],7, 7,6,5,4,3,2,1,0);

    i[0]=  kpi(s_table,o[0])^round_k[3*kalina_128_64_key_len+0];
    i[1]=  kpi(s_table,o[1])^round_k[3*kalina_128_64_key_len+1];


    o[0]=  ksitau(gmul_table_RV, i[0],0, i[1],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[0],1, i[1],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[0],2, i[1],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[0],3, i[1],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[0],4, i[1],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[0],5, i[1],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[0],6, i[1],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[0],7, i[1],7, 7,6,5,4,3,2,1,0);

    o[1]=  ksitau(gmul_table_RV, i[1],0, i[0],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[1],1, i[0],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[1],2, i[0],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[1],3, i[0],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[1],4, i[0],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[1],5, i[0],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[1],6, i[0],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[1],7, i[0],7, 7,6,5,4,3,2,1,0);

    i[0]=  kpi(s_table,o[0])^round_k[2*kalina_128_64_key_len+0];
    i[1]=  kpi(s_table,o[1])^round_k[2*kalina_128_64_key_len+1];


    o[0]=  ksitau(gmul_table_RV, i[0],0, i[1],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[0],1, i[1],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[0],2, i[1],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[0],3, i[1],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[0],4, i[1],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[0],5, i[1],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[0],6, i[1],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[0],7, i[1],7, 7,6,5,4,3,2,1,0);

    o[1]=  ksitau(gmul_table_RV, i[1],0, i[0],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[1],1, i[0],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[1],2, i[0],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[1],3, i[0],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[1],4, i[0],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[1],5, i[0],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[1],6, i[0],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[1],7, i[0],7, 7,6,5,4,3,2,1,0);

    i[0]=  kpi(s_table,o[0])^round_k[1*kalina_128_64_key_len+0];
    i[1]=  kpi(s_table,o[1])^round_k[1*kalina_128_64_key_len+1];


    o[0]=  ksitau(gmul_table_RV, i[0],0, i[1],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[0],1, i[1],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[0],2, i[1],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[0],3, i[1],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[0],4, i[1],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[0],5, i[1],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[0],6, i[1],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[0],7, i[1],7, 7,6,5,4,3,2,1,0);

    o[1]=  ksitau(gmul_table_RV, i[1],0, i[0],0, 0,7,6,5,4,3,2,1)^
           ksitau(gmul_table_RV, i[1],1, i[0],1, 1,0,7,6,5,4,3,2)^
           ksitau(gmul_table_RV, i[1],2, i[0],2, 2,1,0,7,6,5,4,3)^
           ksitau(gmul_table_RV, i[1],3, i[0],3, 3,2,1,0,7,6,5,4)^
           ksitau(gmul_table_RV, i[1],4, i[0],4, 4,3,2,1,0,7,6,5)^
           ksitau(gmul_table_RV, i[1],5, i[0],5, 5,4,3,2,1,0,7,6)^
           ksitau(gmul_table_RV, i[1],6, i[0],6, 6,5,4,3,2,1,0,7)^
           ksitau(gmul_table_RV, i[1],7, i[0],7, 7,6,5,4,3,2,1,0);

    i[0]=  kpi(s_table,o[0])-round_k[0*kalina_128_64_key_len+0];
    i[1]=  kpi(s_table,o[1])-round_k[0*kalina_128_64_key_len+1];
}


void kalina_128_128_prepare(tkalina_128 *kalina, void *iv,void *round_keys, void *big_table){

    kalina->index=0;
    kalina->big_table=big_table;
    kalina->round_keys=round_keys;
    kalina_128_128_encrypt_block(kalina->s,iv,kalina->round_keys,kalina->big_table);
}


void kalina_128_128_CTR(tkalina_128 *kalina, void *out_buf, void *in_buf, uint32_t size, uint32_t n){
    uint64_t *o;
    uint64_t *i;

    uint8_t  *o8=(uint8_t *)out_buf;
    uint8_t  *i8=(uint8_t *)in_buf;
    uint64_t *v=(uint64_t *)kalina->v;
    uint32_t  k;
    uint32_t  l;
    uint32_t  j=0;
    uint32_t  t;

    if(kalina->index!=0){

        while((kalina->index!=kalina_128_key_len_bytes) && (size>0)){

            o8[j]=i8[j]^kalina->v[kalina->index];
            kalina->index++;
            size--;

        }

        kalina->index=0;
        o=(uint64_t *)&o8[j];
        i=(uint64_t *)&i8[j];
        j=0;

    }else{

        o=(uint64_t *)out_buf;
        i=(uint64_t *)in_buf;
    }

    k=size>>3;
    l=size - k*8;
    t=k>>1;

    k=k-t*kalina_128_64_key_len;

    while(t){
        kalina_inc_one(kalina->s,kalina_128_64_key_len);
        kalina_128_128_encrypt_block(v,kalina->s,kalina->round_keys,kalina->big_table);
        o[j]=i[j]^v[0];
        j++;
        o[j]=i[j]^v[1];
        j++;
        t--;
    }

    if(k){
        kalina_inc_one(kalina->s,kalina_128_64_key_len);
        kalina_128_128_encrypt_block(kalina->v,kalina->s,kalina->round_keys,kalina->big_table);

        o[j]=i[j]^v[0];
        j++;
    }

    j=j*8;

    if(l){


        if(k){
            kalina->index=8;
        }else{
            kalina_inc_one(kalina->s,kalina_128_64_key_len);
            kalina_128_128_encrypt_block(v,kalina->s,kalina->round_keys,kalina->big_table);

            kalina->index=0;
        }

        while(l){
            o8[j]=i8[j]^kalina->v[kalina->index];
            kalina->index++;
            j++;
            l--;
        }


        if(kalina->index>=kalina_128_key_len_bytes){
           kalina->index=0;
        }

    }

    if(n){
       o8[j-1] &=((uint8_t)(0xFF<<(8-n)));
    }

}



void kalina_128_128_CFB_E(tkalina_128 *kalina, void *out_buf, void *in_buf, uint32_t size, uint32_t n, bool last){
    uint64_t *o=(uint64_t *)out_buf;
    uint64_t *i=(uint64_t *)in_buf;
    uint64_t *v;

    uint8_t  *o8=(uint8_t *)out_buf;
    uint8_t  *i8=(uint8_t *)in_buf;
    uint8_t  *v8=(uint8_t *)kalina->s;
    uint32_t  k;
    uint32_t  l;
    uint32_t  j=0;
    uint32_t  t;

    k=size>>3;
    l=size - k*8;
    t=k>>1;

    k=k-t*kalina_128_64_key_len;

    while(t){
        o[j]=i[j]^kalina->s[0];
        j++;
        o[j]=i[j]^kalina->s[1];
        j++;
        t--;
        kalina_128_128_encrypt_block(kalina->s,&o[j-kalina_128_64_key_len],kalina->round_keys,kalina->big_table);
    }

    if(k){

        if(last){
            t=kalina_128_key_len_bytes-k*8-l;
            v=(uint64_t *)&v8[t];
            v8=&v8[t];
        }else{
             v=kalina->s;
        }


        o[j]=i[j]^v[t];
        j++;


    }

    j=j*8;

    if(l){

        if(t){
            t=t*8;
        }else{
            t=0;
        }

        while(l){
            o8[j]=i8[j]^v8[t];
            t++;
            j++;
            l--;
        }

    }

     if((n) && (last)){
        o8[j-1] &=((uint8_t)(0xFF<<(8-n)));
     }

     if((size>kalina_128_key_len_bytes) && (!last)){
        kalina_128_128_encrypt_block(kalina->s,&o[j-kalina_128_64_key_len],kalina->round_keys,kalina->big_table);
     }


}

void kalina_128_128_CFB_D(tkalina_128 *kalina, void *out_buf, void *in_buf, uint32_t size, uint32_t n, bool last){
    uint64_t *o=(uint64_t *)out_buf;
    uint64_t *i=(uint64_t *)in_buf;
    uint64_t *v;

    uint8_t  *o8=(uint8_t *)out_buf;
    uint8_t  *i8=(uint8_t *)in_buf;
    uint8_t  *v8=(uint8_t *)kalina->s;
    uint32_t  k;
    uint32_t  l;
    uint32_t  j=0;
    uint32_t  t;

    k=size>>3;
    l=size - k*8;
    t=k>>1;

    k=k-t*kalina_128_64_key_len;

    while(t){
        o[j]=i[j]^kalina->s[0];
        j++;
        o[j]=i[j]^kalina->s[1];
        j++;
        t--;
        kalina_128_128_encrypt_block(kalina->s,&i[j-kalina_128_64_key_len],kalina->round_keys,kalina->big_table);
    }

    if(k){

        if(last){
            t=kalina_128_key_len_bytes-k*8-l;
            v=(uint64_t *)&v8[t];
            v8=&v8[t];
        }else{
             v=kalina->s;
        }


        o[j]=i[j]^v[t];
        j++;


    }

    j=j*8;

    if(l){

        if(t){
            t=t*8;
        }else{
            t=0;
        }

        while(l){
            o8[j]=i8[j]^v8[t];
            t++;
            j++;
            l--;
        }

    }

     if((n) && (last)){
        o8[j-1] &=((uint8_t)(0xFF<<(8-n)));
     }

     if((size>kalina_128_key_len_bytes) && (!last)){
       kalina_128_128_encrypt_block(kalina->s,&i[j-kalina_128_64_key_len],kalina->round_keys,kalina->big_table);
     }


}

