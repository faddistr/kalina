#include "common.h"
#include "galua_table.h"
#include "kalina_tables.h"
#include <string.h>

void kalina_generate_reverse_table(void *rev_s_blocks, const void *forw_s_blocks){
    unsigned i,j;
    uint8_t *in =(uint8_t *)forw_s_blocks;
    uint8_t *out=(uint8_t *)rev_s_blocks;

    for(i=0;i<kalina_tables_num;i++){
        for(j=0;j<kalina_table_chars_num;j++){
            out[i*kalina_table_chars_num+in[i*kalina_table_chars_num+j]]=j;
        }
    }
}

void kalina_make_awesome_table(void *out, void *s_blocks){
    unsigned i,j,k;
    uint8_t *s=(uint8_t *)s_blocks;
    uint8_t *o=(uint8_t *)out;

    for(k=0;k<kalina_tables_num;k++){
      for(i=0;i<kalina_table_chars_num;i++){
           for(j=0;j<kalina_V_num;j++){
                o[(k+0                )*kalina_table_chars_num*kalina_V_num+i*kalina_V_num+j]=galua_mul(V[j*kalina_V_num+(k+0                )], s[k*kalina_table_chars_num+i]);
                o[(k+kalina_tables_num)*kalina_table_chars_num*kalina_V_num+i*kalina_V_num+j]=galua_mul(V[j*kalina_V_num+(k+kalina_tables_num)], s[k*kalina_table_chars_num+i]);
            }
        }
    }
}

void kalina_make_reverse_awesome_table(void *out, void *s_blocks){
    unsigned i,j,k;
    uint8_t tmp[8*256];
    uint8_t *o=(uint8_t *)out;

    kalina_generate_reverse_table(tmp,s_blocks);

    for(k=0;k<kalina_tables_num;k++){
        for(i=0;i<kalina_table_chars_num;i++){
            for(j=0;j<kalina_V_num;j++){
                o[(k+0                )*kalina_table_chars_num*kalina_V_num+i*kalina_V_num+j]=galua_mul_forw(RV[j*kalina_V_num+(k+0                )], tmp[k*kalina_table_chars_num+i]);
                o[(k+kalina_tables_num)*kalina_table_chars_num*kalina_V_num+i*kalina_V_num+j]=galua_mul_forw(RV[j*kalina_V_num+(k+kalina_tables_num)], tmp[k*kalina_table_chars_num+i]);

            }

        }
    }

}

uint8_t galua_mul_forw(const uint8_t a, const uint8_t b)
{
 //peason algorithm
    uint16_t a_16=a;
    uint16_t b_16=b;
    uint16_t p=0;
    uint16_t i=0;

    for(i=0;i<8;i++){

       if ((b_16 & 1)!=0){
           p ^=a_16;
       }

       a_16<<=1;


       if(a_16 & 0x100){
           a_16 ^=0x11D;
       }

       b_16>>=1;
    }

    return (uint8_t)(p & 0x00FF);
}

void kalina_ksi(void *in, void *out, const uint8_t c){

    uint8_t *G=(uint8_t *)in;
    uint8_t *W=(uint8_t *)out;
    uint8_t i=0;
    uint8_t j=0;


    for(i=0;i<8;i++){
        for(j=0;j<c;j++){
            W[j*8+i]=galua_mul(V[i*8+0],G[j*8+0])^
                      galua_mul(V[i*8+1],G[j*8+1])^
                      galua_mul(V[i*8+2],G[j*8+2])^
                      galua_mul(V[i*8+3],G[j*8+3])^
                      galua_mul(V[i*8+4],G[j*8+4])^
                      galua_mul(V[i*8+5],G[j*8+5])^
                      galua_mul(V[i*8+6],G[j*8+6])^
                      galua_mul(V[i*8+7],G[j*8+7]);
        }
    }



}

void kalina_add_mod64(void *a, void *b, const uint8_t c)
{
    uint64_t *a_64=(uint64_t *)a;
    uint64_t *b_64=(uint64_t *)b;
    uint32_t i=0;

    for(i=0;i<c;i++){
        *a_64+=*b_64;
        a_64++;
        b_64++;
    }
}


void kalina_s_block(void *buf, void *s_blocks, const unsigned size)
{
   uint32_t i;
   uint8_t  *ar=(uint8_t *)buf;
   uint8_t  *s_b=(uint8_t *)s_blocks;

   for(i=0;i<size;i++){
       ar[i]=s_b[(i & 0x03L)*256+ar[i]];
   }
}


void kalina_xor(void *a, void *b, const uint8_t c){
    uint32_t i=0;
    uint64_t *a_64=(uint64_t *)a;
    uint64_t *b_64=(uint64_t *)b;

    for(i=0;i<c;i++){
          *a_64++^=*b_64++;
    }
}


void kalina_lsh_64(void *b, unsigned num_8b_blocks, uint8_t n){
    uint64_t *a=(uint64_t *)b;

    while(num_8b_blocks--){
        *a<<=n;
        a++;
    }

}

void kalina_rol_64(void *b, unsigned num_8b_blocks, uint8_t n){

    uint64_t *a=(uint64_t *)b;
    unsigned hi_bit_prev=0;
    unsigned hi_bit_new=0;
    unsigned i,j;

    for(j=0;j<n;j++){
        for(i=0;i<num_8b_blocks;i++){
            hi_bit_new=(*a >> 63);
            *a=(*a << 1) | hi_bit_prev;
            hi_bit_prev=hi_bit_new;
            a++;
        }
        a-=num_8b_blocks;
    }

}

void kalina_inc_one(uint64_t *buf, const unsigned s_64){
    unsigned i;
    unsigned carry;

    for(i=0,carry=1; ((i<s_64) && (carry==1)); i++){
        carry=!(++buf[i]);
    }
}


