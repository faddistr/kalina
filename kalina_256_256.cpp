#include "kalina_256_256.h"

const uint64_t kalina_256_epsilon[32]={ 0x0001000100010001, 0x0001000100010001, 0x0001000100010001, 0x0001000100010001,
                                        0x0002000200020002, 0x0002000200020002, 0x0002000200020002, 0x0002000200020002,
                                        0x0004000400040004, 0x0004000400040004, 0x0004000400040004, 0x0004000400040004,
                                        0x0008000800080008, 0x0008000800080008, 0x0008000800080008, 0x0008000800080008,
                                        0x0010001000100010, 0x0010001000100010, 0x0010001000100010, 0x0010001000100010,
                                        0x0020002000200020, 0x0020002000200020, 0x0020002000200020, 0x0020002000200020,
                                        0x0040004000400040, 0x0040004000400040, 0x0040004000400040, 0x0040004000400040,
                                        0x0080008000800080, 0x0080008000800080, 0x0080008000800080, 0x0080008000800080};

#define kalina_add_4(out,x1,x2,b) out[0]=x1[ 0 ] + x2[ b + 0];\
                                  out[1]=x1[ 1 ] + x2[ b + 1];\
                                  out[2]=x1[ 2 ] + x2[ b + 2];\
                                  out[3]=x1[ 3 ] + x2[ b + 3]


#define kalina_256_256_ksitaupi(t, in, z0, z1, z2, z3, z4, z5, z6, z7) t[ 0 * kalina_table_chars_num + ( (in[ z0 ] >> ( 0 * 8) ) & 0xFF)]^\
                                                                       t[ 1 * kalina_table_chars_num + ( (in[ z1 ] >> ( 1 * 8) ) & 0xFF)]^\
                                                                       t[ 2 * kalina_table_chars_num + ( (in[ z2 ] >> ( 2 * 8) ) & 0xFF)]^\
                                                                       t[ 3 * kalina_table_chars_num + ( (in[ z3 ] >> ( 3 * 8) ) & 0xFF)]^\
                                                                       t[ 4 * kalina_table_chars_num + ( (in[ z4 ] >> ( 4 * 8) ) & 0xFF)]^\
                                                                       t[ 5 * kalina_table_chars_num + ( (in[ z5 ] >> ( 5 * 8) ) & 0xFF)]^\
                                                                       t[ 6 * kalina_table_chars_num + ( (in[ z6 ] >> ( 6 * 8) ) & 0xFF)]^\
                                                                       t[ 7 * kalina_table_chars_num + ( (in[ z7 ] >> ( 7 * 8) ) & 0xFF)]


#define kalina_256_256_ksitaupi_XOR( x, t, in, z0, z1, z2, z3, z4, z5, z6, z7 ) kalina_256_256_ksitaupi( t, in, z0, z1, z2, z3, z4, z5, z6, z7 )^x

#define kalina_256_256_ksitaupi_ADD( x, t, in, z0, z1, z2, z3, z4, z5, z6, z7 ) ( kalina_256_256_ksitaupi( t, in, z0, z1, z2, z3, z4, z5, z6, z7 ) )+x


#define kalina_256_256_ksitaupi_4(o, t, in ) o[0] = kalina_256_256_ksitaupi(t,in, 0,0,3,3,2,2,1,1 );\
                                             o[1] = kalina_256_256_ksitaupi(t,in, 1,1,0,0,3,3,2,2 );\
                                             o[2] = kalina_256_256_ksitaupi(t,in, 2,2,1,1,0,0,3,3 );\
                                             o[3] = kalina_256_256_ksitaupi(t,in, 3,3,2,2,1,1,0,0 )


#define kalina_256_256_ksitaupi_XOR4(o, x, b, t, in ) o[0] = kalina_256_256_ksitaupi_XOR(x[b+0],t,in, 0,0,3,3,2,2,1,1 );\
                                                      o[1] = kalina_256_256_ksitaupi_XOR(x[b+1],t,in, 1,1,0,0,3,3,2,2 );\
                                                      o[2] = kalina_256_256_ksitaupi_XOR(x[b+2],t,in, 2,2,1,1,0,0,3,3 );\
                                                      o[3] = kalina_256_256_ksitaupi_XOR(x[b+3],t,in, 3,3,2,2,1,1,0,0 )

#define kalina_256_256_ksitaupi_ADD4(o, x, b, t, in ) o[0] = kalina_256_256_ksitaupi_ADD(x[b+0],t,in, 0,0,3,3,2,2,1,1 );\
                                                      o[1] = kalina_256_256_ksitaupi_ADD(x[b+1],t,in, 1,1,0,0,3,3,2,2 );\
                                                      o[2] = kalina_256_256_ksitaupi_ADD(x[b+2],t,in, 2,2,1,1,0,0,3,3 );\
                                                      o[3] = kalina_256_256_ksitaupi_ADD(x[b+3],t,in, 3,3,2,2,1,1,0,0 )



void kalina_256_256_generate_KD(void *kd, const void *key, const void *awesome_table){

    uint64_t i[kalina_256_64_key_len];
    uint64_t *table=(uint64_t *)awesome_table;
    uint64_t *k=(uint64_t *)key;
    uint64_t *o=(uint64_t *)kd;


    i[0] = kalina_kd_init_val(K_256, K_256)+k[0];
    i[1] = k[1];
    i[2] = k[2];
    i[3] = k[3];

    kalina_256_256_ksitaupi_XOR4(o,k,0,table,i);
    kalina_256_256_ksitaupi_ADD4(i,k,0,table,o);
    kalina_256_256_ksitaupi_4(o,table,i);

}

void kalina_256_256_generate_pair(void *out, const void *key_0, const void *kd, const void *awesome_table, const unsigned n ){

    const unsigned kalina_256_64_key_len_div_2=kalina_256_64_key_len>>1;
    uint64_t o[kalina_256_64_key_len];
    uint64_t *table=(uint64_t *)awesome_table;
    uint64_t *k=(uint64_t *)key_0;
    uint64_t *i=(uint64_t *)out;
    uint64_t *kt=(uint64_t *)kd;
    uint64_t t[kalina_256_64_key_len];

    kalina_add_4(t,kt,kalina_256_epsilon,n*kalina_256_64_key_len_div_2);
    kalina_add_4(i,t,k,0);
    kalina_256_256_ksitaupi_XOR4(o,t,0,table,i);
    kalina_256_256_ksitaupi_ADD4(i,t,0,table,o);
}

inline void kalina_256_rotate_left_11(void *out, void *in){
    _rotate_func((uint8_t *)in,(uint8_t *)out,11,32)
}


#define kalina_256_256_rotate_key(o,b,x,z0,z1,z2,z3) o[b+0]=x[z0];\
                                                     o[b+1]=x[z1];\
                                                     o[b+2]=x[z2];\
                                                     o[b+3]=x[z3]

void kalina_256_256_generate_round_keys(void *out, const void *key_0, const void *awesome_table){

    uint64_t *o=(uint64_t *)out;
    uint64_t *key=(uint64_t *)key_0;
    uint64_t kd[kalina_256_64_key_len];
    uint64_t rot_key[ kalina_256_64_key_len ];

    kalina_256_256_generate_KD(kd,key_0,awesome_table);

    kalina_256_256_generate_pair(&o[kalina_256_64_key_len*0],key_0,kd,awesome_table,0);
    kalina_256_256_generate_pair(&o[kalina_256_64_key_len*8],key_0,kd,awesome_table,8);

    kalina_256_256_rotate_key(rot_key,0,key,1,2,3,0);
    kalina_256_256_generate_pair(&o[kalina_256_64_key_len*2], rot_key,kd,awesome_table,2);
    kalina_256_256_generate_pair(&o[kalina_256_64_key_len*10],rot_key,kd,awesome_table,10);

    kalina_256_256_rotate_key(rot_key,0,key,2,3,0,1);
    kalina_256_256_generate_pair(&o[kalina_256_64_key_len*4], rot_key,kd,awesome_table,4);
    kalina_256_256_generate_pair(&o[kalina_256_64_key_len*12],rot_key,kd,awesome_table,12);

    kalina_256_256_rotate_key(rot_key,0,key,3,0,1,2);
    kalina_256_256_generate_pair(&o[kalina_256_64_key_len*6], rot_key,kd,awesome_table,6);
    kalina_256_256_generate_pair(&o[kalina_256_64_key_len*14],rot_key,kd,awesome_table,14);

    kalina_256_rotate_left_11(&o[kalina_256_64_key_len*1],&o[kalina_256_64_key_len*0]);
    kalina_256_rotate_left_11(&o[kalina_256_64_key_len*3],&o[kalina_256_64_key_len*2]);

    kalina_256_rotate_left_11(&o[kalina_256_64_key_len*5],&o[kalina_256_64_key_len*4]);
    kalina_256_rotate_left_11(&o[kalina_256_64_key_len*7],&o[kalina_256_64_key_len*6]);

    kalina_256_rotate_left_11(&o[kalina_256_64_key_len*9],&o[kalina_256_64_key_len*8]);
    kalina_256_rotate_left_11(&o[kalina_256_64_key_len*11],&o[kalina_256_64_key_len*10]);

    kalina_256_rotate_left_11(&o[kalina_256_64_key_len*13],&o[kalina_256_64_key_len*12]);

}



void kalina_256_256_encrypt_block( void *out, void *in, const void *roundkey, const void *awesome_table)
{
    uint64_t *i=(uint64_t *)out;
    uint64_t o[4];
    uint64_t *table=(uint64_t *)awesome_table;
    uint64_t *key=(uint64_t *)roundkey;
    uint64_t *block256=(uint64_t *)in;

    kalina_add_4(i,block256,key,0*kalina_256_64_key_len);

    kalina_256_256_ksitaupi_XOR4(o,key,1*kalina_256_64_key_len,table,i);
    kalina_256_256_ksitaupi_XOR4(i,key,2*kalina_256_64_key_len,table,o);

    kalina_256_256_ksitaupi_XOR4(o,key,3*kalina_256_64_key_len,table,i);
    kalina_256_256_ksitaupi_XOR4(i,key,4*kalina_256_64_key_len,table,o);

    kalina_256_256_ksitaupi_XOR4(o,key,5*kalina_256_64_key_len,table,i);
    kalina_256_256_ksitaupi_XOR4(i,key,6*kalina_256_64_key_len,table,o);

    kalina_256_256_ksitaupi_XOR4(o,key,7*kalina_256_64_key_len,table,i);
    kalina_256_256_ksitaupi_XOR4(i,key,8*kalina_256_64_key_len,table,o);

    kalina_256_256_ksitaupi_XOR4(o,key,9*kalina_256_64_key_len,table,i);
    kalina_256_256_ksitaupi_XOR4(i,key,10*kalina_256_64_key_len,table,o);

    kalina_256_256_ksitaupi_XOR4(o,key,11*kalina_256_64_key_len,table,i);
    kalina_256_256_ksitaupi_XOR4(i,key,12*kalina_256_64_key_len,table,o);

    kalina_256_256_ksitaupi_XOR4(o,key,13*kalina_256_64_key_len,table,i);
    kalina_256_256_ksitaupi_ADD4(i,key,14*kalina_256_64_key_len,table,o);
}



void kalina_256_256_prepare(tkalina_256 *kalina, void *iv,void *round_keys, void *big_table){

    kalina->index=0;
    kalina->big_table=big_table;
    kalina->round_keys=round_keys;

    kalina_256_256_encrypt_block(kalina->s,iv,kalina->round_keys,kalina->big_table);

}
/*
 *
 *
 *
*/


void kalina_256_256_CTR(tkalina_256 *kalina,void *out_buf, void *in_buf, uint32_t size, uint32_t n){
    uint64_t *o;
    uint64_t *i;

    uint8_t  *o8=(uint8_t *)out_buf;
    uint8_t  *i8=(uint8_t *)in_buf;
    uint64_t *v=(uint64_t *)kalina->v;
    uint32_t  k;
    uint32_t  l;
    uint32_t  j=0, h=0;
    uint32_t  t;

    if(kalina->index!=0){

        while((kalina->index!=kalina_256_key_len_bytes) && (size>0)){

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
    t=k>>2;

    k=k-t*kalina_256_64_key_len;

    while(t){
        kalina_inc_one(kalina->s,kalina_256_64_key_len);
        kalina_256_256_encrypt_block(v,kalina->s,kalina->round_keys,kalina->big_table);
        o[j]=i[j]^v[0];
        j++;
        o[j]=i[j]^v[1];
        j++;
        o[j]=i[j]^v[2];
        j++;
        o[j]=i[j]^v[3];
        j++;
        t--;
    }

    if(k){
        kalina_inc_one(kalina->s,kalina_256_64_key_len);
        kalina_256_256_encrypt_block(kalina->v,kalina->s,kalina->round_keys,kalina->big_table);
        h=0;
        while(k){
            o[j]=i[j]^v[h];
            j++;
            h++;
            k--;
        }
    }

    j=j*8;

    if(l){


        if(h){
            kalina->index=h*8;
        }else{
            kalina_inc_one(kalina->s,kalina_256_64_key_len);
            kalina_256_256_encrypt_block(v,kalina->s,kalina->round_keys,kalina->big_table);
            kalina->index=0;
        }

        while(l){
            o8[j]=i8[j]^kalina->v[kalina->index];
            kalina->index++;
            j++;
            l--;
        }


        if(kalina->index>=kalina_256_key_len_bytes){
           kalina->index=0;
        }

    }

    if(n){
       o8[j-1] &=((uint8_t)(0xFF<<(8-n)));
    }



}


void kalina_256_256_CFB_E(tkalina_256 *kalina, void *out_buf, void *in_buf, uint32_t size, uint32_t n, bool last){
    uint64_t *o=(uint64_t *)out_buf;
    uint64_t *i=(uint64_t *)in_buf;
    uint64_t *v;

    uint8_t  *o8=(uint8_t *)out_buf;
    uint8_t  *i8=(uint8_t *)in_buf;
    uint8_t  *v8=(uint8_t *)kalina->s;
    uint32_t  k;
    uint32_t  l;
    uint32_t  j=0, h=0;
    uint32_t  t;

    k=size>>3;
    l=size - k*8;
    t=k>>2;

    k=k-t*kalina_256_64_key_len;

    while(t){
        o[j]=i[j]^kalina->s[0];
        j++;
        o[j]=i[j]^kalina->s[1];
        j++;
        o[j]=i[j]^kalina->s[2];
        j++;
        o[j]=i[j]^kalina->s[3];
        j++;
        t--;
        kalina_256_256_encrypt_block(kalina->s,&o[j-kalina_256_64_key_len],kalina->round_keys,kalina->big_table);
    }

    if(k){

        if(last){
            h=kalina_256_key_len_bytes-k*8-l;
            v=(uint64_t *)&v8[h];
            v8=&v8[h];
        }else{
             v=kalina->s;
        }

        h=0;
        while(k){
            o[j]=i[j]^v[h];
            j++;
            h++;
            k--;
        }
    }

    j=j*8;

    if(l){


        if(h){
            t=h*8;
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

     if((size>kalina_256_key_len_bytes) && (!last)){
       kalina_256_256_encrypt_block(kalina->s,&o[j-kalina_256_64_key_len],kalina->round_keys,kalina->big_table);
     }


}

void kalina_256_256_CFB_D(tkalina_256 *kalina, void *out_buf, void *in_buf, uint32_t size, uint32_t n, bool last){
    uint64_t *o=(uint64_t *)out_buf;
    uint64_t *i=(uint64_t *)in_buf;
    uint64_t *v;

    uint8_t  *o8=(uint8_t *)out_buf;
    uint8_t  *i8=(uint8_t *)in_buf;
    uint8_t  *v8=(uint8_t *)kalina->s;
    uint32_t  k;
    uint32_t  l;
    uint32_t  j=0, h=0;
    uint32_t  t;

    k=size>>3;
    l=size - k*8;
    t=k>>2;

    k=k-t*kalina_256_64_key_len;

    while(t){
        o[j]=i[j]^kalina->s[0];
        j++;
        o[j]=i[j]^kalina->s[1];
        j++;
        o[j]=i[j]^kalina->s[2];
        j++;
        o[j]=i[j]^kalina->s[3];
        j++;
        t--;
        kalina_256_256_encrypt_block(kalina->s,&i[j-kalina_256_64_key_len],kalina->round_keys,kalina->big_table);
    }

    if(k){

        if(last){
            h=kalina_256_key_len_bytes-k*8-l;
            v=(uint64_t *)&v8[h];
            v8=&v8[h];
        }else{
             v=kalina->s;
        }

        h=0;
        while(k){
            o[j]=i[j]^v[h];
            j++;
            h++;
            k--;
        }
    }

    j=j*8;

    if(l){


        if(h){
            t=h*8;
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

     if((size>kalina_256_key_len_bytes) && (!last)){
       kalina_256_256_encrypt_block(kalina->s,&i[j-kalina_256_64_key_len],kalina->round_keys,kalina->big_table);
     }
}




