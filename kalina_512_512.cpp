#include "kalina_512_512.h"


const uint64_t kalina_512_epsilon[80]={ 0x0001000100010001, 0x0001000100010001, 0x0001000100010001, 0x0001000100010001, 0x0001000100010001, 0x0001000100010001, 0x0001000100010001, 0x0001000100010001,
                                        0x0002000200020002, 0x0002000200020002, 0x0002000200020002, 0x0002000200020002, 0x0002000200020002, 0x0002000200020002, 0x0002000200020002, 0x0002000200020002,
                                        0x0004000400040004, 0x0004000400040004, 0x0004000400040004, 0x0004000400040004, 0x0004000400040004, 0x0004000400040004, 0x0004000400040004, 0x0004000400040004,
                                        0x0008000800080008, 0x0008000800080008, 0x0008000800080008, 0x0008000800080008, 0x0008000800080008, 0x0008000800080008, 0x0008000800080008, 0x0008000800080008,
                                        0x0010001000100010, 0x0010001000100010, 0x0010001000100010, 0x0010001000100010, 0x0010001000100010, 0x0010001000100010, 0x0010001000100010, 0x0010001000100010,
                                        0x0020002000200020, 0x0020002000200020, 0x0020002000200020, 0x0020002000200020, 0x0020002000200020, 0x0020002000200020, 0x0020002000200020, 0x0020002000200020,
                                        0x0040004000400040, 0x0040004000400040, 0x0040004000400040, 0x0040004000400040, 0x0040004000400040, 0x0040004000400040, 0x0040004000400040, 0x0040004000400040,
                                        0x0080008000800080, 0x0080008000800080, 0x0080008000800080, 0x0080008000800080, 0x0080008000800080, 0x0080008000800080, 0x0080008000800080, 0x0080008000800080,
                                        0x0100010001000100, 0x0100010001000100, 0x0100010001000100, 0x0100010001000100, 0x0100010001000100, 0x0100010001000100, 0x0100010001000100, 0x0100010001000100,
                                        0x0200020002000200, 0x0200020002000200, 0x0200020002000200, 0x0200020002000200, 0x0200020002000200, 0x0200020002000200, 0x0200020002000200, 0x0200020002000200};



#define kalina_512_ADD_8(o,x,y,t)\
    o[0]=x[0]+y[t+0];\
    o[1]=x[1]+y[t+1];\
    o[2]=x[2]+y[t+2];\
    o[3]=x[3]+y[t+3];\
    o[4]=x[4]+y[t+4];\
    o[5]=x[5]+y[t+5];\
    o[6]=x[6]+y[t+6];\
    o[7]=x[7]+y[t+7];


#define kalina_512_ksi_tau(t,in, z0,z1,z2,z3,z4,z5,z6,z7) t[0*kalina_table_chars_num+(((uint8_t *)in)[z0*8+0])]^\
                                                          t[1*kalina_table_chars_num+(((uint8_t *)in)[z1*8+1])]^\
                                                          t[2*kalina_table_chars_num+(((uint8_t *)in)[z2*8+2])]^\
                                                          t[3*kalina_table_chars_num+(((uint8_t *)in)[z3*8+3])]^\
                                                          t[4*kalina_table_chars_num+(((uint8_t *)in)[z4*8+4])]^\
                                                          t[5*kalina_table_chars_num+(((uint8_t *)in)[z5*8+5])]^\
                                                          t[6*kalina_table_chars_num+(((uint8_t *)in)[z6*8+6])]^\
                                                          t[7*kalina_table_chars_num+(((uint8_t *)in)[z7*8+7])]

#define kalina_512_ksi_tau_8(o, t, in) o[0]=kalina_512_ksi_tau(t,in, 0,7,6,5,4,3,2,1);\
                                       o[1]=kalina_512_ksi_tau(t,in, 1,0,7,6,5,4,3,2);\
                                       o[2]=kalina_512_ksi_tau(t,in, 2,1,0,7,6,5,4,3);\
                                       o[3]=kalina_512_ksi_tau(t,in, 3,2,1,0,7,6,5,4);\
                                       o[4]=kalina_512_ksi_tau(t,in, 4,3,2,1,0,7,6,5);\
                                       o[5]=kalina_512_ksi_tau(t,in, 5,4,3,2,1,0,7,6);\
                                       o[6]=kalina_512_ksi_tau(t,in, 6,5,4,3,2,1,0,7);\
                                       o[7]=kalina_512_ksi_tau(t,in, 7,6,5,4,3,2,1,0)

#define kalina_512_ksi_tau_8_XOR(o, x, b, t, in)    o[0]=kalina_512_ksi_tau(t,in, 0,7,6,5,4,3,2,1) ^ x[b+0];\
                                                    o[1]=kalina_512_ksi_tau(t,in, 1,0,7,6,5,4,3,2) ^ x[b+1];\
                                                    o[2]=kalina_512_ksi_tau(t,in, 2,1,0,7,6,5,4,3) ^ x[b+2];\
                                                    o[3]=kalina_512_ksi_tau(t,in, 3,2,1,0,7,6,5,4) ^ x[b+3];\
                                                    o[4]=kalina_512_ksi_tau(t,in, 4,3,2,1,0,7,6,5) ^ x[b+4];\
                                                    o[5]=kalina_512_ksi_tau(t,in, 5,4,3,2,1,0,7,6) ^ x[b+5];\
                                                    o[6]=kalina_512_ksi_tau(t,in, 6,5,4,3,2,1,0,7) ^ x[b+6];\
                                                    o[7]=kalina_512_ksi_tau(t,in, 7,6,5,4,3,2,1,0) ^ x[b+7]

#define kalina_512_ksi_tau_8_ADD(o, x, b, t, in)    o[0]=(kalina_512_ksi_tau(t,in, 0,7,6,5,4,3,2,1)) + x[b+0];\
                                                    o[1]=(kalina_512_ksi_tau(t,in, 1,0,7,6,5,4,3,2)) + x[b+1];\
                                                    o[2]=(kalina_512_ksi_tau(t,in, 2,1,0,7,6,5,4,3)) + x[b+2];\
                                                    o[3]=(kalina_512_ksi_tau(t,in, 3,2,1,0,7,6,5,4)) + x[b+3];\
                                                    o[4]=(kalina_512_ksi_tau(t,in, 4,3,2,1,0,7,6,5)) + x[b+4];\
                                                    o[5]=(kalina_512_ksi_tau(t,in, 5,4,3,2,1,0,7,6)) + x[b+5];\
                                                    o[6]=(kalina_512_ksi_tau(t,in, 6,5,4,3,2,1,0,7)) + x[b+6];\
                                                    o[7]=(kalina_512_ksi_tau(t,in, 7,6,5,4,3,2,1,0)) + x[b+7]





void kalina_512_512_generate_KD(void *kd, const void *key, const void *awesome_table){

    uint64_t i[kalina_512_64_key_len];
    uint64_t *k         =   (uint64_t *)key;
    uint64_t *o         =   (uint64_t *)kd;
    uint64_t *table     =   (uint64_t *)awesome_table;


    i[0] = kalina_kd_init_val(K_512, K_512)+k[0];
    i[1] = k[1];
    i[2] = k[2];
    i[3] = k[3];
    i[4] = k[4];
    i[5] = k[5];
    i[6] = k[6];
    i[7] = k[7];


    kalina_512_ksi_tau_8_XOR(o,k,0,table,i);
    kalina_512_ksi_tau_8_ADD(i,k,0,table,o);
    kalina_512_ksi_tau_8(o,table,i);



}

void kalina_512_512_generate_pair(void *out, const void *key_0, const void *kd, const void *awesome_table, const unsigned n ){
    const unsigned kalina_512_64_key_len_div_2=kalina_512_64_key_len>>1;
    uint64_t o[kalina_512_64_key_len];
    uint64_t *table=(uint64_t *)awesome_table;
    uint64_t *k=(uint64_t *)key_0;
    uint64_t *i=(uint64_t *)out;
    uint64_t *kt=(uint64_t *)kd;
    uint64_t t[kalina_512_64_key_len];

    kalina_512_ADD_8(t,kt,kalina_512_epsilon,n*kalina_512_64_key_len_div_2);
    kalina_512_ADD_8(i,t,k,0);
    kalina_512_ksi_tau_8_XOR(o,t,0,table,i);
    kalina_512_ksi_tau_8_ADD(i,t,0,table,o);



}

inline void kalina_512_rotate_left_19(void *out, void *in){
    _rotate_func((uint8_t *)in,(uint8_t *)out,19,64)
}


#define kalina_512_rotate_key(o,b,k, z0, z1, z2, z3, z4, z5, z6, z7 )   o[b+0]=k[z0];\
                                                                        o[b+1]=k[z1];\
                                                                        o[b+2]=k[z2];\
                                                                        o[b+3]=k[z3];\
                                                                        o[b+4]=k[z4];\
                                                                        o[b+5]=k[z5];\
                                                                        o[b+6]=k[z6];\
                                                                        o[b+7]=k[z7]

void kalina_512_512_generate_round_keys(void *out, const void *key_0, const void *awesome_table){
    uint64_t kd[kalina_512_64_key_len];
    uint64_t *o=(uint64_t *)out;
    uint64_t rot_key[kalina_512_64_key_len];
    uint64_t *key=(uint64_t *)key_0;

    kalina_512_512_generate_KD(kd, key_0, awesome_table);
    kalina_512_512_generate_pair(&o[0*kalina_512_64_key_len],   key_0,                             kd,awesome_table,0);
    kalina_512_512_generate_pair(&o[16*kalina_512_64_key_len],  key_0,                             kd,awesome_table,16);

    kalina_512_rotate_key(rot_key,0, key, 1,2,3,4,5,6,7,0);
    kalina_512_512_generate_pair(&o[2*kalina_512_64_key_len],   rot_key, kd,awesome_table,2);
    kalina_512_512_generate_pair(&o[18*kalina_512_64_key_len],  rot_key, kd,awesome_table,18);

    kalina_512_rotate_key(rot_key,0, key, 2,3,4,5,6,7,0,1);
    kalina_512_512_generate_pair(&o[4*kalina_512_64_key_len],   rot_key, kd,awesome_table,4);

    kalina_512_rotate_key(rot_key,0, key, 3,4,5,6,7,0,1,2);
    kalina_512_512_generate_pair(&o[6*kalina_512_64_key_len],   rot_key, kd,awesome_table,6);

    kalina_512_rotate_key(rot_key,0, key, 4,5,6,7,0,1,2,3);
    kalina_512_512_generate_pair(&o[8*kalina_512_64_key_len],   rot_key, kd,awesome_table,8);

    kalina_512_rotate_key(rot_key,0, key, 5,6,7,0,1,2,3,4);
    kalina_512_512_generate_pair(&o[10*kalina_512_64_key_len],  rot_key, kd,awesome_table,10);

    kalina_512_rotate_key(rot_key,0, key, 6,7,0,1,2,3,4,5);
    kalina_512_512_generate_pair(&o[12*kalina_512_64_key_len],  rot_key, kd,awesome_table,12);

    kalina_512_rotate_key(rot_key,0, key, 7,0,1,2,3,4,5,6);
    kalina_512_512_generate_pair(&o[14*kalina_512_64_key_len],  rot_key, kd,awesome_table,14);

    kalina_512_rotate_left_19(&o[1*kalina_512_64_key_len], &o[0*kalina_512_64_key_len]);
    kalina_512_rotate_left_19(&o[3*kalina_512_64_key_len], &o[2*kalina_512_64_key_len]);
    kalina_512_rotate_left_19(&o[5*kalina_512_64_key_len], &o[4*kalina_512_64_key_len]);
    kalina_512_rotate_left_19(&o[7*kalina_512_64_key_len], &o[6*kalina_512_64_key_len]);

    kalina_512_rotate_left_19(&o[9*kalina_512_64_key_len],  &o[8*kalina_512_64_key_len]);
    kalina_512_rotate_left_19(&o[11*kalina_512_64_key_len], &o[10*kalina_512_64_key_len]);
    kalina_512_rotate_left_19(&o[13*kalina_512_64_key_len], &o[12*kalina_512_64_key_len]);
    kalina_512_rotate_left_19(&o[15*kalina_512_64_key_len], &o[14*kalina_512_64_key_len]);
    kalina_512_rotate_left_19(&o[17*kalina_512_64_key_len], &o[16*kalina_512_64_key_len]);

}

void kalina_512_512_encrypt_block( void *out, const void *in, const void *roundkeys, const void *awesome_table){

    uint64_t i[kalina_512_64_key_len];
    uint64_t *k         =   (uint64_t *)roundkeys;
    uint64_t *o         =   (uint64_t *)out;
    uint64_t *table     =   (uint64_t *)awesome_table;
    uint64_t *block512  =   (uint64_t *)in;


    kalina_512_ADD_8(o,block512,k,  0*kalina_512_64_key_len);
    kalina_512_ksi_tau_8_XOR(i,k,   1*kalina_512_64_key_len,table,o);
    kalina_512_ksi_tau_8_XOR(o,k,   2*kalina_512_64_key_len,table,i);
    kalina_512_ksi_tau_8_XOR(i,k,   3*kalina_512_64_key_len,table,o);
    kalina_512_ksi_tau_8_XOR(o,k,   4*kalina_512_64_key_len,table,i);
    kalina_512_ksi_tau_8_XOR(i,k,   5*kalina_512_64_key_len,table,o);
    kalina_512_ksi_tau_8_XOR(o,k,   6*kalina_512_64_key_len,table,i);
    kalina_512_ksi_tau_8_XOR(i,k,   7*kalina_512_64_key_len,table,o);
    kalina_512_ksi_tau_8_XOR(o,k,   8*kalina_512_64_key_len,table,i);
    kalina_512_ksi_tau_8_XOR(i,k,   9*kalina_512_64_key_len,table,o);
    kalina_512_ksi_tau_8_XOR(o,k,   10*kalina_512_64_key_len,table,i);
    kalina_512_ksi_tau_8_XOR(i,k,   11*kalina_512_64_key_len,table,o);
    kalina_512_ksi_tau_8_XOR(o,k,   12*kalina_512_64_key_len,table,i);
    kalina_512_ksi_tau_8_XOR(i,k,   13*kalina_512_64_key_len,table,o);
    kalina_512_ksi_tau_8_XOR(o,k,   14*kalina_512_64_key_len,table,i);
    kalina_512_ksi_tau_8_XOR(i,k,   15*kalina_512_64_key_len,table,o);
    kalina_512_ksi_tau_8_XOR(o,k,   16*kalina_512_64_key_len,table,i);
    kalina_512_ksi_tau_8_XOR(i,k,   17*kalina_512_64_key_len,table,o);
    kalina_512_ksi_tau_8_ADD(o,k,   18*kalina_512_64_key_len,table,i);
}



void kalina_512_512_prepare(tkalina_512 *kalina, void *iv,void *round_keys, void *big_table){

    kalina->index=0;
    kalina->big_table=big_table;
    kalina->round_keys=round_keys;
    kalina_512_512_encrypt_block(kalina->s,iv,kalina->round_keys,kalina->big_table);
}

void kalina_512_512_CTR(tkalina_512 *kalina,void *out_buf, void *in_buf, uint32_t size, uint32_t n){
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

        while((kalina->index!=kalina_512_key_len_bytes) && (size>0)){

            o8[j]=i8[j]^kalina->v[kalina->index];
            kalina->index++;
            size--;
            j++;

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
    t=k>>3;

    k=k-t*kalina_512_64_key_len;

    while(t){
        kalina_inc_one(kalina->s,kalina_512_64_key_len);
        kalina_512_512_encrypt_block(v,kalina->s,kalina->round_keys,kalina->big_table);
        o[j]=i[j]^v[0];
        j++;
        o[j]=i[j]^v[1];
        j++;
        o[j]=i[j]^v[2];
        j++;
        o[j]=i[j]^v[3];
        j++;
        o[j]=i[j]^v[4];
        j++;
        o[j]=i[j]^v[5];
        j++;
        o[j]=i[j]^v[6];
        j++;
        o[j]=i[j]^v[7];
        j++;
        t--;
    }

    if(k){
        kalina_inc_one(kalina->s,kalina_512_64_key_len);
        kalina_512_512_encrypt_block(v,kalina->s,kalina->round_keys,kalina->big_table);
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
            kalina_inc_one(kalina->s,kalina_512_64_key_len);
            kalina_512_512_encrypt_block(v,kalina->s,kalina->round_keys,kalina->big_table);
            kalina->index=0;
        }

        while(l){
            o8[j]=i8[j]^kalina->v[kalina->index];
            kalina->index++;
            j++;
            l--;
        }

        if(kalina->index>=kalina_512_key_len_bytes){
           kalina->index=0;
        }
    }

     if(n){
        o8[j-1] &=((uint8_t)(0xFF<<(8-n)));
     }


}


void kalina_512_512_CFB_E(tkalina_512 *kalina, void *out_buf, void *in_buf, uint32_t size, uint32_t n, bool last){
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
    t=k>>3;

    k=k-t*kalina_512_64_key_len;

    while(t){
        o[j]=i[j]^kalina->s[0];
        j++;
        o[j]=i[j]^kalina->s[1];
        j++;
        o[j]=i[j]^kalina->s[2];
        j++;
        o[j]=i[j]^kalina->s[3];
        j++;
        o[j]=i[j]^kalina->s[4];
        j++;
        o[j]=i[j]^kalina->s[5];
        j++;
        o[j]=i[j]^kalina->s[6];
        j++;
        o[j]=i[j]^kalina->s[7];
        j++;
        t--;
        kalina_512_512_encrypt_block(kalina->s,&o[j-kalina_512_64_key_len],kalina->round_keys,kalina->big_table);
    }

    if(k){

        if(last){
            h=kalina_512_key_len_bytes-k*8-l;
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

     if((size>kalina_512_key_len_bytes) && (!last)){
       kalina_512_512_encrypt_block(kalina->s,&o[j-kalina_512_64_key_len],kalina->round_keys,kalina->big_table);
     }


}


void kalina_512_512_CFB_D(tkalina_512 *kalina, void *out_buf, void *in_buf, uint32_t size, uint32_t n, bool last){
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
    t=k>>3;

    k=k-t*kalina_512_64_key_len;

    while(t){
        o[j]=i[j]^kalina->s[0];
        j++;
        o[j]=i[j]^kalina->s[1];
        j++;
        o[j]=i[j]^kalina->s[2];
        j++;
        o[j]=i[j]^kalina->s[3];
        j++;
        o[j]=i[j]^kalina->s[4];
        j++;
        o[j]=i[j]^kalina->s[5];
        j++;
        o[j]=i[j]^kalina->s[6];
        j++;
        o[j]=i[j]^kalina->s[7];
        j++;
        t--;
        kalina_512_512_encrypt_block(kalina->s,&i[j-kalina_512_64_key_len],kalina->round_keys,kalina->big_table);
    }

    if(k){

        if(last){
            h=kalina_512_key_len_bytes-k*8-l;
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

     if((size>kalina_512_key_len_bytes) && (!last)){
       kalina_512_512_encrypt_block(kalina->s,&i[j-kalina_512_64_key_len],kalina->round_keys,kalina->big_table);
     }


}


