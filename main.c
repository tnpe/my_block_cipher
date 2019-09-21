#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <time.h>

struct pair
{
    BIGNUM *plaintext;
    BIGNUM *key;
};

BIGNUM *BN_xor(BIGNUM *a, BIGNUM *b)
{
    int i, length;
    BIGNUM *result;
    result = BN_new();
    BN_copy(result, a);
    length = BN_num_bits(a);
    if(BN_num_bits(b) > length)
        length = BN_num_bits(b);
    for(i = 0; i < length; i++)
    {
        if(BN_is_bit_set(a, i))
            if(BN_is_bit_set(b, i))
                BN_clear_bit(result, i);
            else
                BN_set_bit(result, i);
        else
            if(BN_is_bit_set(b, i))
                BN_set_bit(result, i);
            else
                BN_clear_bit(result, i);
    }
    return result;

}

struct pair round_func(struct pair text_and_key, int en_or_de, int round_number)
{
    int i;
    struct pair output_pair;
    BIGNUM *input, *input_left, *input_right, *temp_right, *output, *output_left, *output_right;
    BIGNUM *key, *key_left, *key_right, *round_key;
    input = BN_new();
    key = BN_new();
    BN_copy(input, text_and_key.plaintext);
    BN_copy(key, text_and_key.key);
    input_left = BN_new();
    input_right = BN_new();
    temp_right = BN_new();
    output = BN_new();
    output_left = BN_new();
    output_right = BN_new();
    round_key = BN_new();
    key_left = BN_new();
    key_right = BN_new();
    output_pair.key = BN_new();
    output_pair.plaintext = BN_new();
    BN_copy(input_left, input);
    BN_rshift(input_left, input_left, 16);
    BN_mask_bits(input_left, 16);
    BN_copy(input_right, input);
    BN_mask_bits(input_right, 16);
    BN_copy(output_left, input_right);
    BN_copy(output, input);
    BN_copy(key_left, key);
    BN_rshift(key_left, key_left, 16);
    BN_mask_bits(key_left, 16);
    BN_copy(key_right, key);
    BN_mask_bits(key_right, 16);

    if(en_or_de == 1)   //It's encryption, so move left
    {
        if(BN_is_bit_set(key_left, 15) == 1)
        {
            BN_lshift(key_left, key_left, 1);
            BN_sub_word(key_left, 65536);
            BN_set_bit(key_left, 0);
        }
        else
        {
            BN_lshift(key_left, key_left, 1);
            BN_clear_bit(key_left, 0);
        }

        if(BN_is_bit_set(key_right, 15) == 1)
        {
            BN_lshift(key_right, key_right, 1);
            BN_sub_word(key_right, 65536);
            BN_set_bit(key_right, 0);
        }
        else
        {
            BN_lshift(key_right, key_right, 1);
            BN_clear_bit(key_right, 0);
        }
    }
    if(en_or_de == 0 && round_number != 0)   //It's decryption, so move right
    {
        if(BN_is_bit_set(key_left, 0) == 1)
        {
            BN_rshift(key_left, key_left, 1);
            BN_add_word(key_left, 32768);
            BN_set_bit(key_left, 15);
        }
        else
        {
            BN_rshift(key_left, key_left, 1);
            BN_clear_bit(key_left, 15);
        }

        if(BN_is_bit_set(key_right, 0) == 1)
        {
            BN_rshift(key_right, key_right, 1);
            BN_add_word(key_right, 32768);
            BN_set_bit(key_right, 15);
        }
        else
        {
            BN_rshift(key_right, key_right, 1);
            BN_clear_bit(key_right, 15);
        }

    }
    BN_mul_word(key_left, 65536);
    BN_add(key, key_left, key_right);

    int key_box[32] = {25, 17, 9, 1, 26, 18, 10, 2, 27, 19,
                       11, 3, 21, 31, 15, 7};

    BN_copy(round_key, key);
    BN_mask_bits(round_key, 16);
    for(i = 0; i <= 15; i++)
    {
        if(BN_is_bit_set(key, key_box[i]))
            BN_set_bit(round_key, i);
        else
            BN_clear_bit(round_key, i);
    }


    BN_copy(output_right, BN_xor(input_right, round_key));
    int s_box[4][16] = {{14, 4, 13, 1,
                          2, 15, 11, 8,
                          3, 10, 6, 12,
                          5, 9, 0, 0},
                         {15, 1, 8, 14,
                          6, 11, 3, 4,
                          9, 7, 2, 13,
                          12, 0 ,5 ,10},
                         {13, 3, 11, 5,
                          14, 8 ,0 ,6,
                          4, 15, 1, 12,
                          7, 2, 10, 9},
                         {9, 0, 7, 11,
                          12, 5, 10, 6,
                          15, 3, 1, 14,
                          2, 8, 4, 13}};
    int s_box_index;
    for(i = 0; i <= 3; i++)
    {
        s_box_index = 1*BN_is_bit_set(output_right, (4*i) + 0) +
                      2*BN_is_bit_set(output_right, (4*i) + 1) +
                      4*BN_is_bit_set(output_right, (4*i) + 2) +
                      8*BN_is_bit_set(output_right, (4*i) + 3);
        int s_box_value;
        s_box_value = s_box[i][s_box_index];
        if((int)(s_box_value / 8) == 1)
        {
            BN_set_bit(output_right, (4*i) + 3);
            s_box_value = s_box_value - 8;
        }
        else
            BN_clear_bit(output_right, (4*i) + 3);
        if((int)(s_box_value / 4) == 1)
        {
            BN_set_bit(output_right, (4*i) + 2);
            s_box_value = s_box_value - 4;
        }
        else
            BN_clear_bit(output_right, (4*i) + 2);
        if((int)(s_box_value / 2) == 1)
        {
            BN_set_bit(output_right, (4*i) + 1);
            s_box_value = s_box_value - 2;
        }
        else
            BN_clear_bit(output_right, (4*i) + 1);
        if(s_box_value == 1)
            BN_set_bit(output_right, (4*i) + 0);
        else
            BN_clear_bit(output_right, (4*i) + 0);
    }
    int p_box[16] = {7, 12, 1, 15, 5, 10, 2, 8, 14, 0, 3, 9, 13, 6, 11, 4};
    BN_copy(temp_right, output_right);
    for(i = 0; i <= 15; i++)
    {
        if(BN_is_bit_set(temp_right, p_box[i]))
            BN_set_bit(output_right, i);
        else
            BN_clear_bit(output_right, i);
    }
    BN_copy(output_right, BN_xor(output_right,input_left));
    if(round_number != 15)
    {
        BN_mul_word(output_left, 65536);
        BN_add(output, output_left, output_right);
    }
    else
    {
        BN_mul_word(output_right, 65536);
        BN_add(output, output_left, output_right);
    }
    BN_copy(output_pair.plaintext, output);
    BN_copy(output_pair.key, key);
    return output_pair;

}

struct pair encryption(struct pair text_and_key)
{
    int i;
    for(i = 0; i <= 15; i++)
    {
        text_and_key = round_func(text_and_key, 1, i);
    }
    return text_and_key;
}

struct pair decryption(struct pair text_and_key)
{
    int i;
    for(i = 0; i <= 15; i++)
    {
        text_and_key = round_func(text_and_key, 0, i);
    }
    return text_and_key;
}

int main(int argc, char* argv[])
{
    if(argc != 5)
    {
        printf("Wrong Usage! Run program in command line with:\n"
               "1. parameter 0 for encryption or parameter 1 for decryption;\n"
               "2. encryption or decryption key;\n"
               "3. input file name;\n"
               "4. output file name.\n");
        exit(1);
    }
    FILE *fpr, *fpw;
    fpr = fopen(argv[3], "r");
    fpw = fopen(argv[4], "w");
    if(fpr == NULL)
    {
        printf("The input file cannot be opened!\n");
        exit(1);
    }
    if(fpw == NULL)
    {
        printf("The output file cannot be created!\n");
        exit(1);
    }

    struct pair text_and_key;
    BIGNUM *plaintext;
    BIGNUM *key;
    BIGNUM *ciphertext;
    plaintext = BN_new();
    key = BN_new();
    ciphertext = BN_new();
    text_and_key.key = BN_new();
    text_and_key.plaintext = BN_new();
    unsigned char *input_block, *output_block;
    BN_bin2bn((unsigned char*) argv[2], 4, key);
    input_block = (unsigned char*)malloc(sizeof(unsigned char)*4);
    output_block = (unsigned char*)malloc(sizeof(unsigned char)*4);

    BN_copy(text_and_key.key, key);
    while(1)
    {
        if(fgets(input_block, 5, fpr) != NULL)
        {
            BN_bin2bn(input_block, 4, plaintext);
            BN_copy(text_and_key.plaintext, plaintext);
            if(argv[1][0] == '0')
                BN_copy(ciphertext, encryption(text_and_key).plaintext);
            else if(argv[1][0] == '1')
                BN_copy(ciphertext, decryption(text_and_key).plaintext);
            else
            {
                printf("Use parameter 0 for encryption or parameter 1 for decryption!\n");
                exit(1);
            }
            BN_bn2bin(ciphertext, output_block);
            fputs(output_block, fpw);
        }
        else
            break;
    }

//    while(1)
//    {
//
//        input_block[0] = (unsigned char) (fgetc(fpr));
//        if(feof(fpr))
//        {
//            break ;
//        }
//        input_block[1] = (unsigned char) (fgetc(fpr));
//        if(feof(fpr))
//        {
//            input_block[1] = 0x00;
//            input_block[2] = 0x00;
//
//        }
//        input_block[2] = (unsigned char) (fgetc(fpr));
//        if(feof(fpr))
//        {
//            input_block[2] = 0x00;
//            input_block[3] = 0x00;
//            break ;
//        }
//        input_block[3] = (unsigned char) (fgetc(fpr));
//        if(feof(fpr))
//        {
//            input_block[3] = 0x00;
//        }
//        BN_bin2bn(input_block, 4, plaintext);
//        BN_copy(text_and_key.plaintext, plaintext);
//        BN_copy(ciphertext, decryption(text_and_key).plaintext);
//        BN_bn2bin(ciphertext, output_block);
//        fputs(output_block, fpw);
//    }
    BN_free(ciphertext);
    BN_free(plaintext);
    BN_free(key);
    BN_free(text_and_key.key);
    BN_free(text_and_key.plaintext);
    fclose(fpr);
    fclose(fpw);

    return 0;
}