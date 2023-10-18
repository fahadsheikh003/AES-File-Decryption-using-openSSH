#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

using namespace std;

#endif /* __PROGTEST__ */

const int BUFFER_SIZE = 1024;

bool seal( const char * inFile, const char * outFile, const char * publicKeyFile, const char * symmetricCipher)
{
    // Read the public key from the file
    FILE* publicKey = fopen(publicKeyFile, "rb");
    if (!publicKey) {
        cerr << "Failed to read public key file" << endl;
        return false;
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(publicKey, NULL, NULL, NULL);
    fclose(publicKey);
    if (!pkey) {
        cerr << "Failed to read public key" << endl;
        return false;
    }

    // Create symmetric cipher context
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(symmetricCipher);
    if (!cipher) {
        cerr << "Invalid symmetric cipher" << endl;
        return false;
    }

    // Get the numerical identifier of the cipher
    int nid = EVP_CIPHER_nid(cipher);
    if (nid == NID_undef) {
        cerr << "Failed to get cipher nid." << endl;
        return false;
    }

    const int key_len = EVP_CIPHER_key_length(cipher); // Key length for the cipher algorithm
    const int iv_len = EVP_CIPHER_iv_length(cipher); // IV length for the cipher algorithm

    // Allocate memory for the key and IV
    unsigned char key[key_len];
    unsigned char iv[iv_len];

    // Generate the key and IV
    if (!RAND_bytes(key, key_len)) {
        cerr << "Failed to generate key" << endl;
        return false;
    }
    if (!RAND_bytes(iv, iv_len)) {
        cerr << "Failed to generate IV" << endl;
        return false;
    }

    // Create public key context
    EVP_PKEY_CTX * public_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!public_ctx) {
        cerr << "Failed to create public key context" << endl;
        return false;
    }
    if (EVP_PKEY_encrypt_init(public_ctx) <= 0) {
        cerr << "Failed to initialize public key context" << endl;
        EVP_PKEY_CTX_free(public_ctx);
        return false;
    }
    // if (EVP_PKEY_CTX_set_rsa_padding(public_ctx, RSA_PKCS1_PADDING) <= 0) {
    //     cerr << "Failed to set RSA padding" << endl;
    //     EVP_PKEY_CTX_free(public_ctx);
    //     return false;
    // }
    
    // Length of the public key
    int pub_key_len = EVP_PKEY_size(pkey);

    // Allocate memory for the encrypted key
    unsigned char encrypted_key[pub_key_len];

    // Encrypt the key
    size_t encrypted_len;
    if (EVP_PKEY_encrypt(public_ctx, encrypted_key, &encrypted_len, key, key_len) <= 0) {
        cerr << "Failed to encrypt key" << endl;
        EVP_PKEY_CTX_free(public_ctx);
        return false;
    }
    
    // Free the Public Key Context
    EVP_PKEY_CTX_free(public_ctx);

    // Create cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Failed to create cipher context" << endl;
        return false;
    }

    // Initialize cipher context
    if (!EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
        cerr << "Failed to initialize cipher context" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Open input file
    FILE* input = fopen(inFile, "rb");
    if (!input) {
        cerr << "Failed to open input file" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Open output file
    FILE* output = fopen(outFile, "wb");
    if (!output) {
        cerr << "Failed to open output file" << endl;
        fclose(input);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Allocate memory for the input buffer
    unsigned char in_buf[BUFFER_SIZE];

    // Allocate memory for the output buffer
    unsigned char out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];

    // Read the input file, encrypt it and write it to the output file
    int bytes_read;
    int bytes_written;

    // write numerical identifier of the cipher used in the output file
    fwrite(&nid, sizeof(int), 1, output);

    //write the length of the encrypted key in the output file
    fwrite(&encrypted_len, sizeof(int), 1, output);

    //write encrypted key in the output file
    fwrite(encrypted_key, sizeof(unsigned char), encrypted_len, output);

    //write IV in the output file
    fwrite(iv, sizeof(unsigned char), iv_len, output);    

    while ((bytes_read = fread(in_buf, sizeof(unsigned char), BUFFER_SIZE, input)) > 0) {
        if (!EVP_EncryptUpdate(ctx, out_buf, &bytes_written, in_buf, bytes_read)) {
            cerr << "Failed to encrypt data" << endl;
            fclose(input);
            fclose(output);
            remove(outFile);
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        fwrite(out_buf, sizeof(unsigned char), bytes_written, output);
    }

    if (!EVP_EncryptFinal_ex(ctx, out_buf, &bytes_written)) {
        cerr << "Failed to finalize encryption" << endl;
        fclose(input);
        fclose(output);
        remove(outFile);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    fwrite(out_buf, sizeof(unsigned char), bytes_written, output);    

    // Close input and output files
    fclose(input);
    fclose(output);

    // Free the cipher context
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool open( const char * inFile, const char * outFile, const char * privateKeyFile)
{
    // Open input file
    FILE* input = fopen(inFile, "rb");
    if (!input) {
        cerr << "Failed to open input file" << endl;
        return false;
    }

    // Read the numerical identifier of the cipher used
    int nid;
    fread(&nid, sizeof(int), 1, input);

    // Create Cipher Context
    const EVP_CIPHER* cipher = EVP_get_cipherbynid(nid);
    if (!cipher) {
        cerr << "Invalid cipher" << endl;
        return false;
    }

    // Read the length of the encrypted key
    int encrypted_key_len;
    fread(&encrypted_key_len, sizeof(int), 1, input);

    // Read the encrypted key
    unsigned char encrypted_key[encrypted_key_len];
    fread(encrypted_key, sizeof(unsigned char), encrypted_key_len, input);

    // Read the IV
    int iv_len = EVP_CIPHER_iv_length(cipher);
    unsigned char iv[iv_len];
    fread(iv, sizeof(unsigned char), iv_len, input);

    // Read the private key from the file
    FILE* privateKey = fopen(privateKeyFile, "rb");
    if (!privateKey) {
        cerr << "Failed to read private key file" << endl;
        return false;
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(privateKey, NULL, NULL, NULL);
    fclose(privateKey);
    if (!pkey) {
        cerr << "Failed to read private key" << endl;
        return false;
    }

    // Create private key context
    EVP_PKEY_CTX * private_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!private_ctx) {
        cerr << "Failed to create private key context" << endl;
        return false;
    }
    if (EVP_PKEY_decrypt_init(private_ctx) <= 0) {
        cerr << "Failed to initialize private key context" << endl;
        EVP_PKEY_CTX_free(private_ctx);
        return false;
    }
    // if (EVP_PKEY_CTX_set_rsa_padding(private_ctx, RSA_PKCS1_PADDING) <= 0) {
    //     cerr << "Failed to set RSA padding" << endl;
    //     EVP_PKEY_CTX_free(private_ctx);
    //     return false;
    // }

    // Find the Length of the key
    size_t key_len_decrypted;
    if (EVP_PKEY_decrypt(private_ctx, NULL, &key_len_decrypted, encrypted_key, encrypted_key_len) <= 0) {
        cerr << "Failed to find the length of secret key" << endl;
        EVP_PKEY_CTX_free(private_ctx);
        return false;
    }

    // Allocate memory for the key
    unsigned char key[key_len_decrypted];

    // Decrypt the key
    if (EVP_PKEY_decrypt(private_ctx, key, &key_len_decrypted, encrypted_key, encrypted_key_len) <= 0) {
        cerr << "Failed to decrypt key" << endl;
        EVP_PKEY_CTX_free(private_ctx);
        return false;
    }

    // Free the private key context
    EVP_PKEY_CTX_free(private_ctx);

    // Create cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Failed to create cipher context" << endl;
        return false;
    }

    // Initialize cipher context
    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        cerr << "Failed to initialize cipher context" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Open output file

    FILE* output = fopen(outFile, "wb");
    if (!output) {
        cerr << "Failed to open output file" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Allocate memory for the input buffer
    unsigned char in_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];

    // Allocate memory for the output buffer
    unsigned char out_buf[BUFFER_SIZE];

    // Read the input file, decrypt it and write it to the output file
    int bytes_read;
    int bytes_written;

    while ((bytes_read = fread(in_buf, sizeof(unsigned char), BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH, input)) > 0) {
        if (!EVP_DecryptUpdate(ctx, out_buf, &bytes_written, in_buf, bytes_read)) {
            cerr << "Failed to decrypt data" << endl;
            fclose(input);
            fclose(output);
            remove(outFile);
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        fwrite(out_buf, sizeof(unsigned char), bytes_written, output);
    }

    if (!EVP_DecryptFinal_ex(ctx, out_buf, &bytes_written)) {
        cerr << "Failed to finalize decryption" << endl;
        fclose(input);
        fclose(output);
        remove(outFile);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    fwrite(out_buf, sizeof(unsigned char), bytes_written, output);

    // Close input and output files
    fclose(input);
    fclose(output);

    // Free the cipher context
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

#ifndef __PROGTEST__

int main ( void )
{
    // assert( seal("out.PNG", "sealed.bin", "PublicKey.pem", "aes-128-cbc") );
    // assert( open("sealed.bin", "new_out.PNG", "PrivateKey.pem") );
    // assert( open("sealed_sample.bin", "opened_sample.txt", "PrivateKey.pem") );

    assert( open("1sealed.bin", "1out.PNG", "PrivateKey.pem") );
    assert( open("2sealed.bin", "2out.PNG", "PrivateKey.pem") );
    assert( open("3sealed.bin", "3out.PNG", "PrivateKey.pem") );

    return 0;
}

#endif /* __PROGTEST__ */

