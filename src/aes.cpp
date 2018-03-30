/* aes.cpp
 * AES implementation using OpenSSL
 *
 * Copyright © 2006-2009 Magnus Leksell, all rights reserved. 
 */
#include "aes.h"

namespace ssh
{
    /* aes::aes
     * Constructor.
     */
    aes::aes(unsigned int length) : m_length(length)
    {
        this->m_blockSize = AES_BLOCK_SIZE;
    }

    /* aes::~aes
     * Destructor.
     */
    aes::~aes()
    {
        return;
    }

    /* aes::DecryptInit
     * Initializes the decryption engine.
     */
    bool aes::DecryptInit(const byte * key, const byte * iv)
    {
        AES_set_decrypt_key(key, m_length * 8, &m_key);
        // copy the IV
        memcpy(m_iv, iv, AES_BLOCK_SIZE);
        return true;
    }

    /* aes::EncryptInit
     * Initializes the encryption engine.
     */
    bool aes::EncryptInit(const byte * key, const byte * iv)
    {
        AES_set_encrypt_key(key, m_length * 8, &m_key);
        // copy the IV
        memcpy(m_iv, iv, AES_BLOCK_SIZE);
        return true;
    }

    /* aes::Encrypt
     * Encrypts the data and xor:s it with the IV.
     */
    void aes::Encrypt(const byte * in, byte * out, int len)
    {
        AES_cbc_encrypt(in, out,len, &m_key,m_iv, AES_ENCRYPT);
    }

    /* AES_cbc_encrypt
     * Decrypts the data and xor:s it with the IV.
     */
    void aes::Decrypt(const byte * in, byte * out, int len)
    {
        AES_cbc_encrypt(in, out,len, &m_key,m_iv, AES_DECRYPT);
    }
};