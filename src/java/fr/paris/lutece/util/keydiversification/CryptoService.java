/*
 * Copyright (c) 2002-2017, Mairie de Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */
package fr.paris.lutece.util.keydiversification;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

/**
 * CryptoService
 */
public class CryptoService
{

    private static final String UNICODE_FORMAT = "UTF8";
    public static final String DESEDE_ENCRYPTION_SCHEME = "DESede";

    private Cipher _cipher;
    private SecretKey _key;

    /**
     * Constructor
     *
     * @param strEncryptionKey An encryption key
     * @throws Exception If an error occurs
     */
    public CryptoService(String strEncryptionKey) throws Exception
    {
        byte[] arrayBytes = new byte[DESedeKeySpec.DES_EDE_KEY_LEN];

        for (int i = 0; i < DESedeKeySpec.DES_EDE_KEY_LEN; i++)
        {
            if (i < strEncryptionKey.length())
            {
                arrayBytes[i] = (byte) strEncryptionKey.charAt(i);
            }
        }
        KeySpec ks = new DESedeKeySpec(arrayBytes);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(DESEDE_ENCRYPTION_SCHEME);
        _cipher = Cipher.getInstance(DESEDE_ENCRYPTION_SCHEME);
        _key = skf.generateSecret(ks);
    }

    /**
     * Encrypt
     *
     * @param strSource
     * @return The encrypted string
     * @throws java.security.InvalidKeyException
     * @throws java.io.UnsupportedEncodingException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     */
    public String encrypt(String strSource) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException
    {
        String strEncrypted;
            _cipher.init(Cipher.ENCRYPT_MODE, _key);
            byte[] plainText = strSource.getBytes(UNICODE_FORMAT);
            byte[] encryptedText = _cipher.doFinal(plainText);
            strEncrypted = new String(Base64.getEncoder().encode(encryptedText));
        return strEncrypted;
    }

    /**
     * Decrypt
     *
     * @param strEncrypted The necrypted string
     * @return The decrypted string
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     * @throws java.security.InvalidKeyException
     */
    public String decrypt(String strEncrypted) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException
    {
        String strDecrypted;
        _cipher.init(Cipher.DECRYPT_MODE, _key);
        byte[] encryptedText = Base64.getDecoder().decode( strEncrypted );
        byte[] plainText = _cipher.doFinal(encryptedText);
        strDecrypted = new String(plainText);
        return strDecrypted;
    }

}
