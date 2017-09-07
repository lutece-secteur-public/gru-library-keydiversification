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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This service manages the keys for Identity Providers (IDP) and Service Providers (SP)
 */
public final class DiversificationService
{
    private static Map<String, CryptoService> _mapCryptoServices = new ConcurrentHashMap<>( );

    /**
     * Default constructor
     */
    private DiversificationService( )
    {

    }

    /**
     * Converts the specified IDP key into a key usable by the SP
     * 
     * @param strIDPKey
     *            the IDP key to converts
     * @param strSP
     *            the SP using the key
     * @return the key usable by the SP
     * @throws KeyDiversificationException
     *             if there is an error during the treatment
     */
    public static String getSPKey( String strIDPKey, String strSP ) throws KeyDiversificationException
    {
        CryptoService cryptoService = _mapCryptoServices.get( strSP );
        if ( cryptoService == null )
        {
            cryptoService = new CryptoService( strSP );
            _mapCryptoServices.put( strSP, cryptoService );
        }

        return cryptoService.encrypt( strIDPKey );
    }

    /**
     * Converts the specified SP key into the IDP key
     * 
     * @param strSPKey
     *            the key used by the SP
     * @param strSP
     *            the SP using the key
     * @return the IDP key
     * @throws KeyDiversificationException
     *             if there is an error during the treatment
     */
    public static String getIDPKey( String strSPKey, String strSP ) throws KeyDiversificationException
    {
        CryptoService cryptoService = _mapCryptoServices.get( strSP );
        if ( cryptoService == null )
        {
            cryptoService = new CryptoService( strSP );
            _mapCryptoServices.put( strSP, cryptoService );
        }

        return cryptoService.decrypt( strSPKey );
    }
}
