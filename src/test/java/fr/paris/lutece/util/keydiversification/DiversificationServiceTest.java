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

import fr.paris.lutece.util.keydiversification.DiversificationService;

import java.util.UUID;
import org.junit.Test;



/**
 * DiversificationService Test
 */
public class DiversificationServiceTest
{

    /**
     * Test of getSPKey method, of class DiversificationService.
     * @throws java.lang.Exception
     */
    @Test
    public void testGetSPKey() throws Exception
    {
        System.out.println("DiversificationService test");
        UUID idKey = UUID.randomUUID();
        String strIDPKey = idKey.toString();

        System.out.println("----------------------------------------------------" );
        System.out.println("IDP key           : " + strIDPKey );
        buildKey( "Service provider 1" , strIDPKey );
        buildKey( "Service provider 2" , strIDPKey );
        System.out.println("----------------------------------------------------" );

    }
    
    private static void buildKey( String strSP , String strIDPKey ) throws Exception
    {
        String strSPKey = DiversificationService.getSPKey(strIDPKey, strSP );
        String strRecovery = DiversificationService.getIDPKey(strSPKey, strSP );
 
        System.out.println("----------------------------------------------------" );
        System.out.println("SP name           : " + strSP );
        System.out.println("SP key    (3DES)  : " + strSPKey );
        System.out.println("Recovered IDP key : " + strRecovery );
    }
}
