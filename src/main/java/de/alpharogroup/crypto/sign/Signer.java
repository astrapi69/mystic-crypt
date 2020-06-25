/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.sign;

import java.security.*;
import java.util.Objects;

public final class Signer {

    private final Signature signature;
    private final SignatureBean signatureBean;
    private boolean initialized;

    public Signer(SignatureBean signatureBean) throws NoSuchAlgorithmException {

        Objects.requireNonNull(signatureBean);
        Objects.requireNonNull(signatureBean.getPrivateKey());
        Objects.requireNonNull(signatureBean.getSignatureAlgorithm());
        this.signatureBean = signatureBean;
        this.signature  = Signature.getInstance(this.signatureBean.getSignatureAlgorithm());
    }

    /**
     * Sign the given byte array with the given private key and the appropriate algorithms
     *
     * @param bytesToSign        the bytes to sign
     * @return the signed byte array
     * @throws InvalidKeyException      is thrown if initialization of the cypher object fails
     * @throws SignatureException       is thrown if the signature object is not initialized properly or if this signature algorithm is
     *                                  unable to process the input data provided
     */
    public byte[] sign(byte[] bytesToSign)
            throws InvalidKeyException, SignatureException
    {
        initialize();
        signature.update(bytesToSign);
        return signature.sign();
    }

    private void initialize() throws InvalidKeyException {
        if(!initialized){
            signature.initSign(this.signatureBean.getPrivateKey());
            initialized = true;
        }
    }
}
