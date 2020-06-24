package de.alpharogroup.crypto.sign;

import java.security.*;
import java.util.Objects;

public final class Signer {

    private final Signature signature;
    private final SignatureBean signatureBean;

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
        signature.initSign(this.signatureBean.getPrivateKey());
        signature.update(bytesToSign);
        return signature.sign();
    }
}
