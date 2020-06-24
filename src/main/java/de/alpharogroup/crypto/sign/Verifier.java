package de.alpharogroup.crypto.sign;

import java.security.*;
import java.security.cert.Certificate;
import java.util.Objects;

public final class Verifier {

    private final Signature signature;
    private final VerifyBean verifyBean;

    public Verifier(VerifyBean verifyBean) throws NoSuchAlgorithmException {

        Objects.requireNonNull(verifyBean);
        Objects.requireNonNull(verifyBean.getPublicKey());
        Objects.requireNonNull(verifyBean.getSignatureAlgorithm());
        this.verifyBean = verifyBean;
        this.signature  = Signature.getInstance(this.verifyBean.getSignatureAlgorithm());
    }

    /**
     * Verify.
     *
     * @param bytesToVerify      the bytes to verify
     * @param signedBytes        the signed byte array
     * @return true, if successful otherwise false
     * @throws NoSuchAlgorithmException is thrown if instantiation of the cypher object fails
     * @throws InvalidKeyException      is thrown if initialization of the cypher object fails
     * @throws SignatureException       if the signature object is not initialized properly, the passed-in signature is improperly
     *                                  encoded or of the wrong type, if this signature algorithm is unable to
     *                                  process the input data provided, etc.
     */
    public boolean verify(byte[] bytesToVerify, byte[] signedBytes)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        if (verifyBean.getPublicKey()!=null){
            return verifyWithPublicKey(bytesToVerify, signedBytes);
        }
        return verifyWithCertificate(bytesToVerify, signedBytes);
    }

    /**
     * Verify the given byte array with the given signed byte array with the given public key and the appropriate algorithms
     *
     * @param bytesToVerify      the bytes to verify
     * @param signedBytes        the signed byte array
     * @return true, if successful otherwise false
     * @throws NoSuchAlgorithmException is thrown if instantiation of the cypher object fails
     * @throws InvalidKeyException      is thrown if initialization of the cypher object fails
     * @throws SignatureException       if the signature object is not initialized properly, the passed-in signature is improperly
     *                                  encoded or of the wrong type, if this signature algorithm is unable to
     *                                  process the input data provided, etc.
     */
    private synchronized boolean verifyWithPublicKey(byte[] bytesToVerify, byte[] signedBytes)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        signature.initVerify(verifyBean.getPublicKey());
        signature.update(bytesToVerify);
        return signature.verify(signedBytes);
    }

    /**
     * Verify.
     *
     * @param bytesToVerify      the bytes to verify
     * @param signedBytes        the signed byte array
     * @return true, if successful otherwise false
     * @throws NoSuchAlgorithmException is thrown if instantiation of the cypher object fails
     * @throws InvalidKeyException      is thrown if initialization of the cypher object fails
     * @throws SignatureException       if the signature object is not initialized properly, the passed-in signature is improperly
     *                                  encoded or of the wrong type, if this signature algorithm is unable to
     *                                  process the input data provided, etc.
     */
    private synchronized boolean verifyWithCertificate(byte[] bytesToVerify, byte[] signedBytes)
            throws SignatureException, InvalidKeyException {
        signature.initVerify(verifyBean.getCertificate());
        signature.update(bytesToVerify);
        return signature.verify(signedBytes);
    }

}
