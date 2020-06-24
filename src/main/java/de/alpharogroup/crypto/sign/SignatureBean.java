package de.alpharogroup.crypto.sign;

import java.security.PrivateKey;

public final class SignatureBean {
    private PrivateKey privateKey;
    private String signatureAlgorithm;

    public SignatureBean(PrivateKey privateKey, String signatureAlgorithm) {
        this.privateKey = privateKey;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public SignatureBean() {
    }

    public static SignatureBeanBuilder builder() {
        return new SignatureBeanBuilder();
    }


    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }


    public String getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof SignatureBean)) return false;
        final SignatureBean other = (SignatureBean) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$privateKey = this.getPrivateKey();
        final Object other$privateKey = other.getPrivateKey();
        if (this$privateKey == null ? other$privateKey != null : !this$privateKey.equals(other$privateKey))
            return false;
        final Object this$signatureAlgorithm = this.getSignatureAlgorithm();
        final Object other$signatureAlgorithm = other.getSignatureAlgorithm();
        if (this$signatureAlgorithm == null ? other$signatureAlgorithm != null : !this$signatureAlgorithm.equals(other$signatureAlgorithm))
            return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof SignatureBean;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $privateKey = this.getPrivateKey();
        result = result * PRIME + ($privateKey == null ? 43 : $privateKey.hashCode());
        final Object $signatureAlgorithm = this.getSignatureAlgorithm();
        result = result * PRIME + ($signatureAlgorithm == null ? 43 : $signatureAlgorithm.hashCode());
        return result;
    }

    public String toString() {
        return "SignatureBean(privateKey=" + this.getPrivateKey() + ", signatureAlgorithm=" + this.getSignatureAlgorithm() + ")";
    }

    public static class SignatureBeanBuilder {
        private PrivateKey privateKey;
        private String signatureAlgorithm;

        SignatureBeanBuilder() {
        }

        public SignatureBean.SignatureBeanBuilder privateKey(PrivateKey privateKey) {
            this.privateKey = privateKey;
            return this;
        }

        public SignatureBean.SignatureBeanBuilder signatureAlgorithm(String signatureAlgorithm) {
            this.signatureAlgorithm = signatureAlgorithm;
            return this;
        }

        public SignatureBean build() {
            return new SignatureBean(privateKey, signatureAlgorithm);
        }

        public String toString() {
            return "SignatureBean.SignatureBeanBuilder(privateKey=" + this.privateKey + ", signatureAlgorithm=" + this.signatureAlgorithm + ")";
        }
    }
}
