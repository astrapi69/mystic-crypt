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

import java.security.PublicKey;
import java.security.cert.Certificate;

public final class VerifyBean {
	public static class VerifyBeanBuilder {
		private PublicKey publicKey;
		private Certificate certificate;
		private String signatureAlgorithm;

		VerifyBeanBuilder() {
		}

		public VerifyBean build() {
			return new VerifyBean(publicKey, certificate, signatureAlgorithm);
		}

		public VerifyBean.VerifyBeanBuilder certificate(Certificate certificate) {
			this.certificate = certificate;
			return this;
		}

		public VerifyBean.VerifyBeanBuilder publicKey(PublicKey publicKey) {
			this.publicKey = publicKey;
			return this;
		}

		public VerifyBean.VerifyBeanBuilder signatureAlgorithm(String signatureAlgorithm) {
			this.signatureAlgorithm = signatureAlgorithm;
			return this;
		}

		public String toString() {
			return "VerifyBean.VerifyBeanBuilder(publicKey=" + this.publicKey + ", certificate=" + this.certificate
					+ ", signatureAlgorithm=" + this.signatureAlgorithm + ")";
		}
	}
	public static VerifyBeanBuilder builder() {
		return new VerifyBeanBuilder();
	}
	private PublicKey publicKey;

	private Certificate certificate;

	private String signatureAlgorithm;

	public VerifyBean() {
	}

	public VerifyBean(PublicKey publicKey, Certificate certificate, String signatureAlgorithm) {
		this.publicKey = publicKey;
		this.certificate = certificate;
		this.signatureAlgorithm = signatureAlgorithm;
	}

	public boolean equals(final Object o) {
		if (o == this)
			return true;
		if (!(o instanceof VerifyBean))
			return false;
		final VerifyBean other = (VerifyBean) o;
		final Object this$publicKey = this.getPublicKey();
		final Object other$publicKey = other.getPublicKey();
		if (this$publicKey == null ? other$publicKey != null : !this$publicKey.equals(other$publicKey))
			return false;
		final Object this$certificate = this.getCertificate();
		final Object other$certificate = other.getCertificate();
		if (this$certificate == null ? other$certificate != null : !this$certificate.equals(other$certificate))
			return false;
		final Object this$signatureAlgorithm = this.getSignatureAlgorithm();
		final Object other$signatureAlgorithm = other.getSignatureAlgorithm();
		if (this$signatureAlgorithm == null ? other$signatureAlgorithm != null
				: !this$signatureAlgorithm.equals(other$signatureAlgorithm))
			return false;
		return true;
	}

	public Certificate getCertificate() {
		return this.certificate;
	}

	public PublicKey getPublicKey() {
		return this.publicKey;
	}

	public String getSignatureAlgorithm() {
		return this.signatureAlgorithm;
	}

	public int hashCode() {
		final int PRIME = 59;
		int result = 1;
		final Object $publicKey = this.getPublicKey();
		result = result * PRIME + ($publicKey == null ? 43 : $publicKey.hashCode());
		final Object $certificate = this.getCertificate();
		result = result * PRIME + ($certificate == null ? 43 : $certificate.hashCode());
		final Object $signatureAlgorithm = this.getSignatureAlgorithm();
		result = result * PRIME + ($signatureAlgorithm == null ? 43 : $signatureAlgorithm.hashCode());
		return result;
	}

	public void setCertificate(Certificate certificate) {
		this.certificate = certificate;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}

	public String toString() {
		return "VerifyBean(publicKey=" + this.getPublicKey() + ", certificate=" + this.getCertificate()
				+ ", signatureAlgorithm=" + this.getSignatureAlgorithm() + ")";
	}
}
