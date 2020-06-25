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

import java.security.PrivateKey;

public final class SignatureBean {
	public static class SignatureBeanBuilder {
		private PrivateKey privateKey;
		private String signatureAlgorithm;

		SignatureBeanBuilder() {
		}

		public SignatureBean build() {
			return new SignatureBean(privateKey, signatureAlgorithm);
		}

		public SignatureBean.SignatureBeanBuilder privateKey(PrivateKey privateKey) {
			this.privateKey = privateKey;
			return this;
		}

		public SignatureBean.SignatureBeanBuilder signatureAlgorithm(String signatureAlgorithm) {
			this.signatureAlgorithm = signatureAlgorithm;
			return this;
		}

		public String toString() {
			return "SignatureBean.SignatureBeanBuilder(privateKey=" + this.privateKey + ", signatureAlgorithm="
					+ this.signatureAlgorithm + ")";
		}
	}
	public static SignatureBeanBuilder builder() {
		return new SignatureBeanBuilder();
	}

	private PrivateKey privateKey;

	private String signatureAlgorithm;

	public SignatureBean() {
	}

	public SignatureBean(PrivateKey privateKey, String signatureAlgorithm) {
		this.privateKey = privateKey;
		this.signatureAlgorithm = signatureAlgorithm;
	}

	protected boolean canEqual(final Object other) {
		return other instanceof SignatureBean;
	}

	public boolean equals(final Object o) {
		if (o == this)
			return true;
		if (!(o instanceof SignatureBean))
			return false;
		final SignatureBean other = (SignatureBean) o;
		if (!other.canEqual((Object) this))
			return false;
		final Object this$privateKey = this.getPrivateKey();
		final Object other$privateKey = other.getPrivateKey();
		if (this$privateKey == null ? other$privateKey != null : !this$privateKey.equals(other$privateKey))
			return false;
		final Object this$signatureAlgorithm = this.getSignatureAlgorithm();
		final Object other$signatureAlgorithm = other.getSignatureAlgorithm();
		if (this$signatureAlgorithm == null ? other$signatureAlgorithm != null
				: !this$signatureAlgorithm.equals(other$signatureAlgorithm))
			return false;
		return true;
	}

	public PrivateKey getPrivateKey() {
		return this.privateKey;
	}

	public String getSignatureAlgorithm() {
		return this.signatureAlgorithm;
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

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}

	public String toString() {
		return "SignatureBean(privateKey=" + this.getPrivateKey() + ", signatureAlgorithm="
				+ this.getSignatureAlgorithm() + ")";
	}
}
