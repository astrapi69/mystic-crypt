package de.alpharogroup.crypto.factories;

import java.security.spec.KeySpec;

import javax.crypto.spec.PBEKeySpec;

import de.alpharogroup.crypto.CryptConst;

public class KeySpecFactory
{

	/**
	 * Factory method for creating a new {@link PBEKeySpec} from the given private key. This method
	 * is invoked in the constructor from the derived classes and can be overridden so users can
	 * provide their own version of a new {@link PBEKeySpec} from the given private key.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the new {@link PBEKeySpec} from the given private key.
	 */
	public static KeySpec newPBEKeySpec(final String privateKey)
	{
		if (privateKey == null)
		{
			return new PBEKeySpec(CryptConst.PRIVATE_KEY.toCharArray());
		}
		return new PBEKeySpec(privateKey.toCharArray());
	}


	/**
	 * Factory method for creating a new {@link PBEKeySpec} from the given private key. This method
	 * is invoked in the constructor from the derived classes and can be overridden so users can
	 * provide their own version of a new {@link PBEKeySpec} from the given private key.
	 *
	 * @param privateKey
	 *            the private key
	 * @param salt
	 *            the salt
	 * @param iterationCount
	 *            the iteration count
	 * @return the new {@link PBEKeySpec} from the given private key.
	 */
	public static KeySpec newPBEKeySpec(final String privateKey, final byte[] salt,
		final int iterationCount)
	{
		if (privateKey == null)
		{
			return new PBEKeySpec(CryptConst.PRIVATE_KEY.toCharArray(), salt, iterationCount);
		}
		return new PBEKeySpec(privateKey.toCharArray(), salt, iterationCount);
	}

}
