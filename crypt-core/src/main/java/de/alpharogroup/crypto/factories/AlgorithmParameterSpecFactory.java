package de.alpharogroup.crypto.factories;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.PBEParameterSpec;

/**
 * A factory for creating AlgorithmParameterSpec objects.
 */
public class AlgorithmParameterSpecFactory
{

	/**
	 * Factory method for creating a new {@link PBEParameterSpec} from the given salt and iteration count.
	 *
	 * @param salt the salt
	 * @param iterationCount the iteration count
	 * @return the new {@link PBEParameterSpec} from the given salt and iteration count.
	 */
	public static AlgorithmParameterSpec newPBEParameterSpec(final byte[] salt,final int iterationCount){
		final AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
		return paramSpec;
	}
}
