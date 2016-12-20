package de.alpharogroup.crypto.algorithm;

import org.testng.AssertJUnit;
import org.testng.annotations.Test;

/**
 * Test class for enum {@link KeyPairWithModeAndPaddingAlgorithm}.
 */
public class KeyPairWithModeAndPaddingAlgorithmTest
{

	/**
	 * Test get algorithm.
	 */
	@Test
	public void testGetAlgorithm()
	{
		AssertJUnit.assertEquals(KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_PKCS1PADDING.getAlgorithm(), "RSA/ECB/PKCS1Padding");
	}

}
