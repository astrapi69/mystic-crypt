package de.alpharogroup.crypto.algorithm;

import org.testng.AssertJUnit;
import org.testng.annotations.Test;

public class MacAlgorithmTest
{

	@Test
	public void test()
	{
		String expected = "HmacMD5";
		String actual = MacAlgorithm.HmacMD5.name();
		AssertJUnit.assertEquals(expected, actual);

		expected = "PBEWithHmacMD5";
		actual = MacAlgorithm.PBEWithHmacMD5.name();
		AssertJUnit.assertEquals(expected, actual);

	}

}
