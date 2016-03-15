package de.alpharogroup.crypto.keyrules;


public interface Obfuscatable
{

	/**
	 * Disentangle.
	 *
	 * @return the string
	 */
	String disentangle();

	/**
	 * Obfuscate.
	 *
	 * @return the string
	 */
	String obfuscate();

}