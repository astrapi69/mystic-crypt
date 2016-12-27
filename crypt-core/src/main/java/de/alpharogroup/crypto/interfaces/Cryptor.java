package de.alpharogroup.crypto.interfaces;

/**
 * The interface {@link Cryptor} holds the operation mode.
 */
public interface Cryptor
{
	/**
	 * Factory callback method for get the operation mode. the operation mode can be one of the
	 * following values: ENCRYPT_MODE, DECRYPT_MODE, WRAP_MODE or UNWRAP_MODE
	 *
	 * @return the operation mode
	 */
	int newOperationMode();
}
