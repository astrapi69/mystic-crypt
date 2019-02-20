package de.alpharogroup.crypto.processors.bruteforce;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.Optional;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.alpharogroup.crypto.key.reader.EncryptedPrivateKeyReader;
import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import lombok.NonNull;
import lombok.experimental.UtilityClass;

/**
 * The class {@link PrivateKeyBruteForceProcessor}
 */
@UtilityClass
public class PrivateKeyBruteForceProcessor
{

	/**
	 * Resolve the password from the given private key file. If no password is set an empty Optional
	 * will be returned.
	 *
	 * @param privateKeyFile
	 *            the private key file
	 * @param processor
	 *            the processor
	 * @return the optional
	 */
	public static Optional<String> resolvePassword(File privateKeyFile,
		@NonNull BruteForceProcessor processor)
	{
		Optional<String> optionalPassword = Optional.empty();
		try
		{
			boolean isPasswordProtected = PrivateKeyReader
				.isPrivateKeyPasswordProtected(privateKeyFile);

			if (!isPasswordProtected)
			{


				String attempt;
				attempt = processor.getCurrentAttempt();
				Security.addProvider(new BouncyCastleProvider());
				while (true)
				{
					try
					{
						EncryptedPrivateKeyReader.getKeyPair(privateKeyFile, attempt);
						optionalPassword = Optional.of(attempt);
						break;
					}
					catch (IOException e)
					{
						attempt = processor.getCurrentAttempt();
						processor.increment();
					}
				}
			}
		}
		catch (IOException ex)
		{
			return optionalPassword;
		}
		return optionalPassword;
	}

}
