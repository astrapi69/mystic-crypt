package de.alpharogroup.mystic.crypt.panels;

import java.security.PrivateKey;
import java.security.PublicKey;

import de.alpharogroup.crypto.key.KeySize;
import de.alpharogroup.crypto.key.PrivateKeyHexDecryptor;
import de.alpharogroup.crypto.key.PublicKeyHexEncryptor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class GenerateKeysModelBean
{
	private KeySize keySize;

	private PrivateKey privateKey;

	private PublicKey publicKey;

	private PublicKeyHexEncryptor encryptor;

	private PrivateKeyHexDecryptor decryptor;
}
