package de.alpharogroup.mystic.crypt.panels;

import de.alpharogroup.crypto.key.KeySize;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class GenerateKeysModelBean
{
	private KeySize keySize;
}
