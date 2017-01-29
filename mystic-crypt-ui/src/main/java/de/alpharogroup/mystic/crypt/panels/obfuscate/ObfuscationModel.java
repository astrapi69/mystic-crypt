package de.alpharogroup.mystic.crypt.panels.obfuscate;

import java.io.Serializable;

import de.alpharogroup.crypto.keyrules.Obfuscatable;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ObfuscationModel implements Serializable
{
	private static final long serialVersionUID = 1L;
	private KeyRulesTableModel keyRulesTableModel;
	private Obfuscatable obfuscator;
}
