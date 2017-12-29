package de.alpharogroup.crypto.obfuscation.rules;

import java.util.List;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.FieldDefaults;

/**
 * The class {@link ObfuscationRules} holds a list of obfuscation rules that will be processed with
 * an Obfusactor implementation.
 */
@Getter
@Setter
@EqualsAndHashCode
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
@FieldDefaults(level=AccessLevel.PRIVATE)
public class ObfuscationRules
{

	/** The obfuscation rules. */
	List<Object> rules;

}
