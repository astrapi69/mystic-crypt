package de.alpharogroup.crypto.obfuscation.rules;

import java.util.List;

import de.alpharogroup.crypto.obfuscation.rule.ObfuscationRule;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.Singular;
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
public class ObfuscationRules<C, RW, OR extends ObfuscationRule<C, RW>>
{

	/** The obfuscation rules. */
	@Singular
	List<ObfuscationRule<C, RW>> rules;

}
