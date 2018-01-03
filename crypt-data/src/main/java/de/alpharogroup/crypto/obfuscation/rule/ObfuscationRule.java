package de.alpharogroup.crypto.obfuscation.rule;

import java.io.Serializable;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.FieldDefaults;

@Getter
@Setter
@EqualsAndHashCode
@ToString
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Builder
public class ObfuscationRule<C, RW> implements Serializable
{
	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;
	
    /** The character. */
    C character;

    /** The character(s) that will be replaced with. */
    RW replaceWith;

}
