package de.alpharogroup.crypto.model;

import java.io.Serializable;

import de.alpharogroup.crypto.algorithm.Algorithm;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * The class {@link CryptModel}.
 *
 * @param <C> the generic type of the cipher
 * @param <K> the generic type of the key
 */
@Getter
@Setter
@EqualsAndHashCode
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CryptModel<C, K> implements Serializable
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/** The cipher. */
	private C cipher;

	/** The key. */
	private K key;

	/** The algorithm. */
	private Algorithm algorithm;

	/**
	 * The flag initialized that indicates if the cipher is initialized.
	 */
	private boolean initialized;
}
