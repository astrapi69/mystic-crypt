package de.alpharogroup.random.lotto;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import de.alpharogroup.collections.map.MapExtensions;
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
 * The class {@link WonNumbers} contains the result of the lotto numbers and the played numbers.
 */
@Getter
@Setter
@EqualsAndHashCode
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
@FieldDefaults(level = AccessLevel.PRIVATE)
public class WonNumbers
{

	/** The id. */
	Integer id;

	/** The played lotto numbers. */
	@Builder.Default
	Map<String, List<Collection<Integer>>> wonLottoNumbers = MapExtensions.newHashMap();

	/** The won super six number. */
	Integer wonSuperSixNumber;

	/** The won super number. */
	Integer wonSuperNumber;

	/** The won game seventy seven. */
	Integer wonGameSeventySevenNumber;

}
