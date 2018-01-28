package de.alpharogroup.random.lotto;

import java.util.Map;
import java.util.Set;

import org.testng.annotations.Test;

import de.alpharogroup.collections.map.MapExtensions;
import de.alpharogroup.collections.set.SetExtensions;

public class LottoPlayedNumbersTest
{

	@Test
	public void test()
	{
		Set<Integer> yourNumbers;
		final String userId = "Nick";
		yourNumbers = SetExtensions.newHashSet(3, 7, 22, 23, 34, 45);
		final Map<String, Set<Integer>> playedLottoNumbers = MapExtensions.newHashMap();
		playedLottoNumbers.put(userId, yourNumbers);
		final LottoPlayedNumbers lottoPlayedNumbers = LottoPlayedNumbers
			.builder()
			.playedLottoNumbers(playedLottoNumbers )
			.bonusNumber(23)
			.superSixNumber(4)
			.gameSeventySevenNumber(234556)
			.build();

		final LottoLuckyNumbers lottoLuckyNumbers = LottoLuckyNumbers.builder().build();
	}

}
