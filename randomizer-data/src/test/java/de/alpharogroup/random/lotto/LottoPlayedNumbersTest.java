package de.alpharogroup.random.lotto;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.testng.annotations.Test;

import de.alpharogroup.collections.CollectionExtensions;
import de.alpharogroup.collections.list.ListExtensions;
import de.alpharogroup.collections.map.MapExtensions;
import de.alpharogroup.collections.set.SetExtensions;

public class LottoPlayedNumbersTest
{
	private static final String sixOffourtynineGameType = "6 of 49";
	@Test
	public void test()
	{
		// This numbers are lucky choosen from the lottery queen...
		final Set<Integer> lottoNumbers = SetExtensions.newHashSet(7, 23, 34, 42, 45, 48);
		final LottoLuckyNumbers lottoLuckyNumbers = LottoLuckyNumbers
			.builder()
			.lottoNumbers(lottoNumbers)
			.superNumber(5)
			.superSixNumber(8)
			.gameSeventySeven(543556)
			.build();

		// This numbers is your played lotto numbers...
		List<Set<Integer>> sixOffourtynineGame;

		sixOffourtynineGame = ListExtensions.newArrayList(null,
			SetExtensions.newHashSet(3, 7, 22, 23, 34, 45),
			SetExtensions.newHashSet(13, 17, 21, 23, 34, 48),
			SetExtensions.newHashSet(5, 8, 21, 22, 34, 45));
		final Map<String, List<Set<Integer>>> playedLottoNumbers = MapExtensions.newHashMap();
		playedLottoNumbers.put(sixOffourtynineGameType, sixOffourtynineGame);

		final LottoPlayedNumbers lottoPlayedNumbers = LottoPlayedNumbers
			.builder()
			.playedLottoNumbers(playedLottoNumbers )
			.superNumber(23)
			.superSixNumber(4)
			.gameSeventySevenNumber(234556)
			.build();

		// Lets process if your numbers have won the jackpot...
		final Map<String, List<Collection<Integer>>> result = checkResult(lottoLuckyNumbers, lottoPlayedNumbers);
		final List<Collection<Integer>> list = result.get(sixOffourtynineGameType);
		System.out.println(list);
	}


	public static Map<String, List<Collection<Integer>>> checkResult(final LottoLuckyNumbers lottoLuckyNumbers, final LottoPlayedNumbers lottoPlayedNumbers) {

		final Set<Integer> lottoNumbers = lottoLuckyNumbers.getLottoNumbers();
		final Map<String, List<Set<Integer>>> playedLottoNumbers = lottoPlayedNumbers.getPlayedLottoNumbers();
		final List<Set<Integer>> list = playedLottoNumbers.get(sixOffourtynineGameType);
		final Map<String, List<Collection<Integer>>> wonLottoNumbers = new HashMap<>();
		final List<Collection<Integer>> won = ListExtensions.newArrayList(4);
		wonLottoNumbers.put(sixOffourtynineGameType, won);
		for (final Set<Integer> set : list)
		{
			final Collection<Integer> wonNumbers = CollectionExtensions.intersection(SetExtensions.newHashSet(lottoNumbers), set);
			won.add(wonNumbers);
		}
		return wonLottoNumbers;
	}

}
