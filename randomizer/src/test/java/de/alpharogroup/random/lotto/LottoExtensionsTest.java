/**
 *
 */
package de.alpharogroup.random.lotto;

import static org.testng.Assert.assertNotNull;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.testng.annotations.Test;

import de.alpharogroup.collections.list.ListExtensions;
import de.alpharogroup.collections.map.MapExtensions;
import de.alpharogroup.collections.set.SetExtensions;

/**
 * The unit test class for the class {@link LottoExtensions}.
 */
public class LottoExtensionsTest
{

	private static final String sixOffourtynineGameType = "6 of 49";

	/**
	 * Test method for {@link LottoExtensions#newLottoLuckyNumbers()}.
	 */
	@Test
	public void testNewLottoLuckyNumbers()
	{
		final LottoLuckyNumbers lottoNumbers1 = LottoExtensions.newLottoLuckyNumbers();
		assertNotNull(lottoNumbers1);
	}

	/**
	 * Test method for {@link LottoExtensions#checkResult(LottoLuckyNumbers, LottoPlayedNumbers)}.
	 */
	@Test
	public void testCheckResult()
	{

		// This numbers are lucky choosen from the lottery queen...
		final Set<Integer> lottoNumbers = SetExtensions.newTreeSet(7, 23, 34, 42, 45, 48);
		final LottoLuckyNumbers lottoLuckyNumbers = LottoLuckyNumbers.builder()
			.lottoNumbers(lottoNumbers).superNumber(5).superSixNumber(8).gameSeventySeven(543556)
			.build();

		// This numbers is your played lotto numbers...
		List<Set<Integer>> sixOffourtynineGame;

		sixOffourtynineGame = ListExtensions.newArrayList(null,
			SetExtensions.newTreeSet(3, 7, 22, 23, 34, 45),
			SetExtensions.newTreeSet(13, 17, 21, 23, 34, 48),
			SetExtensions.newTreeSet(5, 8, 21, 22, 34, 45));
		final Map<String, List<Set<Integer>>> playedLottoNumbers = MapExtensions.newHashMap();
		playedLottoNumbers.put(sixOffourtynineGameType, sixOffourtynineGame);

		final LottoPlayedNumbers lottoPlayedNumbers = LottoPlayedNumbers.builder()
			.playedLottoNumbers(playedLottoNumbers).superNumber(23).superSixNumber(4)
			.gameSeventySevenNumber(234556).build();

		// Lets process if your numbers have won the jackpot...
		final WonNumbers wonNumbers = LottoExtensions.checkResult(lottoLuckyNumbers, lottoPlayedNumbers);

		// TODO make the checks...
		System.out.println(wonNumbers);
	}

}
