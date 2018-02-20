/**
 *
 */
package de.alpharogroup.random.lotto;

import static org.testng.Assert.assertNotNull;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.testng.annotations.Test;

import de.alpharogroup.collections.list.ListExtensions;
import de.alpharogroup.collections.map.MapExtensions;
import de.alpharogroup.collections.set.SetExtensions;
import de.alpharogroup.math.MathExtensions;
import lombok.extern.slf4j.Slf4j;

/**
 * The unit test class for the class {@link LottoExtensions}.
 */
@Slf4j
public class LottoExtensionsTest
{

	private static final String sixOffourtynineGameType = "6 of 49";

	/**
	 * Calculate elapsed time in seconds from the given start time as long to the current system
	 * time. This is useful for benchmarking
	 *
	 * @param startTime
	 *            the start time
	 * @return The elapsed time in double
	 */
	public static double calculateElapsedTimeInSeconds(final long startTime)
	{
		final double elapsedTime = ((double)(System.nanoTime() - startTime)) / 1000000;
		return elapsedTime;
	}


	public int calculateDraws(final LottoPlayedNumbers lottoPlayedNumbers, final int winningNumbersCount)
	{
		if (!MathExtensions.isBetween(1, 6, winningNumbersCount))
		{
			log.info("winningNumbersCount have to be between 1 and 5");
			return -1;
		}
		final long startTime = System.nanoTime();
		int count = 0;
		LottoLuckyNumbers luckyNumbers = LottoExtensions.newLottoLuckyNumbers();
		count++;
		WonNumbers wonNumbers = LottoExtensions.checkResult(luckyNumbers, lottoPlayedNumbers);
		boolean breakout = false;
		// int i1 = 3;
		while (!breakout)
		{
			wonNumbers = LottoExtensions.checkResult(luckyNumbers, lottoPlayedNumbers);
			final Map<String, List<Collection<Integer>>> wonLottoNumbers = wonNumbers
				.getWonLottoNumbers();
			if (!wonLottoNumbers.isEmpty())
			{
				final List<Collection<Integer>> collections = wonLottoNumbers
					.get(sixOffourtynineGameType);
				for (int i = 0; i < collections.size(); i++)
				{
					final Collection<Integer> s = collections.get(i);
					if (winningNumbersCount < s.size())
					{
						breakout = true;
						break;
					}
				}
			}
			luckyNumbers = LottoExtensions.newLottoLuckyNumbers();
			count++;
			log.info("This is the " + count + " draw of the lotto queen: " + luckyNumbers);
		}

		log.info("Elapsed time till you have won something: "
			+ calculateElapsedTimeInSeconds(startTime));
		log.info("you have won after " + count + " drawings");
		log.info("you have won: " + wonNumbers);
		return count;
	}

	/**
	 * Test method for calculate how many times for winning of 4 numbers. This test is disabled
	 * because it can take very long time, so be careful if you enable.
	 */
	@Test(enabled = true)
	public void test4NumbersWinLuckyNumbers()
	{
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

		calculateDraws(lottoPlayedNumbers, 3);
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
		final WonNumbers wonNumbers = LottoExtensions.checkResult(lottoLuckyNumbers,
			lottoPlayedNumbers);

		// TODO make the checks...
		System.out.println(wonNumbers);
	}

	/**
	 * Test method for {@link LottoExtensions#newLottoLuckyNumbers()}.
	 */
	@Test
	public void testNewLottoLuckyNumbers()
	{
		final LottoLuckyNumbers luckyNumbers = LottoExtensions.newLottoLuckyNumbers();
		assertNotNull(luckyNumbers);
	}

}
