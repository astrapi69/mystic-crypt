package de.alpharogroup.random.lotto;

import java.security.SecureRandom;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import de.alpharogroup.collections.CollectionExtensions;
import de.alpharogroup.collections.list.ListExtensions;
import de.alpharogroup.collections.set.SetExtensions;
import de.alpharogroup.random.RandomExtensions;
import de.alpharogroup.random.SecureRandomBean;
import lombok.experimental.UtilityClass;

/**
 * The class {@link LottoExtensions}.
 */
@UtilityClass
public final class LottoExtensions
{

	/**
	 * Factory method for create a new {@link LottoLuckyNumbers} object with all drawn numbers
	 *
	 * @return the new {@link LottoLuckyNumbers}
	 */
	public static LottoLuckyNumbers newLottoLuckyNumbers()
	{
		final LottoLuckyNumbers lottoLuckyNumbers = LottoLuckyNumbers.builder()
			.id(RandomExtensions.randomInt(Integer.MAX_VALUE))
			.lottoNumbers(SetExtensions.newTreeSet()).build();
		int cnt = 0;
		final SecureRandom sr = SecureRandomBean.builder()
			.algorithm(SecureRandomBean.DEFAULT_ALGORITHM).buildQuietly();

		while (cnt < 7)
		{
			final int num = 1 + Math.abs(sr.nextInt()) % 49;

			if (!lottoLuckyNumbers.getLottoNumbers().contains(num))
			{
				if (cnt == 6)
				{
					lottoLuckyNumbers.setSuperNumber(num);
				}
				else
				{
					lottoLuckyNumbers.getLottoNumbers().add(num);
				}
				++cnt;
			}
		}
		lottoLuckyNumbers.setSuperSixNumber(RandomExtensions.randomIntBetween(1, 10));
		lottoLuckyNumbers.setGameSeventySeven(RandomExtensions.randomIntBetween(0, 9999999));
		return lottoLuckyNumbers;
	}

	/**
	 * Checks the result if the drawn lotto numbers are equal to the given played numbers. The
	 * result is a {@link WonNumbers} object that keep the winning numbers.
	 *
	 * @param lottoLuckyNumbers
	 *            the lotto lucky numbers
	 * @param lottoPlayedNumbers
	 *            the lotto played numbers
	 * @return the won numbers
	 */
	public static WonNumbers checkResult(final LottoLuckyNumbers lottoLuckyNumbers,
		final LottoPlayedNumbers lottoPlayedNumbers)
	{

		final Set<Integer> lottoNumbers = lottoLuckyNumbers.getLottoNumbers();
		final Map<String, List<Set<Integer>>> playedLottoNumbers = lottoPlayedNumbers
			.getPlayedLottoNumbers();
		final Set<String> keySet = playedLottoNumbers.keySet();
		final WonNumbers wonNumbers = WonNumbers.builder().build();
		final Map<String, List<Collection<Integer>>> wonLottoNumbers1 = wonNumbers
			.getWonLottoNumbers();
		for (final String key : keySet)
		{
			final List<Set<Integer>> list = playedLottoNumbers.get(key);
			final List<Collection<Integer>> sets = ListExtensions
				.newArrayList(wonLottoNumbers1.get(key));
			wonLottoNumbers1.put(key, sets);
			for (final Set<Integer> set : list)
			{
				final Collection<Integer> wonNumbers1 = CollectionExtensions
					.intersection(SetExtensions.newTreeSet(lottoNumbers), set);
				sets.add(wonNumbers1);
			}
		}
		return wonNumbers;
	}

}
