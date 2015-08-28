package de.alpharogroup.crypto;

import java.io.File;
import java.io.IOException;
import java.sql.Date;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.testng.annotations.Test;

import de.alpharogroup.file.read.ReadFileUtils;
import de.alpharogroup.file.search.PathFinder;

public class WordlistProcessorTest
{

	@Test
	public void test() throws IOException
	{
		final File wordlistDir = new File(PathFinder.getSrcTestResourcesDir(), "wordlists");
		final File wordlist_1 = new File(wordlistDir, "default-pw.txt");
		final File wordlist_2 = new File(wordlistDir, "firstnames.txt");
		final File wordlist_3 = new File(wordlistDir, "surnames.txt");
		final List<String> lines1 = ReadFileUtils.readLinesInList(wordlist_1);
		final List<String> lines2 = ReadFileUtils.readLinesInList(wordlist_2);
		final List<String> lines3 = ReadFileUtils.readLinesInList(wordlist_3);
		final Set<String> set = new TreeSet<>();
		set.addAll(lines1);
		set.addAll(lines2);
		set.addAll(lines3);

		final String password = "hash";

		final WordlistsProcessor processor = new WordlistsProcessor(new ArrayList<String>(set),
			password);
		final long start = System.currentTimeMillis();
		final boolean found = processor.process();
		final long end = System.currentTimeMillis();


		System.out.println("Started wordlist attack for the password: " + new Date(start));
		System.out.println("Ended of the wordlist attack for the password: " + new Date(end));
		System.out.println("Password found: " + found);

	}
}
