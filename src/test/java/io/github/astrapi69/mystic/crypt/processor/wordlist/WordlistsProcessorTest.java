/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package io.github.astrapi69.mystic.crypt.processor.wordlist;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Set;

import org.testng.annotations.Test;

import io.github.astrapi69.collection.list.ListFactory;
import io.github.astrapi69.collection.set.SetFactory;
import io.github.astrapi69.file.read.ReadFileExtensions;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link WordlistsProcessor}
 */
public class WordlistsProcessorTest
{

	/**
	 * Test method for test the class {@link WordlistsProcessor}.
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test(enabled = true)
	public void test() throws IOException
	{
		WordlistsProcessor processor;
		boolean found;
		String toCheckAgainst;
		String password;
		File wordlistDir;
		File wordlist_1;
		File wordlist_2;
		File wordlist_3;
		File wordlist_4;
		List<String> lines1;
		List<String> lines2;
		List<String> lines3;
		List<String> lines4;
		Set<String> set;

		wordlistDir = new File(PathFinder.getSrcTestResourcesDir(), "wordlists");
		wordlist_1 = new File(wordlistDir, "default-pw.txt");
		wordlist_2 = new File(wordlistDir, "firstnames.txt");
		wordlist_3 = new File(wordlistDir, "surnames.txt");
		wordlist_4 = new File(wordlistDir, "top25pw.txt");
		lines1 = ReadFileExtensions.readLinesInList(wordlist_1);
		lines2 = ReadFileExtensions.readLinesInList(wordlist_2);
		lines3 = ReadFileExtensions.readLinesInList(wordlist_3);
		lines4 = ReadFileExtensions.readLinesInList(wordlist_4);
		set = SetFactory.newTreeSet();
		set.addAll(lines1);
		set.addAll(lines2);
		set.addAll(lines3);
		set.addAll(lines4);

		password = "hash";
		List<String> words = ListFactory.newArrayList(set);

		processor = new WordlistsProcessor(words, password);
		found = processor.process();
		assertTrue(found);
		toCheckAgainst = processor.getToCheckAgainst();
		assertEquals(toCheckAgainst, password);

		processor = new WordlistsProcessor(words);
		processor.setToCheckAgainst(password);
		found = processor.process();
		assertTrue(found);

	}
}
