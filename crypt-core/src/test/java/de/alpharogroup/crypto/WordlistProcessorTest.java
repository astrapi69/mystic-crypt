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
package de.alpharogroup.crypto;

import java.io.File;
import java.io.IOException;
import java.sql.Date;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.testng.annotations.Test;

import de.alpharogroup.crypto.processors.wordlist.WordlistsProcessor;
import de.alpharogroup.file.read.ReadFileExtensions;
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
		final File wordlist_4 = new File(wordlistDir, "top25pw.txt");
		final List<String> lines1 = ReadFileExtensions.readLinesInList(wordlist_1);
		final List<String> lines2 = ReadFileExtensions.readLinesInList(wordlist_2);
		final List<String> lines3 = ReadFileExtensions.readLinesInList(wordlist_3);
		final List<String> lines4 = ReadFileExtensions.readLinesInList(wordlist_4);
		final Set<String> set = new TreeSet<>();
		set.addAll(lines1);
		set.addAll(lines2);
		set.addAll(lines3);		
		set.addAll(lines4);

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
