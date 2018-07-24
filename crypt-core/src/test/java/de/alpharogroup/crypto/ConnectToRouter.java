/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;

import lombok.extern.slf4j.Slf4j;

/**
 * The class {@link ConnectToRouter} connects to a router.
 */
@Slf4j
public class ConnectToRouter
{

	/**
	 * The main method connects to a router.
	 *
	 * @param args
	 *            the arguments
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void main(final String[] args) throws IOException
	{
		final String password = URLEncoder.encode("", "US-ASCII");

		final URL url = new URL("http://192.168.178.1/");
		final URLConnection connection = url.openConnection();
		connection.setDoOutput(true);

		final PrintWriter out = new PrintWriter(connection.getOutputStream());
		out.println(password);
		out.close();

		final BufferedReader in = new BufferedReader(
			new InputStreamReader(connection.getInputStream()));
		String inputLine;

		while ((inputLine = in.readLine()) != null)
		{
			log.debug(inputLine);
		}

		in.close();
	}
}
