/**
 * Copyright (C) 2015 Asterios Raptis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.alpharogroup.crypto;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;

public class ConnectToRouter
{
	public static void main(final String[] args) throws IOException
	{
		final String password = URLEncoder.encode("", "US-ASCII");

		final URL url = new URL("http://192.168.178.1/");
		final URLConnection connection = url.openConnection();
		connection.setDoOutput(true);

		final PrintWriter out = new PrintWriter(connection.getOutputStream());
		out.println(password);
		out.close();

		final BufferedReader in = new BufferedReader(new InputStreamReader(
			connection.getInputStream()));
		String inputLine;

		while ((inputLine = in.readLine()) != null)
		{
			System.out.println(inputLine);
		}

		in.close();
	}
}
