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
