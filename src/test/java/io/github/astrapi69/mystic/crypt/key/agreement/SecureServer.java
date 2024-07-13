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
package io.github.astrapi69.mystic.crypt.key.agreement;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.random.SecureRandomBuilder;

/**
 * Before you start make sure that the file paths to the keystore.jks and truststore.jks files are
 * correct, and the passwords used in the code match the passwords used when generating the keystore
 * and truststore. <br>
 * # Generate a keystore <br>
 * <code>
 * keytool -genkeypair -alias serverKey -keyalg RSA -keysize 2048 -keystore keystore.jks -validity
 * 365
 * </code> <br>
 * # Export the certificate <br>
 * <code>
 * keytool -export -alias serverKey -keystore keystore.jks -file server.cer
 * </code> <br>
 * # Import the certificate into a truststore <br>
 * <code>
 * keytool -import -alias serverKey -file server.cer -keystore truststore.jks
 * </code>
 */
public class SecureServer
{
	public static void main(String[] args) throws Exception
	{
		char[] password;

		File keystoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"ssl-keystore.jks");
		File trustStoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"ssl-truststore.jks");
		// Step 2: Load KeyStore and TrustStore
		KeyStore keyStore = KeyStore.getInstance("JKS");
		password = "password".toCharArray();
		keyStore.load(new FileInputStream(keystoreFile), password);

		KeyStore trustStore = KeyStore.getInstance("JKS");
		trustStore.load(new FileInputStream(trustStoreFile), password);

		// Step 3: Initialize KeyManagerFactory and TrustManagerFactory
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(keyStore, password);

		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		tmf.init(trustStore);
		// Step 4: Initialize SSLContext
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(),
			SecureRandomBuilder.getInstance().build());
		// Step 5: Use SSLContext for Secure Communication

		SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
		try (SSLServerSocket sss = (SSLServerSocket)ssf.createServerSocket(8443))
		{

			System.out.println("Secure server started. Waiting for connections...");

			while (true)
			{
				try (SSLSocket socket = (SSLSocket)sss.accept();
					var out = socket.getOutputStream();
					var in = socket.getInputStream())
				{
					System.out.println("Client connected");

					// Read client message
					byte[] buffer = new byte[1024];
					int bytesRead = in.read(buffer);
					String clientMessage = new String(buffer, 0, bytesRead);
					System.out.println("Received from client: " + clientMessage);

					// Send response to client
					String response = "Hello from secure server!";
					out.write(response.getBytes());
					out.flush();
				}
			}
		}
	}
}
