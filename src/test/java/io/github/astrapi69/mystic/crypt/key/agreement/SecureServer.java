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
		File keystoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"keystore.jks");
		File trustStoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"truststore.jks");
		// Step 2: Load KeyStore and TrustStore
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(new FileInputStream(keystoreFile), "password".toCharArray());

		KeyStore trustStore = KeyStore.getInstance("JKS");
		trustStore.load(new FileInputStream(trustStoreFile), "password".toCharArray());

		// Step 3: Initialize KeyManagerFactory and TrustManagerFactory
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(keyStore, "password".toCharArray());

		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		tmf.init(trustStore);
		// Step 4: Initialize SSLContext
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(),
			SecureRandomBuilder.getInstance().build());
		// Step 5: Use SSLContext for Secure Communication

		SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
		SSLServerSocket sss = (SSLServerSocket)ssf.createServerSocket(8443);

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
