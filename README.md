# Overview

The target of this parent project is to make encryption and decryption as simple as possible.

## Key features:

 * Encryption with PublicKey and decryption with PrivateKey objects that was generated with openssl or java
 * Encryption and decryption from .pem, .der files that was generated with openssl
 * Hashing passwords
 * Obfuscate text with specified map
 * Hex en- and decryption
 * Creation of randomized data
 * Brute-force processing
 * Wordlist processing
 

## License

The source code comes under the liberal MIT License, making mystic-crypt great for all types of applications.


# Build status and latest maven version

[![Build Status](https://travis-ci.org/astrapi69/mystic-crypt.svg?branch=master)](https://travis-ci.org/astrapi69/mystic-crypt)

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/de.alpharogroup/mystic-crypt/badge.svg)](https://maven-badges.herokuapp.com/maven-central/de.alpharogroup/mystic-crypt)

[![Coverage Status](https://coveralls.io/repos/github/astrapi69/mystic-crypt/badge.svg?branch=develop)](https://coveralls.io/github/astrapi69/mystic-crypt?branch=develop)

auth-security [![Javadoc](https://javadoc-emblem.rhcloud.com/doc/de.alpharogroup/auth-security/badge.svg)](http://www.javadoc.io/doc/de.alpharogroup/auth-security)

crypt-core [![Javadoc](https://javadoc-emblem.rhcloud.com/doc/de.alpharogroup/crypt-core/badge.svg)](http://www.javadoc.io/doc/de.alpharogroup/crypt-core)

crypt-data [![Javadoc](https://javadoc-emblem.rhcloud.com/doc/de.alpharogroup/crypt-data/badge.svg)](http://www.javadoc.io/doc/de.alpharogroup/crypt-data)

randomizer [![Javadoc](https://javadoc-emblem.rhcloud.com/doc/de.alpharogroup/randomizer/badge.svg)](http://www.javadoc.io/doc/de.alpharogroup/randomizer)

## Maven dependency

Maven dependency is now on sonatype.
Check out [sonatype repository](https://oss.sonatype.org/index.html#nexus-search;quick~mystic-crypt) for latest snapshots and releases.

You can first define the version properties:

	<properties>
			...
		<!-- MYSTIC-CRYPT versions -->
		<mystic-crypt.version>4.21.0</mystic-crypt.version>
		<crypt-core.version>${mystic-crypt.version}</crypt-core.version>
		<randomizer.version>${mystic-crypt.version}</randomizer.version>
		<auth-security.version>${mystic-crypt.version}</auth-security.version>
		<crypt-data.version>${mystic-crypt.version}</crypt-data.version>
			...
	</properties>
	
You can add the following dependencies to your project for use the functionality of mystic-crypt.

Add the following maven dependency to your project `pom.xml` if you want to import the core functionality of mystic-core:

		<dependencies>
			...
			<!-- MYSTIC-CRYPT DEPENDENCIES -->
			<dependency>
				<groupId>de.alpharogroup</groupId>
				<artifactId>crypt-core</artifactId>
				<version>${crypt-core.version}</version>
			</dependency>
		</dependencies>

Add the following maven dependency to your project `pom.xml` if you want to import the functionality of randomizer:

		<dependencies>
			...
			<!-- MYSTIC-CRYPT DEPENDENCIES -->
			<dependency>
				<groupId>de.alpharogroup</groupId>
				<artifactId>randomizer</artifactId>
				<version>${randomizer.version}</version>
			</dependency>
		</dependencies>


Add the following maven dependency to your project `pom.xml` if you want to import the functionality of auth-security:

		<dependencies>
			...
			<!-- MYSTIC-CRYPT DEPENDENCIES -->
			<dependency>
				<groupId>de.alpharogroup</groupId>
				<artifactId>auth-security</artifactId>
				<version>${auth-security.version}</version>
			</dependency>
		</dependencies>


Add the following maven dependency to your project `pom.xml` if you want to import only the crypt-data like algorithms, modes, paddings etc.:

		<dependencies>
			...
			<!-- MYSTIC-CRYPT DEPENDENCIES -->
			<dependency>
				<groupId>de.alpharogroup</groupId>
				<artifactId>crypt-data</artifactId>
				<version>${crypt-data.version}</version>
			</dependency>
		</dependencies>


## Want to Help and improve it? ###

The source code for mystic-crypt are on GitHub. Please feel free to fork and send pull requests!

Create your own fork of [astrapi69/mystic-crypt/fork](https://github.com/astrapi69/mystic-crypt/fork)

To share your changes, [submit a pull request](https://github.com/astrapi69/mystic-crypt/pull/new/develop).

Don't forget to add new units tests on your changes.

## Contacting the Developer

Do not hesitate to contact the mystic-crypt developers with your questions, concerns, comments, bug reports, or feature requests.
- Feature requests, questions and bug reports can be reported at the [issues page](https://github.com/astrapi69/mystic-crypt/issues).

## Note

No animals were harmed in the making of this library.

# Donate

If you like this library, please consider a donation through 
<a href="http://flattr.com/thing/4152938/astrapi69mystic-crypt-on-GitHub" target="_blank">
<img src="http://api.flattr.com/button/flattr-badge-large.png" alt="Flattr this" title="Flattr this" border="0" />
</a>

# Similar projects

Here is a list of awesome projects for cryptography:


 * [cryptacular](https://github.com/vt-middleware/cryptacular) The friendly complement to the BouncyCastle crypto API for Java.
 * [JSch](http://www.jcraft.com/jsch/) JSch is a pure Java implementation of SSH2.
 * [Apache Shiro](https://github.com/apache/shiro) Apache Shiro is a powerful and easy-to-use Java security framework that performs authentication, authorization, cryptography, and session management.
 * [commons-ssl](http://juliusdavies.ca/commons-ssl/) Not-Yet-Commons-SSL

