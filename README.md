# mystic-crypt


##Key features:

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

## Maven dependency

Maven dependency is now on sonatype.
Check out [sonatype repository](https://oss.sonatype.org/index.html#nexus-search;quick~mystic-crypt) for latest snapshots and releases.


Add the following maven dependency to your project `pom.xml` if you want to import the core functionality of mystic-core:

Than you can add the dependency to your dependencies:

		<!-- MYSTIC-CRYPT versions -->
		<mystic-crypt.version>4.11.0</mystic-crypt.version>
		<crypt-core.version>${mystic-crypt.version}</crypt-core.version>
		<randomizer.version>${mystic-crypt.version}</randomizer.version>
		<auth-security.version>${mystic-crypt.version}</auth-security.version>

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

Than you can add the dependency to your dependencies:

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

Than you can add the dependency to your dependencies:

		<dependencies>
			...
			<!-- MYSTIC-CRYPT DEPENDENCIES -->
			<dependency>
				<groupId>de.alpharogroup</groupId>
				<artifactId>auth-security</artifactId>
				<version>${auth-security.version}</version>
			</dependency>
		</dependencies>


## Want to Help and improve it? ###

The source code for mystic-crypt are on GitHub. Please feel free to fork and send pull requests!

Create your own fork of [astrapi69/mystic-crypt/fork](https://github.com/astrapi69/mystic-crypt/fork)

To share your changes, [submit a pull request](https://github.com/astrapi69/mystic-crypt/pull/new/master).

Don't forget to add new units tests on your changes.

## Contacting the Developer

Do not hesitate to contact the mystic-crypt developers with your questions, concerns, comments, bug reports, or feature requests.
- Feature requests, questions and bug reports can be reported at the [issues page](https://github.com/astrapi69/mystic-crypt/issues).

# Donate

<a href="http://flattr.com/thing/4152938/astrapi69mystic-crypt-on-GitHub" target="_blank">
<img src="http://api.flattr.com/button/flattr-badge-large.png" alt="Flattr this" title="Flattr this" border="0" />
</a>

