# mystic-crypt

<a href="http://flattr.com/thing/4152938/astrapi69mystic-crypt-on-GitHub" target="_blank"><img src="http://api.flattr.com/button/flattr-badge-large.png" alt="Flattr this" title="Flattr this" border="0" /></a>

[![Build Status](https://travis-ci.org/astrapi69/mystic-crypt.svg?branch=master)](https://travis-ci.org/astrapi69/mystic-crypt)

##Key features:

 * Hashing passwords
 * Obfuscate text with specified map
 * Hex en- and decryption
 * Creation of randomized data
 * Brute-force processing
 * Wordlist processing

## License

The source code comes under the liberal Apache License V2.0, making mystic-crypt great for all types of applications.

## Maven dependency

Maven dependency is now on sonatype.
Check out [sonatype repository](https://oss.sonatype.org/index.html#nexus-search;quick~mystic-crypt) for latest snapshots and releases.


Add the following maven dependency to your project `pom.xml` if you want to import the core functionality of mystic-crypt:

Than you can add the dependency to your dependencies:

		<!-- MYSTIC-CRYPT versions -->
		<mystic-crypt.version>4.8.0</mystic-crypt.version>
		<crypt-core.version>${mystic-crypt.version}</crypt-core.version>
		<randomizer.version>${mystic-crypt.version}</randomizer.version>
		<auth-security.version>${mystic-crypt.version}</auth-security.version>

		<dependencies>
			...
			<dependency>
				<groupId>de.alpharogroup</groupId>
				<artifactId>crypt-core</artifactId>
				<version>${crypt-core.version}</version>
			</dependency>
		</dependencies>
