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

## Build status

[![Build Status](https://travis-ci.org/astrapi69/mystic-crypt.svg?branch=master)](https://travis-ci.org/astrapi69/mystic-crypt)

## Coverage Status

[![Coverage Status](https://coveralls.io/repos/github/astrapi69/mystic-crypt/badge.svg?branch=develop)](https://coveralls.io/github/astrapi69/mystic-crypt?branch=develop)

## Javadoc

auth-api [![Javadoc](https://javadoc-emblem.rhcloud.com/doc/de.alpharogroup/auth-security/badge.svg)](http://www.javadoc.io/doc/de.alpharogroup/auth-api)

auth-security [![Javadoc](https://javadoc-emblem.rhcloud.com/doc/de.alpharogroup/auth-security/badge.svg)](http://www.javadoc.io/doc/de.alpharogroup/auth-security)

crypt-api [![Javadoc](https://javadoc-emblem.rhcloud.com/doc/de.alpharogroup/crypt-core/badge.svg)](http://www.javadoc.io/doc/de.alpharogroup/crypt-api)

crypt-core [![Javadoc](https://javadoc-emblem.rhcloud.com/doc/de.alpharogroup/crypt-core/badge.svg)](http://www.javadoc.io/doc/de.alpharogroup/crypt-core)

crypt-data [![Javadoc](https://javadoc-emblem.rhcloud.com/doc/de.alpharogroup/crypt-data/badge.svg)](http://www.javadoc.io/doc/de.alpharogroup/crypt-data)

randomizer [![Javadoc](https://javadoc-emblem.rhcloud.com/doc/de.alpharogroup/randomizer/badge.svg)](http://www.javadoc.io/doc/de.alpharogroup/randomizer)

randomizer-api [![Javadoc](https://javadoc-emblem.rhcloud.com/doc/de.alpharogroup/randomizer/badge.svg)](http://www.javadoc.io/doc/de.alpharogroup/randomizer-api)

randomizer-data [![Javadoc](https://javadoc-emblem.rhcloud.com/doc/de.alpharogroup/randomizer/badge.svg)](http://www.javadoc.io/doc/de.alpharogroup/randomizer-data)

## Maven Central

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/de.alpharogroup/mystic-crypt/badge.svg)](https://maven-badges.herokuapp.com/maven-central/de.alpharogroup/mystic-crypt)

## Maven dependency

Maven dependency is now on sonatype.
Check out [sonatype repository](https://oss.sonatype.org/index.html#nexus-search;quick~mystic-crypt) for latest snapshots and releases.

![maven-dependencies-diagramm](https://github.com/astrapi69/mystic-crypt/blob/develop/src/main/resources/imgs/mystic-crypt-mvn-dependencies.png)

This erd-diagramm was created with with [netbeans](https://netbeans.org/).

You can first define the version properties:

	<properties>
			...
		<!-- MYSTIC-CRYPT versions -->
		<mystic-crypt.version>5.0.0</mystic-crypt.version>
		<auth-api.version>${mystic-crypt.version}</auth-api.version>
		<auth-security.version>${mystic-crypt.version}</auth-security.version>
		<crypt-api.version>${mystic-crypt.version}</crypt-api.version>
		<crypt-core.version>${mystic-crypt.version}</crypt-core.version>
		<crypt-data.version>${mystic-crypt.version}</crypt-data.version>
		<randomizer.version>${mystic-crypt.version}</randomizer.version>
		<randomizer-api.version>${mystic-crypt.version}</randomizer-api.version>
		<randomizer-data.version>${mystic-crypt.version}</randomizer-data.version>
			...
	</properties>
	
You can add the following dependencies to your project for use the functionality of mystic-crypt.


Add the following maven dependency to your project `pom.xml` if you want to import the functionality of auth-api:

		<dependencies>
			...
			<!-- AUTH-API DEPENDENCY -->
			<dependency>
				<groupId>de.alpharogroup</groupId>
				<artifactId>auth-api</artifactId>
				<version>${auth-api.version}</version>
			</dependency>
			...
		</dependencies>


Add the following maven dependency to your project `pom.xml` if you want to import the functionality of auth-security:

		<dependencies>
			...
			<!-- AUTH-SECURITY DEPENDENCY -->
			<dependency>
				<groupId>de.alpharogroup</groupId>
				<artifactId>auth-security</artifactId>
				<version>${auth-security.version}</version>
			</dependency>
			...
		</dependencies>

Add the following maven dependency to your project `pom.xml` if you want to import the core functionality of mystic-api:

		<dependencies>
			...
			<!-- CRYPT-API DEPENDENCY -->
			<dependency>
				<groupId>de.alpharogroup</groupId>
				<artifactId>crypt-api</artifactId>
				<version>${crypt-api.version}</version>
			</dependency>
			...
		</dependencies>

Add the following maven dependency to your project `pom.xml` if you want to import the core functionality of mystic-core:

		<dependencies>
			...
			<!-- CRYPT-CORE DEPENDENCY -->
			<dependency>
				<groupId>de.alpharogroup</groupId>
				<artifactId>crypt-core</artifactId>
				<version>${crypt-core.version}</version>
			</dependency>
			...
		</dependencies>

Add the following maven dependency to your project `pom.xml` if you want to import only the crypt-data like algorithms, modes, paddings etc.:

		<dependencies>
			...
			<!-- CRYPT-DATA DEPENDENCY -->
			<dependency>
				<groupId>de.alpharogroup</groupId>
				<artifactId>crypt-data</artifactId>
				<version>${crypt-data.version}</version>
			</dependency>
			...
		</dependencies>

Add the following maven dependency to your project `pom.xml` if you want to import the functionality of randomizer:

		<dependencies>
			...
			<!-- RANDOMIZER DEPENDENCY -->
			<dependency>
				<groupId>de.alpharogroup</groupId>
				<artifactId>randomizer</artifactId>
				<version>${randomizer.version}</version>
			</dependency>
			...
		</dependencies>

Add the following maven dependency to your project `pom.xml` if you want to import the functionality of randomizer-api:

		<dependencies>
			...
			<!-- RANDOMIZER DEPENDENCY -->
			<dependency>
				<groupId>de.alpharogroup</groupId>
				<artifactId>randomizer-api</artifactId>
				<version>${randomizer-api.version}</version>
			</dependency>
			...
		</dependencies>


Add the following maven dependency to your project `pom.xml` if you want to import the functionality of randomizer-data:

		<dependencies>
			...
			<!-- RANDOMIZER DEPENDENCY -->
			<dependency>
				<groupId>de.alpharogroup</groupId>
				<artifactId>randomizer-data</artifactId>
				<version>${randomizer-data.version}</version>
			</dependency>
			...
		</dependencies>

## Semantic Versioning

The versions of mystic-crypt are maintained with the Semantic Versioning guidelines.

Release version numbers will be incremented in the following format:

`<major>.<minor>.<patch>`

For more information on SemVer you can visit [semver.org](http://semver.org/).

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

# Donations

This project is kept as an open source product and relies on contributions to remain being developed. 
If you like this project, please consider a donation through paypal: <a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=GVBTWLRAZ7HB8" target="_blank">
<img src="https://www.paypalobjects.com/en_US/GB/i/btn/btn_donateCC_LG.gif" alt="PayPal this" title="PayPal – The safer, easier way to pay online!" border="0" />
</a>

or over bitcoin or bitcoin-cash with:

1Jzso5h7U82QCNmgxxSCya1yUK7UVcSXsW

or over ether with:

0xaB6EaE10F352268B0CA672Dd6e999C86344D49D8

or over flattr: <a href="http://flattr.com/thing/4152938/astrapi69mystic-crypt-on-GitHub" target="_blank">
<img src="http://api.flattr.com/button/flattr-badge-large.png" alt="Flattr this" title="Flattr this" border="0" />
</a>

# Similar projects

Here is a list of awesome projects for cryptography:


 * [cryptacular](https://github.com/vt-middleware/cryptacular) The friendly complement to the BouncyCastle crypto API for Java.
 * [JSch](http://www.jcraft.com/jsch/) JSch is a pure Java implementation of SSH2.
 * [Apache Shiro](https://github.com/apache/shiro) Apache Shiro is a powerful and easy-to-use Java security framework that performs authentication, authorization, cryptography, and session management.
 * [commons-ssl](http://juliusdavies.ca/commons-ssl/) Not-Yet-Commons-SSL
 * [lockbox-java](https://github.com/eloquent/lockbox-java) Simple, strong encryption. 

## Credits

|Travis CI|
|:-:|
|![Travis CI](https://travis-ci.com/images/logos/TravisCI-Full-Color.png)|
|Many thanks to [Travis CI](https://travis-ci.org) for providing a free continuous integration service for open source projects.|
