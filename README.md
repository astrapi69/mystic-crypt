# Overview

<div align="center">

[![Build Status](https://travis-ci.org/astrapi69/mystic-crypt.svg?branch=master)](https://travis-ci.org/astrapi69/mystic-crypt)
[![Coverage Status](https://codecov.io/gh/astrapi69/mystic-crypt/branch/master/graph/badge.svg)](https://codecov.io/gh/astrapi69/mystic-crypt)
[![Open Issues](https://img.shields.io/github/issues/astrapi69/mystic-crypt.svg?style=flat)](https://github.com/astrapi69/mystic-crypt/issues) 
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/de.alpharogroup/mystic-crypt/badge.svg)](https://maven-badges.herokuapp.com/maven-central/de.alpharogroup/mystic-crypt)
[![MIT license](http://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](http://opensource.org/licenses/MIT)
[![Javadoc](http://www.javadoc.io/badge/de.alpharogroup/mystic-crypt.svg)](http://www.javadoc.io/doc/de.alpharogroup/mystic-crypt)

</div>

The target of this parent project is to make encryption and decryption as simple as possible

If you like this project put a ⭐ and donate

## Note

No animals were harmed in the making of this library

# Donations

This project is kept as an open source product and relies on contributions to remain being developed. 
If you like this project, please consider a donation through paypal: <a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=GVBTWLRAZ7HB8" target="_blank">
<img src="https://www.paypalobjects.com/en_US/GB/i/btn/btn_donateCC_LG.gif" alt="PayPal this" title="PayPal – The safer, easier way to pay online!" border="0" />
</a>

or over bitcoin or bitcoin-cash with:

1Jzso5h7U82QCNmgxxSCya1yUK7UVcSXsW

or over ether with:

0xaB6EaE10F352268B0CA672Dd6e999C86344D49D8

or over the donation buttons at the top.

## Key features:

 * checksums from files
 * checksums from serializable objects
 * chain multiply encryptors for securely encrypting your data
 * encryption and decryption strings with character set
 * encryption and decryption of single files
 * sign requests for your google maps urls
 * hex encryption and decryption
 * encryption with PublicKey and decryption with PrivateKey objects that was generated with openssl or java
 * encryption and decryption from .pem, .der files that was generated with openssl
 * obfuscate text with specified map
 * decorate crypt objects with decorators
 * brute-force processing for crack passwords
 * wordlist processing for crack passwords
 * hash byte arrays, strings such as passwords
 * simple encode and decode of string objects with relocation
 * resolve the TrustManagers and KeyManagers from keystore files
 
 
Encryption and decryption processes are always executed in the backround so it is a black box for the user. If you want to 
see this library in action you can download this [gui client](https://github.com/astrapi69/mystic-crypt-ui) and see some features
described above.
 
## License

The source code comes under the liberal MIT License, making mystic-crypt great for all types of applications.

## Maven dependency

Maven dependency is now available on sonatype.
Check out [sonatype repository](https://oss.sonatype.org/index.html#nexus-search;quick~mystic-crypt) for latest snapshots and releases.

You can first define the version properties and add than the following maven dependency to your project `pom.xml` if you want to import the core functionality of mystic-crypt:

	<properties>
			...
		<!-- MYSTIC-CRYPT version -->
		<mystic-crypt.version>7.4</mystic-crypt.version>
			...
	</properties>
			...
		<dependencies>
			...
			<!-- MYSTIC-CRYPT DEPENDENCY -->
			<dependency>
				<groupId>de.alpharogroup</groupId>
				<artifactId>mystic-crypt</artifactId>
				<version>${mystic-crypt.version}</version>
			</dependency>
			...
		</dependencies>	
			
## gradle dependency

You can first define the version in the ext section and add than the following gradle dependency to your project `build.gradle` if you want to import the core functionality of mystic-crypt:

```
ext {
			...
    mysticCryptVersion = "7.4"
			...
}
dependencies {
			...
compile "de.alpharogroup:mystic-crypt:$mysticCryptVersion"
			...
}
```

## Semantic Versioning

The versions of mystic-crypt are maintained with the Semantic Versioning guidelines.

Release version numbers will be incremented in the following format:

`<major>.<minor>.<patch>`

For detailed information on versioning you can visit the [wiki page](https://github.com/lightblueseas/mvn-parent-projects/wiki/Semantic-Versioning).

## Want to Help and improve it? ###

The source code for mystic-crypt are on GitHub. Please feel free to fork and send pull requests!

Create your own fork of [astrapi69/mystic-crypt/fork](https://github.com/astrapi69/mystic-crypt/fork)

To share your changes, [submit a pull request](https://github.com/astrapi69/mystic-crypt/pull/new/develop).

Don't forget to add new units tests on your changes.

## Contacting the Developer

Do not hesitate to contact the mystic-crypt developers with your questions, concerns, comments, bug reports, or feature requests.
- Feature requests, questions and bug reports can be reported at the [issues page](https://github.com/astrapi69/mystic-crypt/issues).

# Similar projects

Here is a list of awesome projects for cryptography:

 * [cryptacular](https://github.com/vt-middleware/cryptacular) The friendly complement to the BouncyCastle crypto API for Java.
 * [JSch](http://www.jcraft.com/jsch/) JSch is a pure Java implementation of SSH2.
 * [Apache Shiro](https://github.com/apache/shiro) Apache Shiro is a powerful and easy-to-use Java security framework that performs authentication, authorization, cryptography, and session management.
 * [commons-ssl](http://juliusdavies.ca/commons-ssl/) Not-Yet-Commons-SSL
 * [lockbox-java](https://github.com/eloquent/lockbox-java) Simple, strong encryption. 
 * [jsql-injection](https://github.com/ron190/jsql-injection) jSQL Injection is a Java application for automatic SQL database injection.
 * [curve25519](https://github.com/signalapp/curve25519-java) Pure Java and JNI backed Curve25519 implementation
 * [vault](https://github.com/hashicorp/vault) A tool for secrets management, encryption as a service, and privileged access management
 * [jasypt](http://www.jasypt.org/) Java Simplified Encryption
 * [CogniCrypt](https://github.com/eclipse-cognicrypt/CogniCrypt) CogniCrypt is an Eclipse plugin that supports Java developers in using Java Cryptographic APIs

## Credits

|**Travis CI**|
|     :---:      |
|[![Travis CI](https://travis-ci.com/images/logos/TravisCI-Full-Color.png)]|
|[![Build Status](https://travis-ci.org/astrapi69/mystic-crypt.svg?branch=master)](https://travis-ci.org/astrapi69/mystic-crypt)|
|Special thanks to [Travis CI](https://travis-ci.org) for providing a free continuous integration service for open source projects|
|     <img width=1000/>     |

|**Nexus Sonatype repositories**|
|     :---:      |
|[![sonatype repository](https://img.shields.io/nexus/r/https/oss.sonatype.org/de.alpharogroup/mystic-crypt.svg?style=for-the-badge)](https://oss.sonatype.org/index.html#nexus-search;gav~de.alpharogroup~mystic-crypt~~~) mystic-crypt|
|Special thanks to [sonatype repository](https://www.sonatype.com) for providing a free maven repository service for open source projects|
|     <img width=1000/>     |

|**codecov.io**|
|     :---:      |
|[![Coverage Status](https://codecov.io/gh/astrapi69/mystic-crypt/branch/master/graph/badge.svg)](https://codecov.io/gh/astrapi69/mystic-crypt)|
|Special thanks to [codecov.io](https://codecov.io) for providing a free code coverage for open source projects|
|     <img width=1000/>     |

|**javadoc.io**|
|     :---:      |
|[![Javadoc](http://www.javadoc.io/badge/de.alpharogroup/mystic-crypt.svg)](http://www.javadoc.io/doc/de.alpharogroup/mystic-crypt) mystic-crypt|
|Special thanks to [javadoc.io](http://www.javadoc.io) for providing a free javadoc documentation for open source projects|
|     <img width=1000/>     |

