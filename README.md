# Overview

<div style="text-align: center">

[![Build Status](https://api.travis-ci.com/astrapi69/mystic-crypt.svg?branch=develop)](https://travis-ci.com/github/astrapi69/mystic-crypt)
[![Coverage Status](https://codecov.io/gh/astrapi69/mystic-crypt/branch/develop/graph/badge.svg)](https://codecov.io/gh/astrapi69/mystic-crypt)
[![Open Issues](https://img.shields.io/github/issues/astrapi69/mystic-crypt.svg?style=flat)](https://github.com/astrapi69/mystic-crypt/issues) 
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.astrapi69/mystic-crypt/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.github.astrapi69/mystic-crypt)
[![MIT license](http://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](http://opensource.org/licenses/MIT)
[![Javadoc](http://www.javadoc.io/badge/io.github.astrapi69/mystic-crypt.svg)](http://www.javadoc.io/doc/io.github.astrapi69/mystic-crypt)

</div>

The target of this parent project is to make encryption and decryption as simple as possible

# Support this project

> Please support this project by simply putting a Github <!-- Place this tag where you want the button to render. -->
<a class="github-button" href="https://github.com/astrapi69/mystic-crypt" data-icon="octicon-star" aria-label="Star astrapi69/mystic-crypt on GitHub">Star ⭐</a>
>
> Share this library with friends on Twitter and everywhere else you can
>
> If you love this project [![donation](https://img.shields.io/badge/donate-❤-ff2244.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=GVBTWLRAZ7HB8)
>
> or for more donation options go the [donations section](#Donations)

## License

The source code comes under the liberal MIT License, making mystic-crypt great for all types of applications.

## Maven dependency

Maven dependency is now available on sonatype.
Check out [sonatype repository](https://oss.sonatype.org/index.html#nexus-search;quick~mystic-crypt) for latest snapshots and releases.

You can first define the version properties and add than the following maven dependency to your project `pom.xml` if you want to import the core functionality of mystic-crypt:

	<properties>
			...
		<!-- MYSTIC-CRYPT version -->
		<mystic-crypt.version>7.9</mystic-crypt.version>
			...
	</properties>
			...
		<dependencies>
			...
			<!-- MYSTIC-CRYPT DEPENDENCY -->
			<dependency>
				<groupId>io.github.astrapi69</groupId>
				<artifactId>mystic-crypt</artifactId>
				<version>${mystic-crypt.version}</version>
			</dependency>
			...
		</dependencies>	

## gradle dependency

You can first define the version in the ext section and add than the following gradle dependency to
your project `build.gradle` if you want to import the core functionality of mystic-crypt:

define version in file gradle.properties

```
mysticCryptVersion=7.9
```

or in build.gradle ext area

```
ext {
			...
    mysticCryptVersion = "7.9"
			...
}
```

and then add the dependency to the dependencies area

```
dependencies {
			...
	implementation("io.github.astrapi69:mystic-crypt:$mysticCryptVersion")
			...
}
```

## Note

No animals were harmed in the making of this library

# Donations

This project is kept as an open source product and relies on contributions to remain being
developed. If you like this library, please consider a donation

over paypal: <br><br>
<a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=MJ7V43GU2H386" target="_blank">
<img src="https://www.paypalobjects.com/en_US/GB/i/btn/btn_donateCC_LG.gif" alt="PayPal this" title="PayPal – The safer, easier way to pay online!" style="border: none" />
</a>
<br><br>
or over bitcoin(BTC) with this address:

bc1ql2y99q7e8psndhcc3gferk03esw3qqf677rhjy

<img src="https://github.com/astrapi69/jgeohash/blob/master/src/main/resources/img/bc1ql2y99q7e8psndhcc3gferk03esw3qqf677rhjy.png"
alt="Donation Bitcoin Wallet" width="250"/>

or over FIO with this address:

FIO7tFMUVAA9cHiPPqKMfMXiSxHrbpiFyRYqTketNuM67aULuwjop

<img src="https://github.com/astrapi69/jgeohash/blob/master/src/main/resources/img/FIO7tFMUVAA9cHiPPqKMfMXiSxHrbpiFyRYqTketNuM67aULuwjop.png"
alt="Donation FIO Wallet" width="250"/>

or over Ethereum(ETH) with:

0xc057D159D3C8f3311E73568b334FF6fE82EB2b7D

<img src="https://github.com/astrapi69/jgeohash/blob/master/src/main/resources/img/0xc057D159D3C8f3311E73568b334FF6fE82EB2b7D.png"
alt="Donation Ethereum Wallet" width="250"/>

or over Ethereum Classic(ETC) with:

0xF708cA86D86C246B69c3F4BAe431eBbe0c2bfddD

<img src="https://github.com/astrapi69/jgeohash/blob/master/src/main/resources/img/0xF708cA86D86C246B69c3F4BAe431eBbe0c2bfddD.png"
alt="Donation Ethereum Classic Wallet" width="250"/>

or over Dogecoin(DOGE) with:

D5yi4Um8cpakd6yPRm2hGWuQ5nrVzhSSW1

<img src="https://github.com/astrapi69/jgeohash/blob/master/src/main/resources/img/D5yi4Um8cpakd6yPRm2hGWuQ5nrVzhSSW1.png"
alt="Donation Dogecoin Wallet" width="250"/>

or over Monero(XMR) with:

49bqeRQ7Bf49oJFVC72pqpe5hFbb62pfXDYPdLsadGGF81KZW2ZfrPZ8PbAVu5X2v1TYAspeczMya3cYQysNS4usRRPQHVw

<img src="https://github.com/astrapi69/jgeohash/blob/master/src/main/resources/img/49bqeRQ7Bf49oJFVC72pqpe5hFbb62pfXDYPdLsadGGF81KZW2ZfrPZ8PbAVu5X2v1TYAspeczMya3cYQysNS4usRRPQHVw.png"
alt="Donation Monero Wallet" width="250"/>

or over flattr:

<a href="https://flattr.com/submit/auto?fid=r7vp62&url=https%3A%2F%2Fgithub.com%2Fastrapi69%2Fmystic-crypt" target="_blank">
<img src="http://api.flattr.com/button/flattr-badge-large.png" alt="Flattr this" title="Flattr this" style="border: none" />
</a>

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
 * [Encryptor4j](https://github.com/martinwithaar/Encryptor4j) Strong encryption for Java simplified

## Credits

|**Travis CI**|
|     :---:      |
|[![Travis CI](https://travis-ci.com/images/logos/TravisCI-Full-Color.png)]|
|[![Build Status](https://api.travis-ci.com/astrapi69/mystic-crypt.svg?branch=master)](https://travis-ci.com/github/astrapi69/mystic-crypt)|
|Special thanks to [Travis CI](https://travis-ci.com) for providing a free continuous integration service for open source projects|
|     <img width=1000/>     |

|**Nexus Sonatype repositories**|
|     :---:      |
|[![sonatype repository](https://img.shields.io/nexus/r/https/oss.sonatype.org/io.github.astrapi69/mystic-crypt.svg?style=for-the-badge)](https://oss.sonatype.org/index.html#nexus-search;gav~io.github.astrapi69~mystic-crypt~~~) mystic-crypt|
|Special thanks to [sonatype repository](https://www.sonatype.com) for providing a free maven repository service for open source projects|
|     <img width=1000/>     |

|**codecov.io**|
|     :---:      |
|[![Coverage Status](https://codecov.io/gh/astrapi69/mystic-crypt/branch/develop/graph/badge.svg)](https://codecov.io/gh/astrapi69/mystic-crypt)|
|Special thanks to [codecov.io](https://codecov.io) for providing a free code coverage for open source projects|
|     <img width=1000/>     |

|**javadoc.io**|
|     :---:      |
|[![Javadoc](http://www.javadoc.io/badge/io.github.astrapi69/mystic-crypt.svg)](http://www.javadoc.io/doc/io.github.astrapi69/mystic-crypt) mystic-crypt|
|Special thanks to [javadoc.io](http://www.javadoc.io) for providing a free javadoc documentation for open source projects|
|     <img width=1000/>     |

