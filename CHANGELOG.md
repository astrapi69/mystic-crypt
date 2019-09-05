## Change log
----------------------

Version 7.1-SNAPSHOT
-------------

ADDED:

- gradle as build system
- new encryptor class created for encrypting java object in a generic way
- new decryptor class created for decrypt an encrypted {@link File} object that was previously encrypted and return the decrypted result as generic java object 

CHANGED:

- update of dependency crypt-api version to 7.1

Version 7
-------------

CHANGED:

- removed depracated class CryptConst
- changed from modules to simple project
- moved crypt-api to own project
- moved crypt-data to own project
- moved crypt-core to the top of this project so crypt-core is now mystic-crypt
- new method in the utility class Hasher with private key parameter created

Version 6
-------------

ADDED:
 
- new dependency jobj-core in version 3.2.1 added
- new dependency jaxb-api in version 2.3.1 added
- new dependency jobj-contract-verifier in version 3.2 added

CHANGED:

- update of parent version to 5.2 
- constant class CryptConst tags as deprecated, will be removed in next minor release
- update of guava version to 27.1-jre
- update of commons-codec version to 1.12
- update of bouncycastle version to 1.62
- update of file-worker version to 5.2
- update of jcommons-lang version to 5.2.2
- update of test-objects version to 5.2
- update of silly-collections version to 5.2.1
- update of randomizer version to 6.1
- update of commons-codec version to 1.12
- change provider of code coverage to codecov.io

Version 5.8
-------------

CHANGED:

- update of parent version to 4.6
- update of file-worker version to 5.1
- update of jcommons-lang version to 5.1.1
- update of test-objects version to 5.0.1
- update of silly-collections version to 5.1

Version 5.7
-------------

CHANGED:

- update of parent version to 4.5
- update of file-worker version to 5.0.1
- update of jcommons-lang version to 5.1
- update of silly-collections version to 5
- update of randomizer version to 5.6
- update of guava version to 27.0.1-jre

Version 5.6
-------------

ADDED:
 
- new enum value NEGATECASE in Operation class that indicates to negate the case of the given character value
- new blockchain classes created for Block, Address and Transaction
- new extension created class for simple obfuscation
- new hash methods created for hash blocks in a blockchain and calculate the merkle root hash
- new obfuscation test data for unit test 
- new lombok.config files added to projects

CHANGED:

- moved obfuscation classes to appropriate packages
- update of silly-collections version to 4.34.1
- unit tests extended for improve code coverage
- simple obfuscation implementation improved

Version 5.5
-------------

ADDED:
 
- new methods for encode and decode string objects in HexExtensions class created
- new enum created that holds union words for chaining algorithms

CHANGED:

- update of parent version to 4.1
- update of file-worker version to 4.23
- update of jcommons-lang version to 4.35
- update of resourcebundle-inspector version to 3
- update of guava version to 26.0-jre

Version 5.4
-------------

ADDED:
 
- new unit tests created

CHANGED:

- deleted deprecated class
- deleted unit test class deprecated class
- cleaned up of exclude classes in code coverage maven plugin

Version 5.3
-------------

CHANGED:

- javadoc improved and extended 
- deleted deprecated methods and classes
- unit tests extended for improve code coverage

Version 5.2
-------------

CHANGED:

- moved auth relevant projects to own [project](https://github.com/astrapi69/auth)
- update of parent version to 4
- removed unneeded .0 at the end of version
- update of file-worker version to 4.22
- update of jcommons-lang version to 4.34
- update of test-objects version to 4.28
- update of silly-collections version to 4.33
- update of jobject-extensions version to 1.12
- update of resourcebundle-inspector version to 2.22
- update of randomizer version to 5.4
- update of bouncycastle version to 1.60
- update of guava version to 25.1-jre
- unit tests extended for improve code coverage

Version 5.1.0
-------------

ADDED:
 
- moved all left intefaces to the api projects 
- moved all enums to the api projects 
- provide new package.html for the javadoc of new packages

CHANGED:

- moved random relevant projects to own [project](https://github.com/astrapi69/randomizer)
- update of dependency version of silly-collections
- update of dependency version of jcommons-lang
- update of dependency version of file-worker 
- update of dependency version of resourcebundle-inspector 
- update of dependency version of jobject-extensions 
- unit tests extended for improve code coverage


Version 5.0.0
-------------

ADDED:
 
- this changelog file
- protect and encrypt private key with password
- write protected private key with password to a file
- paypal button as markdown added
- new classes that declares simple and complex rules for obfuscation of characters
- moved intefaces to new api projects
- added new meanbean dependency for better unit testing of beans
- provide package.html for the javadoc of packages

CHANGED:

- interfaces moved to api projects
- moved several classes to appropriate named packages 
- javadoc improved and extended 
- deleted deprecated classes
- en- and decryption of file extended
- refactoring: moved classes to appropriate package
- Obfuscation classes uses now guava BiMap

Version 4.24.0
-------------

ADDED:
 
- new eclipse launch scripts created
- created PULL_REQUEST_TEMPLATE.md file
- created CODE_OF_CONDUCT.md file
- created CONTRIBUTING.md file
- created GoogleMapsUrlSigner class that is a possible solution to that [issue](https://github.com/astrapi69/mystic-crypt/issues/6)
- created new intefaces of blockchain domain
- added guava dependency

CHANGED:

- refactoring of several classes
- update of parent version
- update of dependency version of silly-collections
- update of dependency version of jcommons-lang
- update of dependency version of file-worker 
- update of dependency version of test-objects 
- sorted pom.xml's

Version 4.23.0
-------------

ADDED:
 
- new eclipse launch scripts created

CHANGED:

- update of dependency version of silly-collections
- update of dependency version of jcommons-lang
- update of parent version
- update of dependency version of file-worker 

Version 4.22.0
-------------

ADDED:
 
- created new CertificateExtensions, HashExtensions class
- added new reader method for der files
- javadoc image in the READE.md added with a reference to the online javadoc site
- mvn depencencies diagramm image added in the READE.md

CHANGED:

- extended reader and writer methods
- unit tests improved and extended 
- javadoc improved and extended 
- update of parent version

Version 4.21.0
-------------

ADDED:
 
- added jsr305 dependency
- new method in CertFactory for create a x509 cert v1
- created new unit tests 
- code coverage added
- created new SecureRandomBuilder, CertificateReader and CertificateWriter classes

CHANGED:

- unit tests improved
- javadoc improved and extended 

Version 4.20.0
-------------

ADDED:
 
- created new model class SignInWithRedirectionModel with redirection

CHANGED:

- moved mystic-crypt-ui project to own repository

Version 4.19.0
-------------

ADDED:
 
- initial version of a obfuscate demo

Version 4.18.0
-------------

ADDED:
 
- created panels for the demo app
- new enum KeySize created that holds the bit size for private keys
- new class EnableButtonBehavior created for demo project
- create new CipherTypes.dat file that contain ciphers
- generate key pair keys with gui for demo project

CHANGED:

- gui examples extended in the demo project

Version 4.17.0
-------------

ADDED:
 
- new project mystic-crypt-ui for demos created
- created readers and writers for public and private keys
- new method for resolve the public key from a private key
- new abstract classes for encrypt and decrypt

CHANGED:

- update of license headers
- refactoring: moved several classes to appropriate packages
- optimized factory for cipher creation

Version 4.16.0
-------------

ADDED:
 
- chainable encryptor and decryptor created
- created new project crypt-data

CHANGED:

- moved all algorithms and enums to the new project crypt-data

Version 4.15.0
-------------

ADDED:
 
- new classes for encryption and decryption with public and private keys
  that take byte arrays as arguments in the encryption and decryption process
- new class for build a SecureRandom object
- new factory for Certificate object creation
- new inteface Cryptor created for define the operation mode
- new factory class for KeyStore object

CHANGED:

- javadoc extended and improved
- rename of interfaces from encryptor and decryptor
- extended crypt model and adapted related classes
- update of documentation in README.md file

Version 4.14.0
-------------

ADDED:
 
- new encryptor and decryptor classes for base64 pem files created
- new enum for modes, paddings created
- created new crypt model and extracted all relevant data to the crypt model 

CHANGED:

- update of several dependencies versions
- renamed GenericCryptor to AbstractCryptor
- update the abstract cryptor to the new crypt model
- unit tests improved
- javadoc extended and improved

Version 4.13.0
-------------

CHANGED:

- update of several dependencies versions

Version 4.12.0
-------------

ADDED:
 
- new exception for security created

Version 4.11.0
-------------

ADDED:
 
- new method for create a random token

CHANGED:

- update of license header from all files

Version 4.10.0
-------------

ADDED:
 
- create new top25pw.txt for unit tests with WordlistProcessorTest
- create KeyPairAlgorithm class
- create new enum for mac algorithms
- create new interface generators for random data 

CHANGED:

- update of Algorithm interface and RandomExtensions class


Version 4.9.0
-------------

ADDED:
 
- new class Credentials created

CHANGED:

- documentation of README.md file improved and extended 
- update of several dependencies versions

Version 4.8.0
-------------

ADDED:
 
- using git-flow for new releases 
- added license header to all files
- new AuthenticationResult class created for authentication

CHANGED:

- documentation of README.md file improved and extended 
- javadoc improved and extended 

Version 4.7.0
-------------

ADDED:
 
- New factory classes and new abstract classes for en and decrypting

CHANGED:

- resourcebundle-inspector version upgrade to 2.7.0


Version 4.6.0
-------------

ADDED:
 
- created new abstract cryptor class with callback methods

CHANGED:

- update of parent version

...

Version 4.2.0
-------------

CHANGED:

- rename of classes to a more appropriate name
- javadoc improved and extended 

Version 4.1.0
-------------

CHANGED:

- javadoc improved and extended  
- renamed util classes
- deleted depracated classes

Version 4.0.0
-------------

ADDED:
 
- moved project jaulp.security to mystic-crypt and rename it to auth-security
- created a simple wordlist processor that was requested from an issue

CHANGED:

- new major version 4.0.0 and using new jdk version 8
- altered .travis.yml email address
- update of lombok version to 1.16.6

Version 3.12.0
-------------

ADDED:
 
- created new maven profile for deploy on sonatype

CHANGED:

- maven-compiler-plugin.version updated to 3.3
- maven-javadoc-plugin.version updated to 2.10.3
- nexus-staging-maven-plugin version updated to version 1.6.5
- Refactoring from method parameters and made method parameters final

Version 3.11.0
-------------

ADDED:
 
- added flattr image for donations
- added .travis.yml file and build-status image
- moved jaulp.random project as new module project randomizer in parent project mystic-crypt

CHANGED:

- update of lombok version to 1.16.4
- javadoc extended and improved

Version 3.10.0
-------------

ADDED:
 
- initial version of mystic-crypt
- moved from project jaulp.core 
- adoption of version from jaulp.core

CHANGED:

- javadoc extended and improved

-------------

Notable links:
[keep a changelog](http://keepachangelog.com/en/1.0.0/) Don’t let your friends dump git logs into changelogs