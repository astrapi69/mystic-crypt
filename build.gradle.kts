import org.gradle.jvm.tasks.Jar
import org.jetbrains.kotlin.config.KotlinCompilerVersion
import java.net.URI

val lombokVersion = "1.18.10"
val randomBeansVersion = "3.9.0"
val meanbeanVersion = "2.0.3"
val testngVersion = "7.0.0"
val junitVersion = "4.12"
val mockitoCoreVersion = "3.1.0"
val cryptApiVersion = "7.2"
val cryptDataVersion = "7.2"
val modelCoreVersion = "1.6.2"
val fileWorkerVersion = "5.2"
val jcommonsLangVersion = "5.2.2"
val testObjectsVersion = "5.2"
val sillyCollectionsVersion = "5.4"
val xmlExtensionsVersion = "6.2.1"
val jobjCoreVersion = "3.3"
val jobjCopyVersion = "3.2"
val jobjContractVerifierVersion = "3.2"
val jobjectCloneVersion = "3.1.2"
val randomizerVersion = "6.3"
val commonsCodecVersion = "1.13"
val bouncycastleVersion = "1.64"

plugins {
	jacoco
    signing
    id("io.franzbecker.gradle-lombok") version "3.2.0"
    id("java")
    id("maven-publish")
    id("signing")
    id("com.github.ben-manes.versions") version "0.27.0"
    id("org.jetbrains.kotlin.jvm") version "1.3.61"
}

apply(plugin = "jacoco")

group = "de.alpharogroup"
version = "7.3-SNAPSHOT"
description = "mystic-crypt"
java.sourceCompatibility = JavaVersion.VERSION_1_8

repositories {
    jcenter()
    mavenLocal()
    mavenCentral()
}


dependencies {
    implementation("org.projectlombok:lombok:${lombokVersion}")
    annotationProcessor("org.projectlombok:lombok:${lombokVersion}")
    implementation("commons-codec:commons-codec:${commonsCodecVersion}")
    implementation("de.alpharogroup:crypt-api:${cryptApiVersion}")
    implementation("de.alpharogroup:crypt-data:${cryptDataVersion}")
    implementation("de.alpharogroup:randomizer-core:${randomizerVersion}")
    implementation("de.alpharogroup:file-worker:${fileWorkerVersion}")
    implementation("de.alpharogroup:model-core:${modelCoreVersion}")
    implementation("de.alpharogroup:xml-extensions:${xmlExtensionsVersion}")
    implementation("de.alpharogroup:silly-collections:${sillyCollectionsVersion}")
    implementation("de.alpharogroup:jobject-clone:${jobjectCloneVersion}")
    implementation("de.alpharogroup:jobj-core:${jobjCoreVersion}")
    implementation("de.alpharogroup:jobj-copy:${jobjCopyVersion}")
    implementation("org.bouncycastle:bcprov-jdk15on:${bouncycastleVersion}")
    implementation("org.bouncycastle:bcprov-ext-jdk15on:${bouncycastleVersion}")
    implementation("org.bouncycastle:bcpkix-jdk15on:${bouncycastleVersion}")
    testImplementation("de.alpharogroup:test-objects:${testObjectsVersion}")
    testImplementation("de.alpharogroup:jcommons-lang:${jcommonsLangVersion}")
    testImplementation("de.alpharogroup:jobj-contract-verifier:${jobjContractVerifierVersion}")
    testImplementation("io.github.benas:random-beans:${randomBeansVersion}")
    testImplementation("org.meanbean:meanbean:${meanbeanVersion}")
    testImplementation("org.testng:testng:${testngVersion}")
    testImplementation("junit:junit:${junitVersion}")
    testImplementation("org.mockito:mockito-core:${mockitoCoreVersion}")
    implementation(kotlin("stdlib", KotlinCompilerVersion.VERSION))
}


val sourcesJar by tasks.registering(Jar::class) {
    archiveClassifier.set("sources")
    from(sourceSets.main.get().allJava)
}

val javadocJar by tasks.registering(Jar::class) {
    archiveClassifier.set("javadoc")
    from(tasks["javadoc"])
}


publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            artifact(sourcesJar.get())
            artifact(javadocJar.get())
            artifactId = "${rootProject.name}"
            pom {
                name.set("${rootProject.name}")
                url.set("https://github.com/astrapi69/"+"${rootProject.name}")
                description.set("The target of this project is to make encryption and decryption as simple as possible")
                organization {
                    name.set("Alpha Ro Group UG (haftungsbeschrängt)")
                    url.set("http://www.alpharogroup.de/")
                }
                issueManagement {
                    system.set("GitHub")
                    url.set("https://github.com/astrapi69/"+"${rootProject.name}"+"/issues")
                }
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("http://www.opensource.org/licenses/mit-license.php")
                        distribution.set("repo")
                    }
                }
                developers {
                    developer {
                        id.set("astrapi69")
                        name.set("Asterios Raptis")
                    }
                }
                scm {
                    connection.set("scm:git:git:@github.com:astrapi69/"+"${rootProject.name}"+".git")
                    developerConnection.set("scm:git:git@github.com:astrapi69/"+"${rootProject.name}"+".git")
                    url.set("git:@github.com:astrapi69/"+"${rootProject.name}"+".git")
                }
            }

            repositories {
                maven {
                    credentials {
                        val usernameString = System.getenv("ossrhUsername")
                                ?: project.property("ossrhUsername")
                        val passwordString = System.getenv("ossrhPassword")
                                ?: project.property("ossrhPassword")
                        username = usernameString.toString()
                        password = passwordString.toString()
                    }
                    val releasesRepoUrl = "https://oss.sonatype.org/service/local/staging/deploy/maven2/"
                    val snapshotsRepoUrl = "https://oss.sonatype.org/content/repositories/snapshots"
                    val projectVersion = version.toString()
                    val urlString = if(projectVersion.endsWith("SNAPSHOT"))  snapshotsRepoUrl else releasesRepoUrl
                    url = URI.create(urlString)
                }
            }
        }
    }
}

signing {
    sign(publishing.publications["mavenJava"])
}


tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}

val test by tasks.getting(Test::class) {
    useTestNG { }
}

tasks.jacocoTestReport {
    reports {
        xml.isEnabled = false
        csv.isEnabled = false
        html.isEnabled = true
        html.destination = file("$buildDir/reports/coverage")
    }
}

tasks.jacocoTestCoverageVerification {
    violationRules {
        rule {
            limit {
                minimum = "0.9".toBigDecimal()
            }
        }
    }
}

val testCoverage by tasks.registering {
    group = "verification"
    description = "Runs the unit tests with coverage"

    dependsOn(":test", ":jacocoTestReport", ":jacocoTestCoverageVerification")
    val jacocoTestReport = tasks.findByName("jacocoTestReport")
    jacocoTestReport?.mustRunAfter(tasks.findByName("test"))
    tasks.findByName("jacocoTestCoverageVerification")?.mustRunAfter(jacocoTestReport)
}
