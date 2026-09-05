# pinned on purpose with := (not ?=): the shell's JAVA_HOME (e.g. sdkman's "current") may point at
# an older JDK, and this project's toolchain is JDK 25 (gradle.properties projectSourceCompatibility)
JAVA_HOME := /home/astrapi69/.sdkman/candidates/java/25-tem

# every target goes through this, so the JDK pin lives in one place
GRADLE := JAVA_HOME=$(JAVA_HOME) ./gradlew

# the runnable uber-jar built by shadowJar: mystic-crypt-<version>-all.jar
CLI_JAR := $(shell find build/libs -maxdepth 1 -name '*-all.jar' 2>/dev/null | head -1)

# a PIT run deletes this fixture; the pitest target restores it rather than leaving it to memory
PIT_FIXTURE := src/test/resources/crypt/test.txt

.DEFAULT_GOAL := help

.PHONY: help build build-fast test clean cli run spotless spotless-java spotless-misc \
	pitest jacoco-coverage jacoco-report jar javadoc dependencies dependency-updates \
	version-catalog-format version-catalog-update publish-local publish-central tag-release

help:
	@echo "mystic-crypt - make targets"
	@echo ""
	@echo "  build                   clean build: tests + Jacoco + Spotless check (the everyday gate)"
	@echo "  build-fast              assemble without running tests"
	@echo "  test                    tests only"
	@echo "  clean                   remove build output"
	@echo "  cli                     build the runnable uber-jar (shadowJar)"
	@echo "  run ARGS='...'          run the uber-jar, e.g. make run ARGS='keygen --help'"
	@echo ""
	@echo "  spotless                format and apply license headers (run before committing)"
	@echo "  spotless-java           Java sources only"
	@echo "  spotless-misc           everything else"
	@echo ""
	@echo "  pitest                  PIT mutation testing, then restore the fixture PIT deletes"
	@echo "  jacoco-coverage         verify the coverage thresholds"
	@echo "  jacoco-report           write the coverage report"
	@echo ""
	@echo "  jar                     the library jar"
	@echo "  javadoc                 the javadoc"
	@echo "  dependencies            print the dependency tree"
	@echo "  dependency-updates      report newer versions of dependencies and plugins"
	@echo "  version-catalog-format  sort and format gradle/libs.versions.toml"
	@echo "  version-catalog-update  write the newer versions into the catalog"
	@echo ""
	@echo "  publish-local           install into the local Maven repository"
	@echo "  publish-central         upload to Maven Central (needs CONFIRM=yes)"
	@echo "  tag-release             PUBLISHES: the RELEASE tag triggers publish.yml (needs CONFIRM=yes)"

build:
	$(GRADLE) clean build

build-fast:
	$(GRADLE) assemble -x test

test:
	$(GRADLE) test

clean:
	$(GRADLE) clean

cli:
	$(GRADLE) shadowJar
	@echo "built: $$(find build/libs -maxdepth 1 -name '*-all.jar' | head -1)"

# usage: make run ARGS='keygen -a EC --curve secp256r1 --print-details'
run:
	@test -n "$(CLI_JAR)" || { echo "no uber-jar yet - run 'make cli' first"; exit 1; }
	$(JAVA_HOME)/bin/java -jar $(CLI_JAR) $(ARGS)

spotless:
	$(GRADLE) spotlessApply

spotless-java:
	$(GRADLE) spotlessJavaApply

spotless-misc:
	$(GRADLE) spotlessMiscApply

# --rerun-tasks --no-build-cache because a cached PIT run reports success in milliseconds without
# producing numbers. The fixture is restored whether PIT passed or failed, and PIT's exit code is
# the target's exit code: a gate that cannot report must not report green.
pitest:
	@set -e; \
	$(GRADLE) pitest --rerun-tasks --no-build-cache; status=$$?; \
	git checkout -- $(PIT_FIXTURE) 2>/dev/null || true; \
	git status --short -- src/test/resources | grep . && echo "NOTE: PIT left changes above" || true; \
	exit $$status

jacoco-coverage:
	$(GRADLE) jacocoTestCoverageVerification

jacoco-report:
	$(GRADLE) jacocoTestReport

jar:
	$(GRADLE) jar

javadoc:
	$(GRADLE) javadoc

dependencies:
	$(GRADLE) dependencies

dependency-updates:
	$(GRADLE) dependencyUpdates

version-catalog-format:
	$(GRADLE) versionCatalogFormat

version-catalog-update:
	$(GRADLE) versionCatalogUpdate

publish-local:
	$(GRADLE) publishToMavenLocal

# publishingType is USER_MANAGED, so this uploads a bundle that still waits for a click in the
# Portal. That is a net, not a permission: a published version can never be replaced.
publish-central:
	@test "$(CONFIRM)" = "yes" || { \
		echo "publish-central uploads to Maven Central. Re-run with CONFIRM=yes if that is intended."; \
		exit 1; }
	$(GRADLE) publishAllPublicationsToCentralPortal

# In THIS repository tagging is publishing: .github/workflows/publish.yml triggers on 'RELEASE-*'
# tag pushes. crypt-api and crypt-data differ - there the tag is only a marker. Decide whether to
# upload BEFORE the tag, not after it.
tag-release:
	@test "$(CONFIRM)" = "yes" || { \
		echo "tag-release creates a RELEASE tag, and pushing it triggers publish.yml, which uploads"; \
		echo "to Maven Central. Re-run with CONFIRM=yes if that is intended."; \
		exit 1; }
	$(GRADLE) tagRelease
