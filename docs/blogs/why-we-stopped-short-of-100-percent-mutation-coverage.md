# Why We Stopped Short of 100% Mutation Coverage (On Purpose)

*How a Java cryptography library found nine real bugs by asking "why can nothing kill this mutant?" — and why the honest answer, for the last fifteen, was "don't."*

---

## The metric that lies to you

Here is a test that gives you 100% line coverage:

```java
@Test
void isValid() {
    KeyPairInfo info = new KeyPairInfo("RSA", 2048);
    info.isValid();
}
```

It runs the line. It executes every branch inside it. A coverage report will color it green. And it asserts nothing at all — it would pass identically if `isValid()` always returned `false`, always threw, or deleted your home directory as a side effect. Coverage tells you code *ran*. It cannot tell you whether the test would notice if the code were wrong.

We ran into this directly. `KeyPairInfo.isValid` in one of our libraries had an inverted condition: a perfectly normal `RSA`/2048 key pair was reported *invalid*, and an unrecognized algorithm name fell through into a key-size probe that escaped as a raw `InvocationTargetException` — which the existing test asserted as the *expected*, correct outcome. The suite was green. The behavior was backwards.

That's not a hypothetical. It's one of nine defects we found this way across three interlocking Java libraries — `crypt-api`, `crypt-data`, and `mystic-crypt`, a symmetric/asymmetric encryption, hashing, and key-agreement stack — while pushing from "high coverage" toward something that actually means what people assume coverage means. This post is about that process, what it found, and — the part most engineering blogs skip — exactly where we decided to stop, and why stopping there was the correct engineering decision rather than a shortcut.

## Coverage is the floor. Mutation testing is the bar.

Mutation testing works backwards from the usual approach. Instead of asking "did my tests run this code," a tool called [PIT](https://pitest.org/) automatically rewrites your compiled bytecode in small, deliberate ways — flips a `<` to `<=`, replaces a `return true` with `return false`, deletes a method call, negates a boolean — and reruns your test suite against each mutant. If a test fails, the mutant is *killed*: something in your suite would have noticed that exact bug. If every test still passes, the mutant *survives*, and you've found a sentence of your program that could be silently wrong forever and nothing would tell you.

A *mutation score* of 98% means 98% of these deliberately injected bugs get caught by your tests. It is a much harder number to fake than coverage, because you can't satisfy it by merely executing a line — you have to write an assertion sharp enough to distinguish the correct behavior from a specific wrong one.

The self-checking property of crypto code makes this especially sharp. Most cryptographic bugs are *silent*: encrypt, then decrypt, and you get your data back either way, whether the code is correct or subtly broken. A round-trip test alone will not save you. You need the test to check the *right* thing, and mutation testing is how you find out where it doesn't.

## The process

We settled on a five-stage loop, deliberately adversarial at every stage:

1. **Coverage.** Write tests until the per-class report plateaus. Every remaining gap needs a specific, written reason — not "hard to test."
2. **Independent verification.** A second reviewer — instructed to distrust the first — re-runs everything from scratch, re-reads the raw coverage XML rather than trusting a summary, and reads every new test line by line looking for the ones that structurally cannot fail: no assertion, a value compared with itself, a parameterized case that always exercises the same branch.
3. **Fix.** Address what stage 2 found.
4. **Mutation.** Run PIT over the *whole* suite — old tests included, because old tests are exactly where bugs like the `KeyPairInfo` one hide. Every surviving mutant gets traced to the assertion that would have killed it, and that assertion gets written. A survivor that can't be killed needs a stated, specific reason.
5. **Final verification.** An independent re-measurement from a clean build, and a second read of every new "equivalent mutant" argument against the actual source, trying to disprove it.

The stage that mattered most was the second one, applied at every level: don't trust the number, read the assertion. And it paid off immediately.

## What eight rounds of "why can't this be killed" actually found

A few, in the words we used when writing them up for our own testing-strategy documentation:

**The bug that was hiding behind another bug.** `PBEFileEncryptor` computed the decorated version of a file's content and then discarded it, encrypting the raw file instead. Its sibling `PBEFileDecryptor` re-read the file from disk on every loop iteration instead of chaining the transformation, so with more than one decorator only the innermost one ever got stripped. Every round-trip test passed, because "the encryptor never adds a decorator" and "the decryptor never removes one" cancel out perfectly. It took a single surviving mutant on the decorator loop — and the discipline of asking *why didn't anything notice this deletion* — to find it.

**An infinite loop, in a security tool.** `PrivateKeyBruteForceProcessor.resolvePassword` checks whether a private key file is password-protected before brute-forcing it. For an *unencrypted* PKCS#8 key, that check correctly returns false — but the surrounding code entered the brute-force loop anyway. The PEM reader then threw a `PEMException` on every single attempt, and because `PEMException` extends `IOException`, the loop's `catch` swallowed it as a signal to try a longer password. There is no input that terminates. Nothing pins runtime as an assertion, so nothing in the suite ever noticed a tool meant to test password strength would hang forever on the easiest possible input.

**Silent data loss from the wrong Apache Commons call.** `undecorateWithBytearrayDecorator` used `ArrayUtils.removeElements(result, prefix)` to strip a known prefix from a byte array — except that method removes matching bytes from *anywhere* in the array, not just the start. Decorate `"hello"` with prefix `"he"` and suffix `"lo"`, then undecorate it, and you get `"llo"` back. Decorate `"ab"` with prefix `"ab"` and you get back nothing at all. The fix is one method call; finding it required a round-trip test that compared against the *original* bytes rather than trusting the transformation's own output.

**The one that should worry you most.** The private helper `endsWith`, used by that same decorator code, could fall through to an unconditional `return true` whether the suffix genuinely matched *or* the array simply ran out of bytes first. Downstream, that led to `Arrays.copyOf` being called with a negative length — `NegativeArraySizeException`. And the *existing test asserted that crash as correct behavior*. This was the fourth defect we found this cycle where a passing test had encoded a bug as a specification. Test-driven development doesn't save you from writing the wrong test; it just makes the wrong test durable.

**A flaky test, root-caused instead of ignored.** One test — tampering a stored password hash and asserting verification then fails — failed intermittently, roughly one run in sixteen, and had resisted reproduction across eight prior manual runs. Mutation testing forced a fresh, clean-tree run that happened to hit it. The hash is stored as 43 characters of unpadded base64; the *last* character of an unpadded base64 string encodes only 4 significant bits, with the rest discarded by the decoder. The test flipped exactly that last character. One value in sixteen, the flip changed a bit the decoder throws away anyway, the "tampered" hash decoded to the exact same bytes, and `verify()` correctly said it was fine — because it was. The fix was moving the tamper to the *first* character, which a sibling test for a different hash algorithm had already learned to do, with a comment explaining why. Nobody had applied the same lesson to this one.

**An "equivalent mutant" that turned out not to be.** Two methods derive a UTF-8 byte buffer from a caller's password and wipe it with `Arrays.fill` when they're done — code hygiene against leaving secrets sitting in the heap. A mutant that deletes the wipe survived, and the first-pass reasoning called it equivalent: the buffer is a local variable that never leaves the method, so nothing could observe whether it got wiped. That's a reasonable-sounding argument, and it was wrong. Bouncy Castle's internal hashing utility takes that exact array *by reference*. Swap in a digest that records every buffer it's handed — no production code change required, just a test-only substitute — and you can read the "local" variable's contents from outside the method after the call returns. The adversarial verification stage exists precisely to catch confident, plausible, wrong arguments like this one. It found it, and now a real test asserts the wipe actually happens.

## Getting from "good" to "as good as it gets" — and finding the difference between the two

After the first full pass, the three libraries stood at 100% (78/78 mutants — the smallest of the three, with room to spare), 96.7%, and 98.5% mutation score, each surviving mutant written up with a specific, source-grounded argument for why it couldn't be killed.

Before shipping, we went back over every one of those arguments a second time, adversarially, trying to disprove each one rather than restate it. Seven of them didn't survive the second look — but not because we found a way to kill them. We found they weren't equivalent mutants at all. They were dead code wearing an equivalent mutant's clothes.

Take this pattern, which showed up three times:

```java
if (associatedData != null && associatedData.length > 0)
{
    finalAssociatedData = ArrayUtils.addAll(commitmentTag, associatedData);
}
```

The mutant changes `> 0` to `>= 0`, and the first-pass argument was correct as far as it went: both variants produce the same result, because `ArrayUtils.addAll` with an empty second array already returns a content-identical copy. Fine — an equivalent mutant. But *why is the guard there at all*, if the call it protects already handles the empty case correctly on its own? It isn't protecting anything. The honest fix wasn't a test. It was deleting the redundant half of the condition:

```java
if (associatedData != null)
{
    finalAssociatedData = ArrayUtils.addAll(commitmentTag, associatedData);
}
```

Same story with a `MessageDigest.reset()` called immediately after `MessageDigest.getInstance()` — which always returns an already-reset digest — and with a length check guarding a call to `Arrays.stream(...).forEach(...)`, where streaming an empty array already calls the consumer zero times. Three unrelated call sites, one underlying lesson: "this boundary is unobservable" and "this condition is redundant" look identical from a mutation report, and only look different once you read one level up, to *why the guard exists in the first place*. Removing the seven redundant guards killed their mutants and simplified the methods in the same commit. Mutation score moved from 96.7% to 98.5% to (after this second pass) 98.8% for the larger library, and to 99.6% for the other.

## The fifteen we left alone, and exactly why

That second pass left fifteen surviving mutants across the two libraries that weren't at 100%. The temptation at this point — and it's a real one, once you've built the habit of treating every survivor as a bug report — is to keep pushing until the number hits 100. We didn't, and wrote down the reason for every single one rather than a blanket "the rest are fine."

They sort into exactly three buckets:

**Three are provably impossible, not merely difficult.** One is `System.exit()` in a CLI's `main` method: it terminates the JVM, and the API that older Java versions used to intercept that call from inside a test — `SecurityManager` — was removed in a recent JDK. There is no supported way to observe this from the same process anymore, at any cost. The other two are `verify()` methods where `javap -c -l` — reading the actual compiled bytecode — shows the "mutated" instruction and the original instruction are the identical `iconst_0` / `ireturn` pair. The mutation tool rewrote a `return false` into `return false`. No test written in any style distinguishes a program from itself.

**Ten can only be killed by making the code worse.** A verifiable-secret-sharing implementation's reconstruction arithmetic produces byte-identical output on both sides of a boundary mutant — provably, with the algebra spelled out — and the only way to make that difference observable would be to have the method leak which internal code path it took, adding an information side-channel to a security-sensitive method purely to satisfy a testing tool. A key-encapsulation command's success path is unreachable because the underlying algorithm's correctness property *guarantees* two independently derived shared secrets are equal; making the failure path reachable would mean deliberately breaking that guarantee. A `private` boundary check would need its visibility widened for no reason a real caller has, trading encapsulation for a percentage point. And one survivor guards an explicit resource-cleanup call — removing it doesn't just create an equivalent mutant, it creates an actual file-descriptor leak, so the "fix" a mutation score would reward is not a fix at all. We didn't apply any of these.

**Two are dead code for a reason that has nothing to do with mutation testing.** Fall-through `return` statements after every preceding attempt in a chain already returns on success — genuinely unreachable given the current logic, not merely unobservable through a black-box test. Restructuring them away would be tidying, not testing, and doesn't belong in the same commit as the rest of this work.

None of the fifteen is unfinished. Each one is either physically impossible to kill, or killable only by trading away a real property — resource safety, encapsulation, an algorithm's own correctness guarantee, or the absence of a side channel — for a cosmetic improvement to a dashboard.

## The actual takeaway

A mutation score isn't a target. It's a question generator. Every surviving mutant is really asking: *why does nothing here care if this breaks?* Sometimes the honest answer is "because a test is missing," and you go write it, and — as happened nine times in this project — you occasionally find a live production bug on the way, some of them with an existing test that had quietly agreed the bug was the specification. Sometimes the honest answer is "because this line is dead weight," and the fix is a deletion, not a test. And sometimes — after you've genuinely tried to disprove your own reasoning, not just restated it — the honest answer is "because killing this would require making the software worse." At that point the correct move isn't to keep pushing the number. It's to write the reason down where the next person can check it, and stop.

Full numbers, every surviving mutant, and the source-level argument for each one are public: [`docs/TESTING.md`](../TESTING.md) and [`docs/COVERAGE_EXCEPTIONS.md`](../COVERAGE_EXCEPTIONS.md) in the [`mystic-crypt`](https://github.com/astrapi69/mystic-crypt) repository.
