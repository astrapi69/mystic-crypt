/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.random.api;

/**
 * The interface {@link HumanDataGenerator} for generate random names, gender, jobs and other human data.
 */
public interface HumanDataGenerator {

    /**
     * New first name.
     *
     * @param female the female
     * @return the string
     */
    String newFirstName(boolean female);

    /**
     * New family name.
     *
     * @param female the female
     * @return the string
     */
    String newFamilyName(boolean female);

    /**
     * New gender.
     *
     * @return the string
     */
    String newGender();

    /**
     * New job name.
     *
     * @return the string
     */
    String newJobName();

    /**
     * New language.
     *
     * @return the string
     */
    String newLanguage();

    /**
     * New title.
     *
     * @return the string
     */
    String newTitle();

    /**
     * New nickname.
     *
     * @return the string
     */
    String newNickname();

    /**
     * New username.
     *
     * @return the string
     */
    String newUsername();
}
