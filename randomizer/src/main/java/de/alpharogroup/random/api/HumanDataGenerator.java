/**
 * Copyright (C) 2015 Asterios Raptis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
