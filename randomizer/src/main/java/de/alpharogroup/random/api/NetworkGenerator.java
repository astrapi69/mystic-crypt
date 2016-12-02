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
 * The interface {@link NetworkGenerator}  for generate random data like email, file names, urls, domain names and other network elements.
 */
public interface NetworkGenerator {

    /**
     * New email.
     *
     * @return the string
     */
    String newEmail();

    /**
     * New filename.
     *
     * @return the string
     */
    String newFilename();

    /**
     * New url.
     *
     * @return the string
     */
    String newUrl();

    /**
     * New domainname.
     *
     * @return the string
     */
    String newDomainname();

    /**
     * New ip address 4.
     *
     * @return the string
     */
    String newIpAddress4();

    /**
     * New ip address 6.
     *
     * @return the string
     */
    String newIpAddress6();

    /**
     * New mac address.
     *
     * @return the string
     */
    String newMacAddress();

    /**
     * New sha 1.
     *
     * @return the string
     */
    String newSha1();

    /**
     * New sha 256.
     *
     * @return the string
     */
    String newSha256();

    /**
     * New mime type.
     *
     * @return the string
     */
    String newMimeType();
}
