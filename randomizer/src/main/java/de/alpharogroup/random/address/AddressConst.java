/**
 * Copyright (C) 2007 Asterios Raptis
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
package de.alpharogroup.random.address;

/**
 * A constant class for Addresses.
 * 
 * @version 1.0
 * @author Asterios Raptis
 */
public class AddressConst
{

	/**
	 * Constant from an Array with the countries.
	 */
	public final static String[] COUNTRIES = { "Afghanistan", "Albania", "Algeria",
			"American Samoa", "Andorra", "Angola", "Anguilla", "Antarctica", "Antigua",
			"Argentina", "Armenia", "Aruba", "Australia", "Austria", "Azerbaijan", "Bahamas",
			"Bahrain", "Bangladesh", "Barbados", "Belarus", "Belgium", "Belize", "Benin",
			"Bermuda", "Bhutan", "Bolivia", "Botswana", "Brazil", "British Indian Ocean Territory",
			"British Virgin Islands", "Brunei Darussalam", "Bulgaria", "Burkina Faso", "Burundi",
			"Cacos Islands", "Cambodia", "Cameroon", "Canada", "Cape Verde", "Cayman Islands",
			"Central African Republic", "Chad", "Chile", "China", "Christmas Island", "Colombia",
			"Comoros", "Congo", "Cook Islands", "Costa Rica", "Croatia", "Cuba", "Cyprus",
			"Czech Republic", "Denmark", "Djibouti", "Dominica", "Dominican Republic",
			"East Timor", "Ecuador", "Egypt", "El Salvador", "Equatorial Guinea", "Eritrea",
			"Estonia", "Ethiopia", "Falkland Islands", "Faroe Islands", "Fiji", "Finland",
			"France", "French Guiana", "French Polynesia", "French Southern Territory",
			"Futuna Islands", "Gabon", "Gambia", "Georgia", "Germany", "Ghana", "Gibraltar",
			"Greece", "Greenland", "Grenada", "Guadeloupe", "Guam", "Guatemala", "Guinea",
			"Guyana", "Haiti", "Heard and Mcdonald Island", "Honduras", "Hong Kong", "Hungary",
			"Iceland", "India", "Indonesia", "Iran", "Iraq", "Ireland", "Israel", "Italy",
			"Ivory Coast", "Jamaica", "Japan", "Jordan", "Kazakhstan", "Kenya", "Kiribati",
			"Korea, Democratic People's Rep", "Korea, Republic Of", "Kuwait", "Kyrgyzstan",
			"Lao People's Democratic Republ", "Latvia", "Lebanon", "Lesotho", "Liberia",
			"Libyan Arab Jamahiriya", "Lithuania", "Luxembourg", "Macau", "Macedonia",
			"Madagascar", "Malawi", "Malaysia", "Maldives", "Mali", "Malta", "Marshall Islands",
			"Martinique", "Mauritania", "Mauritius", "Mayotte", "Mexico", "Micronesia",
			"Moldova, Republic Of", "Monaco", "Mongolia", "Montserrat", "Morocco", "Mozambique",
			"Myanmar", "Namibia", "Nauru", "Nepal", "Netherlands", "Netherlands Antilles",
			"New Caledonia", "New Zealand", "Nicaragua", "Niger", "Nigeria", "Niue",
			"Norfolk Island", "Northern Mariana Islands", "Norway", "Oman", "Pakistan", "Palau",
			"Panama", "Papua New Guinea", "Paraguay", "Peru", "Philippines", "Poland", "Portugal",
			"Puerto Rico", "Qatar", "Reunion", "Romania", "Russian Federation", "Rwanda",
			"Saint Kitts", "Samoa", "San Marino", "Sao Tome", "Saudi Arabia", "Senegal",
			"Seychelles", "Sierra Leone", "Singapore", "Slovakia", "Slovenia", "Solomon Islands",
			"Somalia", "South Africa", "South Georgia", "Spain", "Sri Lanka", "St. Helena",
			"St. Lucia", "St. Pierre", "St. Vincent and Grenadines", "Sudan", "Suriname",
			"Svalbard and Jan Mayen Island", "Swaziland", "Sweden", "Switzerland",
			"Syrian Arab Republic", "Taiwan", "Tajikistan", "Tanzania", "Thailand", "Togo",
			"Tokelau", "Tonga", "Trinidad", "Tunisia", "Turkey", "Turkmenistan", "Tuvalu",
			"Uganda", "Ukraine", "United Arab Emirates", "United Kingdom",
			"United States of America", "Uruguay", "Uzbekistan", "Vanuatu", "Vatican City State",
			"Venezuela", "Viet Nam", "Western Sahara", "Yemen", "Zaire", "Zambia", "Zimbabwe" };

	/**
	 * Constant from an Array with cities.
	 */
	public final static String[] CITIES = { "Abidjan", "Abu", "Acapulco", "Aguascalientes",
			"Akron", "Alexandria", "Allentown", "Amarillo", "Amsterdam", "Anchorage", "Appleton",
			"Aruba", "Asheville", "Athens", "Atlanta", "Augusta", "Austin", "Baltimore", "Bamako",
			"Bangor", "Barbados", "Barcelona", "Basel", "Baton", "Beaumont", "Berlin", "Bermuda",
			"Birmingham", "Boise", "Bologna", "Boston", "Brussels", "Bucharest", "Budapest",
			"Buffalo", "Cairo", "Calgary", "Cancun", "Cape", "Caracas", "Casper", "Cedar",
			"Charleston", "Charlotte", "Charlottesville", "Chicago", "Chihuahua", "Cincinnati",
			"Cleveland", "Colorado", "Columbia", "Columbus", "Conakry", "Copenhagen", "Corpus",
			"Dakar", "Dallas", "Dayton", "Daytona", "Denver", "Detroit", "Dubai", "Dublin",
			"Durango", "Durban", "Dusseldorf", "East", "Evansville", "Fairbanks", "Fayetteville",
			"Florence", "Fort", "Fortaleza", "Frankfurt", "Fresno", "Gainesville", "Geneva",
			"George", "Glasgow", "Gothenburg", "Greensboro", "Greenville", "Grenada",
			"Guadalajara", "Guangzhou", "Guatemala", "Guaymas", "Gulfport", "Gunnison", "Hamburg",
			"Harrisburg", "Hartford", "Hermosillo", "Honolulu", "Houston", "Huntington",
			"Huntsville", "Idaho", "Indianapolis", "Istanbul", "Jackson", "Jacksonville",
			"Johannesburg", "Kalamazoo", "Kalispell", "Kansas", "Kiev", "Las Vegas", "Lexington",
			"Lima", "Lisbon", "Little", "London", "Louisville", "Lubbock", "Lynchburg", "Lyon",
			"Macon", "Madison", "Madrid", "Manchester", "Melbourne", "Memphis", "Mexico City",
			"Miami", "Milan", "Milwaukee", "Minneapolis", "Monroe", "Monterrey", "Montgomery",
			"Montreal", "Moscow", "Munich", "Nashville", "Nassau", "Newcastle", "Norfolk",
			"Oakland", "Oklahoma", "Omaha", "Ontario", "Orange", "Orlando", "Paris",
			"Philadelphia", "Phoenix", "Pittsburgh", "Pocatello", "Portland", "Prague", "Richmond",
			"Rio", "Rochester", "Rome", "Sacramento", "Santiago", "Sao Paolo", "Sarasota",
			"Savannah", "Seattle", "Shannon", "Shreveport", "Stockholm", "Stuttgart", "Tokyo",
			"Toledo", "Toronto", "Torreon", "Toulouse", "Tucson", "Tulsa", "Turin", "Vancouver",
			"Venice", "Veracruz", "Vienna", "Villahermosa", "Warsaw", "Washington", "Wichita",
			"Worcester", "Zurich" };

}
