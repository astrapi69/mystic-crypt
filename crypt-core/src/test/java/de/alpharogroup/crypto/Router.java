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
package de.alpharogroup.crypto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Router {
	private String vendor;
	private String model;
	private String version;
	private String accessType;
	private String username;
	private String pw;
	private String permissions;
	private String notes;

	public String toLine() {
		StringBuilder sb = new StringBuilder();
		sb.append(this.vendor);
		sb.append(";");
		sb.append(this.model);
		sb.append(";");
		sb.append(this.version);
		sb.append(";");
		sb.append(this.accessType);
		sb.append(";");
		sb.append(this.username);
		sb.append(";");
		sb.append(this.pw);
		sb.append(";");
		sb.append(this.permissions);
		sb.append(";");
		sb.append(this.notes);
		sb.append(";");
		return sb.toString();
	}
}
