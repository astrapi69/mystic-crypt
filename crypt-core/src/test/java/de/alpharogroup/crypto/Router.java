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
