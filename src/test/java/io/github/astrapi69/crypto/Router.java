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
package io.github.astrapi69.crypto;

/**
 * The class {@link Router} holds data for a router
 */
public class Router
{

	/** The access type. */
	private String accessType;
	/** The model. */
	private String model;
	/** The notes. */
	private String notes;
	/** The permissions. */
	private String permissions;
	/** The pw. */
	private String pw;
	/** The username. */
	private String username;
	/** The vendor. */
	private String vendor;
	/** The version. */
	private String version;

	Router(String accessType, String model, String notes, String permissions, String pw,
		String username, String vendor, String version)
	{
		this.accessType = accessType;
		this.model = model;
		this.notes = notes;
		this.permissions = permissions;
		this.pw = pw;
		this.username = username;
		this.vendor = vendor;
		this.version = version;
	}

	public static RouterBuilder builder()
	{
		return new RouterBuilder();
	}

	protected boolean canEqual(final Object other)
	{
		return other instanceof Router;
	}

	@Override
	public boolean equals(final Object o)
	{
		if (o == this)
			return true;
		if (!(o instanceof Router))
			return false;
		final Router other = (Router)o;
		if (!other.canEqual(this))
			return false;
		final Object this$accessType = this.getAccessType();
		final Object other$accessType = other.getAccessType();
		if (this$accessType == null
			? other$accessType != null
			: !this$accessType.equals(other$accessType))
			return false;
		final Object this$model = this.getModel();
		final Object other$model = other.getModel();
		if (this$model == null ? other$model != null : !this$model.equals(other$model))
			return false;
		final Object this$notes = this.getNotes();
		final Object other$notes = other.getNotes();
		if (this$notes == null ? other$notes != null : !this$notes.equals(other$notes))
			return false;
		final Object this$permissions = this.getPermissions();
		final Object other$permissions = other.getPermissions();
		if (this$permissions == null
			? other$permissions != null
			: !this$permissions.equals(other$permissions))
			return false;
		final Object this$pw = this.getPw();
		final Object other$pw = other.getPw();
		if (this$pw == null ? other$pw != null : !this$pw.equals(other$pw))
			return false;
		final Object this$username = this.getUsername();
		final Object other$username = other.getUsername();
		if (this$username == null ? other$username != null : !this$username.equals(other$username))
			return false;
		final Object this$vendor = this.getVendor();
		final Object other$vendor = other.getVendor();
		if (this$vendor == null ? other$vendor != null : !this$vendor.equals(other$vendor))
			return false;
		final Object this$version = this.getVersion();
		final Object other$version = other.getVersion();
		if (this$version == null ? other$version != null : !this$version.equals(other$version))
			return false;
		return true;
	}

	public String getAccessType()
	{
		return this.accessType;
	}

	public void setAccessType(String accessType)
	{
		this.accessType = accessType;
	}

	public String getModel()
	{
		return this.model;
	}

	public void setModel(String model)
	{
		this.model = model;
	}

	public String getNotes()
	{
		return this.notes;
	}

	public void setNotes(String notes)
	{
		this.notes = notes;
	}

	public String getPermissions()
	{
		return this.permissions;
	}

	public void setPermissions(String permissions)
	{
		this.permissions = permissions;
	}

	public String getPw()
	{
		return this.pw;
	}

	public void setPw(String pw)
	{
		this.pw = pw;
	}

	public String getUsername()
	{
		return this.username;
	}

	public void setUsername(String username)
	{
		this.username = username;
	}

	public String getVendor()
	{
		return this.vendor;
	}

	public void setVendor(String vendor)
	{
		this.vendor = vendor;
	}

	public String getVersion()
	{
		return this.version;
	}

	public void setVersion(String version)
	{
		this.version = version;
	}

	@Override
	public int hashCode()
	{
		final int PRIME = 59;
		int result = 1;
		final Object $accessType = this.getAccessType();
		result = result * PRIME + ($accessType == null ? 43 : $accessType.hashCode());
		final Object $model = this.getModel();
		result = result * PRIME + ($model == null ? 43 : $model.hashCode());
		final Object $notes = this.getNotes();
		result = result * PRIME + ($notes == null ? 43 : $notes.hashCode());
		final Object $permissions = this.getPermissions();
		result = result * PRIME + ($permissions == null ? 43 : $permissions.hashCode());
		final Object $pw = this.getPw();
		result = result * PRIME + ($pw == null ? 43 : $pw.hashCode());
		final Object $username = this.getUsername();
		result = result * PRIME + ($username == null ? 43 : $username.hashCode());
		final Object $vendor = this.getVendor();
		result = result * PRIME + ($vendor == null ? 43 : $vendor.hashCode());
		final Object $version = this.getVersion();
		result = result * PRIME + ($version == null ? 43 : $version.hashCode());
		return result;
	}

	public RouterBuilder toBuilder()
	{
		return new RouterBuilder().accessType(this.accessType).model(this.model).notes(this.notes)
			.permissions(this.permissions).pw(this.pw).username(this.username).vendor(this.vendor)
			.version(this.version);
	}

	/**
	 * To line.
	 *
	 * @return the string
	 */
	public String toLine()
	{
		final StringBuilder sb = new StringBuilder();
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

	@Override
	public String toString()
	{
		return "Router(accessType=" + this.getAccessType() + ", model=" + this.getModel()
			+ ", notes=" + this.getNotes() + ", permissions=" + this.getPermissions() + ", pw="
			+ this.getPw() + ", username=" + this.getUsername() + ", vendor=" + this.getVendor()
			+ ", version=" + this.getVersion() + ")";
	}

	public static class RouterBuilder
	{
		private String accessType;
		private String model;
		private String notes;
		private String permissions;
		private String pw;
		private String username;
		private String vendor;
		private String version;

		RouterBuilder()
		{
		}

		public Router.RouterBuilder accessType(String accessType)
		{
			this.accessType = accessType;
			return this;
		}

		public Router build()
		{
			return new Router(accessType, model, notes, permissions, pw, username, vendor, version);
		}

		public Router.RouterBuilder model(String model)
		{
			this.model = model;
			return this;
		}

		public Router.RouterBuilder notes(String notes)
		{
			this.notes = notes;
			return this;
		}

		public Router.RouterBuilder permissions(String permissions)
		{
			this.permissions = permissions;
			return this;
		}

		public Router.RouterBuilder pw(String pw)
		{
			this.pw = pw;
			return this;
		}

		@Override
		public String toString()
		{
			return "Router.RouterBuilder(accessType=" + this.accessType + ", model=" + this.model
				+ ", notes=" + this.notes + ", permissions=" + this.permissions + ", pw=" + this.pw
				+ ", username=" + this.username + ", vendor=" + this.vendor + ", version="
				+ this.version + ")";
		}

		public Router.RouterBuilder username(String username)
		{
			this.username = username;
			return this;
		}

		public Router.RouterBuilder vendor(String vendor)
		{
			this.vendor = vendor;
			return this;
		}

		public Router.RouterBuilder version(String version)
		{
			this.version = version;
			return this;
		}
	}
}
