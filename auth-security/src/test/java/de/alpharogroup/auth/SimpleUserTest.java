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
package de.alpharogroup.auth;

import java.io.File;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.testng.AssertJUnit;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.auth.interfaces.Permission;
import de.alpharogroup.auth.interfaces.Role;
import de.alpharogroup.auth.interfaces.User;
import de.alpharogroup.file.csv.CsvFileExtensions;
import de.alpharogroup.file.search.PathFinder;

/**
 * Test class for the class {@link SimpleUser}.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public class SimpleUserTest
{

	/** The testuser. */
	User<Permission, Role<Permission>> testuser;

	/** The accessrights1. */
	List<String> accessrights1;

	/** The accessrights2. */
	List<String> accessrights2;

	/** The testrole. */
	Role<Permission> testrole;

	/** The testrole2. */
	Role<Permission> testrole2;

	/** The ars. */
	Set<Permission> ars;

	/** The ars2. */
	Set<Permission> ars2;

	/**
	 * Sets up method will be invoked before every unit test method in this class.
	 *
	 * @throws Exception
	 *             the exception
	 */
	@BeforeMethod
	protected void setUp() throws Exception
	{
		final File srctestresDir = PathFinder.getSrcTestResourcesDir();
		final File resources = new File(srctestresDir, "resources");
		final File userrole = new File(resources, "userrole");
		final File directorrole = new File(resources, "directorrole");
		this.accessrights1 = CsvFileExtensions.readFileToList(userrole);
		this.accessrights2 = CsvFileExtensions.readFileToList(directorrole);
		this.ars = new HashSet<>(this.accessrights1.size());
		this.ars2 = new HashSet<>(this.accessrights2.size());
		for (final String object : this.accessrights1)
		{
			final Permission accrig = new SimplePermission();
			accrig.setDescription(object);
			accrig.setPermissionName(object);
			this.ars.add(accrig);
		}
		for (final String object : this.accessrights2)
		{
			final Permission accrig = new SimplePermission();
			accrig.setDescription(object);
			accrig.setPermissionName(object);
			this.ars2.add(accrig);
		}
		this.testrole = new SimpleRole();
		this.testrole.setPermissions(this.ars);

		this.testrole2 = new SimpleRole();
		this.testrole2.setDescription("");
		this.testrole2.setRolename("");
		this.testrole2.setPermissions(this.ars2);

		this.testuser = new SimpleUser();
		this.testuser.setUsername("Leonidas");
		this.testuser.addRole(this.testrole);
		this.testuser.addRole(this.testrole2);

	}

	/**
	 * Tear down method will be invoked after every unit test method in this class.
	 *
	 * @throws Exception
	 *             the exception
	 */
	@AfterMethod
	protected void tearDown() throws Exception
	{
	}

	/**
	 * Test method for {@link de.alpharogroup.auth.SimpleUser#getRoles()}.
	 */
	@Test(enabled = true)
	public void testGetRoles()
	{
		final Set<Permission> expected = new HashSet<>(this.ars);
		expected.addAll(this.ars2);
		final Set<Role<Permission>> compare = this.testuser.getRoles();
		for (final Role<Permission> role2 : compare)
		{
			final Object obj = role2;
			final Role<Permission> role = (SimpleRole)obj;
			final Set<Permission> ar = role.getPermissions();
			for (final Permission object : ar)
			{
				final boolean result = expected.contains(object);
				AssertJUnit.assertTrue("", result);
			}
		}
	}

	/**
	 * Test method for {@link de.alpharogroup.auth.SimpleUser#getUsername()}.
	 */
	@Test
	public void testGetUsername()
	{
		final String expected = "Leonidas";
		final String compare = this.testuser.getUsername();
		final boolean result = expected.equals(compare);
		AssertJUnit.assertTrue("", result);
	}

}
