/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.auth;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;
import static org.testng.AssertJUnit.assertNull;

import java.io.File;
import java.util.List;

import org.meanbean.test.BeanTester;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.auth.api.Session;
import de.alpharogroup.auth.api.SessionContext;
import de.alpharogroup.file.csv.CsvFileExtensions;
import de.alpharogroup.file.search.PathFinder;
import de.alpharogroup.random.RandomObjectsExtensions;

/**
 * The unit test class for the class {@link UserSessionContext}
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public class UserSessionContextTest
{

	/** The permissions. */
	List<String> permissions;

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
		this.permissions = CsvFileExtensions.readFileToList(userrole);
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
	 * Test method for {@link UserSessionContext#addSession(Session)}
	 */
	@Test
	public void testaddSession()
	{
		final SessionContext<String, String, String> sessionContext = UserSessionContext
			.getInstance();
		assertNotNull(sessionContext);
		UserSession session = UserSession.builder().id(RandomObjectsExtensions.newRandomId())
			.build();
		assertNotNull(session);
		sessionContext.addSession(session);
		Session<String, String> session2 = sessionContext.getSession(session.getId());
		assertEquals(session, session2);
	}

	/**
	 * Test method for {@link UserSessionContext#getInstance()}
	 */
	@Test
	public void testGetInstance()
	{
		final SessionContext<String, String, String> sessionContext = UserSessionContext
			.getInstance();
		assertNotNull(sessionContext);
	}

	/**
	 * Test method for {@link UserSessionContext#removeSession(Session)}
	 */
	@Test
	public void testRemoveSession()
	{
		final SessionContext<String, String, String> sessionContext = UserSessionContext
			.getInstance();
		assertNotNull(sessionContext);
		UserSession session = UserSession.builder().id(RandomObjectsExtensions.newRandomId())
			.build();
		assertNotNull(session);
		sessionContext.addSession(session);
		Session<String, String> session2 = sessionContext.getSession(session.getId());
		assertEquals(session, session2);
		sessionContext.removeSession(session.getId());
		session2 = sessionContext.getSession(session.getId());
		assertNull(session2);
	}
	
	/**
	 * Test method for {@link UserSessionContext}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(UserSessionContext.class);
	}

}
