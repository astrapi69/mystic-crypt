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
package de.alpharogroup.mystic.crypt.actions;

import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import javax.swing.AbstractAction;

import org.springframework.context.ApplicationContext;
import org.springframework.core.io.Resource;

import de.alpharogroup.io.StreamExtensions;
import de.alpharogroup.mystic.crypt.help.HelpJFrame;
import de.alpharogroup.mystic.crypt.spring.SpringApplicationContext;

/**
 * The Class ShowLicenseFrameAction.
 */
public class ShowLicenseFrameAction extends AbstractAction {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/** The Constant LICENCE_TITLE. */
	private static final String LICENCE_TITLE = "Licence";

	/**
	 * Instantiates a new show license frame action.
	 *
	 * @param name
	 *            the name
	 */
	public ShowLicenseFrameAction(final String name) {
		super(name);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void actionPerformed(final ActionEvent e) {
		final String licence = loadLicense();
		final HelpJFrame frame = new HelpJFrame(LICENCE_TITLE, licence);
		frame.setVisible(true);
	}

	/**
	 * Load license.
	 *
	 * @return the string
	 */
	private String loadLicense() {

		final ApplicationContext ctx = SpringApplicationContext.getInstance().getApplicationContext();
		final Resource resource = ctx.getResource("classpath:LICENSE.txt");
		InputStream is = null;
		final StringBuffer license = new StringBuffer();
		try {
			String thisLine;
			is = resource.getInputStream();
			final BufferedReader br = new BufferedReader(new InputStreamReader(is));
			while ((thisLine = br.readLine()) != null) {
				license.append(thisLine + "\n");
			}
		} catch (final IOException ex) {
			ex.printStackTrace();
		} finally {
			try {
				StreamExtensions.close(is);
			} catch (final IOException e) {
				e.printStackTrace();
			}
		}
		return license.toString();
	}

}