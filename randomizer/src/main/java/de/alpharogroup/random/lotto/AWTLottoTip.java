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
package de.alpharogroup.random.lotto;

import java.awt.Button;
import java.awt.Font;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Label;
import java.awt.TextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.Random;

/**
 * The class {@link AWTLottoTip} is a simple gui for generate lotto numbers. Try it by execute this
 * class.
 */
public class AWTLottoTip extends Frame implements ActionListener
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = -7391368005948229039L;

	/**
	 * The main method.
	 *
	 * @param args
	 *            the arguments
	 */
	public static void main(final String args[])
	{
		final AWTLottoTip lotto = new AWTLottoTip();
		lotto.setVisible(true);
	}

	/** The lbl llucky number one. */
	private Label lblLluckyNumberOne;

	/** The lbl lucky number two. */
	private Label lblLuckyNumberTwo;

	/** The lbl lucky number three. */
	private Label lblLuckyNumberThree;

	/** The lbl lucky number four. */
	private Label lblLuckyNumberFour;

	/** The lbl lucky number five. */
	private Label lblLuckyNumberFive;

	/** The lbl lucky number six. */
	private Label lblLuckyNumberSix;

	/** The lbl last but not least lucky number. */
	private Label lblLastButNotLeastLuckyNumber;

	/** The txt llucky number one. */
	private TextField txtLluckyNumberOne;

	/** The txt lucky number two. */
	private TextField txtLuckyNumberTwo;

	/** The txt lucky number three. */
	private TextField txtLuckyNumberThree;

	/** The txt lucky number four. */
	private TextField txtLuckyNumberFour;

	/** The txt lucky number five. */
	private TextField txtLuckyNumberFive;

	/** The txt lucky number six. */
	private TextField txtLuckyNumberSix;

	/** The txt last but not least lucky number. */
	private TextField txtLastButNotLeastLuckyNumber;

	/** The btn generate lucky numbers. */
	private Button btnGenerateLuckyNumbers;

	/** The gbc. */
	private GridBagConstraints gbc;

	/**
	 * Instantiates a new {@link AWTLottoTip} object.
	 */
	public AWTLottoTip()
	{

		this.initComponents();

		this.initLayout();

		this.addWindowListener(new WindowAdapter()
		{

			/**
			 * (non-Javadoc)
			 */
			@Override
			public void windowClosed(final WindowEvent we)
			{
				System.exit(0);
			}

			/**
			 * (non-Javadoc)
			 */
			@Override
			public void windowClosing(final WindowEvent we)
			{
				System.exit(0);
			}

		});

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void actionPerformed(final ActionEvent ae)
	{
		if (ae.getActionCommand().equals("Generiere Glueckszahlen"))
		{

			final BitSet b = new BitSet();
			final Random r = new Random();
			final List<Integer> v = new ArrayList<>();
			final List<TextField> vt = new ArrayList<>();

			vt.add(0, this.txtLluckyNumberOne);
			vt.add(1, this.txtLuckyNumberTwo);
			vt.add(2, this.txtLuckyNumberThree);
			vt.add(3, this.txtLuckyNumberFour);
			vt.add(4, this.txtLuckyNumberFive);
			vt.add(5, this.txtLuckyNumberSix);
			vt.add(6, this.txtLastButNotLeastLuckyNumber);

			int cnt = 0;

			while (cnt < 7)
			{
				final int num = 1 + Math.abs(r.nextInt()) % 49;
				if (!b.get(num))
				{
					b.set(num);
					++cnt;
				}
			}
			for (int i = 1; i <= 49; ++i)
			{
				if (b.get(i))
				{
					final Integer ob = i;
					v.add(ob);
				}
			}
			final int num = Math.abs(r.nextInt()) % 7;
			final Integer zuz = v.get(num);
			v.remove(num);
			v.add(zuz);
			for (int z = 0; z < 7; ++z)
			{
				final TextField t = vt.get(z);
				t.setText("       " + v.get(z).toString());
			}
		}
	}

	/**
	 * Inits the components.
	 */
	private void initComponents()
	{
		this.btnGenerateLuckyNumbers = new Button("Generiere Glueckszahlen");
		this.btnGenerateLuckyNumbers.setFont(new Font("Times", Font.BOLD, 14));
		this.btnGenerateLuckyNumbers.addActionListener(this);

		this.lblLluckyNumberOne = new Label("1.Lottozahl");
		this.lblLuckyNumberTwo = new Label("2.Lottozahl");
		this.lblLuckyNumberThree = new Label("3.Lottozahl");
		this.lblLuckyNumberFour = new Label("4.Lottozahl");
		this.lblLuckyNumberFive = new Label("5.Lottozahl");
		this.lblLuckyNumberSix = new Label("6.Lottozahl");
		this.lblLastButNotLeastLuckyNumber = new Label("Zusatzszahl");

		this.txtLluckyNumberOne = new TextField(6);
		this.txtLuckyNumberTwo = new TextField(6);
		this.txtLuckyNumberThree = new TextField(6);
		this.txtLuckyNumberFour = new TextField(6);
		this.txtLuckyNumberFive = new TextField(6);
		this.txtLuckyNumberSix = new TextField(6);
		this.txtLastButNotLeastLuckyNumber = new TextField(6);
	}

	/**
	 * Inits the layout.
	 */
	private void initLayout()
	{
		final GridBagLayout gbl = new GridBagLayout();
		this.setLayout(gbl);

		final Insets i = new Insets(0, 0, 0, 0);

		this.gbc = new GridBagConstraints(0, 0, 1, 1, 0.0, 0.0, GridBagConstraints.EAST,
			GridBagConstraints.NONE, i, 0, 0);
		gbl.setConstraints(this.lblLluckyNumberOne, this.gbc);

		this.gbc = new GridBagConstraints(1, 0, 1, 1, 0.0, 0.0, GridBagConstraints.EAST,
			GridBagConstraints.NONE, i, 0, 0);
		gbl.setConstraints(this.lblLuckyNumberTwo, this.gbc);

		this.gbc = new GridBagConstraints(2, 0, 1, 1, 0.0, 0.0, GridBagConstraints.EAST,
			GridBagConstraints.NONE, i, 0, 0);
		gbl.setConstraints(this.lblLuckyNumberThree, this.gbc);

		this.gbc = new GridBagConstraints(3, 0, 1, 1, 0.0, 0.0, GridBagConstraints.EAST,
			GridBagConstraints.NONE, i, 0, 0);
		gbl.setConstraints(this.lblLuckyNumberFour, this.gbc);

		this.gbc = new GridBagConstraints(4, 0, 1, 1, 0.0, 0.0, GridBagConstraints.EAST,
			GridBagConstraints.NONE, i, 0, 0);
		gbl.setConstraints(this.lblLuckyNumberFive, this.gbc);

		this.gbc = new GridBagConstraints(5, 0, 1, 1, 0.0, 0.0, GridBagConstraints.EAST,
			GridBagConstraints.NONE, i, 0, 0);
		gbl.setConstraints(this.lblLuckyNumberSix, this.gbc);

		this.gbc = new GridBagConstraints(6, 0, 1, 1, 0.0, 0.0, GridBagConstraints.EAST,
			GridBagConstraints.NONE, i, 0, 0);
		gbl.setConstraints(this.lblLastButNotLeastLuckyNumber, this.gbc);

		this.gbc = new GridBagConstraints(0, 1, 1, 1, 0.0, 0.0, GridBagConstraints.WEST,
			GridBagConstraints.NONE, i, 0, 0);
		gbl.setConstraints(this.txtLluckyNumberOne, this.gbc);

		this.gbc = new GridBagConstraints(1, 1, 1, 1, 0.0, 0.0, GridBagConstraints.WEST,
			GridBagConstraints.NONE, i, 0, 0);
		gbl.setConstraints(this.txtLuckyNumberTwo, this.gbc);

		this.gbc = new GridBagConstraints(2, 1, 1, 1, 0.0, 0.0, GridBagConstraints.WEST,
			GridBagConstraints.NONE, i, 0, 0);
		gbl.setConstraints(this.txtLuckyNumberThree, this.gbc);

		this.gbc = new GridBagConstraints(3, 1, 1, 1, 0.0, 0.0, GridBagConstraints.WEST,
			GridBagConstraints.NONE, i, 0, 0);
		gbl.setConstraints(this.txtLuckyNumberFour, this.gbc);

		this.gbc = new GridBagConstraints(4, 1, 1, 1, 0.0, 0.0, GridBagConstraints.WEST,
			GridBagConstraints.NONE, i, 0, 0);
		gbl.setConstraints(this.txtLuckyNumberFive, this.gbc);

		this.gbc = new GridBagConstraints(5, 1, 1, 1, 0.0, 0.0, GridBagConstraints.WEST,
			GridBagConstraints.NONE, i, 0, 0);
		gbl.setConstraints(this.txtLuckyNumberSix, this.gbc);

		this.gbc = new GridBagConstraints(6, 1, 1, 1, 0.0, 0.0, GridBagConstraints.WEST,
			GridBagConstraints.NONE, i, 0, 0);
		gbl.setConstraints(this.txtLastButNotLeastLuckyNumber, this.gbc);

		this.gbc = new GridBagConstraints(7, 1, 3, 1, 0.0, 0.0, GridBagConstraints.WEST,
			GridBagConstraints.NONE, i, 0, 0);
		gbl.setConstraints(this.btnGenerateLuckyNumbers, this.gbc);

		this.add(this.lblLluckyNumberOne);
		this.add(this.lblLuckyNumberTwo);
		this.add(this.lblLuckyNumberThree);
		this.add(this.lblLuckyNumberFour);
		this.add(this.lblLuckyNumberFive);
		this.add(this.lblLuckyNumberSix);
		this.add(this.lblLastButNotLeastLuckyNumber);
		this.add(this.txtLluckyNumberOne);
		this.add(this.txtLuckyNumberTwo);
		this.add(this.txtLuckyNumberThree);
		this.add(this.txtLuckyNumberFour);
		this.add(this.txtLuckyNumberFive);
		this.add(this.txtLuckyNumberSix);
		this.add(this.txtLastButNotLeastLuckyNumber);
		this.add(this.btnGenerateLuckyNumbers);

		this.setBounds(100, 100, 800, 120);
	}

}
