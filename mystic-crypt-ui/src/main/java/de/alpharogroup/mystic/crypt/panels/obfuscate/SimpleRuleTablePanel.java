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
package de.alpharogroup.mystic.crypt.panels.obfuscate;

import javax.swing.GroupLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.LayoutStyle;

import de.alpharogroup.collections.pairs.KeyValuePair;
import de.alpharogroup.swing.GenericJTable;
import lombok.Getter;
import lombok.NonNull;


@Getter
public class SimpleRuleTablePanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private JLabel lblKeyRules;
    private JScrollPane scpKeyRules;
    private GenericJTable<KeyValuePair<String, String>> tblKeyRules;
    private final ObfuscationModel model;

    public SimpleRuleTablePanel(@NonNull final ObfuscationModel model) {
    	this.model = model;
    	initialize();
    }

	/**
	 * Initialize Panel.
	 */
	protected void initialize()
	{
		initializeComponents();
		initializeLayout();
	}

	/**
	 * Initialize layout.
	 */
	protected void initializeLayout()
	{
		initializeGroupLayout();
	}

	protected void initializeComponents() {

        scpKeyRules = new JScrollPane();
        tblKeyRules = new GenericJTable<>(this.model.getKeyRulesTableModel());
        lblKeyRules = new JLabel();

        scpKeyRules.setViewportView(tblKeyRules);

        lblKeyRules.setText("Table of key rules for obfuscate");
    }

    protected void initializeGroupLayout()
	{
        final GroupLayout layout = new GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(28, 28, 28)
                .addComponent(lblKeyRules)
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(scpKeyRules, GroupLayout.DEFAULT_SIZE, 1231, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(31, Short.MAX_VALUE)
                .addComponent(lblKeyRules)
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(scpKeyRules, GroupLayout.PREFERRED_SIZE, 189, GroupLayout.PREFERRED_SIZE)
                .addGap(32, 32, 32))
        );
	}

}
