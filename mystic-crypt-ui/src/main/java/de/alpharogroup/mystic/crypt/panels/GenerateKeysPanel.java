package de.alpharogroup.mystic.crypt.panels;

import java.awt.event.ActionEvent;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JComboBox;

import org.apache.commons.codec.DecoderException;
import org.jdesktop.swingx.JXPanel;

import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.algorithm.KeyPairWithModeAndPaddingAlgorithm;
import de.alpharogroup.crypto.factories.KeyPairFactory;
import de.alpharogroup.crypto.key.KeySize;
import de.alpharogroup.crypto.key.PrivateKeyExtensions;
import de.alpharogroup.crypto.key.PrivateKeyHexDecryptor;
import de.alpharogroup.crypto.key.PublicKeyExtensions;
import de.alpharogroup.crypto.key.PublicKeyHexEncryptor;
import de.alpharogroup.crypto.model.CryptModel;
import lombok.Getter;
import net.miginfocom.swing.MigLayout;

@Getter
public class GenerateKeysPanel extends JXPanel
{

	private static final long serialVersionUID = 1L;

	private CryptographyPanel cryptographyPanel;

	private EnDecryptPanel enDecryptPanel;

	private PrivateKey privateKey;
	private PublicKey publicKey;

	private PublicKeyHexEncryptor encryptor;

	private PrivateKeyHexDecryptor decryptor;

	public GenerateKeysPanel()
	{
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
	 * Initialize components.
	 */
	protected void initializeComponents()
	{
		cryptographyPanel = new CryptographyPanel(){

			private static final long serialVersionUID = 1L;
			@Override
			protected void onChangeKeySize(final ActionEvent actionEvent)
			{
				GenerateKeysPanel.this.onChangeKeySize(actionEvent);
			}

			@Override
			protected void onClear(final ActionEvent actionEvent)
			{
				GenerateKeysPanel.this.onClear(actionEvent);
			}

			@Override
			protected void onGenerate(final ActionEvent actionEvent)
			{
				GenerateKeysPanel.this.onGenerate(actionEvent);
			}
			@Override
			protected void onSavePrivateKey(final ActionEvent actionEvent)
			{
				GenerateKeysPanel.this.onSavePrivateKey(actionEvent);
			}
			@Override
			protected void onSavePublicKey(final ActionEvent actionEvent)
			{
				GenerateKeysPanel.this.onSavePublicKey(actionEvent);
			}
		};
		enDecryptPanel = new EnDecryptPanel(){
			@Override
			protected void onDecrypt(final ActionEvent actionEvent)
			{
				GenerateKeysPanel.this.onDecrypt(actionEvent);
			}
			@Override
			protected void onEncrypt(final ActionEvent actionEvent)
			{
				GenerateKeysPanel.this.onEncrypt(actionEvent);
			}
		};
	}

	/**
	 * Initialize layout.
	 */
	protected void initializeLayout()
	{
		setLayout(new MigLayout());
		add(cryptographyPanel,   "wrap");
		add(enDecryptPanel);
	}

	// callbacks

	/**
	 * Callback method that can be overwritten to provide specific action for the on change key
	 * size.
	 *
	 * @param actionEvent
	 *            the action event
	 */
	@SuppressWarnings("unchecked")
	protected void onChangeKeySize(final ActionEvent actionEvent)
	{
		final JComboBox<String> cb = (JComboBox<String>)actionEvent.getSource();
		final Object selected = cb.getSelectedItem();
		System.out.println("selected item:" + selected);
	}

	/**
	 * Callback method that can be overwritten to provide specific action for the on save public
	 * key.
	 *
	 * @param actionEvent
	 *            the action event
	 */
	protected void onSavePublicKey(final ActionEvent actionEvent)
	{
		System.out.println("onSavePublicKey");
	}

	/**
	 * Callback method that can be overwritten to provide specific action for the on save private
	 * key.
	 *
	 * @param actionEvent
	 *            the action event
	 */
	protected void onSavePrivateKey(final ActionEvent actionEvent)
	{
		System.out.println("onSavePrivateKey");
	}

	/**
	 * Callback method that can be overwritten to provide specific action for the on clear.
	 *
	 * @param actionEvent
	 *            the action event
	 */
	protected void onClear(final ActionEvent actionEvent)
	{
		System.out.println("onClear");
	}

	/**
	 * Callback method that can be overwritten to provide specific action for the on generate.
	 *
	 * @param actionEvent
	 *            the action event
	 */
	protected void onGenerate(final ActionEvent actionEvent)
	{
		System.out.println("onGenerate");
		final KeySize selected = (KeySize)getCryptographyPanel().getCmbKeySize().getSelectedItem();
		try
		{
			final KeyPair keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, selected.getKeySize());

			privateKey = keyPair.getPrivate();
			publicKey = keyPair.getPublic();

			final String privateKeyFormat = PrivateKeyExtensions.toPemFormat(privateKey);

			final String publicKeyFormat = PublicKeyExtensions.toPemFormat(publicKey);

			getCryptographyPanel().getTxtPrivateKey().setText(privateKeyFormat);
			getCryptographyPanel().getTxtPublicKey().setText(publicKeyFormat);
		}
		catch (final NoSuchAlgorithmException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (final IOException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}


	/**
	 * Callback method that can be overwritten to provide specific action for the on decrypt.
	 *
	 * @param actionEvent the action event
	 */
	protected void onDecrypt(final ActionEvent actionEvent)
	{
		System.out.println("onDecrypt");
		decryptor = new PrivateKeyHexDecryptor(privateKey);
		try
		{
			final String decryted = decryptor.decrypt(getEnDecryptPanel().getTxtEncrypted().getText());
			getEnDecryptPanel().getTxtToEncrypt().setText(decryted);
			getEnDecryptPanel().getTxtEncrypted().setText("");
		}
		catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
			| IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException
			| InvalidAlgorithmParameterException | DecoderException | IOException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}


	/**
	 * Callback method that can be overwritten to provide specific action for the on encrypt.
	 *
	 * @param actionEvent the action event
	 */
	protected void onEncrypt(final ActionEvent actionEvent)
	{
		System.out.println("onEncrypt");

		final CryptModel<Cipher, PublicKey> encryptModel = CryptModel.<Cipher, PublicKey> builder()
			.key(publicKey)
			.algorithm(KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA256AndMGF1Padding)
			.build();

		try
		{
			encryptor = new PublicKeyHexEncryptor(publicKey);

			getEnDecryptPanel().getTxtEncrypted().setText(encryptor.encrypt(getEnDecryptPanel().getTxtToEncrypt().getText()));
			getEnDecryptPanel().getTxtToEncrypt().setText("");
		}
		catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException
			| NoSuchPaddingException | UnsupportedEncodingException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (final IllegalBlockSizeException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (final BadPaddingException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (final IOException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
