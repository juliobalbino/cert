import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class Main2 {

	public static void main(String[] args) {

		assinarXML("C:\\Users\\JulioDev\\Downloads\\teste.xml");
	}

	public static void assinarXML(String arquivoXML) {
		String tokenCaminho;
		String tokenNomeAmigavel;
		String tokenSenha;

		try {
			// CERTIFICADO DIGITAL EM ARQUIVO
			tokenCaminho = "C://Users//JulioDev//Downloads//40475821823_000001010394903.pfx";
			tokenNomeAmigavel = "key";
			tokenSenha = "Julio65612556.";

			// CERTIFICADO DIGITAL EM SMARTCARD
			// tokenCaminho = "";
			// tokenNomeAmigavel = "";
			// tokenSenha = "";

			// CORRIGI BUG DO TRANSFORM
			System.setProperty("javax.xml.transform.TransformerFactory",
					"com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl");

			// Create a DOM XMLSignatureFactory that will be used to generate the
			// enveloped signature.
			XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

			// Create a Reference to the enveloped document (in this case, you
			// are signing the whole document, so a URI of "" signifies that,
			// and also specify the SHA1 digest algorithm and the ENVELOPED Transform.
			Reference ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA1, null),
					Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
					null, null);

			// Create the SignedInfo.
			SignedInfo si = fac.newSignedInfo(
					fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
					fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));

			// Load the KeyStore and get the signing key and certificate.
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(new FileInputStream(tokenCaminho), tokenSenha.toCharArray());
			KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(tokenNomeAmigavel,
					new KeyStore.PasswordProtection(tokenSenha.toCharArray()));
			
			X509Certificate cert = (X509Certificate) keyEntry.getCertificate();

			// Create the KeyInfo containing the X509Data.
			KeyInfoFactory kif = fac.getKeyInfoFactory();
			List x509Content = new ArrayList();
			x509Content.add(cert.getSubjectX500Principal().getName());
			x509Content.add(cert);
			X509Data xd = kif.newX509Data(x509Content);
			KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

			// Instantiate the document to be signed.
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(arquivoXML));

			// Create a DOMSignContext and specify the RSA PrivateKey and
			// location of the resulting XMLSignature's parent element.
			DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement());

			// Create the XMLSignature, but don't sign it yet.
			XMLSignature signature = fac.newXMLSignature(si, ki);

			// Marshal, generate, and sign the enveloped signature.
			signature.sign(dsc);
			// Output the resulting document.
			OutputStream os = new FileOutputStream(arquivoXML);
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer trans = tf.newTransformer();
			trans.transform(new DOMSource(doc), new StreamResult(os));
		} catch (NoSuchAlgorithmException | ParserConfigurationException | SAXException | KeyStoreException
				| CertificateException | UnrecoverableEntryException | InvalidAlgorithmParameterException
				| MarshalException | XMLSignatureException | TransformerConfigurationException e) {
			Logger.getLogger(null);
		} catch (FileNotFoundException ex) {
			Logger.getLogger(null);
		} catch (IOException | TransformerException ex) {
			Logger.getLogger(null);
		}
	}
}
