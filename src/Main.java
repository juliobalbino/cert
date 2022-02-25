
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Collections;


import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;



public class Main {

	public static void main(String[] args) throws Exception, Exception {

		String xml = Files.readString(Path.of("//home//orangebox//eclipse-workspace//BarueriWSCLient//src//wssaopaulo//PedidoConsultaCNPJ.xml"));
		
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
		javax.xml.crypto.dsig.Reference ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA1, null),
				Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null,
				null);
		
		// Create the SignedInfo (RSA).
		SignedInfo si = fac.newSignedInfo(
				fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
				fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));
		
		// Load the KeyStore and get the signing key and certificate.
		KeyStore ks = KeyStore.getInstance("");
		ks.load(new java.io.FileInputStream("//home//orangebox//Downloads//julio.pfx"), "Julio65612556.".toCharArray());
		KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry("BA8A233C-8C74-4D7E-B74D-35EC1F71C4C8",
				new KeyStore.PasswordProtection("Julio65612556.".toCharArray()));
		X509Certificate cert = (X509Certificate) keyEntry.getCertificate();
		
		// Create the KeyInfo containing the X509Data.
		KeyInfoFactory kif = fac.getKeyInfoFactory();
		java.util.List x509Content = new java.util.ArrayList();
		
		x509Content.add(cert.getSubjectX500Principal().getName());
		x509Content.add(cert);
		
		X509Data xd = kif.newX509Data(x509Content);
		KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));
		
		// Transformando String �xml� em Document.
		
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document doc = dbf.newDocumentBuilder()
				.parse(new org.xml.sax.InputSource(new java.io.ByteArrayInputStream(xml.getBytes("UTF-8"))));
		DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement());
		XMLSignature signature = fac.newXMLSignature(si, ki);
		
		signature.sign(dsc);
		javax.xml.transform.dom.DOMSource domSource = new javax.xml.transform.dom.DOMSource(doc);
		
		java.io.StringWriter writer = new java.io.StringWriter();

		javax.xml.transform.stream.StreamResult result = new javax.xml.transform.stream.StreamResult(writer);
		javax.xml.transform.TransformerFactory tf = javax.xml.transform.TransformerFactory.newInstance();
		javax.xml.transform.Transformer transformer = tf.newTransformer();
		
		transformer.transform(domSource, result);
		
		xml = writer.toString();
		
		writer.close();

	}

}
