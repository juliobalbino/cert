import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
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
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;


public class Main3 {
	
  public static void main(String[] args) throws Exception {
   InputStream in = new FileInputStream(new File("//home//orangebox//Downloads//teste.xml"));
   OutputStream os = new FileOutputStream(new File("//home//orangebox//Downloads//testeAssinado.xml"));

  //elemento que deve ser assinado
  String tagName="pedidoDeCompra";
  String elementoID = "pedido12345";

  //chave(certificado)
  String pathCertificado = "//home//orangebox//Downloads//40475821823_000001010394903.pfx";
  String senhaCertificado = "Julio65612556.";
  String alias = "BA8A233C-8C74-4D7E-B74D-35EC1F71C4C8";
  
  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
  dbf.setNamespaceAware(true);
  org.w3c.dom.Document doc = dbf.newDocumentBuilder().parse(in);

  InputStream entrada = new FileInputStream(pathCertificado);
  KeyStore ks = KeyStore.getInstance("pkcs12");
  try { 
    ks.load(entrada, senhaCertificado.toCharArray());
			
    if (ks.getEntry(alias, new KeyStore.PasswordProtection(senhaCertificado.toCharArray()))==null){
      throw new Exception("Alias existe?");
    }		
  } catch (IOException e) {
     throw new Exception("Senha do Certificado Digital incorreta ou Certificado inv�lido.");
  }
  KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) 
     ks.getEntry(alias, new KeyStore.PasswordProtection(senhaCertificado.toCharArray()));

  DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getElementsByTagName(tagName).item(0));

  //Assembling the XML Signature
  XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

  List transforms = new ArrayList();
  transforms.add(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
  transforms.add(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null));

  Reference ref = fac.newReference("#" + elementoID, //
                       fac.newDigestMethod(DigestMethod.SHA1, null),//
                       transforms, null, null);

  SignedInfo si = fac.newSignedInfo(//
                      fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, //
                     (C14NMethodParameterSpec) null), //
                      fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),//
                      Collections.singletonList(ref));

  KeyInfoFactory kif = fac.getKeyInfoFactory();

  List x509Content = new ArrayList();
  x509Content.add(keyEntry.getCertificate());

  X509Data kv = kif.newX509Data(x509Content);
  KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));
  XMLSignature signature = fac.newXMLSignature(si, ki);

  signature.sign(dsc);

  TransformerFactory tf = TransformerFactory.newInstance();
  Transformer trans = tf.newTransformer();

   //salva resultado no arquivo de sa�da
   trans.transform(new DOMSource(doc), new StreamResult(os));

  }
}
