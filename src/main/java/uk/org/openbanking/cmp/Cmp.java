/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.org.openbanking.cmp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509DefaultEntryConverter;
import org.bouncycastle.asn1.x509.X509NameEntryConverter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;

import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import org.apache.commons.codec.binary.Base64;
//import sun.security.x509.GeneralName;
//import sun.security.x509.X500Name;

/**
 *
 * @author fgyara
 */
public class Cmp {
    
    public static void main (String args[]) throws Exception {
        
        // generate a key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        
        System.out.println("Generating with pub key:" + kp.getPublic().toString());
        
        ProtectedPKIMessage mesg = Cmp.getCert( 
                1,                      // certReqId
                "AdminCA1",             // issuerCN (used to create issuerDN)
                "user",                 // subjectCN (used to create subjectDN)
                kp,                     // keypair
                "101010",               // sender nonce
                "1"                     // transaction id
        );
        
        // asn1
        byte[] asn1Bytes = mesg.toASN1Structure().toASN1Object().getEncoded();
        
        //der
        // byte[] derBytes = mesg.toASN1Object().toASN1Object().getEncoded();
        
        byte[] b64Enc = Base64.encodeBase64(asn1Bytes);
        
        System.out.println(new String(b64Enc));
        
        
    }
    
    public static ProtectedPKIMessage getCert(
        long certReqId,
        String issuerCN,
        String subjectCN,
        KeyPair keyPair,
        String senderNonce,
        String transactionId) throws IOException, CRMFException, CMPException {
        
        CertificateRequestMessageBuilder msgbuilder = new CertificateRequestMessageBuilder(BigInteger.valueOf(1));
        
        X509NameEntryConverter dnconverter = new X509DefaultEntryConverter();
        X500Name issuerDN = X500Name.getInstance(new X509Name("CN=" + issuerCN).toASN1Object());
        X500Name subjectDN = X500Name.getInstance(new X509Name("CN=" + subjectCN, dnconverter).toASN1Object());
        msgbuilder.setIssuer(issuerDN);
        msgbuilder.setSubject(subjectDN);
        
        final byte[]                  bytes = keyPair.getPublic().getEncoded();
        final ByteArrayInputStream    bIn = new ByteArrayInputStream(bytes);
        final ASN1InputStream         dIn = new ASN1InputStream(bIn);
        final SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((ASN1Sequence)dIn.readObject());
        msgbuilder.setPublicKey(keyInfo);
        GeneralName sender = new GeneralName(subjectDN);
        msgbuilder.setAuthInfoSender(sender);
        
        // RAVerified POP
        msgbuilder.setProofOfPossessionRaVerified();
        CertificateRequestMessage msg = msgbuilder.build();
        GeneralName recipient = new GeneralName(issuerDN);
        ProtectedPKIMessageBuilder pbuilder = new ProtectedPKIMessageBuilder(sender, recipient);
        pbuilder.setMessageTime(new Date());
        // senderNonce
        pbuilder.setSenderNonce(senderNonce.getBytes());
        
        // TransactionId
        pbuilder.setTransactionID(transactionId.getBytes());
        
        // Key Id used (required) by the recipient to do a lot of stuff
        pbuilder.setSenderKID("KeyId".getBytes());
        org.bouncycastle.asn1.crmf.CertReqMessages msgs = new org.bouncycastle.asn1.crmf.CertReqMessages(msg.toASN1Structure());
        org.bouncycastle.asn1.cmp.PKIBody pkibody = new org.bouncycastle.asn1.cmp.PKIBody(org.bouncycastle.asn1.cmp.PKIBody.TYPE_INIT_REQ, msgs);
        pbuilder.setBody(pkibody);
        JcePKMACValuesCalculator jcePkmacCalc = new JcePKMACValuesCalculator();
        
        // FG: commented out lines do not compile
        // not sure if the replacements work
            
        // final AlgorithmIdentifier digAlg = new AlgorithmIdentifier("1.3.14.3.2.26"); // SHA1
        final AlgorithmIdentifier digAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26"));
        
        // final AlgorithmIdentifier macAlg = new AlgorithmIdentifier("1.2.840.113549.2.7"); // HMAC/SHA1
        final AlgorithmIdentifier macAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.2.7"));
        
        
        jcePkmacCalc.setup(digAlg, macAlg);
        PKMACBuilder macbuilder = new PKMACBuilder(jcePkmacCalc);
        MacCalculator macCalculator = macbuilder.build("password".toCharArray());
        ProtectedPKIMessage message = pbuilder.build(macCalculator);   
        
        return message;
    }
    
}
