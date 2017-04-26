package org.cloudfoundry.identity.uaa;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.junit.Test;

public class CheckCertCRLTest {

    @Test
    public void checkCRLTest() throws Exception {
        FileInputStream fileInputStream = new FileInputStream ("src/test/resources/device-certificate.pem");
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(fileInputStream);
        List<String> crlUrls = getCRLUrls(cert);
        X509CRL crl = getCRL(crlUrls.get(0));
        //System.out.println("Cert is :" + cert);
        //System.out.println("Distribution point is :" + crlUrls);
        System.out.println("CRL is :" + crl);
        System.out.println("CRL revocation status :" + crl.isRevoked(cert));
        fileInputStream.close();
    }

    @Test
    public void checkCRLWithPKIXCertValidatorTest() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        FileInputStream fileInputStream = new FileInputStream ("src/test/resources/certificate.pem");
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
        Collection<? extends Certificate> generateCertificates = certFactory.generateCertificates(fileInputStream);
        List list = new ArrayList(generateCertificates);
        CertPath path = certFactory.generateCertPath(list);
        for(Certificate c : generateCertificates ) {
            System.out.println("Certificate " + c);
           
        }
        System.out.println("Certificates size " + generateCertificates.size());
        fileInputStream.close();
        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(generateCertificates);
        CertStore store = CertStore.getInstance("Collection", ccsp);
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        Set<TrustAnchor> paramSet = new HashSet();
        paramSet.add(new TrustAnchor((X509Certificate) list.get(1), null));
        PKIXParameters params = new PKIXParameters(paramSet);
        params.addCertStore(store);
        params.setRevocationEnabled(true);
        params.setTrustAnchors(paramSet);
        CertPathValidatorResult cpvResult = cpv.validate(path, params);
        
    }

    @Test
    public void checkCRLRevokedTest() throws Exception {
        FileInputStream fileInputStream = new FileInputStream ("src/test/resources/certificate-revoked.pem");
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(fileInputStream);
        List<String> crlUrls = getCRLUrls(cert);
        X509CRL crl = getCRL(crlUrls.get(0));
        System.out.println("Distribution point is :" + crlUrls);
        //System.out.println("CRL is :" + crl);
        System.out.println("CRL revocation status :" + crl.isRevoked(cert));
        fileInputStream.close();
    }

    @Test
    public void checkOCSPTest() throws Exception {
        FileInputStream fileInputStream = new FileInputStream ("src/test/resources/certificate.pem");
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(fileInputStream);
        //PKIXRevocationChecker pathChecker = new RevocationChecker();
        getOcspUrl(cert);
        fileInputStream.close();
    }

    private List<String> getCRLUrls(X509Certificate cert) throws IOException {
        //CRL distribution point extension oid
        String crlDistributionPointOid = Extension.cRLDistributionPoints.getId();
        byte[] extensionValue = cert.getExtensionValue(crlDistributionPointOid);
        ASN1InputStream oAsnInStream = new ASN1InputStream(extensionValue);
        ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
        oAsnInStream.close();
        ASN1OctetString dosCrlDP = (ASN1OctetString) derObjCrlDP;
        ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(dosCrlDP.getOctets());
        CRLDistPoint distPoint = CRLDistPoint.getInstance(asn1Sequence);
        return getCrlUrls(distPoint);
    }

    private AuthorityInformationAccess getOcspUrl(X509Certificate cert) throws IOException {
        //OCSP distribution point extension oid
        String authorityInfoAccessOid = Extension.authorityInfoAccess.getId();
        byte[] extensionValue = cert.getExtensionValue(authorityInfoAccessOid);
        ASN1InputStream oAsnInStream = new ASN1InputStream(extensionValue);
        ASN1Primitive derObjOCSP = oAsnInStream.readObject();
        oAsnInStream.close();
        ASN1OctetString dosOCSP = (ASN1OctetString) derObjOCSP;
        ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(dosOCSP.getOctets());
        AuthorityInformationAccess ocspUrl = AuthorityInformationAccess.getInstance(asn1Sequence);
        System.out.println("OCSP " + ocspUrl);
        return ocspUrl;
    }

    private List<String> getCrlUrls(CRLDistPoint distPoint) {
        List<String> crlUrls = new ArrayList<String>();
        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            DistributionPointName dpn = dp.getDistributionPoint();
            // Look for URIs in fullName
            if (dpn != null
                && dpn.getType() == DistributionPointName.FULL_NAME) {
                GeneralName[] genNames = GeneralNames.getInstance(
                        dpn.getName()).getNames();
                // Look for an URI
                for (int j = 0; j < genNames.length; j++) {
                    if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
                        String url = DERIA5String.getInstance(
                                genNames[j].getName()).getString();
                        crlUrls.add(url);
                    }
                }
            }
        }
        return crlUrls;
    }

    private X509CRL getCRL(String location) throws Exception
    {
        X509CRL result = null;
        try
        {
            URL url = new URL(location);
            
            if (url.getProtocol().equals("http") || url.getProtocol().equals("https"))
            {
                Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("grc-americas-pitc-sanraz.proxy.corporate.gtm.ge.com", 8080));
                HttpURLConnection conn = (HttpURLConnection) url.openConnection(proxy);
                //HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setUseCaches(false);
                //conn.setConnectTimeout(2000);
                conn.setDoInput(true);
                conn.connect();
                if (conn.getResponseCode() == HttpURLConnection.HTTP_OK)
                {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    result = (X509CRL) cf.generateCRL(conn.getInputStream());
                }
                else
                {
                    throw new Exception(conn.getResponseMessage());
                }
            }
        }
        catch (Exception e)
        {
            throw new Exception("Certificate CRL could not be checked." + e.getMessage());
        }
        return result;
    }
}
