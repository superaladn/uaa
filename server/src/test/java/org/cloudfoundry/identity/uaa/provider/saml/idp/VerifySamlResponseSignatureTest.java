package org.cloudfoundry.identity.uaa.provider.saml.idp;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.validation.Schema;

import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.common.xml.SAMLSchemaBuilder;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityTestHelper;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.StaticCredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import com.sun.org.apache.xml.internal.security.Init;
import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

@SuppressWarnings("deprecation")
public class VerifySamlResponseSignatureTest {
    String goodXml = "<samlp:Response Version=\"2.0\" ID=\"w1O1VjTjU1DOuh--3iHuC-Zw7ng\" IssueInstant=\"2016-12-09T07:38:19.716Z\" InResponseTo=\"a114592f98f8605e4eb7i9bc46if0fa\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">gefssprd</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status><saml:Assertion ID=\"oD5AiBcljLnYZuqnb._4KOqt_o7\" IssueInstant=\"2016-12-09T07:38:19.748Z\" Version=\"2.0\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:Issuer>gefssprd</saml:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n<ds:Reference URI=\"#oD5AiBcljLnYZuqnb._4KOqt_o7\">\n<ds:Transforms>\n<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n</ds:Transforms>\n<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n<ds:DigestValue>rQc5ShOokZUhszj3T+n7ae+vFU4=</ds:DigestValue>\n</ds:Reference>\n</ds:SignedInfo>\n<ds:SignatureValue>\nU77bN/Gu4fPhDJKx6e3Zix4lWxDQdWQ7wf9Ue29tCj4wNqMXn/jF2CSvtV7SBrX3epdLxOn3X9i5\nxdS5kIN7S2fE5xBlS/YU6YKV/BnZxSjaFcefOKfYxzuiEfqNmy1YymOKJ8McwvJhq6pLa7C3SwY2\nCRH9VX2/g3cgwwhAofOmJF4BbtiSw7qdcjrR6e/zPHtIkpR/3I5DNaCMDUigbp917Z2PqRI5dtnw\nlfpKOS4kGJ+RuvOsY6bgaouOhxDyO6oON2caN59aofw3+keO2Qo39IhHrRCR5P7rs4M2bgh7vypG\n1AwcXt/Y4vnWTFwnOZKNglj9Wfz3apIVCnjAFg==\n</ds:SignatureValue>\n<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>\nMIIF0jCCBLqgAwIBAgIQQ1o/lFE0WjjMkuXclNXkIzANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UE\nBhMCVVMxCzAJBgNVBAgTAkRFMRMwEQYDVQQHEwpXaWxtaW5ndG9uMSQwIgYDVQQKExtDb3Jwb3Jh\ndGlvbiBTZXJ2aWNlIENvbXBhbnkxLzAtBgNVBAMTJlRydXN0ZWQgU2VjdXJlIENlcnRpZmljYXRl\nIEF1dGhvcml0eSA1MB4XDTE2MTAwNjAwMDAwMFoXDTE5MTAwNjIzNTk1OVowgeQxCzAJBgNVBAYT\nAlVTMQ4wDAYDVQQREwUwNjgyODELMAkGA1UECBMCQ1QxEjAQBgNVBAcTCUZhaXJmaWVsZDEdMBsG\nA1UECRMUMzEzNSBFYXN0b24gVHVybnBpa2UxITAfBgNVBAoTGEdlbmVyYWwgRWxlY3RyaWMgQ29t\ncGFueTEtMCsGA1UECxMkUHJvdmlkZWQgYnkgR2VuZXJhbCBFbGVjdHJpYyBDb21wYW55MRcwFQYD\nVQQLEw5FbnRlcnByaXNlIFNTTDEaMBgGA1UEAxMRZnNzLmdlY29tcGFueS5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDlBHUDmBJ411lLFHyrdqAop9ET1vkG0iBeeRqxunElCixS\nMVbEtAxTreppVgr9R0iDxAw0PifmK0i0w8zrD7MzlNzLmUbQ5fpaxzHO0/RGFA1QhqwlwWYpntyw\n7l4s2/NoRT7Ip/WIlMe4poL4lYFg2vL+rZezEY82etgB/u1OF7Lp9W3KWWQtke+UVDjuUcYaaVYY\niNAY/mmmhmqvcMDmYtoCyoeJk/nd/zwYLlpb9A6RA5sLuT2Ly4Q8gYJ8lGbxAlmPrrTmwgq8DHDr\nWthYeyN8PPeuy7AbiEkYHO9IQX/zQzQHy8IlDw4Iua7yJpzDihkyRajIzMBo2Cd2YKqtAgMBAAGj\nggHaMIIB1jAfBgNVHSMEGDAWgBTyu1Xu/I/P0D8UaBqVfnkOqxcw9DAdBgNVHQ4EFgQUrY6TGHXz\n6LuX6eny3Ie6ulMOr5owDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYI\nKwYBBQUHAwEGCCsGAQUFBwMCMEsGA1UdIAREMEIwNgYLKwYBBAGyMQECAggwJzAlBggrBgEFBQcC\nARYZaHR0cHM6Ly9jcHMudXNlcnRydXN0LmNvbTAIBgZngQwBAgIwUAYDVR0fBEkwRzBFoEOgQYY/\naHR0cDovL2NybC51c2VydHJ1c3QuY29tL1RydXN0ZWRTZWN1cmVDZXJ0aWZpY2F0ZUF1dGhvcml0\neTUuY3JsMIGCBggrBgEFBQcBAQR2MHQwSwYIKwYBBQUHMAKGP2h0dHA6Ly9jcnQudXNlcnRydXN0\nLmNvbS9UcnVzdGVkU2VjdXJlQ2VydGlmaWNhdGVBdXRob3JpdHk1LmNydDAlBggrBgEFBQcwAYYZ\naHR0cDovL29jc3AudXNlcnRydXN0LmNvbTAzBgNVHREELDAqghFmc3MuZ2Vjb21wYW55LmNvbYIV\nd3d3LmZzcy5nZWNvbXBhbnkuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQAq679gtYsk62uc2eX1EV43\nkxA3hwWRnxjJLzMC6jT0u4KD9EHQeimVRiAjZh/KnlakBJSrK1OT/5wS8r6ni5UCpXsCkPNDH7wb\nbBMhvg0EE6L/nF3RB0VM1co/atRizA+5lstEXYFDwdT5nrZzlYNTK1V4lZDXaDy0Ti3qd3f3V8cM\nAlKu2kgGa5OmZiFnx1icyQgnhkHhFai64vKjq1SJ/d7iSt7BPbyYwkjcIMBFIh/6Tj3aHiVDdRdm\n+fX+BZn//Lb0+KdoGTFdP3wD/e8q2fipFfcy395uQLgsqRkZ7eha7sfGcdzJc83xhb4Tj3b/KNG1\nHSVC5JgFiTSGZJp6\n</ds:X509Certificate>\n</ds:X509Data>\n<ds:KeyValue>\n<ds:RSAKeyValue>\n<ds:Modulus>\n5QR1A5gSeNdZSxR8q3agKKfRE9b5BtIgXnkasbpxJQosUjFWxLQMU63qaVYK/UdIg8QMND4n5itI\ntMPM6w+zM5Tcy5lG0OX6WscxztP0RhQNUIasJcFmKZ7csO5eLNvzaEU+yKf1iJTHuKaC+JWBYNry\n/q2XsxGPNnrYAf7tThey6fVtyllkLZHvlFQ47lHGGmlWGIjQGP5ppoZqr3DA5mLaAsqHiZP53f88\nGC5aW/QOkQObC7k9i8uEPIGCfJRm8QJZj6605sIKvAxw61rYWHsjfDz3rsuwG4hJGBzvSEF/80M0\nB8vCJQ8OCLmu8iacw4oZMkWoyMzAaNgndmCqrQ==\n</ds:Modulus>\n<ds:Exponent>AQAB</ds:Exponent>\n</ds:RSAKeyValue>\n</ds:KeyValue>\n</ds:KeyInfo>\n</ds:Signature><saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">212068247</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\"https://bae1ba4a-998f-4038-b2d6-8097ba9cf1c0.predix-uaa.run.asv-pr.ice.predix.io/saml/SSO/alias/bae1ba4a-998f-4038-b2d6-8097ba9cf1c0.cloudfoundry-saml-login\" NotOnOrAfter=\"2016-12-09T07:43:19.748Z\" InResponseTo=\"a114592f98f8605e4eb7i9bc46if0fa\"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"2016-12-09T07:33:19.748Z\" NotOnOrAfter=\"2016-12-09T07:43:19.748Z\"><saml:AudienceRestriction><saml:Audience>bae1ba4a-998f-4038-b2d6-8097ba9cf1c0.cloudfoundry-saml-login</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement SessionIndex=\"oD5AiBcljLnYZuqnb._4KOqt_o7\" AuthnInstant=\"2016-12-09T07:38:19.748Z\"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name=\"ssoid\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">212068247</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"st\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">CA</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"firstname\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">Brittany</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"mail\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">brittany.johnson@ge.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"telephonenumber\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">+19259688051</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"city\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">San Ramon</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"initials\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">Brittany</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"cn\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">Johnson, Brittany M</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"gessouid\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">31CB1B1E-9619-1DB6-EC57-0003BA128A2E</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"title\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">Sr Software Engineer</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"georaclehrid\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">212068247</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"lastname\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">Johnson</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"street\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">2623 Camino Ramon</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"company\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">DIG PPT-Predix Engineering Services</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>";
    String badXml = "<samlp:Response Version=\"2.0\" ID=\"H_FCTpJMxuXmWGQlThwJz8uH8rF\" IssueInstant=\"2016-12-09T08:07:33.670Z\" InResponseTo=\"a2cdjhhd634ai731fj4cjgcc0530f8\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">gefssprd</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status><saml:Assertion ID=\"HXh08nUCUJaU4jQo-4wkeCbuKVb\" IssueInstant=\"2016-12-09T08:07:33.704Z\" Version=\"2.0\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:Issuer>gefssprd</saml:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n<ds:Reference URI=\"#HXh08nUCUJaU4jQo-4wkeCbuKVb\">\n<ds:Transforms>\n<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n</ds:Transforms>\n<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n<ds:DigestValue>m74eAXj1l0Y2UKu9ruiVMWRRkgI=</ds:DigestValue>\n</ds:Reference>\n</ds:SignedInfo>\n<ds:SignatureValue>\nx0ooVpDQF/PYQvgUUz52Ue/tUZe31iXD4XUDuR83dcHXhnyZhJQ4nKhRC3gSYG7RYweVxeVYwdDJ\n6fbIYxj9inSfnLdZygRC2vxVxo+4MPHUJpv7bYvkTwUvpgc860G2DjTenhbPbmjF2cOApHzBYnzG\nJ1tcBkM9ozWSEi9YkfuTfo+0KKKG22K01mPcLTU860vvKokWsyERzuhXmUKlUbifhq15E3s0qVJS\n2W0Ss+wrWjhohgDArt5YlG6NsnlzCLx3SsS9fEk4S9YWv5Yz+9TCz42dIisaWPvk1syX8aNHKic0\nHfauVv28XG7dKTd/EBf2z9W9aHKYgVkS7/ti9Q==\n</ds:SignatureValue>\n<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>\nMIIF0jCCBLqgAwIBAgIQQ1o/lFE0WjjMkuXclNXkIzANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UE\nBhMCVVMxCzAJBgNVBAgTAkRFMRMwEQYDVQQHEwpXaWxtaW5ndG9uMSQwIgYDVQQKExtDb3Jwb3Jh\ndGlvbiBTZXJ2aWNlIENvbXBhbnkxLzAtBgNVBAMTJlRydXN0ZWQgU2VjdXJlIENlcnRpZmljYXRl\nIEF1dGhvcml0eSA1MB4XDTE2MTAwNjAwMDAwMFoXDTE5MTAwNjIzNTk1OVowgeQxCzAJBgNVBAYT\nAlVTMQ4wDAYDVQQREwUwNjgyODELMAkGA1UECBMCQ1QxEjAQBgNVBAcTCUZhaXJmaWVsZDEdMBsG\nA1UECRMUMzEzNSBFYXN0b24gVHVybnBpa2UxITAfBgNVBAoTGEdlbmVyYWwgRWxlY3RyaWMgQ29t\ncGFueTEtMCsGA1UECxMkUHJvdmlkZWQgYnkgR2VuZXJhbCBFbGVjdHJpYyBDb21wYW55MRcwFQYD\nVQQLEw5FbnRlcnByaXNlIFNTTDEaMBgGA1UEAxMRZnNzLmdlY29tcGFueS5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDlBHUDmBJ411lLFHyrdqAop9ET1vkG0iBeeRqxunElCixS\nMVbEtAxTreppVgr9R0iDxAw0PifmK0i0w8zrD7MzlNzLmUbQ5fpaxzHO0/RGFA1QhqwlwWYpntyw\n7l4s2/NoRT7Ip/WIlMe4poL4lYFg2vL+rZezEY82etgB/u1OF7Lp9W3KWWQtke+UVDjuUcYaaVYY\niNAY/mmmhmqvcMDmYtoCyoeJk/nd/zwYLlpb9A6RA5sLuT2Ly4Q8gYJ8lGbxAlmPrrTmwgq8DHDr\nWthYeyN8PPeuy7AbiEkYHO9IQX/zQzQHy8IlDw4Iua7yJpzDihkyRajIzMBo2Cd2YKqtAgMBAAGj\nggHaMIIB1jAfBgNVHSMEGDAWgBTyu1Xu/I/P0D8UaBqVfnkOqxcw9DAdBgNVHQ4EFgQUrY6TGHXz\n6LuX6eny3Ie6ulMOr5owDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYI\nKwYBBQUHAwEGCCsGAQUFBwMCMEsGA1UdIAREMEIwNgYLKwYBBAGyMQECAggwJzAlBggrBgEFBQcC\nARYZaHR0cHM6Ly9jcHMudXNlcnRydXN0LmNvbTAIBgZngQwBAgIwUAYDVR0fBEkwRzBFoEOgQYY/\naHR0cDovL2NybC51c2VydHJ1c3QuY29tL1RydXN0ZWRTZWN1cmVDZXJ0aWZpY2F0ZUF1dGhvcml0\neTUuY3JsMIGCBggrBgEFBQcBAQR2MHQwSwYIKwYBBQUHMAKGP2h0dHA6Ly9jcnQudXNlcnRydXN0\nLmNvbS9UcnVzdGVkU2VjdXJlQ2VydGlmaWNhdGVBdXRob3JpdHk1LmNydDAlBggrBgEFBQcwAYYZ\naHR0cDovL29jc3AudXNlcnRydXN0LmNvbTAzBgNVHREELDAqghFmc3MuZ2Vjb21wYW55LmNvbYIV\nd3d3LmZzcy5nZWNvbXBhbnkuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQAq679gtYsk62uc2eX1EV43\nkxA3hwWRnxjJLzMC6jT0u4KD9EHQeimVRiAjZh/KnlakBJSrK1OT/5wS8r6ni5UCpXsCkPNDH7wb\nbBMhvg0EE6L/nF3RB0VM1co/atRizA+5lstEXYFDwdT5nrZzlYNTK1V4lZDXaDy0Ti3qd3f3V8cM\nAlKu2kgGa5OmZiFnx1icyQgnhkHhFai64vKjq1SJ/d7iSt7BPbyYwkjcIMBFIh/6Tj3aHiVDdRdm\n+fX+BZn//Lb0+KdoGTFdP3wD/e8q2fipFfcy395uQLgsqRkZ7eha7sfGcdzJc83xhb4Tj3b/KNG1\nHSVC5JgFiTSGZJp6\n</ds:X509Certificate>\n</ds:X509Data>\n<ds:KeyValue>\n<ds:RSAKeyValue>\n<ds:Modulus>\n5QR1A5gSeNdZSxR8q3agKKfRE9b5BtIgXnkasbpxJQosUjFWxLQMU63qaVYK/UdIg8QMND4n5itI\ntMPM6w+zM5Tcy5lG0OX6WscxztP0RhQNUIasJcFmKZ7csO5eLNvzaEU+yKf1iJTHuKaC+JWBYNry\n/q2XsxGPNnrYAf7tThey6fVtyllkLZHvlFQ47lHGGmlWGIjQGP5ppoZqr3DA5mLaAsqHiZP53f88\nGC5aW/QOkQObC7k9i8uEPIGCfJRm8QJZj6605sIKvAxw61rYWHsjfDz3rsuwG4hJGBzvSEF/80M0\nB8vCJQ8OCLmu8iacw4oZMkWoyMzAaNgndmCqrQ==\n</ds:Modulus>\n<ds:Exponent>AQAB</ds:Exponent>\n</ds:RSAKeyValue>\n</ds:KeyValue>\n</ds:KeyInfo>\n</ds:Signature><saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">212068247</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\"https://bae1ba4a-998f-4038-b2d6-8097ba9cf1c0.predix-uaa.run.asv-pr.ice.predix.io/saml/SSO/alias/bae1ba4a-998f-4038-b2d6-8097ba9cf1c0.cloudfoundry-saml-login\" NotOnOrAfter=\"2016-12-09T08:12:33.704Z\" InResponseTo=\"a2cdjhhd634ai731fj4cjgcc0530f8\"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"2016-12-09T08:02:33.704Z\" NotOnOrAfter=\"2016-12-09T08:12:33.704Z\"><saml:AudienceRestriction><saml:Audience>bae1ba4a-998f-4038-b2d6-8097ba9cf1c0.cloudfoundry-saml-login</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement SessionIndex=\"HXh08nUCUJaU4jQo-4wkeCbuKVb\" AuthnInstant=\"2016-12-09T08:07:33.703Z\"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name=\"ssoid\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">212068247</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"st\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">CA</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"firstname\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">Brittany</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"mail\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">brittany.johnson@ge.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"telephonenumber\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">+19259688051</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"city\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">San Ramon</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"initials\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">Brittany</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"cn\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">Johnson, Brittany M</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"gessouid\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">31CB1B1E-9619-1DB6-EC57-0003BA128A2E</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"title\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">Sr Software Engineer</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"georaclehrid\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">212068247</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"lastname\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">Johnson</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"street\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">2623 Camino Ramon</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"company\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">DIG PPT-Predix Engineering Services</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>";
    
    String metadataCert = "MIIF0jCCBLqgAwIBAgIQQ1o/lFE0WjjMkuXclNXkIzANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkRFMRMwEQYDVQQHEwpXaWxtaW5ndG9uMSQwIgYDVQQKExtDb3Jwb3JhdGlvbiBTZXJ2aWNlIENvbXBhbnkxLzAtBgNVBAMTJlRydXN0ZWQgU2VjdXJlIENlcnRpZmljYXRlIEF1dGhvcml0eSA1MB4XDTE2MTAwNjAwMDAwMFoXDTE5MTAwNjIzNTk1OVowgeQxCzAJBgNVBAYTAlVTMQ4wDAYDVQQREwUwNjgyODELMAkGA1UECBMCQ1QxEjAQBgNVBAcTCUZhaXJmaWVsZDEdMBsGA1UECRMUMzEzNSBFYXN0b24gVHVybnBpa2UxITAfBgNVBAoTGEdlbmVyYWwgRWxlY3RyaWMgQ29tcGFueTEtMCsGA1UECxMkUHJvdmlkZWQgYnkgR2VuZXJhbCBFbGVjdHJpYyBDb21wYW55MRcwFQYDVQQLEw5FbnRlcnByaXNlIFNTTDEaMBgGA1UEAxMRZnNzLmdlY29tcGFueS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDlBHUDmBJ411lLFHyrdqAop9ET1vkG0iBeeRqxunElCixSMVbEtAxTreppVgr9R0iDxAw0PifmK0i0w8zrD7MzlNzLmUbQ5fpaxzHO0/RGFA1QhqwlwWYpntyw7l4s2/NoRT7Ip/WIlMe4poL4lYFg2vL+rZezEY82etgB/u1OF7Lp9W3KWWQtke+UVDjuUcYaaVYYiNAY/mmmhmqvcMDmYtoCyoeJk/nd/zwYLlpb9A6RA5sLuT2Ly4Q8gYJ8lGbxAlmPrrTmwgq8DHDrWthYeyN8PPeuy7AbiEkYHO9IQX/zQzQHy8IlDw4Iua7yJpzDihkyRajIzMBo2Cd2YKqtAgMBAAGjggHaMIIB1jAfBgNVHSMEGDAWgBTyu1Xu/I/P0D8UaBqVfnkOqxcw9DAdBgNVHQ4EFgQUrY6TGHXz6LuX6eny3Ie6ulMOr5owDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMEsGA1UdIAREMEIwNgYLKwYBBAGyMQECAggwJzAlBggrBgEFBQcCARYZaHR0cHM6Ly9jcHMudXNlcnRydXN0LmNvbTAIBgZngQwBAgIwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1RydXN0ZWRTZWN1cmVDZXJ0aWZpY2F0ZUF1dGhvcml0eTUuY3JsMIGCBggrBgEFBQcBAQR2MHQwSwYIKwYBBQUHMAKGP2h0dHA6Ly9jcnQudXNlcnRydXN0LmNvbS9UcnVzdGVkU2VjdXJlQ2VydGlmaWNhdGVBdXRob3JpdHk1LmNydDAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRydXN0LmNvbTAzBgNVHREELDAqghFmc3MuZ2Vjb21wYW55LmNvbYIVd3d3LmZzcy5nZWNvbXBhbnkuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQAq679gtYsk62uc2eX1EV43kxA3hwWRnxjJLzMC6jT0u4KD9EHQeimVRiAjZh/KnlakBJSrK1OT/5wS8r6ni5UCpXsCkPNDH7wbbBMhvg0EE6L/nF3RB0VM1co/atRizA+5lstEXYFDwdT5nrZzlYNTK1V4lZDXaDy0Ti3qd3f3V8cMAlKu2kgGa5OmZiFnx1icyQgnhkHhFai64vKjq1SJ/d7iSt7BPbyYwkjcIMBFIh/6Tj3aHiVDdRdm+fX+BZn//Lb0+KdoGTFdP3wD/e8q2fipFfcy395uQLgsqRkZ7eha7sfGcdzJc83xhb4Tj3b/KNG1HSVC5JgFiTSGZJp6";
    
    @Test
    public void testVerifySamlResponseWithTrustEngineGood()
            throws ConfigurationException, UnmarshallingException, Base64DecodingException, NoSuchAlgorithmException,
            InvalidKeySpecException, IOException, SecurityException, SAXException {
        Document document = readSamlResponse(this.goodXml);
        Init.init();
        // needed to get unmarshaller to load
        DefaultBootstrap.bootstrap();
        Element responseRoot = document.getDocumentElement();
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(document.getDocumentElement());
        Response samlResponse = (Response) unmarshaller.unmarshall(responseRoot);
        // file must not have the -----BEGIN PUBLIC KEY----- or ----- END PUBLIC KEY----- and no /n at end of key
        StaticCredentialResolver credResolver = new StaticCredentialResolver(
                VerifySamlResponseSignatureTest.getKey("gesso-good-pubkey.pem"));
        KeyInfoCredentialResolver kiResolver = SecurityTestHelper.buildBasicInlineKeyInfoResolver();
        ExplicitKeySignatureTrustEngine trustEngine = new ExplicitKeySignatureTrustEngine(credResolver, kiResolver);
        Security.getProviders();
        CriteriaSet criteriaSet = new CriteriaSet();
        System.out.println("Issuer: " + samlResponse.getIssuer().getValue());
        criteriaSet.add(new EntityIDCriteria(samlResponse.getIssuer().getValue()));
        criteriaSet.add(new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
        criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
        assertTrue("Assertion signature was not valid",
                trustEngine.validate(samlResponse.getAssertions().get(0).getSignature(), criteriaSet));
    }
    
    @Test
    public void testVerifySamlResponseWithTrustEngineBad()
            throws ConfigurationException, UnmarshallingException, Base64DecodingException, NoSuchAlgorithmException,
            InvalidKeySpecException, IOException, SecurityException, SAXException {
        Document document = readSamlResponse(this.badXml);
        Init.init();
        // needed to get unmarshaller to load
        DefaultBootstrap.bootstrap();
        Element responseRoot = document.getDocumentElement();
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(document.getDocumentElement());
        Response samlResponse = (Response) unmarshaller.unmarshall(responseRoot);
        // file must not have the -----BEGIN PUBLIC KEY----- or ----- END PUBLIC KEY----- and no /n at end of key
        StaticCredentialResolver credResolver = new StaticCredentialResolver(
                VerifySamlResponseSignatureTest.getKey("gesso-good-pubkey.pem"));
        KeyInfoCredentialResolver kiResolver = SecurityTestHelper.buildBasicInlineKeyInfoResolver();
        ExplicitKeySignatureTrustEngine trustEngine = new ExplicitKeySignatureTrustEngine(credResolver, kiResolver);
        Security.getProviders();
        CriteriaSet criteriaSet = new CriteriaSet();
        System.out.println("Issuer: " + samlResponse.getIssuer().getValue());
        criteriaSet.add(new EntityIDCriteria(samlResponse.getIssuer().getValue()));
        criteriaSet.add(new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
        criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
        assertTrue("Assertion signature was not valid",
                trustEngine.validate(samlResponse.getAssertions().get(0).getSignature(), criteriaSet));
    }

    @Test
    public void testVerifySamlResponseWithSignatureValidatorGood() throws Exception {
        System.out.println("Testing Good response.");
        Document document = readSamlResponse(this.goodXml);
        Init.init();
        // needed to get unmarshaller to load
        DefaultBootstrap.bootstrap();
        Element responseRoot = document.getDocumentElement();
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(document.getDocumentElement());
        Response samlResponse = (Response) unmarshaller.unmarshall(responseRoot);
//        System.out.println("Testing against given key in .pem file.");
//        Credential validatingCredentialFromFile = VerifySamlResponseSignatureTest.getKey("gesso-good-pubkey.pem")
//                .get(0);
      System.out.println("Testing against given key from metadata string.");
      Credential validatingCredentialFromFile = VerifySamlResponseSignatureTest.getKeyFromString(this.metadataCert);
        SignatureValidator sigValidatorPemFile = new SignatureValidator(validatingCredentialFromFile);
        try {
            sigValidatorPemFile.validate(samlResponse.getAssertions().get(0).getSignature());
        } catch (ValidationException e) {
            System.out.println("Validation failed against given key in .pem file.");
            e.printStackTrace();
        }

        System.out.println("Testing against certificate given in assertion.");
        KeyInfo keyInfo = (KeyInfo) samlResponse.getAssertions().get(0).getSignature().getKeyInfo();
        List<PublicKey> publicKeyList = KeyInfoHelper.getPublicKeys(keyInfo);
        BasicX509Credential creds = new BasicX509Credential();
        creds.setUsageType(UsageType.SIGNING);
        creds.setPublicKey(publicKeyList.get(0));
        SignatureValidator sigValidator = new SignatureValidator(creds);
        try {
            sigValidator.validate(samlResponse.getAssertions().get(0).getSignature());
        } catch (ValidationException e) {
            System.out.println("Validation failed against certificate given in assertion.");
            e.printStackTrace();
        }
    }

    @Test
    public void testVerifySamlResponseWithSignatureValidatorBad() throws Exception {
        System.out.println("Testing Bad response.");
        Document document = readSamlResponse(this.badXml);
        Init.init();
        // needed to get unmarshaller to load
        DefaultBootstrap.bootstrap();
        Element responseRoot = document.getDocumentElement();
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(document.getDocumentElement());
        Response samlResponse = (Response) unmarshaller.unmarshall(responseRoot);
        System.out.println("Testing against given key in .pem file.");
        Credential validatingCredentialFromFile = VerifySamlResponseSignatureTest.getKey("gesso-good-pubkey.pem")
                .get(0);
        SignatureValidator sigValidatorPemFile = new SignatureValidator(validatingCredentialFromFile);
        try {
            sigValidatorPemFile.validate(samlResponse.getAssertions().get(0).getSignature());
        } catch (ValidationException e) {
            System.out.println("Validation failed against given key in .pem file.");
            e.printStackTrace();
        }

        System.out.println("Testing against certificate given in assertion.");
        KeyInfo keyInfo = (KeyInfo) samlResponse.getAssertions().get(0).getSignature().getKeyInfo();
        List<PublicKey> publicKeyList = KeyInfoHelper.getPublicKeys(keyInfo);
        BasicX509Credential creds = new BasicX509Credential();
        creds.setUsageType(UsageType.SIGNING);
        creds.setPublicKey(publicKeyList.get(0));
        SignatureValidator sigValidator = new SignatureValidator(creds);
        try {
            sigValidator.validate(samlResponse.getAssertions().get(0).getSignature());
        } catch (ValidationException e) {
            System.out.println("Validation failed against certificate given in assertion.");
            e.printStackTrace();
        }
    }

    public static List<Credential> getKey(String fileName)
            throws Base64DecodingException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        Path path = Paths.get(System.getProperty("user.dir") + "/src/test/resources/" + fileName);
        byte[] pemBytes = Files.readAllBytes(path);
        // X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.decode(PROVIDER_PUB_KEY.getBytes("UTF-8")));
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.decode(pemBytes));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
        BasicX509Credential creds = new BasicX509Credential();
        creds.setUsageType(UsageType.SIGNING);
        creds.setPublicKey(publicKey);
        System.out.println(publicKey);
        List<Credential> credentialList = new ArrayList<Credential>();
        credentialList.add(creds);
        return credentialList;
    }

    public static Credential getKeyFromString(String x509Certificate) throws Base64DecodingException,
            NoSuchAlgorithmException, InvalidKeySpecException, IOException, CertificateException {
        byte[] pemBytes = x509Certificate.getBytes();
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        InputStream is = new ByteArrayInputStream(Base64.decode(pemBytes));
        X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
        is.close();
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(cer.getPublicKey().getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
        BasicCredential validatingCredential = new BasicCredential();
        validatingCredential.setUsageType(UsageType.SIGNING);
        validatingCredential.setPublicKey(publicKey);
        System.out.println(publicKey);
        return validatingCredential;
    }

    public Document readSamlResponse(String xmlResponse) throws SAXException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        Schema schema = SAMLSchemaBuilder.getSAML11Schema();
        factory.setNamespaceAware(true);
        factory.setIgnoringElementContentWhitespace(true);
        factory.setSchema(schema);
        DocumentBuilder builder;
        Document document = null;
        try {
            builder = factory.newDocumentBuilder();
            System.out.println("Path" + System.getProperty("user.dir"));
            final InputStream stream = new ByteArrayInputStream(xmlResponse.getBytes(StandardCharsets.UTF_8));
            document = builder.parse(stream);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return document;
    }

    // This method does not work for validating signature due to format of the xml file
    public Document readSamlResponseFromXmlFile(String fileName) throws SAXException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        Schema schema = SAMLSchemaBuilder.getSAML11Schema();
        factory.setNamespaceAware(true);
        factory.setIgnoringElementContentWhitespace(true);
        factory.setSchema(schema);
        DocumentBuilder builder;
        Document document = null;
        try {
            builder = factory.newDocumentBuilder();
            System.out.println("Path" + System.getProperty("user.dir"));
            document = builder.parse(System.getProperty("user.dir") + "/src/test/resources/" + fileName);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return document;
    }
}
