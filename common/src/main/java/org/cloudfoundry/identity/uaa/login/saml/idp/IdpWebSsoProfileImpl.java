package org.cloudfoundry.identity.uaa.login.saml.idp;

import org.cloudfoundry.identity.uaa.login.saml.idp.IdpSamlAuthentication.IdpSamlCredentialsHolder;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.XMLSignatureBuilder;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

public class IdpWebSsoProfileImpl extends WebSSOProfileImpl implements IdpWebSsoProfile {

    @SuppressWarnings("unchecked")
    @Override
    public void sendResponse(Authentication authentication, SAMLMessageContext context, WebSSOProfileOptions options)
            throws SAMLException, MetadataProviderException, MessageEncodingException, SecurityException,
            MarshallingException, SignatureException {

        IdpSamlCredentialsHolder credentials = (IdpSamlCredentialsHolder) authentication.getCredentials();
        Authentication openIdAuthentication = credentials.getOpenidAuthenticationToken();

        IDPSSODescriptor idpDescriptor = (IDPSSODescriptor) context.getLocalEntityRoleMetadata();
        SPSSODescriptor spDescriptor = (SPSSODescriptor) context.getPeerEntityRoleMetadata();
        AuthnRequest authnRequest = (AuthnRequest) context.getInboundSAMLMessage();

        AssertionConsumerService assertionConsumerService = getAssertionConsumerService(options, idpDescriptor,
                spDescriptor);

        context.setPeerEntityEndpoint(assertionConsumerService);

        Assertion assertion = buildAssertion(authnRequest, context.getPeerEntityId(), context.getLocalEntityId(),
                openIdAuthentication.getName());
        if (spDescriptor.getWantAssertionsSigned()) {
            signAssertion(assertion, context.getLocalSigningCredential());
        }
        Response samlResponse = createResponse(context, assertionConsumerService, assertion);
        context.setOutboundMessage(samlResponse);
        context.setOutboundSAMLMessage(samlResponse);

        sendMessage(context, false);
    }

    private Response createResponse(SAMLMessageContext context, AssertionConsumerService assertionConsumerService,
            Assertion assertion) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) builderFactory
                .getBuilder(Response.DEFAULT_ELEMENT_NAME);
        Response response = responseBuilder.buildObject();

        buildCommonAttributes(context.getLocalEntityId(), response, assertionConsumerService);

        response.getAssertions().add(assertion);

        buildStatusSuccess(response);
        return response;
    }

    private void buildCommonAttributes(String localEntityId, Response response, Endpoint service) {

        response.setID(generateID());
        response.setIssuer(getIssuer(localEntityId));
        response.setVersion(SAMLVersion.VERSION_20);
        response.setIssueInstant(new DateTime());

        if (service != null) {
            response.setDestination(service.getLocation());
        }
    }

    private Assertion buildAssertion(AuthnRequest authnRequest, String audienceURI, String issuerEntityId,
            String nameIdStr) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) builderFactory
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID(generateID());
        assertion.setIssueInstant(new DateTime());
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssuer(getIssuer(issuerEntityId));

        buildAssertionAuthnStatement(assertion);
        buildAssertionConditions(assertion, audienceURI);
        buildAssertionSubject(assertion, authnRequest, nameIdStr);

        return assertion;
    }

    private void buildAssertionAuthnStatement(Assertion assertion) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<AuthnStatement> authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) builderFactory
                .getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
        AuthnStatement authnStatement = authnStatementBuilder.buildObject();
        authnStatement.setAuthnInstant(new DateTime());
        authnStatement.setSessionIndex(generateID());

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<AuthnContext> authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) builderFactory
                .getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
        AuthnContext authnContext = authnContextBuilder.buildObject();

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) builderFactory
                .getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        authnContext.setAuthnContextClassRef(authnContextClassRef);
        authnStatement.setAuthnContext(authnContext);
        assertion.getAuthnStatements().add(authnStatement);
    }

    private void buildAssertionConditions(Assertion assertion, String audienceURI) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<Conditions> conditionsBuilder = (SAMLObjectBuilder<Conditions>) builderFactory
                .getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
        Conditions conditions = conditionsBuilder.buildObject();
        conditions.setNotBefore(new DateTime());
        // TODO: Make the assertion TTL configurable.
        conditions.setNotOnOrAfter(new DateTime().plusMinutes(5));

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<AudienceRestriction> audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) builderFactory
                .getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<Audience> audienceBuilder = (SAMLObjectBuilder<Audience>) builderFactory
                .getBuilder(Audience.DEFAULT_ELEMENT_NAME);
        Audience audience = audienceBuilder.buildObject();
        audience.setAudienceURI(audienceURI);
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        assertion.setConditions(conditions);
    }

    private void buildAssertionSubject(Assertion assertion, AuthnRequest authnRequest, String nameIdStr) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) builderFactory
                .getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = subjectBuilder.buildObject();

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<NameID> nameIdBuilder = (SAMLObjectBuilder<NameID>) builderFactory
                .getBuilder(NameID.DEFAULT_ELEMENT_NAME);
        NameID nameId = nameIdBuilder.buildObject();
        nameId.setValue(nameIdStr);
        nameId.setFormat(NameIDType.UNSPECIFIED);
        subject.setNameID(nameId);

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) builderFactory
                .getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<SubjectConfirmationData> subjectConfirmationDataBuilder = (SAMLObjectBuilder<SubjectConfirmationData>) builderFactory
                .getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
        SubjectConfirmationData subjectConfirmationData = subjectConfirmationDataBuilder.buildObject();

        // TODO: Make this configurable.
        subjectConfirmationData.setNotOnOrAfter(new DateTime().plusMinutes(5));
        subjectConfirmationData.setInResponseTo(authnRequest.getID());
        subjectConfirmationData.setRecipient(authnRequest.getAssertionConsumerServiceURL());
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        // TODO: Add subject confirmation data. Should look like this:
        // <saml:SubjectConfirmationData NotOnOrAfter="2016-01-07T18:36:33Z"
        // Recipient="http://localhost:8080/uaa/saml/SSO/alias/cloudfoundry-saml-login"
        // InResponseTo="aad2f88932ji24c3fi86gga85f1173"
        // />
        subject.getSubjectConfirmations().add(subjectConfirmation);
        assertion.setSubject(subject);
    }

    private void buildStatusSuccess(Response response) {
        buildStatus(response, StatusCode.SUCCESS_URI);
    }

    private void buildStatus(Response response, String statusCodeStr) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory
                .getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(statusCodeStr);

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) builderFactory
                .getBuilder(Status.DEFAULT_ELEMENT_NAME);
        Status status = statusBuilder.buildObject();
        status.setStatusCode(statusCode);
        response.setStatus(status);
    }

    private void signAssertion(Assertion assertion, Credential credential)
            throws SecurityException, MarshallingException, SignatureException {
        SignatureBuilder signatureBuilder = (SignatureBuilder) builderFactory
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME);
        Signature signature = signatureBuilder.buildObject();
        signature.setSigningCredential(credential);

        SecurityHelper.prepareSignatureParams(signature, credential, null, null);
        assertion.setSignature(signature);

        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(assertion);
        marshaller.marshall(assertion);

        Signer.signObject(signature);
    }
}