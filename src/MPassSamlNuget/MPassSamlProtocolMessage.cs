using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace MPassSamlNuget
{
    public class MPassSamlProtocolMessage : AuthenticationProtocolMessage
    {
        public string RequestIssuer { get; set; }
        public string RequestID { get; set; }
        public string ResponseID { get; set; }
        public ISystemClock Clock { get; }
        public X509Certificate2 ServiceCertificate { get; set; }
        public X509Certificate2 IdentityProviderCertificate { get; set; }
        public TimeSpan SamlMessageTimeout { get; set; }

        public MPassSamlProtocolMessage(ISystemClock clock)
        {
            Clock = clock;
        }

        public string RelayState
        {
            get { return GetParameter(nameof(RelayState)); }
            set { SetParameter(nameof(RelayState), value); }
        }

        public string BuildAuthRequestForm(string assertionConsumerUrl)
        {
            const string authnRequestTemplate =
                @"<saml2p:AuthnRequest ID=""{0}"" Version=""2.0"" IssueInstant=""{1}"" Destination=""{2}"" AssertionConsumerServiceURL=""{3}"" xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion"">" +
                  @"<saml2:Issuer>{4}</saml2:Issuer>" +
                  @"<saml2p:NameIDPolicy AllowCreate=""true""/>" +
                @"</saml2p:AuthnRequest>";
            return SignAndEncode("SAMLRequest", String.Format(authnRequestTemplate, 
                RequestID, XmlConvert.ToString(Clock.UtcNow), IssuerAddress, assertionConsumerUrl, RequestIssuer));
        }

        public string BuildLogoutRequest(string nameID, string sessionIndex)
        {
            const string logoutRequestTemplate =
                @"<saml2p:LogoutRequest ID=""{0}"" Version=""2.0"" IssueInstant=""{1}"" Destination=""{2}"" xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion"">" +
                    @"<saml2:Issuer>{3}</saml2:Issuer>" +
                    @"<saml2:NameID>{4}</saml2:NameID>" +
                    @"<saml2p:SessionIndex>{5}</saml2p:SessionIndex>" +
                @"</saml2p:LogoutRequest>";

            return SignAndEncode("SAMLRequest", string.Format(logoutRequestTemplate, 
                RequestID, XmlConvert.ToString(Clock.UtcNow), IssuerAddress, RequestIssuer, nameID, sessionIndex));
        }

        public string BuildLogoutResponse(string responseID)
        {
            const string logoutResponseTemplate =
                @"<saml2p:LogoutResponse ID=""{0}"" Version=""2.0"" IssueInstant=""{1}"" Destination=""{2}"" InResponseTo=""{3}"" xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion"">" +
                    @"<saml2:Issuer>{4}</saml2:Issuer>" +
                    @"<saml2p:Status>" +
                        @"<saml2p:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/>" +
                    @"</saml2p:Status>" +
                @"</saml2p:LogoutResponse>";

            return SignAndEncode("SAMLResponse", string.Format(logoutResponseTemplate,
                responseID, XmlConvert.ToString(Clock.UtcNow), IssuerAddress, RequestID, RequestIssuer));
        }

        #region Parsing and Verification
        private XmlDocument LoadAndVerifyResponse(string samlResponse, string expectedDestination, IEnumerable<string> validStatusCodes, out XmlNamespaceManager ns)
        {
            var result = new XmlDocument();
            ns = new XmlNamespaceManager(result.NameTable);
            ns.AddNamespace("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");
            ns.AddNamespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

            result.LoadXml(Decode(samlResponse));
            var responseElement = result.DocumentElement;
            if (responseElement == null) throw new ApplicationException("SAML Response invalid");
            

            // verify Signature
            if (!Verify(result, IdentityProviderCertificate))
            {
                throw new ApplicationException("SAML Response signature invalid");
            }

            // verify IssueInstant
            var issueInstant = responseElement.GetAttribute("IssueInstant");
            if ((issueInstant == null) || ((Clock.UtcNow - XmlConvert.ToDateTimeOffset(issueInstant)).Duration() > SamlMessageTimeout))
            {
                throw new ApplicationException("SAML Response expired");
            }

            // verify Destination, according to [SAMLBind, 3.5.5.2]
            var responseDestination = responseElement.GetAttribute("Destination");
            if ((responseDestination == null) || !responseDestination.Equals(expectedDestination, StringComparison.CurrentCultureIgnoreCase))
            {
                throw new ApplicationException("SAML Response is not for this Service");
            }

            // verify InResponseTo
            if (responseElement.GetAttribute("InResponseTo") != RequestID)
            {
                throw new ApplicationException("SAML Response not expected");
            }

            // verify StatusCode
            var statusCodeValueAttribute = responseElement.SelectSingleNode("saml2p:Status/saml2p:StatusCode/@Value", ns);
            if (statusCodeValueAttribute == null)
            {
                throw new ApplicationException("SAML Response does not contain a StatusCode Value");
            }
            if (!validStatusCodes.Contains(statusCodeValueAttribute.Value, StringComparer.OrdinalIgnoreCase))
            {
                var statusMessageNode = responseElement.SelectSingleNode("saml2p:Status/saml2p:StatusMessage", ns);
                throw new ApplicationException($"Received failed SAML Response, status code: '{statusCodeValueAttribute.Value}', status message: '{statusMessageNode?.InnerText}'");
            }
            return result;
        }

        public ClaimsIdentity LoadAndVerifyLoginResponse(string samlResponse, string expectedDestination, out string sessionIndex)
        {
            var responseDoc = LoadAndVerifyResponse(samlResponse, expectedDestination, new[] { "urn:oasis:names:tc:SAML:2.0:status:Success" }, out var ns);

            // get to Assertion
            var assertionNode = responseDoc.SelectSingleNode("/saml2p:Response/saml2:Assertion", ns);
            if (assertionNode == null)
            {
                throw new ApplicationException("SAML Response does not contain an Assertion");
            }

            // verify Audience
            var audienceNode = assertionNode.SelectSingleNode("saml2:Conditions/saml2:AudienceRestriction/saml2:Audience", ns);
            if ((audienceNode == null) || (audienceNode.InnerText != RequestIssuer))
            {
                throw new ApplicationException("The SAML Assertion is not for this Service");
            }

            // get SessionIndex
            var sessionIndexAttribute = assertionNode.SelectSingleNode("saml2:AuthnStatement/@SessionIndex", ns);
            if (sessionIndexAttribute == null)
            {
                throw new ApplicationException("The SAML Assertion AuthnStatement does not contain a SessionIndex");
            }
            sessionIndex = sessionIndexAttribute.Value;

            // get to Subject
            var subjectNode = assertionNode.SelectSingleNode("saml2:Subject", ns);
            if (subjectNode == null)
            {
                throw new ApplicationException("No Subject found in SAML Assertion");
            }

            // verify SubjectConfirmationData, according to [SAMLProf, 4.1.4.3]
            var subjectConfirmationDataNode = subjectNode.SelectSingleNode("saml2:SubjectConfirmation/saml2:SubjectConfirmationData", ns) as XmlElement;
            if (subjectConfirmationDataNode == null)
            {
                throw new ApplicationException("No Subject/SubjectConfirmation/SubjectConfirmationData found in SAML Assertion");
            }
            if (!subjectConfirmationDataNode.GetAttribute("Recipient").Equals(expectedDestination, StringComparison.CurrentCultureIgnoreCase))
            {
                throw new ApplicationException("The SAML Response is not for this Service");
            }
            if (!subjectConfirmationDataNode.HasAttribute("NotOnOrAfter") || XmlConvert.ToDateTimeOffset(subjectConfirmationDataNode.GetAttribute("NotOnOrAfter")) < Clock.UtcNow)
            {
                throw new ApplicationException("Expired SAML Assertion");
            }

            // get NameID, which is normally an IDNP
            var nameIDNode = subjectNode.SelectSingleNode("saml2:NameID", ns);
            if (nameIDNode == null)
            {
                throw new ApplicationException("No Subject/NameID found in SAML Assertion");
            }

            // transform subject attributes to claims identity
            var identity = new ClaimsIdentity(MPassSamlDefaults.AuthenticationScheme, "Username", "Role");
            identity.AddClaim(new Claim("Username", nameIDNode.InnerText));

            foreach (XmlElement attributeElement in assertionNode.SelectNodes("saml2:AttributeStatement/saml2:Attribute", ns))
            {
                var attributeName = attributeElement.GetAttribute("Name");
                identity.AddClaims(attributeElement.SelectNodes("saml2:AttributeValue", ns)?.Cast<XmlElement>().Select(e => e.InnerXml).Select(value => new Claim(attributeName, value)));
            }
            return identity;
        }

        public string LoadAndVerifyLogoutRequest(string samlRequest, string expectedDestination, string expectedNameID, string expectedSessionIndex)
        {
            var result = new XmlDocument();
            result.LoadXml(Decode(samlRequest));

            // verify Signature
            if (!Verify(result, IdentityProviderCertificate))
            {
                throw new ApplicationException("LogoutRequest signature invalid");
            }

            var ns = new XmlNamespaceManager(result.NameTable);
            ns.AddNamespace("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");
            ns.AddNamespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

            // verify IssueInstant
            var issueInstantAttribute = result.SelectSingleNode("/saml2p:LogoutRequest/@IssueInstant", ns);
            if ((issueInstantAttribute == null) ||
                ((DateTime.UtcNow - XmlConvert.ToDateTime(issueInstantAttribute.Value, XmlDateTimeSerializationMode.Utc)).Duration() > SamlMessageTimeout))
            {
                throw new ApplicationException("The LogoutRequest is expired");
            }

            // verify Destination, according to [SAMLBind, 3.5.5.2]
            var requestDestination = result.SelectSingleNode("/saml2p:LogoutRequest/@Destination", ns);
            if ((requestDestination == null) || !requestDestination.Value.Equals(expectedDestination, StringComparison.CurrentCultureIgnoreCase))
            {
                throw new ApplicationException("The LogoutRequest is not for this Service");
            }

            // verify NameID
            var nameIDElement = result.SelectSingleNode("/saml2p:LogoutRequest/saml2:NameID", ns);
            if ((nameIDElement == null) || ((expectedNameID != null) && !nameIDElement.InnerText.Equals(expectedNameID, StringComparison.CurrentCultureIgnoreCase)))
            {
                throw new ApplicationException("The LogoutRequest received is for a different user");
            }

            // verify SessionIndex
            var sessionIndexElement = result.SelectSingleNode("/saml2p:LogoutRequest/saml2p:SessionIndex", ns);
            if ((sessionIndexElement == null) || ((expectedSessionIndex != null) && !sessionIndexElement.InnerText.Equals(expectedSessionIndex, StringComparison.CurrentCultureIgnoreCase)))
            {
                throw new ApplicationException("The LogoutRequest is not expected in this user session");
            }

            // get LogoutRequest ID
            var logoutRequestIDAttribute = result.SelectSingleNode("/saml2p:LogoutRequest/@ID", ns);
            if (logoutRequestIDAttribute == null)
            {
                throw new ApplicationException("LogoutRequest does not have an ID");
            }
            return logoutRequestIDAttribute.Value;
        }

        public void LoadAndVerifyLogoutResponse(string samlResponse, string expectedDestination)
        {
            LoadAndVerifyResponse(samlResponse, expectedDestination,
                new[] { "urn:oasis:names:tc:SAML:2.0:status:Success", "urn:oasis:names:tc:SAML:2.0:status:PartialLogout" }, out var ns);
        }
        #endregion

        #region Signature
        private string SignAndEncode(string samlParameter, string xml)
        {
            var doc = new XmlDocument();
            doc.LoadXml(xml);

            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(ServiceCertificate));

            var signedXml = new SignedXml(doc)
            {
                SigningKey = ServiceCertificate.PrivateKey,
                KeyInfo = keyInfo
            };
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;

            var messageID = doc.DocumentElement.GetAttribute("ID");
            var reference = new Reference("#" + messageID);
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            signedXml.AddReference(reference);

            signedXml.ComputeSignature();
            // insert after Issuer
            doc.DocumentElement.InsertAfter(signedXml.GetXml(), doc.DocumentElement.FirstChild);

            SetParameter(samlParameter, Encode(doc.OuterXml));
            return BuildFormPost();
        }
        #endregion

        private string Encode(string message)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(message));
        }

        private static string Decode(string message)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(message));
        }

        private static bool Verify(XmlDocument document, X509Certificate2 publicCertificate)
        {
            var signedXml = new SignedXml(document);
            var signatureNode = document.DocumentElement["Signature", "http://www.w3.org/2000/09/xmldsig#"];
            if (signatureNode == null) return false;
            signedXml.LoadXml(signatureNode);

            return signedXml.CheckSignature(publicCertificate, true);
        }

    }
}
