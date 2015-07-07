/**
 * 
 */
package org.keysupport.shibboleth.idp.x509;

import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.keysupport.bc.scvp.ExampleSCVPClient;
import org.keysupport.bc.scvp.SCVPException;
import org.keysupport.util.DataUtil;
import org.opensaml.security.SecurityException;
import org.opensaml.security.trust.TrustEngine;
import org.opensaml.security.x509.X509Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Todd E. Johnson
 * Based on example from: https://gist.github.com/serac/e3c33ebf83a99f8423f3#file-policytrustengine-java
 * @author Marvin S. Addison
 */
public class SCVPTrustEngine implements TrustEngine<X509Credential> {

	/**
	 * Logger instance.
	 */
	private final Logger logger = LoggerFactory
			.getLogger(SCVPTrustEngine.class);

	/**
	 * The URL for the SCVP server/service
	 */
	private final String scvpServerURL;

	/**
	 * Requisite policies that must be satisfied.
	 */
	private final List<String> requiredPolicyOids;

	/**
	 * Creates a new trust engine instance that enforces existence of given
	 * policy OIDs on candidate certificates.
	 * 
	 * @param policyOids
	 *            List of certificate policy OIDs that will be used as the
	 *            initial policy set for the SCVP request.
	 */
	public SCVPTrustEngine(@NotEmpty String serverURL,
			@NotEmpty final List<String> policyOids) {
		scvpServerURL = (String) Constraint.isNotEmpty(serverURL,
				"Server URK cannot be null or empty");
		requiredPolicyOids = (List<String>) Constraint.isNotEmpty(policyOids,
				"Policy OIDs cannot be null or empty");

	}

	@Override
	public boolean validate(@Nonnull X509Credential x509Credential,
			@Nullable CriteriaSet criterions) throws SecurityException {

		Provider jceProvider = new BouncyCastleProvider();
		Security.addProvider(jceProvider);
		ExampleSCVPClient client = new ExampleSCVPClient(jceProvider);

		boolean acceptableCert = false;
		X509Certificate eeCert = x509Credential.getEntityCertificate();
		logger.info("Preparing for SCVP validation for certificate Subject: "
				+ eeCert.getSubjectX500Principal().getName());
		/*
		 * Adding DER encoded Request and Response in HEX for troubleshooting.
		 */
		logger.debug("SCVP Request: "
				+ DataUtil.byteArrayToString(client.getFullRequest()));
		logger.debug("SCVP Response: "
				+ DataUtil.byteArrayToString(client.getFullResponse()));
		try {
			acceptableCert = client.validate(scvpServerURL, eeCert,
					requiredPolicyOids);
		} catch (SCVPException e) {
			throw new SecurityException("Error with SCVP Client: "
					+ e.getLocalizedMessage());
		}
		return acceptableCert;
	}

}
