import { Meteor } from 'meteor/meteor';

import { Users } from '../../models/server';
import { SAMLServiceProvider } from './lib/ServiceProvider';
import { SAMLUtils } from './lib/Utils';

Meteor.methods({
	samlLogout(provider: string) {
		// Make sure the user is logged in before we initiate SAML Logout
		if (!Meteor.userId()) {
			throw new Meteor.Error('error-invalid-user', 'Invalid user', { method: 'samlLogout' });
		}
		if (!provider) {
			throw new Meteor.Error('no-saml-provider', 'SAML internal error', {
				method: 'getSamlServiceProviderOptions',
			});
		}

		const providerConfig = SAMLUtils.getSamlServiceProviderOptions(provider);

		SAMLUtils.log(`Logout request from ${ JSON.stringify(providerConfig) }`);
		// This query should respect upcoming array of SAML logins
		const user = Users.getSAMLByIdAndSAMLProvider(Meteor.userId(), provider);
		if (!user || !user.services || !user.services.saml) {
			return;
		}

		const { nameID, idpSession } = user.services.saml;
		SAMLUtils.log(`NameID for user ${ Meteor.userId() } found: ${ JSON.stringify(nameID) }`);

		const _saml = new SAMLServiceProvider(providerConfig);

		const request = _saml.generateLogoutRequest({
			nameID: nameID || idpSession,
			sessionIndex: idpSession,
		});

		SAMLUtils.log('----Logout Request----');
		SAMLUtils.log(request);

		// request.request: actual XML SAML Request
		// request.id: comminucation id which will be mentioned in the ResponseTo field of SAMLResponse

		Users.setSamlInResponseTo(Meteor.userId(), request.id);

		const result = _saml.syncRequestToUrl(request.request, 'logout');
		SAMLUtils.log(`SAML Logout Request ${ result }`);

		return result;
	},
});
