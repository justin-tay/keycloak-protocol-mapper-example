package com.example.keycloak.protocol.oidc.mappers;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

public class ClientSessionNoteMapper extends AbstractOIDCProtocolMapper
		implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

	public static final String PROVIDER_ID = "oidc-clientsessionmodel-note-mapper";

	private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

	static {
		ProviderConfigProperty property;
		property = new ProviderConfigProperty();
		property.setName("client.session.note");
		property.setLabel("Client Session Note");
		property.setHelpText("Name of stored client session note within the ClientSessionModel.note map");
		property.setType(ProviderConfigProperty.STRING_TYPE);
		configProperties.add(property);

		OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
		OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, ClientSessionNoteMapper.class);
	}

	@Override
	public String getDisplayCategory() {
		return TOKEN_MAPPER_CATEGORY;
	}

	@Override
	public String getDisplayType() {
		return "Client Session Note";
	}

	@Override
	public String getHelpText() {
		return "Map a custom client session note to a token claim.";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return configProperties;
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
			KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
		String noteName = mappingModel.getConfig().get("client.session.note");
		String noteValue = clientSessionCtx.getClientSession().getNote(noteName);
		if (noteValue == null) {
			// Attempt with the prefix
			noteValue = clientSessionCtx.getClientSession()
					.getNote(AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + noteName);
		}
		if (noteValue != null) {
			OIDCAttributeMapperHelper.mapClaim(token, mappingModel, noteValue);
		}
	}
}