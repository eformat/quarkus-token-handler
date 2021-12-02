import {OAuthClient} from '../../oauth/oauthClient';

export interface RefreshProps {
    oauthClient: OAuthClient;
    onSessionExpired: () => void;
}
