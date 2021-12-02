import React, {useState} from 'react';
import {RemoteError} from '../../utilities/remoteError';
import {RefreshProps} from './refreshProps';
import {RefreshState} from './refreshState';

export function RefreshView(props: RefreshProps) {

    const [state, setState] = useState<RefreshState>({
        error: null,
    });

    function isButtonDisabled(): boolean {
        return false;
    }
    
    async function execute() {

        try {

            await props.oauthClient.refresh();

        } catch (e) {

            const remoteError = e as RemoteError;
            if (remoteError) {

                // Permanent 401s, which include a refresh attempt, mean the session is expired
                if (remoteError.getStatus() === 401) {
                    
                    props.onSessionExpired();

                } else {
                
                    setState((state: any) => {
                        return {
                            ...state,
                            welcomeMessage: '',
                            error: remoteError.toDisplayFormat(),
                        };
                    });
                }
            }
        }
    }

    return (
        <div className='container'>
            <h2>Refresh</h2>
            <p>The SPA asks the API for to refresh encrypted cookies using the refresh token</p>
            <button 
                id='signOut' 
                className='btn btn-primary operationButton'
                onClick={execute}
                disabled={isButtonDisabled()}>
                    Refresh
            </button>
            {state && state.error &&
            <div>
                <p className='alert alert-danger' id='signOutErrorResult'>{state.error}</p>
            </div>}
            <hr/>
        </div>
    )
}
