#!/bin/bash

##############################################################
# Basic automation to get tokens from the Authorization Server
##############################################################

BFF_API_BASE_URL='https://api.example.com:9443/tokenhandler'
WEB_BASE_URL='https://www.example.com'
AUTHORIZATION_SERVER_BASE_URL='https://login.example.com:8443'
REALM_NAME=bff
RESPONSE_FILE=data/response.txt
LOGIN_COOKIES_FILE=data/login_cookies.txt
KEYCLOAK_COOKIES_FILE=data/keycloak_cookies.txt
MAIN_COOKIES_FILE=data/main_cookies.txt
TEST_USERNAME=user
TEST_PASSWORD=password
CLIENT_ID=bff_client
#export http_proxy='http://127.0.0.1:8888'

#
# Ensure that we are in the folder containing this script
#
cd "$(dirname "${BASH_SOURCE[0]}")"

#
# Get a header value from the HTTP response file
#
function getHeaderValue(){
  local _HEADER_NAME=$1
  local _HEADER_VALUE=$(cat $RESPONSE_FILE | grep -i "^$_HEADER_NAME" | sed -r "s/^$_HEADER_NAME: (.*)$/\1/i")
  local _HEADER_VALUE=${_HEADER_VALUE%$'\r'}
  echo $_HEADER_VALUE
}

#
# Pattern matching to dig out a field value from an auto submit HTML form, via the second pattern match
#
function getHtmlFormValue(){
  local _FIELD_NAME=$1
  local _FIELD_LINE=$(cat $RESPONSE_FILE | grep -i $_FIELD_NAME)
  local _FIELD_VALUE=$(echo $_FIELD_LINE | sed -r "s/^.*$_FIELD_NAME=([_a-zA-Z0-9-]*)[&amp;|\"]+.*$/\1/i")
  echo $_FIELD_VALUE
}

#
# Temp data is stored in this folder
#
mkdir -p data

#
# First get the authorization request URL
#
HTTP_STATUS=$(curl -k -i -s -X POST "$BFF_API_BASE_URL/login/start" \
-H "origin: $WEB_BASE_URL" \
-H 'content-type: application/json' \
-H 'accept: application/json' \
-c $LOGIN_COOKIES_FILE \
-o $RESPONSE_FILE -w '%{http_code}')
if [ "$HTTP_STATUS" == '000' ]; then
  echo '*** Connectivity problem encountered, please check endpoints and whether an HTTP proxy tool is running'
  exit 1
fi
if [ "$HTTP_STATUS" != '200' ]; then
  echo "*** Start login failed with status $HTTP_STATUS"
  exit 1
fi
JSON=$(tail -n 1 $RESPONSE_FILE)
echo $JSON | jq
AUTHORIZATION_REQUEST_URL=$(jq -r .authorizationRequestUrl <<< "$JSON")


#
# Follow redirects until the login HTML form is returned and save cookies
#
HTTP_STATUS=$(curl -k -i -L -s -X GET "$AUTHORIZATION_REQUEST_URL" \
-c $KEYCLOAK_COOKIES_FILE \
-o $RESPONSE_FILE -w '%{http_code}')
if [ $HTTP_STATUS != '200' ]; then
  echo "*** Problem encountered during an OpenID Connect authorization redirect, status: $HTTP_STATUS"
  exit 1
fi

SESSION_CODE=$(getHtmlFormValue session_code)
EXECUTION=$(getHtmlFormValue execution)
TAB_ID=$(getHtmlFormValue tab_id)

echo "SESSION_CODE:" ${SESSION_CODE}
echo "EXECUTION:" ${EXECUTION}
echo "TAB_ID:" ${TAB_ID}

#
# Login using kc form flow response should be a redirect with code and session state
#
HTTP_STATUS=$(curl -k -i -s -X POST "$AUTHORIZATION_SERVER_BASE_URL/auth/realms/$REALM_NAME/login-actions/authenticate?client_id=$CLIENT_ID&session_code=$SESSION_CODE&execution=$EXECUTION&tab_id=$TAB_ID" \
-H 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode "username=$TEST_USERNAME" \
--data-urlencode "password=$TEST_PASSWORD" \
-b $KEYCLOAK_COOKIES_FILE \
-c $KEYCLOAK_COOKIES_FILE \
-o $RESPONSE_FILE -w '%{http_code}')
if [ $HTTP_STATUS != '302' ]; then
  echo "*** Problem encountered starting code grant flow, status: $HTTP_STATUS"
  exit 1
fi

#
# Read the response details
#
APP_URL=$(getHeaderValue 'location')
if [ "$APP_URL" == '' ]; then
  echo '*** API driven login did not complete successfully'
  exit 1
fi
PAGE_URL_JSON='{"pageUrl":"'$APP_URL'"}'
echo $PAGE_URL_JSON | jq

#
# End the login by swapping the code for tokens
#
HTTP_STATUS=$(curl -k -i -s -X POST "$BFF_API_BASE_URL/login/end" \
-H "origin: $WEB_BASE_URL" \
-H 'content-type: application/json' \
-H 'accept: application/json' \
-c $MAIN_COOKIES_FILE \
-b $LOGIN_COOKIES_FILE \
-d $PAGE_URL_JSON \
-o $RESPONSE_FILE -w '%{http_code}')
if [ "$HTTP_STATUS" != '200' ]; then
  echo "*** Problem encountered ending the login, status $HTTP_STATUS"
  JSON=$(tail -n 1 $RESPONSE_FILE) 
  echo $JSON | jq
  exit 1 
fi
JSON=$(tail -n 1 $RESPONSE_FILE) 
echo $JSON | jq
IS_LOGGED_IN=$(jq -r .isLoggedIn <<< "$JSON")
HANDLED=$(jq -r .handled <<< "$JSON")
if [ "$IS_LOGGED_IN" != 'true'  ] || [ "$HANDLED" != 'true' ]; then
   echo '*** End login returned an unexpected payload'
   exit 1
fi

exit 0