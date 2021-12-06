#!/bin/bash

#set -x

# Requires openssl, nodejs, jq, base64

kid=${1:-$(openssl rand -hex 16)}

header='
{
  "alg": "RS256"
}'

header=$(echo "{\"kid\":\"$kid\"}" $header | jq -cs add)

payload='
{
  "sub": "bff_client",
  "iss": "bff_client",
  "aud": "https://localhost:8443/auth/realms/bff_client",
  "typ": "RegistrationAccessToken",
  "registration_auth": "authenticated"
}'

jti=$(openssl rand -hex 4)-$(openssl rand -hex 2)-$(openssl rand -hex 2)-$(openssl rand -hex 2)-$(openssl rand -hex 4)

# Use jq to set the dynamic `iat` and `exp`
# fields on the header using the current time.
# `iat` is set to now, and `exp` is now + 100 second.
payload=$(
    echo "${payload}" | jq --arg jti $jti --arg time_str "$(date +%s)" \
    '
    ($time_str | tonumber) as $time_num
    | .iat=$time_num
    | .exp=($time_num + 100)
    | .jti=$jti
    '
)

base64_encode()
{
    declare input=${1:-$(</dev/stdin)}
    # Use `tr` to URL encode the output from base64.
    printf '%s' "${input}" | base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n'
}

json() {
    declare input=${1:-$(</dev/stdin)}
    printf '%s' "${input}" | jq -c .
}

hmacsha256_sign()
{
    declare input=${1:-$(</dev/stdin)}
    printf '%s' "${input}" | openssl dgst -binary -sha256 -hmac "${secret}"
}

if [ ! -f bff-client-pkcs8.key ]; then
  # Private and Public keys
  openssl genrsa -out bff-client.key 2048
  #openssl genpkey -algorithm RSA -out bff-client.key -pkeyopt rsa_keygen_bits:2048
  #openssl pkcs8 -topk8 -nocrypt -inform pem -in bff-client.key -outform pem -out bff-client-pkcs8.key
  #openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_mgf1_md:sha256 -pkeyopt rsa_pss_keygen_saltlen:32 -out bff-client.key
  #openssl genpkey -algorithm RSA -out bff-client.key -pkeyopt rsa_keygen_bits:2048
  openssl rsa -pubout -in bff-client.key -out bff-client.pem
fi

header_base64=$(echo "${header}" | json | base64_encode)
payload_base64=$(echo "${payload}" | json | base64_encode)

header_payload=$(echo "${header_base64}.${payload_base64}")
signature=$(echo "${header_payload}" | hmacsha256_sign | base64_encode)

# Export JWT
echo "${header_payload}.${signature}" > jwt.txt

# Create JWK from public key
if [ ! -d ./node_modules/pem-jwk ]; then
  # A tool to convert PEM to JWK
  npm install pem-jwk
fi

#echo "--- JWT Private ---"
#cat jwt.txt

jwk=$(./node_modules/.bin/pem-jwk bff-client.key)
# Add additional fields
jwk=$(echo '{"use":"sig"}' $jwk $header | jq -cs add)
# Export JWK
echo '{"keys":['$jwk']}'| jq . > jwks-private.json
#echo -e "\n--- JWK Private ---"
#jq . jwks-private.json
jwk=$(./node_modules/.bin/pem-jwk bff-client.pem)
# Add additional fields
jwk=$(echo '{"use":"sig"}' $jwk $header | jq -cs add)
# Export JWK
echo '{"keys":['$jwk']}'| jq . > jwks-public.json

#echo -e "\n--- JWK Public ---"
#jq . jwks-public.json
