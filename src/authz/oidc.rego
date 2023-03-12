# METADATA
# title: package to handle OIDC
# description: xyz
package oidc

import future.keywords.if

jwks := jwks_request("https://login.microsoftonline.com/common/discovery/v2.0/keys").body

jwks_request(url) := http.send({
  "url": url,
  "method": "GET",
  "force_cache": true,
  "force_cache_duration_seconds": 3600 # Cache response for an hour
})

bearer_token := token if {
	# Bearer tokens are contained inside of the HTTP Authorization header. This rule
	# parses the header and extracts the Bearer token value. If no Bearer token is
	# provided, the `bearer_token` value is undefined.
	v := input.headers.authorization
	startswith(v, "Bearer ")
	token := substring(v, count("Bearer "), -1)
}

# unverified -> extract key ID kid to get JWT public key jwk
headers := io.jwt.decode(bearer_token)[0]

jwk := jwks.keys[item] if {
	some item
	jwks.keys[item].kid == headers.kid
}

# METADATA
# title: verified claims form a JWT token
# description: Extract the payload of a JWT token after verification
claims := payload if {
	[valid, _, payload] := io.jwt.decode_verify(bearer_token, jwk)
	valid
}

username = claims.username
roles := claims.roles
