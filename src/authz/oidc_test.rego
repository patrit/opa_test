package oidc

import future.keywords.in


now_ns := time.now_ns()
now_s := floor(now_ns / 1000000000)
my_claim := {
  "name":  "Random Dude",
  "roles": ["role001","role002"],
  "username": "dude",
  "iss": "my_iss",
  "sub": "mailto:dude@no.where",
  "nbf": now_s, # not before
  "exp": now_s + 3600, # expires in 1h
  "iat": now_s, # jwt creation time
  "jti": "jti666"
}
# pem ceriticates defined below
my_jwk := crypto.x509.parse_rsa_private_key(cert_private)
my_header := {"alg": "RS256", "typ":"JWT", "kid": "key001"}
my_jwt := io.jwt.encode_sign(my_header, my_claim, my_jwk)

test_rs256_verify {
  io.jwt.verify_rs256(my_jwt, cert_public)
}

test_rs256_decode {
  [header, payload, _] := io.jwt.decode(my_jwt)
  header.alg == "RS256"
  payload.username == "dude"
}

test_rs256_decode_verify {
  [valid, header, payload] := io.jwt.decode_verify(my_jwt, {"cert": cert_public})
  header.alg == "RS256"
  payload.username == "dude"
  valid
}

test_alg_correct {
  [valid, _, _] := io.jwt.decode_verify(my_jwt, {"cert": cert_public, "alg": "RS256"})
  valid
}

test_alg_unknown {
  [valid, _, _] := io.jwt.decode_verify(my_jwt, {"cert": cert_public, "alg": "UNKNOWN"})
  not valid
}

test_alg_mismatch {
  [valid, _, _] := io.jwt.decode_verify(my_jwt, {"cert": cert_public, "alg": "RS512"})
  not valid
}

test_iss_missing {
  claim = {}
  jwt := io.jwt.encode_sign(my_header, claim, my_jwk)
  [valid, _, _] := io.jwt.decode_verify(jwt, {"cert": cert_public})
  valid
}

test_iss_wrong {
  claim = {"iss": "wrong"}
  jwt := io.jwt.encode_sign(my_header, claim, my_jwk)
  [valid, _, _] := io.jwt.decode_verify(jwt, {"cert": cert_public, "iss": "foo"})
  not valid
}

test_iss_correct {
  claim = {"iss": "correct"}
  jwt := io.jwt.encode_sign(my_header, claim, my_jwk)
  [valid, _, _] := io.jwt.decode_verify(jwt, {"cert": cert_public, "iss": "correct"})
  valid
}

test_time_lower {
  [valid, _, _] := io.jwt.decode_verify(my_jwt, {"cert": cert_public, "time": now_ns - 10000000000})
  not valid
}

test_time_upper {
  [valid, _, _] := io.jwt.decode_verify(my_jwt, {"cert": cert_public, "time": now_ns + 3601000000000})
  not valid
}

test_time_correct {
  [valid, _, _] := io.jwt.decode_verify(my_jwt, {"cert": cert_public, "time": now_ns + 10000000000})
  valid
}

test_nbf_not_yet_achieved {
  claim = {"nbf": now_s + 100, "exp": now_s + 101}
  jwt := io.jwt.encode_sign(my_header, claim, my_jwk)
  [valid, _, _] := io.jwt.decode_verify(jwt, {"cert": cert_public})
  not valid
}

test_exp_achieved {
  claim = {"nbf": now_s - 2, "exp": now_s - 1}
  jwt := io.jwt.encode_sign(my_header, claim, my_jwk)
  [valid, _, _] := io.jwt.decode_verify(jwt, {"cert": cert_public})
  not valid
}

test_nbf_exp_within {
  claim = {"nbf": now_s - 2, "exp": now_s + 10}
  jwt := io.jwt.encode_sign(my_header, claim, my_jwk)
  [valid, _, _] := io.jwt.decode_verify(jwt, {"cert": cert_public})
  valid
  [valid2, _, _] := io.jwt.decode_verify(jwt, {"cert": cert_public, "time": now_ns})
  valid2
}

test_aud_verify {
  claim = {"aud": "http://no.where"}
  jwt := io.jwt.encode_sign(my_header, claim, my_jwk)
  [valid, _, _] := io.jwt.decode_verify(jwt, {"cert": cert_public, "aud": "http://no.where"})
  valid
}

test_aud_wrong {
  claim = {"aud": "http://no.where"}
  jwt := io.jwt.encode_sign(my_header, claim, my_jwk)
  [valid, _, _] := io.jwt.decode_verify(jwt, {"cert": cert_public, "aud": "http://some.where"})
  not valid
}

test_aud_missing_twice {
  claim = {}
  jwt := io.jwt.encode_sign(my_header, claim, my_jwk)
  [valid, _, _] := io.jwt.decode_verify(jwt, {"cert": cert_public})
  valid
}

test_aud_verify_missing {
  claim = {}
  jwt := io.jwt.encode_sign(my_header, claim, my_jwk)
  [valid, _, _] := io.jwt.decode_verify(jwt, {"cert": cert_public, "aud": "missing"})
  not valid
}

# test using the oidc package
mock_http_send(_) := {"body": {"keys": [{"kid": "key001", "cert": cert_public}, {"kid": "key002"}]}}
mock_input := {"headers": {"authorization": sprintf("Bearer %s", [my_jwt])}}

test_oidc_bearer_token {
  t := bearer_token
    with input as mock_input
  t == my_jwt
}

test_oidc_bearer_token_unextractable {
  not bearer_token
    with input as {"headers": {"authorization": sprintf("Invalid %s", [my_jwt])}}
}

# METADATA
# description: test that the correct key id is extracted from the JWT
test_oidc_kid {
  k := headers.kid
    with input as mock_input
  k == "key001"
}

test_oidc_kid_not_existing {
  jwt := io.jwt.encode_sign({"alg": "RS256"}, {}, my_jwk)
  not headers.kid
    with input as {"headers": {"authorization": sprintf("Bearer %s", [jwt])}}
}

test_oidc_jwk {
  k := jwk
    with http.send as mock_http_send
    with input as mock_input
  k.kid == "key001"
}

test_oidc_jwk_with_empty_jwks {
  not jwk
    with jwks as {"keys": []}
    with input as mock_input
}

test_oidc_username {
  c := username
    with jwk as {"cert": cert_public}
    with input as mock_input
  c == "dude"
}

test_oidc_roles {
  c := roles
    with jwk as {"cert": cert_public}
    with input as mock_input
  c == ["role001","role002"]
}


# openssl genrsa -out jwtRSA256-private.pem 2048
# openssl rsa -in jwtRSA256-private.pem -pubout -outform PEM -out jwtRSA256-public.pem
# cat jwtRSA256-private.pem
cert_private := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC24rTAJ8W9zWbg
0Dicm4zvQI12GsvPEFHL0Gp+enEZCVR7RsRu8ADkYflQ6zkPgxS89swmYl84f/XJ
JPjYwDxFCFrqpZy6+3N7O4K5rmAaPSeFhYWI3jrUvU1hdd2OoS3/QWcNa3OWIgDT
uDtGKfz2RUjKVamhR1xqTWtKzTPXPGklVCF3yqvEeOGPpT7BBC0oEhI3MlNgnT1e
UQ69/7/DEfte2MVOMbdcGAHFvgKSCYAN4myfBdLq8TDK/lRc3I9nx9U5QAYQCNLG
tEHwL+vDopCHpkbNl5MWEXsHHkO/PAdQIap15Y1gsXoVlwTwo/perpPSmlkZOY5d
9E41LcsJAgMBAAECggEASECFf1rXLPaum8e3beuoQMdke9H3Tf1ZC2fyArjV4LnG
ZhOdvGRWPeQVDup3NxEmysbH/awkiVpIXKieJWfBB9bWsFgwdNCtnXRz326sKgGa
EQ6gpGODo5OMNCJQHy6/UNZiY7NdTWVupTZmOICTHypdKQ6xvvVF5ftjFYC/Z9sa
TpyX053HJD34SUMyuuDrXYq+fkR2MMbMKaAjn5hGEVIT6YBIWK8jwWkQdBzBTy75
Z+yFC+3DTFljQZpktuu/rkmWp4VgcYEnudXI9f2wsaHm8VVF+eUyN4rwNgcRb4ZJ
Nq7A7jTjU7Xn9aQx0XfqbDjbfhZdBYGE2JwSsOZm7wKBgQDz64kuFGpp2L5HF5PH
IZrBTA/HvtN7n10Jm/Pu5kFzs+vBqW1mpjiyZ/BB3vglxegO4WdQvi6043PvB6k+
/FkN97a6QF2V0KsgThzq+4TRe0n/3vRoXhmCsKqXj/dath+reNjJ42UyNJi9OZrc
RGtHfsWW2F0ILIBsO1X9YkfqSwKBgQC/8V0Ow62rIK4LzRwrpGD10aLOyxlTJcBk
o3AZzyHmvKmA1oP+8PyKNLeIo5IuhwFB9lzkrCMnewMSdjL7zhdhezUPv7haYLNQ
oBOSdd2gIp6cmcM+Msq5mh140zdE9oFi0Rw9SDG+9H9VMv4jArWWdjiD90ofyl0v
0XGMJ00LewKBgAY/v4j1rvA9REqv+PI+EyfmmfTlF6fwIkMPwsUZEw4yytRwUcQy
d/tiHE6jtrnJAzP2ZF42MR4jQaIbESPy9RkdgontAjjHWsr+FVGT1ghD31Z10M8n
sgGeIxC0+IJTbiZHd05czAfoPw2B/0yrWBBB2DAQJPoDodqj/oT6UptXAoGAF60a
IXwZrAY38dS3KNr56tiVEJUU5qC9fqx6Y3SdZezXq8DKP2RSgmnGSeCDY6Hbkdtl
0f85xuDxnBFgcJcXYzrjbLHld6B9/fAA+gv37ozWq9J7tuxk/Uf5YrILG0Kc6yeI
KDcDi9505nmHx6HJ7Glgx0Z1qj44CHH5Y6RlaIkCgYEA0m4tY8yqo5hlaVmjXgor
iHSlwA9b+TXgS/wcCewfubKuXA9p9hiirYkHxnz/mkurWxZdLlntqPgNAfvW/41/
n9eGWnc5PD+51vlLb1DSFu3aIeLmuM+8UbMCxguqA9/iTIHHR7NO76CHsq1OGCBM
jwM3QTNogwT6l3iTxYhmg2I=
-----END PRIVATE KEY-----`

# cat jwtRSA256-public.pem
cert_public := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtuK0wCfFvc1m4NA4nJuM
70CNdhrLzxBRy9BqfnpxGQlUe0bEbvAA5GH5UOs5D4MUvPbMJmJfOH/1yST42MA8
RQha6qWcuvtzezuCua5gGj0nhYWFiN461L1NYXXdjqEt/0FnDWtzliIA07g7Rin8
9kVIylWpoUdcak1rSs0z1zxpJVQhd8qrxHjhj6U+wQQtKBISNzJTYJ09XlEOvf+/
wxH7XtjFTjG3XBgBxb4CkgmADeJsnwXS6vEwyv5UXNyPZ8fVOUAGEAjSxrRB8C/r
w6KQh6ZGzZeTFhF7Bx5DvzwHUCGqdeWNYLF6FZcE8KP6Xq6T0ppZGTmOXfRONS3L
CQIDAQAB
-----END PUBLIC KEY-----`