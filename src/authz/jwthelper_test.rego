package jwthelper

import future.keywords.in

secret = "foo"
secret64 = base64url.encode_no_pad(secret)

test_jwt_io_hs256 {    
    # Encode and sign same token. Note, however, that the result is different.
    # The reason is that the encode_sign function is not using "compact" encoding of the header or payload objects.
    result_hs256 := io.jwt.encode_sign({"alg":"HS256", "typ":"JWT"}, {"username": "dude"}, {"kty":"oct","k":secret64})
    #result_parts_hs256 := io.jwt.decode_verify(result_hs256, {"secret": secret})
    #result_valid_hs256 := io.jwt.verify_hs256(result_hs256, secret)

    [_, payload, _] := io.jwt.decode(result_hs256)
    payload.username == "dude"
}

my_claim := {"name":"Random Dude","roles":["role001","role002"],"username": "B000001"}
my_input = {
  "headers": {
    "authorization": concat(" ", ["Bearer", io.jwt.encode_sign(
      {"alg":"HS256", "typ":"JWT"},
      my_claim,
      {"kty":"oct","k":secret64})])
  }
}

test_decode_claims {
  c := claims
    with input as my_input
  c == my_claim
}

test_decode_claims_username {
  u := username
    with input as my_input
  u == "B000001"
}

test_decode_claims_roles {
  r := roles
    with input as my_input
  "role001" in r
}