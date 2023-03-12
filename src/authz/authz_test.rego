package authz

test_post_allowed {
	allow with input as {"path": ["users"], "method": "POST"}
}

test_get_denied {
	not allow with input as {"path": ["users"], "method": "GET"}
}

test_get_user_allowed {
	allow with input as {"path": ["users", "bob"], "method": "GET", "user_id": "bob"}
}

test_get_another_user_denied {
	not allow with input as {"path": ["users", "bob"], "method": "GET", "user_id": "alice"}
}

test_has_gwg_education {
	allow
  	with data.gwg.has_gwg_education as true
}

test_has_gwg_education_no {
	not allow
  	with data.gwg.has_gwg_education as false
}

#todo_test_user_allowed_http_client_data {
#	false # Remember to test this later!
#}

