package authz

import data.gwg.has_gwg_education

default allow := false

allow {
	input.path = ["users"]
	input.method = "POST"
}

allow {
	input.path = ["users", profile_id]
	input.method = "GET"
	profile_id = input.user_id
}

allow {
	has_gwg_education
}
