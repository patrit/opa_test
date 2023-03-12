package edu

my_edu := {"K000001": ["gwg"], "K000002": ["zoomba"]}

test_has_gwg_education {
	has_gwg_education with input as {"user": "K000001"}
		with data.education as my_edu
}

test_has_no_gwg_education {
	not has_gwg_education with input as {"user": "K000002"}
		with data.education as my_edu
}

test_has_no_entry {
	not has_gwg_education with input as {"user": "K000003"}
		with data.education as my_edu
}
