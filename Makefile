build:
	opa build src --optimize=1 --entrypoint=authz -t wasm

test:
	opa test --coverage=true -v src > coverage.json
