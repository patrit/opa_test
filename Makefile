build:
	opa build src --optimize=1 --entrypoint=authz -t wasm

test:
	opa test -v src && \
	opa test --coverage=true -v src > coverage.json

format:
	opa fmt -w src
