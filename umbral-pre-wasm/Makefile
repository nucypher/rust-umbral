SHELL = /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := build
.DELETE_ON_ERROR:
.SUFFIXES:

build: pkg

pkg: src
	wasm-pack build
	# temporary fix for https://github.com/rustwasm/wasm-pack/issues/427
	# (setting a custom package name)
	sed -i ".bak" -e 's/"name": "umbral-pre-wasm"/"name": "umbral-pre"/g' pkg/package.json
	# Temporary fix for https://github.com/rustwasm/wasm-pack/issues/922
	# (adding missing package files to the manifest)
	sed -i ".bak" -e 's/"umbral_pre_wasm_bg.wasm"/"umbral_pre_wasm_bg.wasm", "umbral_pre_wasm_bg.js", "umbral_pre_wasm_bg.wasm.d.ts"/g' pkg/package.json
	# Add keywords
	sed -i ".bak" -e 's/"sideEffects": false/"sideEffects": false, "keywords": ["umbral", "nucypher"]/g' pkg/package.json
	rm pkg/package.json.bak
