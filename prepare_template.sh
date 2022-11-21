#!/usr/bin/env bash

# todo: do it with go generate

echo "package main
const pageTmpl = \`"`cat src/tmpl/out.html`"\`" > src/template.go
