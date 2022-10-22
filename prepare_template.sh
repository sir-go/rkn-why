#!/usr/bin/env bash

echo "package main
const pageTmpl = \`"`cat src/tmpl/out.html`"\`" > src/template.go
