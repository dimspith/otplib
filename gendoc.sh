#!env bash
dir=$(dirname "$0")
cd "$dir"
rm -rf "$dir"/htmldocs
nim doc --project --index:on --git.url:https://github.com/dimspith/otplib --outdir:htmldocs otplib.nim
