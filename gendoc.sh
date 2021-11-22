#!env bash
dir=$(dirname "$0")
cd "$dir"
rm -rfI "$dir"/htmldocs
nim doc --project --index:on --git.url:https://github.com/dimspith/otplib --outdir:htmldocs src/otplib.nim
