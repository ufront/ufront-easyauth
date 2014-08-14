#!/bin/sh

libname='ufront-easyauth'
rm -f "${libname}.zip"
zip -r "${libname}.zip" haxelib.json src LICENSE.txt README.md
echo "Saved as ${libname}.zip - please run git tag"
