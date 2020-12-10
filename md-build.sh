
#!/bin/bash

filename=$1
BASENAME=${filename%.*}

mmark $filename > $BASENAME.xml
`which xml2rfc` --legacy --html $BASENAME.xml
`which xml2rfc` --legacy --text $BASENAME.xml