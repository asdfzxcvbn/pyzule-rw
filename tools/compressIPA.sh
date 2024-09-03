cd $TMPDIR
mkdir -p `dirname $OUTPUT`
rm $OUTPUT &> /dev/null
zip -r $OUTPUT Payload > /dev/null

