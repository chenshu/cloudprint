# !/bin/sh

[ $# != "2" ] && echo "Usage: pack.sh tarfile install.sh" && exit 0

INSCOUNT=`ls -l $2|awk '{print \$5}'`
INSCOUNT=`printf %08d $INSCOUNT`
dd if=$0 bs=1 skip=00000506 count=00000101|sed "s/\${INSTL}/$INSCOUNT/g"|dd of=$1.sh

dd if=$2 of=$1.sh bs=1 seek=00000101

OFFSET=`expr 00000101 + $INSCOUNT`
SKIP=`expr 00000506 + 00000101`
dd if=$0 of=$1.sh bs=1 seek=$OFFSET skip=$SKIP count=00000009

OFFSET=`expr $OFFSET + 00000009`
gzip -c $1 | dd of=$1.sh bs=1 seek=$OFFSET

chmod +x $1.sh
exit 0

# !/bin/sh

HEADSIZE=`expr 00000101 + 00000009 + ${INSTL}`

dd if=$0 bs=1 skip=$HEADSIZE|tar zxvf -


exit 0

