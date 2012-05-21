tar -xvf templates.tar
rm -rf templates.tar
mkdir -p /etc/cloudprint
rm -rf /etc/cloudprint/templates
mv templates /etc/cloudprint
mv cloudprint /sbin/
