tar -xvf templates.tar
rm -rf templates.tar
mkdir -p /var/run/cloudprint
rm -rf /var/run/cloudprint/templates
mv templates /var/run/cloudprint
mv cloudprint /sbin/
