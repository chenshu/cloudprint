cd /home/fred/pyinstaller-1.5.1
python Configure.py
python Makespec.py --onefile ~/code/cloudprint/cloudprint.py
python Build.py cloudprint/cloudprint.spec
cd /home/fred/code/cloudprint
tar -cvf templates.tar templates
mv templates.tar /home/fred/pyinstaller-1.5.1/cloudprint/dist
cd /home/fred/pyinstaller-1.5.1/cloudprint/dist
tar -cvf package.tar cloudprint templates.tar
/home/fred/code/cloudprint/pack.sh package.tar /home/fred/code/cloudprint/install.sh
mv package.tar.sh cloudprint.bin
rm -rf package.tar templates.tar cloudprint
cd ../
rm -rf cloudprint.spec build warncloudprint.txt
