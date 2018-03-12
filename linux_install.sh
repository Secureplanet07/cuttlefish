#!/bin/bash

INSTALLDIR=`pwd`

# install golang if not present
echo "[*] checking if golang is installed"
if ! [[ -x "$(command -v go)" ]]
then
	echo "[!] golang not installed, installing golang to /usr/local/"
	cd ~/Downloads
	curl -O 'https://dl.google.com/go/go1.9.3.linux-amd64.tar.gz'
	sudo tar -C /usr/local -xzf ~/Downloads/go1.9.3.linux-amd64.tar.gz
	echo 'PATH="$PATH:/usr/local/go/bin"' >> ~/.bashrc
	source ~/.bashrc
fi
echo "[+] golang is installed!"
cd $INSTALLDIR
echo "[*] changing gopath to current dir"
export GOPATH=$INSTALLDIR
echo "[*] installing go dependencies"
go get -u github.com/wayneashleyberry/terminal-dimensions
echo "[*] compiling project"
go build
echo "[*] linking to /usr/local/bin"
echo 'PATH="$PATH:/usr/local/bin"' >> ~/.bashrc
source ~/.bashrc
ln -s $(pwd)/cuttlefish /usr/local/bin/cuttlefish 
echo "[*] installing non-distro tools"
apt-get install gobuster
echo "[*] downloading SecLists to ~/Documents/tools/"
mkdir ~/Documents/tools
cd ~/Documents/tools
git clone https://github.com/danielmiessler/SecLists
echo "[+] installation complete!"