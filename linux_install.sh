#!/bin/bash

INSTALLDIR=`pwd`

# install golang if not present
echo "[*] checking if golang is installed"
if ! [[ -x "$(command -v go)" ]]
then
	echo "[!] golang not installed, installing golang to /usr/local/"
	cd ~/Downloads
	echo "[*] downloading golang install files temporarily to ~/Downloads"
	curl -O 'https://dl.google.com/go/go1.9.3.linux-amd64.tar.gz'
	sudo tar -C /usr/local -xzf ~/Downloads/go1.9.3.linux-amd64.tar.gz
	echo "[*] adding go binaries to PATH"
	echo 'export PATH="$PATH:/usr/local/go/bin"' >> ~/.bashrc
	source ~/.bashrc
	export PATH="$PATH:/usr/local/go/bin"
	echo "[*] PATH: $PATH"
fi
echo "[+] golang is installed!"
cd $INSTALLDIR
echo "[*] changing gopath to current dir"
echo 'export GOPATH=$INSTALLDIR' >> ~/.bashrc
source ~/.bashrc
export GOPATH=$(pwd)
echo "[*] GOPATH: $GOPATH"
echo "[*] installing go dependencies"
/usr/local/go/bin/go get -u github.com/wayneashleyberry/terminal-dimensions
/usr/local/go/bin/go get -u github.com/kardianos/osext
echo "[*] compiling project"
/usr/local/go/bin/go build
echo "[*] linking to /usr/local/bin"
echo 'export PATH="$PATH:/usr/local/bin"' >> ~/.bashrc
source ~/.bashrc
export PATH="$PATH:/usr/local/bin"
echo "[*] PATH: $PATH"
rm /usr/local/bin/cuttlefish
ln -s $INSTALLDIR/cuttlefish /usr/local/bin/cuttlefish 
echo "[*] cuttlefish: $(which cuttlefish)"
echo "[*] installing non-distro tools"
apt-get install gobuster -y
apt-get install ident-user-enum -y
echo "[*] downloading SecLists to ~/Documents/tools/"
mkdir ~/Documents/tools
cd ~/Documents/tools
git clone https://github.com/danielmiessler/SecLists
echo "[+] install info:"
echo "	[*] install dir: $INSTALLDIR"
echo "	[*] go binaries: $(which go)"
echo "	[*] GOPATH: $GOPATH"
echo "	[*] PATH: $PATH"
echo "	[*] cuttlefish: $(which cuttlefish)"
echo "[+] installation complete!"