#!/bin/bash

# install golang if not present
echo "[*] checking if golang is installed"
if ! [[ -x "$(command -v go)" ]]
then
	echo "[!] golang not installed, installing golang to /usr/local/"
	curl -O 'https://dl.google.com/go/go1.9.3.linux-amd64.tar.gz' ~/Downloads/go1.9.3.linux-amd64.tar.gz
	tar -C /usr/local -xzf ~/Downloads/go1.9.3.linux-amd64.tar.gz
	export PATH="$PATH:/usr/local/go/bin"
fi
echo "[+] golang is installed!"

echo "[*] changing gopath to current dir"
export GOPATH="$(pwd)"
echo "[*] installing go dependencies"
go get -u github.com/wayneashleyberry/terminal-dimensions
echo "[*] compiling project"
go build
echo "[*] linking to /usr/local/bin"
export PATH="$PATH:/usr/local/bin"
ln -s $(pwd)/cuttlefish /usr/local/bin/cuttlefish 
echo "[+] installation complete!"