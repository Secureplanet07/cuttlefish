#!/bin/bash

if ! [[ -x "$(command -v go)" ]]
then
	echo "[!] you need to install go first"
	echo "[!] run ./linux_install.sh"
fi

if ! [[ -x "$(command -v cuttlefish)" ]]
then
	echo "[!] you need to install cuttlefish first"
	echo "[!] run ./linux_install.sh"
fi

export GOPATH=`pwd`
echo "[*] pulling new version"
git pull
echo "[*] compiling new version"
go build
echo "[+] done!"