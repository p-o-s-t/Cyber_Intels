#! /usr/bin/env bash
## Updated: 28 Nov 2022
## Assist with creation of custom Analyst Machine
## Instructions provided 'as is'
## Instructions were used on xbuntu 22.04
sudo apt-get purge -y apport
cd ~/Desktop

# Machine is up to date
sudo apt-get update -y
sudo apt-get full-upgrade -y

# Utilities
sudo apt-get install -y vim git pip3 snap 7zip vpnc openvpn curl ripgrep exiftool
#sudo apt-get install git -y
#sudo apt-get install pip3 -y
#sudo apt-get install snap -y
#sudo apt-get install 7zip -y
#sudo apt-get install vpnc -y
#sudo apt-get install openvpn -y
#sudo apt-get install curl -y
#sudo apt-get install -y ripgrep
sudo apt-get update
sudo apt-get update --fix-missing
sudo apt-get upgrade -y 
sudo apt-get install --fix-broken

# GitHub projects
mkdir tools && cd tools
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
pip3 install -r requirements.txt
cd ..
git clone https://github.com/mxrch/ghunt
cd ghunt
python3 -m pip install -r requirements.txt
cd ..
wget https://gchq.github.io/CyberChef/CyberChef_v9.46.0.zip
unzip CyberChef_v9.46.0.zip
rm CyberChef_v9.46.0.zip

# Download applications
cd ..
wget https://www.torproject.org/dist/torbrowser/11.5.8/tor-browser-linux64-11.5.8_en-US.tar.xz
tar -xf tor*
cd tor-browser*
cp start-tor-browser.desktop ~/Desktop/
cd ~/Desktop
wget https://maltego-downloads.s3.us-east-2.amazonaws.com/linux/Maltego.v4.3.1.deb
sudo dpkg -i Maltego.v4.3.1.deb -y
wget "https://portswigger.net/burp/releases/download?product=pro&version=2022.11.2&type=Linux" -O burpsuite_pro_linux_v2022_11_2.sh
chmod +x burpsuite_pro_linux_v2022_11_2.sh
./burpsuite_pro_linux_v2022_11_2.sh
sudo snap install firefox
sudo snap install brave
sudo snap install keepassxc
sudo snap install vlc

# Cleanup
sudo apt-get update --fix-missing
sudo apt-get -y upgrade
sudo apt-get --fix-broken install
echo
read -rsp $'Press enter to continue...\n'
echo
