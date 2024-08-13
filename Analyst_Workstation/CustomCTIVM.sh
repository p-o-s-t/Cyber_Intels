#! /usr/bin/env bash
## Intended for use with Ubuntu 20.04 LTS

## Basic Setup
cd ~/Desktop
sudo apt-get purge apport -y
sudp apt-get purge popularity-contest -y
sudo apt-get update -y
sudo apt-get full-upgrade -y
sudo apt-get install -y curl build-essential dkms gcc make perl default-jre ffmpeg python3-pip git exiftool keepassxc torbrowser-launcher p7zip-full snapd docker.io docker-compose
sudo snap install vlc brave nmap audacity telegram-desktop discord rocketchat-desktop
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb
rm google-chrome-stable_current_amd64.deb 
wget https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.3_all.deb
sudo dpkg -i protonvpn-stable-release_1.0.3_all.deb 
sudo apt-get update -y
sudo apt-get install protonvpn -y
rm protonvpn-stable-release_1.0.3_all.deb 


## Tools Setup
mkdir tools && cd tools
mkdir CyberChef && cd CyberChef
wget https://gchq.github.io/CyberChef/CyberChef_v9.54.0.zip
unzip CyberChef*
cd ..
wget https://maltego-downloads.s3.us-east-2.amazonaws.com/linux/Maltego.v4.3.0.deb
sudo dpkg -i ./Maltego.v4.3.0.deb
rm Maltego.v4.3.0.deb
git clone https://github.com/Datalux/Osintgram.git
cd Osintgram ## CLI
sudo -H pip install -r requirements.txt -I
cd ..
git clone https://github.com/sherlock-project/sherlock.git
cd sherlock/
python3 -m pip install -r requirements.txt
cd ..
git clone https://github.com/WebBreacher/WhatsMyName
cd WhatsMyName/whatsmyname
python3 -m pip install -r requirements.txt
cd ../..
wget https://github.com/obsidianmd/obsidian-releases/releases/download/v1.0.3/obsidian_1.0.3_amd64.snap
sudo snap install --dangerous --classic ./obsidian_1.0.3_amd64.snap
rm obsidian_1.0.3_amd64.snap

#git clone https://github.com/OpenCTI-Platform/docker.git OpenCTI/opencti-docker
#cd OpenCTI/opencti-docker
#cp .env.sample .env
#cat /proc/sys/kernel/random/uuid
#sudo sysctl -w vm.max_map_count=1048575
#sudo echo "vm.max_map_count=1048575" >> /etc/sysctl.conf
#set -a ; source .env


## Python Tools
sudo -H pip install youtube-dl
sudo -H pip install yt-dlp
sudo -H pip install youtube-tool
sudo pip install eml-analyzer


## Templates
cd ~/Desktop
mkdir templates && cd templates
git clone https://github.com/tjnull/TJ-OSINT-Notebook
cd TJ-OSINT-Notebook/
rm README.md What\ Is\ Intelligence\ What\ is\ OSINT.md
mv Raw\ Markdown/* ../
rm -rf TJ-OSINT-Notebook/
git clone https://github.com/WebBreacher/obsidian-osint-templates
wget https://github.com/deadbits/Analyst-CaseFile/blob/master/security-analysis.mtz

## Create Walkthrough on what to do for Firefox
#Pending

## Cleanup
cd ~/Pictures
wget https://wallpapercave.com/wp/qNRgJez.jpg
gsettings set org.gnome.desktop.background picture-uri file:////home/ctia2/Pictures/qNRgJez.jpg
sudo apt-get update --fix-missing
sudo apt-get -y upgrade
sudo apt-get --fix-broken install
sudo apt-get autoremove -y
echo
read -rsp $'Press enter to continue...\n'
echo
