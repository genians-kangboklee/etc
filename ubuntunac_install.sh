#!/usr/bin/env bash

[[ -n $DEBUG ]] && set -x
set -o errtrace         # Make sure any error trap is inherited
set -o nounset          # Disallow expansion of unset variables
set -o pipefail         # Use last non-zero exit code in a pipeline

ID=`whoami`

if [[ "$ID" != "root" ]]; then
	echo "You must be root for install"
	exit
fi

TMP_DIR="$(rm -rf /tmp/upgrade* && mktemp -d -t upgrade.XXXXXXXXXX)"
LOG_FILE="${TMP_DIR}/install.log"

export DEBIAN_FRONTEND=noninteractive

PROMPT="${PROMPT:-1}"
DPKGCONFOPT="-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
REL="${REL:-$(awk -F'=' '/UBUNTU_CODENAME/ {print $2}' /etc/os-release)}"
CODENAME=""
PLATFORM_ARCH=$(arch)
LOCAL_MIRROR="${LOCAL_MIRROR:-}"
ROOT_MIRROR="${ROOT_MIRROR:-}"
REPO_MIRROR="${REPO_MIRROR:-}"
REPO_URI="${REPO_URI:-archive.ubuntu.com}"
TARGET="${TARGET:-}"
UPGRADE="${UPGRADE:-}"
INSTALL="${INSTALL:-}"
KERNEL_UPGRADE="${KERNAL_UPGRADE:-}"
DEB="${DEB:-}"
LOCALE="${LOCALE:-}"
TIMEZONE="${TIMEZONE:-}"
DOWNLOADTARGET="${DOWNLOADTARGET:-}"
LOCALTARGET="${LOCALTARGET:-}"
SSHPORT="${SSHPORT:-}"
SSHALLALLOW="${SSHALLALLOW:-}"
KERNELUP="${KERNELUP:-}"
NETDRV="${NETDRV:-}"

apt update
#apt -y upgrade
apt -y install lsof ${DPKGCONFOPT}
apt -y install net-tools ${DPKGCONFOPT}
apt -y install lsb-release

# check dpkg lock
PKGLOCK=`lsof /var/lib/dpkg/lock`
if [[ "x$PKGLOCK" != "x" ]]; then
	echo "Could not get lock /var/lib/dpkg/lock"
	exit
fi

KERNEL="5.4.0-186-generic"
PERCONA_VERSION="8.0.37-29-1"
FILEBEAT_VERSION="7.17.7"
ELASTIC_VERSION="6.8.6"
LOCALCONF="/disk/sys/conf/local.conf"
CENABLEPASSWORD="/disk/sys/conf/CENABLEPASSWORD"
UDEVRULE="/etc/udev/rules.d/70-persistent-net.rules"
LDCONFNAC="aaa-genian-nac.conf"

function log::exec() {
  printf "[%s]: \033[34mEXEC:    \033[0m%s\n" "$(date +'%Y-%m-%dT%H:%M:%S.%N%z')" "$*" >> "$LOG_FILE"
}


function utils::quote() {
  	if [ $(echo "$*" | tr -d "\n" | wc -c) -eq 0 ]; then
    	echo "''"
  	elif [ $(echo "$*" | tr -d "[a-z][A-Z][0-9]:,.=~_/\n-" | wc -c) -gt 0 ]; then
    	printf "%s" "$*" | sed -e "1h;2,\$H;\$!d;g" -e "s/'/\'\"\'\"\'/g" | sed -e "1h;2,\$H;\$!d;g" -e "s/^/'/g" -e "s/$/'/g"
  	else
    	echo "$*"
  	fi
}


function command::exec() {
	local command="$*"
	command="$(utils::quote "$command")"
    log::exec "[command]" "bash -c $(printf "%s" "${command}")"
	COMMAND_OUTPUT=$(eval bash -c "${command}" 2>> "$LOG_FILE" | tee -a "$LOG_FILE")
    local status=$?
    return $status
}

function util::getcodename()
{
	echo $(awk -F'=' '/UBUNTU_CODENAME/ {print $2}' /etc/os-release)
}

function util::setbash()
{
	rm -v /bin/sh
	ln -s /bin/bash /bin/sh
}

function install::basepkg()
{
	/usr/geni/alder stop > /dev/null 2>&1
	# procmon 종료
	systemctl stop procmon.service > /dev/null 2>&1

	# 설치과정에서 적용된 apt proxy 설정 제거
	#truncate -s 0 /etc/apt/apt.conf

	systemctl stop rpcbind > /dev/null 2>&1
	systemctl disable rpcbind > /dev/null 2>&1
	systemctl mask rpcbind > /dev/null 2>&1

	systemctl stop snmpd snmptrapd apache2 ipsec strongswan-starter mysql elasticsearch winbind smbd \
		samba-ad-dc nmbd tomcat8 tomcat9 tomcat10 syslog-ng nfs-server samba nmb > /dev/null 2>&1
	systemctl mask snmpd snmptrapd apache2 ipsec strongswan-starter mysql elasticsearch winbind smbd \
		samba-ad-dc nmbd tomcat8 tomcat9 tomcat10 syslog-ng nfs-server samba nmb > /dev/null 2>&1

	apt update

	apt -y install vim dialog libpam-pwquality traceroute \
		wget gnupg2 debsums libnuma1 psmisc curl libmecab2 cabextract \
		dnsutils tcpdump strace gftp python3-pip lsof jq \
		gdb systemd-coredump udhcpc libreadline-dev \
		libboost-thread-dev libboost-filesystem-dev libsodium-dev kmod \
		syslog-ng openssh-server nfs-common \
		ethtool ipcalc ifenslave vlan iptables arping unzip zip libtinyxml2.6.2v5 \
		bridge-utils dmidecode \
		nmap ntpdate net-tools libc-ares2 lrzsz \
		sysstat libtalloc2 iproute2 ansible \
		httrack lsb-release ${DPKGCONFOPT}

	if [[ "x$CODENAME" == "xnoble" ]]; then
		apt -y install libaio1t64 libtirpc-dev libncurses6 libtinfo6 libpcre3-dev libpcap0.8t64 libjsoncpp25 libldap2 ${DPKGCONFOPT}
	elif [[ "x$CODENAME" == "xjammy" ]]; then
		apt -y install libaio1 dpkg-sig libncurses5 libpcap0.8 libjsoncpp25 libldap-2.5-0 ${DPKGCONFOPT}
	else
		apt -y install libaio1 dpkg-sig libncurses5 libpcap0.8 libjsoncpp1 libldap-2.4-2 ${DPKGCONFOPT}
	fi

	if [[ "x$KERNELUP" != "xno" ]]; then
		if [[ "x$PLATFORM_ARCH" == "xx86_64" ]]; then
			apt -y install linux-image-${KERNEL} ${DPKGCONFOPT}
		fi
	fi

	if [[ "x$CODENAME" == "xbionic" ]]; then
		apt -y install libsnmp30 ${DPKGCONFOPT}
	fi
	if [[ "x$CODENAME" == "xfocal" ]]; then
		apt -y install libsnmp35 ${DPKGCONFOPT}
	fi
	if [[ "x$CODENAME" == "xjammy" ]]; then
		apt -y install libsnmp40 ${DPKGCONFOPT}
	fi
	if [[ "x$CODENAME" == "xnoble" ]]; then
		apt -y install libsnmp40t64 ${DPKGCONFOPT}
	fi

	echo "krb5-config krb5-config/add_servers_realm string TESTDOMAIN" | debconf-set-selections
	echo "krb5-config krb5-config/default_realm string TESTDOMAIN" | debconf-set-selections
	echo "krb5-config krb5-config/kerberos_servers string kdc" | debconf-set-selections
	echo "krb5-config krb5-config/admin_server string kdc" | debconf-set-selections

	if [[ "$TARGET" == "GPC" ]]; then
		apt -y install nfs-kernel-server ldap-utils pigz samba winbind krb5-user libcommons-dbcp-java \
			rrdtool libexpat1 libltdl7 libsybdb5 libpq5 \
			unixodbc-dev apt-transport-https fonts-nanum ${DPKGCONFOPT}
		if [[ "x$CODENAME" == "xnoble" ]]; then
			apt -y install libapr1t64 libaprutil1t64 libodbc2 ${DPKGCONFOPT}
			# 24.04 awscli
			wget -4 --no-check-certificate https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -O ${TMP_DIR}/awscliv2.zip
			unzip ${TMP_DIR}/awscliv2.zip -d ${TMP_DIR}
			sudo ${TMP_DIR}/aws/install
		else
			apt -y install libapr1 libaprutil1 awscli libodbc1 ${DPKGCONFOPT}
		fi
	fi

	systemctl disable networkd-dispatcher > /dev/null 2>&1
	systemctl stop networkd-dispatcher > /dev/null 2>&1

	if [[ "x$PLATFORM_ARCH" == "xx86_64" ]]; then
		VLANQ=`grep -E '^8021q' /etc/modules`
		if [[ "x$VLANQ" = "x" ]]; then
			echo "8021q" >> /etc/modules
		fi
	fi

	# 초기 설치 후 dhcp 비활성화
	#sed -i "s/^[^#]*\(      dhcp4: \).*/\1no/" /etc/netplan/01-netcfg.yaml
	# 기본 bond 인터페이스 생성
	#echo -e "  bonds:\n    bond0:\n      dhcp4: no" >> /etc/netplan/01-netcfg.yaml

	systemctl unmask unattended-upgrades
	# 자동 설치 서비스 비활성화
	systemctl stop unattended-upgrades
	systemctl disable unattended-upgrades
	apt -y purge --auto-remove unattended-upgrades
	systemctl stop apt-daily-upgrade.timer
	systemctl disable apt-daily-upgrade.timer
	systemctl mask apt-daily-upgrade.service
	systemctl stop apt-daily.timer
	systemctl disable apt-daily.timer
	systemctl mask apt-daily.service
}

function install::nacpkg()
{
	apt update

	apt -y install snmptrapd snmpd snmp ${DPKGCONFOPT}

	systemctl disable snmpd snmptrapd

	apt -y install apache2 libapache2-mod-security2 libapache2-mod-qos ${DPKGCONFOPT}

	if [[ "$CODENAME" == "xfocal" || "$CODENAME" == "xjammy" || "$CODENAME" == "xnoble" ]]; then
		apt -y install strongswan ${DPKGCONFOPT}
	fi

	if [[ "$TARGET" == "GPC" ]]; then
		apt -y install libapache2-mod-jk ${DPKGCONFOPT}
	fi
	# enable apache module
	a2enmod ssl
	a2enmod rewrite
	a2enmod proxy
	a2enmod proxy_http
	a2enmod cache
	a2enmod cache_disk
	a2enmod headers
	a2enmod remoteip
	a2dismod mpm_event
	a2enmod mpm_worker
	a2enmod qos

	if [[ "$TARGET" != "GPC" ]]; then
		systemctl unmask apache2
		return 0
	fi

	# 설치하자마자 실행되는것을 방지하기 위해 mask
	systemctl mask apache2
	systemctl mask mysql
	systemctl mask tomcat9
	systemctl mask tomcat8
	systemctl mask tomcat10
	systemctl mask elasticsearch
	systemctl mask winbind
	systemctl mask smbd
	systemctl mask samba-ad-dc
	systemctl mask nmbd
	systemctl mask nmb
	systemctl mask samba

	if [[ "x$CODENAME" == "xbionic" ]]; then
		apt -y install tomcat8 libmysql-java libmysqlclient20 libjemalloc1 ${DPKGCONFOPT}
	fi
	if [[ "x$CODENAME" == "xfocal" || "x$CODENAME" == "xjammy" ]]; then
		apt -y install libmariadb-java libmysqlclient21 libjemalloc2 ${DPKGCONFOPT}
	fi
	if [[ "x$CODENAME" == "xnoble" ]]; then
		apt -y install libmariadb-java libmysqlclient21 libjemalloc2 ${DPKGCONFOPT}
	fi

	apt -y install libnuma1 psmisc mysql-common libmecab2 zlib1g debsums ${DPKGCONFOPT}

	echo "percona-server-server percona-server-server/root-pass password" | debconf-set-selections
	echo "percona-server-server percona-server-server/re-root-pass password" | debconf-set-selections
	echo "percona-server-server percona-server-server/default-auth-override select Use Strong Password Encryption (RECOMMENDED)" | debconf-set-selections
	echo "percona-server-server percona-server-server/remove-data-dir boolean true" | debconf-set-selections
	echo "percona-server-server percona-server-server/data-dir note Ok" | debconf-set-selections

	PS_DOWNLOADURL="https://downloads.percona.com/downloads/Percona-Server-8.0/Percona-Server-8.0.18-9/binary/debian/bionic/x86_64"
	if [[ "x$CODENAME" == "xbionic" ]]; then
		wget -4 --no-check-certificate ${PS_DOWNLOADURL}/percona-server-common_8.0.18-9-1.bionic_amd64.deb -O ${TMP_DIR}/percona-server-common_8.0.18-9-1.bionic_amd64.deb
		dpkg -i ${TMP_DIR}/percona-server-common_8.0.18-9-1.bionic_amd64.deb
		wget -4 --no-check-certificate ${PS_DOWNLOADURL}/libperconaserverclient21_8.0.18-9-1.bionic_amd64.deb -O ${TMP_DIR}/libperconaserverclient21_8.0.18-9-1.bionic_amd64.deb
		dpkg -i ${TMP_DIR}/libperconaserverclient21_8.0.18-9-1.bionic_amd64.deb
		wget -4 --no-check-certificate ${PS_DOWNLOADURL}/percona-server-client_8.0.18-9-1.bionic_amd64.deb -O ${TMP_DIR}/percona-server-client_8.0.18-9-1.bionic_amd64.deb
		dpkg -i ${TMP_DIR}/percona-server-client_8.0.18-9-1.bionic_amd64.deb
		wget -4 --no-check-certificate ${PS_DOWNLOADURL}/percona-server-server_8.0.18-9-1.bionic_amd64.deb -O ${TMP_DIR}/percona-server-server_8.0.18-9-1.bionic_amd64.deb
		dpkg -i ${TMP_DIR}/percona-server-server_8.0.18-9-1.bionic_amd64.deb
	elif [[ "x$CODENAME" == "xfocal" || "x$CODENAME" == "xjammy" ]]; then
		apt -y install libgflags2.2
		apt -y install libperconaserverclient21=${PERCONA_VERSION}.${CODENAME} \
			percona-server-server=${PERCONA_VERSION}.${CODENAME} \
			percona-server-client=${PERCONA_VERSION}.${CODENAME} \
			percona-server-common=${PERCONA_VERSION}.${CODENAME} ${DPKGCONFOPT}
	elif [[ "x$CODENAME" == "xnoble" ]]; then
		apt remove -y libperconaserverclient* percona-server* --allow-change-held-packages > /dev/null 2>&1
		ln -s libaio.so.1t64.0.2 /lib/x86_64-linux-gnu/libaio.so.1 > /dev/null 2>&1

		apt -y install libperconaserverclient21=${PERCONA_VERSION}.${CODENAME} \
			percona-server-server=${PERCONA_VERSION}.${CODENAME} \
			percona-server-client=${PERCONA_VERSION}.${CODENAME} \
			percona-server-common=${PERCONA_VERSION}.${CODENAME} ${DPKGCONFOPT}

		apt remove -y libperconaserverclient21 --allow-change-held-packages > /dev/null 2>&1
	fi

	if [[ "x$CODENAME" == "xfocal" || "x$CODENAME" == "xjammy" || "x$CODENAME" == "xnoble" ]]; then
		systemctl disable filebeat
		systemctl mask filebeat
		apt -y install filebeat=${FILEBEAT_VERSION} ${DPKGCONFOPT}
	fi

	apt update

	if [[ "x$CODENAME" == "xfocal" || "x$CODENAME" == "xjammy" || "x$CODENAME" == "xnoble" ]]; then
		# Java 17
		apt -y install openjdk-17-jre-headless ${DPKGCONFOPT}
		update-alternatives --set java /usr/lib/jvm/java-17-openjdk-amd64/bin/java
	else
		# Java 11
		apt -y install openjdk-11-jre-headless ${DPKGCONFOPT}
		update-alternatives --set java /usr/lib/jvm/java-11-openjdk-amd64/bin/java
	fi

	# Elastic 초기 설치는 6.x 버전
	if [[ "x$(apt list --installed 2>/dev/null | grep elasticsearch)" == "x" ]]; then
		apt -y install elasticsearch=${ELASTIC_VERSION} ${DPKGCONFOPT}
	fi

	apt-mark hold elasticsearch

	systemctl unmask apache2 > /dev/null 2>&1
	systemctl unmask mysql > /dev/null 2>&1
	systemctl unmask tomcat9 > /dev/null 2>&1
	systemctl unmask tomcat8 > /dev/null 2>&1
	systemctl unmask tomcat10 > /dev/null 2>&1
	systemctl unmask elasticsearch > /dev/null 2>&1

	systemctl disable winbind > /dev/null 2>&1
	#systemctl unmask winbind > /dev/null 2>&1
	systemctl disable smbd > /dev/null 2>&1
	#systemctl unmask smbd > /dev/null 2>&1
	systemctl disable samba-ad-dc > /dev/null 2>&1
	#systemctl unmask samba-ad-dc > /dev/null 2>&1
	systemctl disable nmbd > /dev/null 2>&1
	#systemctl unmask nmbd > /dev/null 2>&1
	systemctl disable nmb > /dev/null 2>&1
	#systemctl unmask nmb > /dev/null 2>&1
	systemctl disable samba > /dev/null 2>&1
	#systemctl unmask samba > /dev/null 2>&1
}

function upgrade::kernel()
{
	local target=$1

	#
	apt update

	local aptkernel=`apt-cache search linux-image-${target} | awk -F ' ' '{print $1}'`

	if [[ "x${aptkernel}" = "x" ]]; then
		echo "UPGRADE::KERNEL. ${target} NOT FOUND."
		return 0
	fi

	apt -y install ${aptkernel} ${DPKGCONFOPT}

	local grubmenu=`awk -F\' '/submenu / {print $4}' /boot/grub/grub.cfg | head -1`
	local grubentry=`awk -F\' '/menuentry / {print $4}' /boot/grub/grub.cfg |grep ${target}|grep -v recovery`

	if [[ "x${grubmenu}" = "x" || "x${grubentry}" = "x" ]]; then
		echo "UPGRADE::KERNEL. GRUB NOT FOUND."
		return 0
	fi
	sed -i "s/GRUB_DEFAULT=.*/GRUB_DEFAULT=\"${grubmenu}>${grubentry}\"/g" /etc/default/grub
	update-grub2
}

function upgrade::config()
{
	ln -s /usr/sbin/iptables /sbin/iptables > /dev/null 2>&1

	if [[ "x$KERNELUP" != "xno" ]]; then
		if [[ "x$PLATFORM_ARCH" == "xx86_64" ]]; then
			# 부팅커널 변경
			OLDKERN=$(apt-mark showhold|grep linux-image|sed -ne 's/linux-image-//p')
			for i in $OLDKERN; do
				apt-mark unhold $OLDKERN > /dev/null 2>&1
			done
			upgrade::kernel "${KERNEL}"
			apt-mark hold linux-image-$KERNEL linux-headers-$KERNEL
		fi
	fi

	if [[ ! -f $LOCALCONF ]]; then
		echo "root/admin123!" > /etc/account.conf
		ADMIN=`cat /etc/account.conf | awk -F '/' '{print $1}'`
		PASS=`cat /etc/account.conf | awk -F '/' '{print $2}'`

		# local.conf 파일을 생성한다.
		mkdir -p /disk/sys/conf
		echo "" > $LOCALCONF
		chown $ADMIN:$ADMIN $LOCALCONF
		chmod 755 $LOCALCONF

		touch $CENABLEPASSWORD
		chown $ADMIN:$ADMIN $CENABLEPASSWORD
		chmod 600 $CENABLEPASSWORD

		CPASS=`echo -n $PASS | sha256sum | awk '{print $1}'`
		echo "$ADMIN:$CPASS" > $CENABLEPASSWORD

		# 현재 설치가 양산단계에서 진행되고 있음을 표시한다.
		echo "install-point=factory" >> $LOCALCONF

		if [[ "x$SSHPORT" != "x" ]]; then
			echo "ssh_port=$SSHPORT" >> $LOCALCONF
		fi
		if [[ "x$SSHALLALLOW" != "x" ]]; then
			echo "ssh_allallow=$SSHALLALLOW" >> $LOCALCONF
		fi
	fi
    if [[ ! -f $UDEVRULE ]]; then
        NUM=0
        INTERFACES=`ip link | grep -E "eth[0-9]+.*:|ens[0-9]+.*:|eno[0-9]+.*:|enp[0-9]+.*:" | awk -F ': ' '{print $2}'`
        touch $UDEVRULE
        for interface in $INTERFACES; do
            MAC=`ip link show $interface | grep link/ether | awk -F ' ' '{print $2}'`
			RULE=""
			if [[ "x$NETDRV" != "x" ]]; then
            	RULE="SUBSYSTEM==\"net\", ACTION==\"add\", DRIVERS==\"$NETDRV\", ATTR{address}==\"$MAC\", ATTR{type}==\"1\", NAME=\"eth$NUM\""
			else
            	RULE="SUBSYSTEM==\"net\", ACTION==\"add\", DRIVERS==\"?*\", ATTR{address}==\"$MAC\", ATTR{type}==\"1\", NAME=\"eth$NUM\""
			fi
            echo $RULE >> $UDEVRULE
            IP=`ifconfig $interface | grep -E 'inet ' | awk -F ' ' '{print $2}'`
            if [[ "x$IP" != "x" ]]; then
                NETMASK=`ifconfig $interface | grep -E 'inet ' | awk -F ' ' '{print $4}'`
                ETH=eth$NUM
                EXISTS=`cat $LOCALCONF | grep interface_${ETH}_address`
                if [[ "x$EXISTS" == "x" ]]; then
                    echo "interface_${ETH}_address=$IP $NETMASK" >> $LOCALCONF
                fi
                DEFGW=`ip route | grep -E "^default via [0-9]+.[0-9]+.[0-9]+.[0-9]+ dev $interface" | awk -F ' ' '{print $3}'`
                if [[ "x$DEFGW" != "x" ]]; then
                    DEFGWEXISTS=`cat $LOCALCONF | grep ip_default-gateway`
                    if [[ "x$DEFGWEXISTS" == "x" ]]; then
                        echo "ip_default-gateway=$DEFGW" >> $LOCALCONF
                    fi
                fi
            fi
            NUM=$(( $NUM + 1 ))
        done
    fi
	if [[ "x$CODENAME" == "xfocal" || "x$CODENAME" == "xjammy" || "x$CODENAME" == "xnoble" ]]; then
    	NAMESERVER=`resolvectl dns | grep -E 'Link.*: [0-9]+.[0-9]+.[0-9]+.[0-9]' | awk -F ' ' '{print $4}'`
	else
		NAMESERVER=`systemd-resolve --status | grep 'DNS Servers' | awk -F ' ' '{print $3}'`
	fi
    if [[ "x$NAMESERVER" != "x" ]]; then
        EXISTS=`cat $LOCALCONF | grep ip_name-server`
        if [[ "x$EXISTS" == "x" ]]; then
            echo "ip_name-server=$NAMESERVER" >> $LOCALCONF
        fi
    fi
}

function upgrade::nac()
{
	if [[ "x$DOWNLOADTARGET" != "x" ]]; then
		GDEB=$(/usr/bin/curl -w "%{filename_effective}" -sSkLO ${DOWNLOADTARGET})
		DEBPKGCODENAME=`dpkg-deb --info $GDEB | grep Subarchitecture | awk -F ' ' '{print $2}'`
		if [[ "$DEBPKGCODENAME" != "$CODENAME" ]]; then
			echo "Ubuntu CodeName error. $DEBPKGCODENAME != $CODENAME"
			rm $GDEB
			exit -1
		fi
		dpkg -i --force-overwrite $GDEB
		rm $GDEB
	else
		dpkg -i --force-overwrite $LOCALTARGET
	fi

	#
	echo -n '/usr/geni/lib' > /etc/ld.so.conf.d/${LDCONFNAC}
	ldconfig

	if [[ "x$LOCALE" != "x" ]]; then
		sed -Ei "s#system-locale.*#system-locale=${LOCALE}#g" $LOCALCONF
	fi
	if [[ "x$TIMEZONE" != "x" ]]; then
		timedatectl set-timezone ${TIMEZONE}
	fi

	#
	echo -n '/usr/geni/lib' > /etc/ld.so.conf.d/${LDCONFNAC}
	ldconfig
	
	[[ ! -d /disk/sys/conf/certs || ! -f /disk/sys/conf/certs/server.crt || ! -f /disk/sys/conf/certs/ssl.cer || ! -f /disk/data/custom/ssl.cer ]] && { rm -rf /disk/sys/conf/certs > /dev/null 2>&1; /etc/init.d/gensslkey; }

	systemctl enable syslog-ng

	ln -s /etc/apparmor.d/usr.sbin.mysqld /etc/apparmor.d/disable/ > /dev/null 2>&1
	apparmor_parser -R /etc/apparmor.d/usr.sbin.mysqld > /dev/null 2>&1

	#systemctl stop apparmor > /dev/null 2>&1
	#systemctl disable apparmor > /dev/null 2>&1
}

function clean::pkg()
{
	apt -y purge --auto-remove tomcat8 --allow-change-held-packages > /dev/null 2>&1
	systemctl disable tomcat8 > /dev/null 2>&1
	rm -rf /etc/systemd/system/tomcat8.service > /dev/null 2>&1
	systemctl mask tomcat8 > /dev/null 2>&1
	apt -y purge --auto-remove openjdk-11-jre-headless > /dev/null 2>&1
	apt -y purge --auto-remove tomcat9 --allow-change-held-packages > /dev/null 2>&1
	systemctl disable tomcat9 > /dev/null 2>&1
	rm -rf /etc/systemd/system/tomcat9.service > /dev/null 2>&1
	systemctl mask tomcat9 > /dev/null 2>&1
	apt -y purge --auto-remove openjdk-11-jre-headless > /dev/null 2>&1
}

# genian-nac 에서 동작하는 procmond 종료
# shell 을 dash에서 bash로 변경
# genian-nac 에서 사용하던 ldconfig 삭제
function init::env()
{
	# procmon 종료
	systemctl stop procmon.service > /dev/null 2>&1
	/usr/geni/alder stop > /dev/null 2>&1

	echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
	echo "dash dash/sh boolean false" | debconf-set-selections
	DEBIAN_FRONTEND=noninteractive dpkg-reconfigure dash

	util::setbash

	rm -rf /etc/ld.so.conf.d/genian-nac.conf > /dev/null 2>&1
	rm -rf /etc/ld.so.conf.d/aaa-genian-nac.conf > /dev/null 2>&1
	ldconfig
}

function hold::package()
{
	# package hold
	apt-mark hold libpercona* percona-server* elasticsearch apache2* tomcat8* tomcat9* tomcat10* > /dev/null 2>&1
}

function unhold::package()
{
	# package unhold
	apt-mark unhold libpercona* percona-server* elasticsearch apache2* tomcat8* tomcat9* tomcat10* linux-image* linux-headers* > /dev/null 2>&1

	if [[ "x$(apt list --installed 2>/dev/null | grep elasticsearch)" != "x" ]]; then
		apt-mark hold elasticsearch > /dev/null 2>&1
	fi
}

function init::depends()
{
	sed -Ei '/^Pre-Depends.*(tomcat[0-9]+, elasticsearch, percona-server-server.*)|(dialog, syslog-ng, unzip, zip.*libtinyxml2.6.2v5.*apache2.*)/d' /var/lib/dpkg/status > /dev/null 2>&1
	sed -Ei 's#/usr/geni/alder stop.*#/usr/geni/alder stop >/dev/null || true#g' /var/lib/dpkg/info/genian-nac-ns.prerm > /dev/null 2>&1
	sed -Ei '/.*(remove|rm).*(\\/disk|\\/var\\/geni|\\/usr\\/geni).*/d' /var/lib/dpkg/info/genian-nac-ns.postrm > /dev/null 2>&1
	sed -Ei 's#/usr/geni/alder stop.*#/usr/geni/alder stop >/dev/null || true#g' /var/lib/dpkg/info/genian-nac.prerm > /dev/null 2>&1
	sed -Ei '/.*(remove|rm).*(\\/disk|\\/var\\/geni|\\/usr\\/geni).*/d' /var/lib/dpkg/info/genian-nac.postrm > /dev/null 2>&1
	sed -Ei '/^(rm|cp).*log4j/d' /usr/geni/systemdscript/elasticsearch/elasticsearch-genconf.sh > /dev/null 2>&1

	rm -rf /etc/systemd/system/{smbd*,samba*,nmb*} > /dev/null 2>&1

	[[ -f /etc/samba/smb.conf ]] && { rm -rf /etc/samba/smb.conf; touch /etc/samba/smb.conf; rm -rf /etc/systemd/system/smbd.service; systemctl mask smbd.service > /dev/null 2>&1; }
	[[ -f /etc/systemd/system/nmbd.service ]] && { rm -rf /etc/systemd/system/nmbd.service; systemctl mask nmbd.service > /dev/null 2>&1; }
	[[ -f /etc/systemd/system/winbind.service ]] && { rm -rf /etc/systemd/system/winbind.service; systemctl mask winbind.service > /dev/null 2>&1; }
	[[ -f /etc/systemd/system/mysql.service ]] && { rm -rf /etc/systemd/system/mysql.service; systemctl mask mysql.service > /dev/null 2>&1; }
	[[ -f /etc/systemd/system/elasticsearch.service ]] && { rm -rf /etc/systemd/system/elasticsearch.service; systemctl mask elasticsearch.service > /dev/null 2>&1; }
	[[ -f /etc/systemd/system/apache2.service ]] && { rm -rf /etc/systemd/system/apache2.service; systemctl mask apache2.service > /dev/null 2>&1; }

	systemctl stop smbd winbind samba-ad-dc nmbd nmb samba > /dev/null 2>&1
	systemctl mask smbd winbind samba-ad-dc nmbd nmb samba > /dev/null 2>&1

	apt update
	apt --fix-broken -y install ${DPKGCONFOPT}
	apt -y install curl ${DPKGCONFOPT}
}

# sources.list 초기화
function init::sourcelist()
{
	# genian-nac 에서 사용하던것 삭제
	rm -rf /etc/apt/sources.list.d/genian*
	rm -rf /etc/apt/sources.list.d/elastic-*
	rm -rf /etc/apt/sources.list.d/percona*

	# bionic 에서 시작
	echo -n "" > /etc/apt/sources.list
	echo "deb http://ports.ubuntu.com/ubuntu-ports bionic main restricted" >> /etc/apt/sources.list
	echo "deb http://ports.ubuntu.com/ubuntu-ports bionic-updates main restricted" >> /etc/apt/sources.list
	echo "deb http://ports.ubuntu.com/ubuntu-ports bionic universe" >> /etc/apt/sources.list
	echo "deb http://ports.ubuntu.com/ubuntu-ports bionic-updates universe" >> /etc/apt/sources.list
	echo "deb http://ports.ubuntu.com/ubuntu-ports bionic multiverse" >> /etc/apt/sources.list
	echo "deb http://ports.ubuntu.com/ubuntu-ports bionic-updates multiverse" >> /etc/apt/sources.list
	echo "deb http://ports.ubuntu.com/ubuntu-ports bionic-backports main restricted universe multiverse" >> /etc/apt/sources.list
	echo "deb http://ports.ubuntu.com/ubuntu-ports bionic-security main restricted" >> /etc/apt/sources.list
	echo "deb http://ports.ubuntu.com/ubuntu-ports bionic-security universe" >> /etc/apt/sources.list
	echo "deb http://ports.ubuntu.com/ubuntu-ports bionic-security multiverse" >> /etc/apt/sources.list

	# x86이면 ubuntu-ports(ARM) 에서 ubuntu 로 변경
	if [[ "x$PLATFORM_ARCH" == "xx86_64" ]]; then
		sed -i "s#ubuntu-ports#ubuntu#g" /etc/apt/sources.list
	fi

	# ROOT_MIRROR 예) $REPO_URI 
	if [[ "x$ROOT_MIRROR" != "x" ]]; then
		sed -i "s#ports.ubuntu.com#$ROOT_MIRROR#g" /etc/apt/sources.list
	fi

	# ROOT_MIRROR 와 REPO_MIRROR은 함께 사용할 수 없음

	# REPO_MIRROR 설정은 폐쇄망

	if [[ "x$REPO_MIRROR" == "x" ]] && [[ "x$PLATFORM_ARCH" == "xx86_64" ]]; then
		# ROOT_MIRROR에 의해서 변경되었으면 sed 에 의해서 변경 안되므로 OK
		sed -i "s#ports.ubuntu.com#mirror.kakao.com#g" /etc/apt/sources.list
	elif [[ "x$PLATFORM_ARCH" == "xx86_64" ]]; then
		sed -i "s#ports.ubuntu.com#$REPO_MIRROR/$REPO_URI#g" /etc/apt/sources.list

		if [[ "$TARGET" == "GPC" ]]; then
			cat << EOF > ${TMP_DIR}/GPG-KEY-elasticsearch
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2.0.14 (GNU/Linux)

mQENBFI3HsoBCADXDtbNJnxbPqB1vDNtCsqhe49vFYsZN9IOZsZXgp7aHjh6CJBD
A+bGFOwyhbd7at35jQjWAw1O3cfYsKAmFy+Ar3LHCMkV3oZspJACTIgCrwnkic/9
CUliQe324qvObU2QRtP4Fl0zWcfb/S8UYzWXWIFuJqMvE9MaRY1bwUBvzoqavLGZ
j3SF1SPO+TB5QrHkrQHBsmX+Jda6d4Ylt8/t6CvMwgQNlrlzIO9WT+YN6zS+sqHd
1YK/aY5qhoLNhp9G/HxhcSVCkLq8SStj1ZZ1S9juBPoXV1ZWNbxFNGwOh/NYGldD
2kmBf3YgCqeLzHahsAEpvAm8TBa7Q9W21C8vABEBAAG0RUVsYXN0aWNzZWFyY2gg
KEVsYXN0aWNzZWFyY2ggU2lnbmluZyBLZXkpIDxkZXZfb3BzQGVsYXN0aWNzZWFy
Y2gub3JnPokBOAQTAQIAIgUCUjceygIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgEC
F4AACgkQ0n1mbNiOQrRzjAgAlTUQ1mgo3nK6BGXbj4XAJvuZDG0HILiUt+pPnz75
nsf0NWhqR4yGFlmpuctgCmTD+HzYtV9fp9qW/bwVuJCNtKXk3sdzYABY+Yl0Cez/
7C2GuGCOlbn0luCNT9BxJnh4mC9h/cKI3y5jvZ7wavwe41teqG14V+EoFSn3NPKm
TxcDTFrV7SmVPxCBcQze00cJhprKxkuZMPPVqpBS+JfDQtzUQD/LSFfhHj9eD+Xe
8d7sw+XvxB2aN4gnTlRzjL1nTRp0h2/IOGkqYfIG9rWmSLNlxhB2t+c0RsjdGM4/
eRlPWylFbVMc5pmDpItrkWSnzBfkmXL3vO2X3WvwmSFiQbkBDQRSNx7KAQgA5JUl
zcMW5/cuyZR8alSacKqhSbvoSqqbzHKcUQZmlzNMKGTABFG1yRx9r+wa/fvqP6OT
RzRDvVS/cycws8YX7Ddum7x8uI95b9ye1/Xy5noPEm8cD+hplnpU+PBQZJ5XJ2I+
1l9Nixx47wPGXeClLqcdn0ayd+v+Rwf3/XUJrvccG2YZUiQ4jWZkoxsA07xx7Bj+
Lt8/FKG7sHRFvePFU0ZS6JFx9GJqjSBbHRRkam+4emW3uWgVfZxuwcUCn1ayNgRt
KiFv9jQrg2TIWEvzYx9tywTCxc+FFMWAlbCzi+m4WD+QUWWfDQ009U/WM0ks0Kww
EwSk/UDuToxGnKU2dQARAQABiQEfBBgBAgAJBQJSNx7KAhsMAAoJENJ9ZmzYjkK0
c3MIAIE9hAR20mqJWLcsxLtrRs6uNF1VrpB+4n/55QU7oxA1iVBO6IFu4qgsF12J
TavnJ5MLaETlggXY+zDef9syTPXoQctpzcaNVDmedwo1SiL03uMoblOvWpMR/Y0j
6rm7IgrMWUDXDPvoPGjMl2q1iTeyHkMZEyUJ8SKsaHh4jV9wp9KmC8C+9CwMukL7
vM5w8cgvJoAwsp3Fn59AxWthN3XJYcnMfStkIuWgR7U2r+a210W6vnUxU4oN0PmM
cursYPyeV0NX/KQeUeNMwGTFB6QHS/anRaGQewijkrYYoTNtfllxIu9XYmiBERQ/
qPDlGRlOgVTd9xUfHFkzB52c70E=
=92oX
-----END PGP PUBLIC KEY BLOCK-----
EOF
			cat ${TMP_DIR}/GPG-KEY-elasticsearch | apt-key add -
			#echo "deb http://$REPO_MIRROR/artifacts.elastic.co/packages/7.x/apt stable main" > /etc/apt/sources.list.d/elastic-7.x.list
			echo "deb http://$REPO_MIRROR/artifacts.elastic.co/packages/6.x/apt stable main" > /etc/apt/sources.list.d/elastic-6.x.list

			cat << EOF > ${TMP_DIR}/percona-keyring.pub
mQINBFd0veABEADyFa8jPHXhhX1XS9W7Og4p+jLxB0aowElk4Kt6lb/mYjwKmQ77
9ZKUAvb1xRYFU1/NEaykEl/jxE7RA/fqlqheZzBblB3WLIPM0sMfh/D4fyFCaKKF
k2CSwXtYfhk9DOsBP2K+ZEg0PoLqMbLIBUxPl61ZIy2tnF3G+gCfGu6pMHK7WTtI
nnruMKk51s9Itc9vUeUvRGDcFIiEEq0xJhEX/7J/WAReD5Am/kD4CvkkunSqbhhu
B6DV9tAeEFtDppEHdFDzfHfTOwlHLgTvgVETDgLgTRXzztgBVKl7Gdvc3ulbtowB
uBtbuRr49+QIlcBdFZmM6gA4V5P9/qrkUaarvuIkXWQYs9/8oCd3SRluhdxXs3xX
1/gQQXYHUhcdAWrqS56txncXf0cnO2v5kO5rlOX1ovpNQsc69R52LJKOLA1Kmjca
JNtC+4e+SF2upK14gtXK384z7owXYUA4NRZOEu+UAw7wAoiIWPUfzMEHYi8I3Rsz
EtpVyOQC5YyYgwzIdt4YxlVJ0CUoinvtIygies8LkA5GQvaGJHYG1aQ3i9WDddCX
wtoV1uA4EZlEWjTXlSRc92jhSKut/EWbmYHEUhmvcfFErrxUPqirpVZHSaXY5Rdh
KVFyx9JcRuIQ0SJxeHQPlaEkyhKpTDN5Cw7USLwoXfIu2w0w0W06LdXZ7wARAQAB
tDtQZXJjb25hIERldmVsb3BtZW50IFRlYW0gKFBhY2thZ2luZyBrZXkpIDxpbmZv
QHBlcmNvbmEuY29tPokCNwQTAQgAIQUCWwLC+wIbAwULCQgHAgYVCAkKCwIEFgID
AQIeAQIXgAAKCRCTNKJfhQfvpYf+D/oD7dFS0eXR4OH2g8CACNeTWB2EJ57W0gyL
wko42IjBSOSogB4BMm/3vlk8PefikTU5+Z/fYK3OIJV7kMIEXNfnNzr3QWvafHRR
qGUoTmvP29O5Y4s7oGllIUOlr9gwtSGfHnjtF+WZBhko2uH6KvXBJay28ye4S8sS
zDQdk8RULFN4hfIT4duOjo7Clf4iZtoUX7bVN32NRYH8Ss4IvbdDOAjlzjQa+NgO
SEsDvP3DwRoZQcAIMXngOMlPa/SA87pAcOup/8AvX3i7F7ZfWkKys3jpoSRyt0Ol
InpOrlJqJY4ugSxNkCgz+21kb1EVtIjSY8LAMPzZ5OAiiG0MyOTUyKFhzAkE1Mn3
Cs9TzNjybPlvPGt6CsckjgReL2XQBqITRsmLOwzWguuqduBlPISVoeGUPpEBj7Hv
Ca7p9QbEaXtN5JmlAFLwPTuM4S5IxG5bEXMFECKL45J8F9G/EGs/qO/HSebQsJ/+
i5Ct6gElUwIOaaCUPpWG0qwR2aP4QAndvLsaGN7v6BmtLYw8+n5vjIueFXh/gRyI
8eOIxrCUYhukkdM+YQ0h6Xd+X8FvHdYRGHmW86Ro2HkBqqKyXbab04+769jpzCdM
b0oKzXapU94mKuWZ+fOncshTpUN17neFzb1YIc2kcwb3rQxDJNd7IR3mq+d3yapk
vTYlP7uFk7RGUGVyY29uYSBNeVNRTCBEZXZlbG9wbWVudCBUZWFtIChQYWNrYWdp
bmcga2V5KSA8bXlzcWwtZGV2QHBlcmNvbmEuY29tPokCOQQwAQgAIwUCWwLD2Rwd
IFVzZXIgSUQgaXMgbm8gbG9uZ2VyIHZhbGlkAAoJEJM0ol+FB++lW4UQALX2/ofm
ALXhdC0nlh4X1MJLPpmLjyZKTyK3YNOUJukzGW0LVGIq4SAvPxw4oc4zQ1PCQuUG
oj062Fd4sWF1oGFQBOVUAebnyCOcAE1ybcpw9FhdB6ZGa0hTx1RD9jg+OT8e1u62
XbQyRuLBbbncyIt/lhTcqnCVv14auolAVLuFqiFx5uk2n1x5Y5bs6ABt9Ka0MhYZ
m6Qyhm0kGNYn+AiHEwNgdAboe155zp2augVVDmGS+s+tVD60nnWzZLsZGCCZh2gJ
jyxxXNaIeY7OyaMRQFa3gBVGd7UeJZ1d3MR4nR7wlKMUXSC8a0l+bkgi/sgyAJNg
X3bCiEDRIGxGv/Dgg1/ahKVEch/W0Y+0DyifPzAFtnCBH0c2GJUrU8/c2i1iKhYf
/r/711136Oqd5LDROQGzo4dnzdTs3qEeWdIVkgSwaLUFrw6Kq0tAnZSqHK2WQw3C
1oPdlBMimysOhJnwsmYbtlgRF2/rU7QiuJvMHXqBPfOSHKRcy5hoa5S2+PCe/IXB
Qmod1MlmfsUH6TjwC5SWGFaIm76+ROsiQKie28fAqRLKqeNvuaMqxTsVpYofQZXE
JcSyhwhTcaQxsrYYM+4z8sbdxiIqR7PW6BthsAKCrOr6U53Pm00+yI16Tt7FNcVc
wHl+lRTe/EhDQ93LvbFvB4/Svx/GLdlvdsHaiQI3BBMBCgAhBQJXdL3gAhsDBQsJ
CAcDBRUKCQgLBRYCAwEAAh4BAheAAAoJEJM0ol+FB++l4koQAKkrRP+K/p/TGlnq
lbNyS5gdSIB1hxT3iFwIdF9EPZq0U+msh8OY7omV/82rJp4T5cIJFvivtWQpEwpU
jJtqBzVrQlF+12D1RFPSoXkmk6t4opAmCsAmAtRHaXIzU9WGJETaHl57Trv5IPMv
15X3TmLnk1mDMSImJoxWJMyUHzA37BlPjvqQZv5meuweLCbL4qJS015s7Uz+1f/F
siDLsrlE0iYCAScfBeRSKF4MSnk5huIGgncaltKJPnNYppXUb2wt+4X2dpY3/V0B
oiG8YBxV6N7sA7lC/OoYF6+H3DMlSxGBQEb1i9b6ypwZIbG6CnM2abLqO67D3XGx
559/FtAgxrDBX1f63MQKlu+tQ9mOrCvSbt+bMGT6frFopgH6XiSOhOiMmjUazVRB
sXRK/HM5qIk5MK0tGPSgpc5tr9NbMDmp58OQZYQscslKhx0EDDYHQyHfYFS2qodu
RwQG4BgpZm2xjGM/auCvdZ+pxjqy7dnEXvMVf0i1BylkyW4p+oK5nEwY3KHljsRx
uJ0+gjfyj64ihNMSqDX5k38T2GPSXm5XAN+/iazlIuiqPQKLZWUjTOwr2/AA6Azt
U/fmsXV2swz8WekqT2fphvWKUOISr3tEGG+HF1iIY43BoAMHYYOcdSI1ZODZq3Wi
c+zlN1WzPshDB+d3acxeV5JhstvPuQINBFd0veABEACfuHVbey5qG5P6rRhAX2pd
d/f7iwHdcW1+evxCfCR5fHzsO1LRwlHM9GRqlztKzgxzAIfgUXqdMXUs6vW8agfk
u553h8gBqrhdq9NH65/YenzV/Sv9c/EGzsBQurau1RC4gfJ4jgAedu4FQKZvVr//
0NTWuJm3el3orYYz4rLq79avSgD7Q/uK8/j71zgCJixsFzjC8ehRlOtMdetPTY36
zc2LjQSMTSpE7SvEbrk6yDKpQvZabl3dmkEkBvoFpat7x+i3ZtBCzRFTx2rH/9DW
KCO+SuGVBXs8vhLtAvKKjbWGGU9LrmESZcahI6fliH5w28NvpOuJlr8Rn/6jQmJD
DPKO50XKM8hpT6DBqIE99YqYLUzXAKf4Y88FyHvlO6kiVbXaOYz1OTqCWVqjaMYF
biPW6NgDX0hyE9uG0lfNA9P5edqyPSEaTN+kpD9OVqG6R0uPBCFY8u25NrNRhMqI
FQdvI54eEtN0ktFP0FrlFFkg6S+l+3Qsr9sMDKCUVTJ/BkKwqkdhTv5XY4KiIEJQ
jvMKr0vH5lYiPDGX/3KsJL+rxJjA++4Wh40WBLYDSDWSAfCPSokg1lRjOaMDhnH5
YnUeEk6Mhy61DQRsH+xEpeL/F1L06u0Wh+0iXqKXJA4jvU4XwGSkzg3yaablkYnu
n5myhIQYswIdCyEH4Wl3SQARAQABiQIfBBgBCgAJBQJXdL3gAhsMAAoJEJM0ol+F
B++lxqkQAIC7jz1CWt+tbKgutLRFcxexNQZoTAAPTk3OjqqeCLWO1cmHtmjNSXTc
5rpX78vPEYQjzQpAARZxAppAdeJHBzm9Qrfiyo7TW8P0Gf9c9p1mPUtl2g0BNvRU
7zYzgCF1aIwKtS+XO2UdTT56Gy5vaxd1BiTg8J9ytkIGSkuSXSOASeGC5RmN3SaD
6yomVa483k9kVhhSOUzKwYK9f2WgGhI1xxpVF5LbbRhCoEz4ia/TqJoWdH/agul3
4AGWOgPRhMu+FEpb/nons73XTwQtcXiZAe9z4ZltVsSciolgRzPwkXxMmWVMme9Y
ymVCPTrzxPi6nc6npSZzE275m02u86V2htwD2MbSuGmcTdmAPPfXgQ5XM57ELElD
bNA1eN1jZAhzYBLv63X+nNOy6ysuac5Q7ozyBOIpNksLleA0+FzsnYmPlGqzYtnD
6nFglDn898jk/LWkwitL472fh8RRbDYffsXealiy6W2TYKrQl52ajLV7D5PUUS9x
SlAPcdPSuXAzh7GhOKDommWwLfPo0uYN3Xja+AkW135ctz4evCpvZjkBTfog07FG
lumduUK5fHvJYiSyV1P5SKr4722C8jWCo2YcS+IsZgVFFuY1bG6HtiImpP75IM0G
3g1uyd2OhF9nGDSxjp4kKWnUoGdV0P1bUXaAbvXRzlIcx7dOD7tZ
EOF
			openssl base64 -d -in ${TMP_DIR}/percona-keyring.pub -out /etc/apt/trusted.gpg.d/percona-keyring.gpg

			echo "deb http://$REPO_MIRROR/repo.percona.com/prel/apt bionic main" > /etc/apt/sources.list.d/percona-prel-release.list
			echo "deb http://$REPO_MIRROR/repo.percona.com/ps-80/apt bionic main" > /etc/apt/sources.list.d/percona-ps-80-release.list
			echo "deb http://$REPO_MIRROR/repo.percona.com/tools/apt bionic main" > /etc/apt/sources.list.d/percona-tools-release.list
		fi
	fi

	# LOCAL_MIRROR 는 저장장치에 repository 가 구성되어있음
	if [[ "$LOCAL_MIRROR" == "1" ]]; then
		sed -i -e "s#http:/#file:#g" -e "s#https:/#file:#g" /etc/apt/sources.list \
			/etc/apt/sources.list.d/elastic-7.x.list /etc/apt/sources.list.d/elastic-6.x.list \
			/etc/apt/sources.list.d/percona-prel-release.list /etc/apt/sources.list.d/percona-ps-80-release.list /etc/apt/sources.list.d/percona-tools-release.list
	fi
}

function clean::apt()
{
	apt remove -y libperconaserverclient* percona-release percona-server* --allow-change-held-packages > /dev/null 2>&1
	apt clean
}

function update::currentpkg()
{
	if [[ "$UPGRADE" != "1" ]]; then
		return 0
	fi

	apt update
	apt --fix-broken -y install ${DPKGCONFOPT}
	apt -y upgrade ${DPKGCONFOPT}
}

function upgrade::sourcelist()
{
	local target=$1

	sed -i "s/bionic/${target}/g" /etc/apt/sources.list
	sed -i "s/bionic/${target}/g" /etc/apt/sources.list.d/*

	if [[ "x$target" = "xjammy" ]]; then
		sed -i "s/focal/${target}/g" /etc/apt/sources.list
		sed -i "s/focal/${target}/g" /etc/apt/sources.list.d/*
	fi

	if [[ "x$target" = "xnoble" ]]; then
		sed -i "s/focal/${target}/g" /etc/apt/sources.list
		sed -i "s/focal/${target}/g" /etc/apt/sources.list.d/*
		sed -i "s/jammy/${target}/g" /etc/apt/sources.list
		sed -i "s/jammy/${target}/g" /etc/apt/sources.list.d/*
	fi
}

function install::repo()
{
	# REPO_MIRROR를 사용하면 폐쇄망
	if [[ "x$REPO_MIRROR" != "x" ]] || [[ "x$PLATFORM_ARCH" != "xx86_64" ]]; then
		return
	fi

	if [[ "$TARGET" == "GPC" ]]; then
		wget -4 --no-check-certificate -O ${TMP_DIR}/percona-release_latest.$(lsb_release -sc 2>/dev/null)_all.deb https://repo.percona.com/percona/apt/percona-release_latest.$(lsb_release -sc 2>/dev/null)_all.deb
		dpkg -i --force-overwrite ${TMP_DIR}/percona-release_latest.$(lsb_release -sc 2>/dev/null)_all.deb
		percona-release setup ps80

		wget -4 --no-check-certificate -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
		#echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" > /etc/apt/sources.list.d/elastic-7.x.list
		echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" > /etc/apt/sources.list.d/elastic-6.x.list
	fi
	apt update
}

function upgrade::rel()
{
	local target=$1

	update::currentpkg

	upgrade::sourcelist "${target}"

	# syslog-ng-core 때문에 설치가 실패하는 문제가 있음
	apt remove -y syslog-ng-core
	apt update
	apt --fix-broken -y install ${DPKGCONFOPT}
	apt -y dist-upgrade ${DPKGCONFOPT}

	cp -f /etc/lsb-release.dpkg-dist /etc/lsb-release > /dev/null 2>&1
}


function help::usage()
{
  cat << EOF

Upgrade NAC to focal/jammy NAC.
  20.04 -> focal
  22.04 -> jammy
  24.04 -> noble
Usage:
  $(basename "$0") [command]

Available Commands:

Flag:
  - rel (focal or jammy or noble)

Example:

  ########## 폐쇄망환경에서 외부저장디스크를 통해서 업그레이드 ##########
  
  mkdir -p /var/spool/apt-mirror && mount /dev/sdxxxxx /var/spool/apt-mirror

  (정책서버)
  $0 upgrade -rel focal -locale ko -timezone Asia/Seoul -localmirror -repomirror var/spool/apt-mirror/mirror -target GPC -deb [http://download]/tmp/NAC-UBUNTU-R-113129-5.0.54.0425.deb
  OR
  $0 install -locale ko -timezone Asia/Seoul -localmirror -repomirror var/spool/apt-mirror/mirror -target GPC -deb [http://download]/tmp/NAC-UBUNTU-R-113129-5.0.54.0425.deb

  (네트워크센서)
  $0 upgrade -rel focal -locale ko -timezone Asia/Seoul -localmirror -repomirror var/spool/apt-mirror/mirror -target GNS -deb [http://download]/tmp/NAC-UBUNTUNS-R-113129-5.0.54.0425.deb
  OR
  $0 install -locale ko -timezone Asia/Seoul -localmirror -repomirror var/spool/apt-mirror/mirror -target GNS -deb [http://download]/tmp/NAC-UBUNTUNS-R-113129-5.0.54.0425.deb

  ########## 인터넷망환경에서 업그레이드 ##########

  (정책서버)
  $0 upgrade -rel focal -locale ko -timezone Asia/Seoul -target GPC -deb [http://download]/tmp/NAC-UBUNTU-R-113129-5.0.54.0425.deb
  OR
  $0 install -locale ko -timezone Asia/Seoul -target GPC -deb [http://download]/tmp/NAC-UBUNTU-R-113129-5.0.54.0425.deb

  (네트워크센서)
  $0 upgrade -rel focal -locale ko -timezone Asia/Seoul -target GNS -deb [http://download]/tmp/NAC-UBUNTUNS-R-113129-5.0.54.0425.deb
  OR
  $0 install -locale ko -timezone Asia/Seoul -target GNS -deb [http://download]/tmp/NAC-UBUNTUNS-R-113129-5.0.54.0425.deb

  curl -sSLk http://172.29.74.155:8000/`basename $0` | sudo DEBUG=1 INSTALL=1 PROMPT=0 TARGET=GPC LOCALE=ko TIMEZONE=Asia/Seoul \
DEB=https://download.geninetworks.com/tftpboot/NAC/GNOS/v5.0/RELEASE/AAT/NAC-UBUNTU-R-121077-5.0.57.1106.deb bash -
  curl -sSLk http://172.29.74.155:8000/`basename $0` | sudo DEBUG=1 UPGRADE=1 PROMPT=0 TARGET=GPC LOCALE=ko TIMEZONE=Asia/Seoul REL=focal \
DEB=https://download.geninetworks.com/tftpboot/NAC/GNOS/v5.0/RELEASE/AAT/NAC-UBUNTU-R-121077-5.0.57.1106.deb bash -


  curl -sSLk http://172.29.74.155:8000/`basename $0` | sudo DEBUG=1 INSTALL=1 PROMPT=0 TARGET=GNS LOCALE=ko TIMEZONE=Asia/Seoul \
DEB=https://download.geninetworks.com/tftpboot/NAC/GNOS/v5.0/RELEASE/AAT/NAC-UBUNTUNS-R-121077-5.0.57.1106.deb bash -
  curl -sSLk http://172.29.74.155:8000/`basename $0` | sudo DEBUG=1 UPGRADE=1 PROMPT=0 TARGET=GNS LOCALE=ko TIMEZONE=Asia/Seoul REL=focal \
DEB=https://download.geninetworks.com/tftpboot/NAC/GNOS/v5.0/RELEASE/AAT/NAC-UBUNTUNS-R-121077-5.0.57.1106.deb bash -
EOF
  exit 1
}

while [ "${1:-}" != "" ]; do
  case $1 in
    install )       INSTALL=1
                    ;;
    upgrade )       UPGRADE=1
                    ;;
    -sshport )      shift
                    SSHPORT=${1:-$SSHPORT}
                    ;;
    -sshall )       SSHALLALLOW=1
                    ;;
    -kernelup )     shift
                    KERNELUP=${1:-$KERNELUP}
                    ;;
    -target )       shift
                    TARGET=${1:-$TARGET}
                    ;;
    -locale )       shift
                    LOCALE=${1:-$LOCALE}
                    ;;
    -timezone )     shift
                    TIMEZONE=${1:-$TIMEZONE}
                    ;;
    -localmirror )  LOCAL_MIRROR=1
                    ;;
    -repomirror )   shift
                    REPO_MIRROR=${1:-$REPO_MIRROR}
                    ;;
    -repouri )      shift
                    REPO_URI=${1:-$REPO_URI}
                    ;;
    -rootmirror )   shift
                    ROOT_MIRROR=${1:-$ROOT_MIRROR}
                    ;;
    -deb )          shift
                    DEB=${1:-$DEB}
                    ;;
    -rel )          shift
                    REL=${1:-$REL}
                    ;;
    -kernel )       shift
                    KERNEL_UPGRADE=${1:-$KERNEL_UPGRADE}
                    ;;
    -netdrv )       shift
                    NETDRV=${1:-$NETDRV}
                    ;;
    * )             help::usage
                    exit 1
  esac
  shift
done

if [[ "x$KERNEL_UPGRADE" != "x" ]]; then
	upgrade::kernel "${KERNEL_UPGRADE}"
	exit 0
fi

CODENAME=$(util::getcodename)

printf "Genians $TARGET. $CODENAME(REL=$REL) $DEB\n"
if [[ "x$TARGET" != "xGPC" ]] && [[ "x$TARGET" != "xGNS" ]]; then
	echo
	echo "-target options:"
	echo "GPC     POLICY CENTER SERVER"
	echo "GNS     NETWORK SENSOR"
	echo
	exit -1
fi

if [[ "$PROMPT" == "1" ]]; then
	printf "Genians NAC Upgrade. Continue (y/n)?"
	read answer
	if [[ "x$answer" != "xy" ]]; then
		exit 1
	fi
elif [[ "$INSTALL" != "1" ]]; then
	UPGRADE=1
fi

init::env
init::depends
unhold::package
clean::pkg
clean::apt

# sourcelist 를 초기화 한다. bionic 에서 시작
init::sourcelist

# 현재 운영체제에 따라서 sourcelist 변경
if [[ "x$CODENAME" == "xfocal" ]]; then
	upgrade::sourcelist "focal"
fi
if [[ "x$CODENAME" == "xjammy" ]]; then
	upgrade::sourcelist "jammy"
fi
if [[ "x$CODENAME" == "xnoble" ]]; then
	upgrade::sourcelist "noble"
fi

update::currentpkg

# 업그레이드 (bionic -> focal)
if [[ "x$CODENAME" == "xbionic" && "$UPGRADE" == "1" && "x$REL" != "xbionic" ]]; then
	upgrade::rel "focal"
fi
CODENAME=$(util::getcodename)
# 업그레이드 (focal -> jammy)
if [[ "x$CODENAME" == "xfocal" && "$UPGRADE" == "1" && "x$REL" != "xfocal" ]]; then
	upgrade::rel "jammy"
fi
CODENAME=$(util::getcodename)
# 업그레이드 (jammy -> noble)
if [[ "x$CODENAME" == "xjammy" && "$UPGRADE" == "1" && "x$REL" != "xjammy" ]]; then
	upgrade::rel "noble"
fi
CODENAME=$(util::getcodename)

if [[ "$UPGRADE" == "1" && "x$REL" != "x$CODENAME" ]]; then
	echo
	echo "ERROR: OS Upgrade from $CODENAME to $REL fails."
	echo
	exit -1
fi

[[ "x$CODENAME" == "xbionic" ]] && KERNEL="4.15.0-144-generic" && LDCONFNAC="genian-nac.conf"
[[ "x$CODENAME" == "xjammy" ]] && KERNEL="5.15.0-91-generic"
[[ "x$CODENAME" == "xnoble" ]] && KERNEL="6.8.0-31-generic"

# 업그레이드 후에 repo 등록
install::repo

if [[ "$UPGRADE" == "1" || "$INSTALL" == "1" ]]; then
	if [[ "x$DEB" != "x" ]]; then
		# 로컬에 파일이 존재하거나 다운로드 가능한지 확인
		LOCALTARGET=$DEB
		if [[ $LOCALTARGET == http* ]]; then
			DOWNLOADTARGET=$LOCALTARGET
			LOCALTARGET=
		fi
		printf "	DEB $LOCALTARGET $DOWNLOADTARGET\n"
		if [[ "x$DOWNLOADTARGET" != "x" ]]; then
			if ( /usr/bin/curl -o/dev/null -sfI "$DOWNLOADTARGET" ); then
				echo "$DOWNLOADTARGET exist"
				GDEB=$(/usr/bin/curl -w "%{filename_effective}" -sSkLO ${DOWNLOADTARGET})
				DEBPKGCODENAME=`dpkg-deb --info $GDEB | grep Subarchitecture | awk -F ' ' '{print $2}'`
				if [[ "$DEBPKGCODENAME" != "$CODENAME" ]]; then
					echo "Ubuntu CodeName error. $DEBPKGCODENAME != $CODENAME"
					rm $GDEB
					exit -1
				fi
			else
				echo "$DOWNLOADTARGET not exist"
				exit -1
			fi
		else
			if [[ -f "$LOCALTARGET" ]]; then
				echo "$LOCALTARGET exist"
				DEBPKGCODENAME=`dpkg-deb --info $LOCALTARGET | grep Subarchitecture | awk -F ' ' '{print $2}'`
				if [[ "$DEBPKGCODENAME" != "$CODENAME" ]]; then
					echo "Ubuntu CodeName error. $DEBPKGCODENAME != $CODENAME"
					exit -1
				fi
			else
				echo "$LOCALTARGET not exist"
				exit -1
			fi
		fi
	fi

	util::setbash

	apt update

	install::basepkg

	install::nacpkg

	upgrade::config

	hold::package

	# remove netplan
	# rm -rf /etc/netplan/*

	if [[ "x$DEB" != "x" ]]; then
		upgrade::nac
	fi

	util::setbash

	sync

	if [[ "$PROMPT" == "1" ]]; then
		printf "Genians $TARGET installed. now reboot (y/n)?"
		read answer
		if [[ "x$answer" = "xy" ]]; then
			reboot -f
		fi
	else
		reboot -f
	fi
fi
