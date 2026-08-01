FROM localhost/helloctr:latest
USER 0
RUN cat > /etc/yum.repos.d/rocky-scap.repo <<'REPO'
[rocky-baseos]
name=Rocky Linux 9 - BaseOS
baseurl=https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/
gpgcheck=1
gpgkey=https://dl.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-9
enabled=1
priority=100
excludepkgs=openssl*,glibc*
[rocky-appstream]
name=Rocky Linux 9 - AppStream
baseurl=https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/
gpgcheck=1
gpgkey=https://dl.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-9
enabled=1
priority=100
excludepkgs=openssl*,glibc*
REPO
RUN set -eux; dnf -y install --setopt=install_weak_deps=0 openscap-scanner scap-security-guide openscap-utils; test -f /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml; command -v autotailor; dnf -y clean all
