Name:           openaaa
Summary:        OpenAAA
Version:        1.0.0
Release:        0
License:        MIT
Group:          Applications/System
Source:         %{name}-%{version}.tar.gz
URL:            https://github.com/n13l/openaaa
BuildRequires:  flex bison gperf pkgconfig

%description
OpenAAA

%package vpn
Summary: OpenAAA VPN Plugin
Group: Applications/System
%description vpn
OpenAAA VPN Plugin

%package pkcs11
Summary: OpenAAA PKCS#11 Bridge
Group: Applications/System
%description pkcs11
OpenAAA PKCS#11 Bridge

%build
#export CFLAGS="$RPM_OPT_FLAGS"
#export CPPFLAGS="$RPM_OPT_FLAGS"
echo "path: %{_tmppath}/%{name}-%{version}"
echo "buildroot: ${buildroot}"
echo "home: ${HOME}"
make defconfig
make

%install
make modules_install
mkdir -p ${HOME}/rpmbuild/BUILDROOT/openaaa-1.0.0-0.x86_64/usr/lib64/openaaa/modules/
cp -R /opt/aaa/lib/openaaa/modules/* ${HOME}/rpmbuild/BUILDROOT/openaaa-1.0.0-0.x86_64/usr/lib64/openaaa/modules/

%clean
rm -rf %{buildroot}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-, root, root)

%files vpn
%defattr(-, root, root)
%{_libdir}/openaaa/modules/openvpn/vpn-0.0.1.so

%files pkcs11
%defattr(-, root, root)
%{_libdir}/openaaa/modules/pkcs11/pkcs11-0.0.1.so
