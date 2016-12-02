Name:           openaaa
Summary:        OpenAAA
Version:        0.0.0
Release:        1%{dist}
License:        MIT
Group:          Applications/System
Source0:        %{name}-%{version}.tar.gz
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

%prep
%setup -q

%build
#export CFLAGS="$RPM_OPT_FLAGS"
#export CPPFLAGS="$RPM_OPT_FLAGS"
#echo "RPM_OPT_FLAGS: ${RPM_OPT_FLAGS}"
#echo "path: %{_tmppath}/%{name}-%{version}"
#echo "buildroot: ${buildroot}"
#echo "home: ${HOME}"
#echo "build: %{buildroot}"
#find %{buildroot}
#find /build/
#ls -la /build/openaaa-0.0.1.tar.xz
#tar xf /build/openaaa-0.0.1.tar.xz
#echo "${PWD}"
#find .
make defconfig DEBUG=1 -j1
make -j1

%install
make modules_install INSTALL_PATH="%{buildroot}"
find %{buildroot}

%clean
rm -rf %{buildroot}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-, root, root)

%files vpn
%defattr(-, root, root)
/lib/openaaa/modules/openvpn/vpn-%{version}.so

%files pkcs11
%defattr(-, root, root)
/lib/openaaa/modules/pkcs11/pkcs11-%{version}.so
