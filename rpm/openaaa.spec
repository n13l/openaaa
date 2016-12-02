Name:           openaaa
Summary:        OpenAAA
Version:        %{_version}
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
make defconfig DEBUG=1 -j1
make -j1

%install
make modules_install INSTALL_MOD_PATH="%{buildroot}/%{_libdir}"
find %{buildroot}

%clean
rm -rf %{buildroot}

%post -p /sbin/ldconfig
find %{buildroot}
%postun -p /sbin/ldconfig
find %{buildroot}

%files
%defattr(-, root, root)
%{_libdir}/*

%files vpn
%defattr(-, root, root)
%{_libdir}/lib/openaaa/modules/openvpn/*

%files pkcs11
%defattr(-, root, root)
%{_libdir}/lib/openaaa/modules/pkcs11/*
