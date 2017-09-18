Name:           openaaa
Summary:        OpenAAA
Version:        %{_version}
Release:        1%{dist}
License:        MIT
Group:          Applications/System
Source0:        %{name}-%{version}.tar.gz
URL:            https://github.com/n13l/openaaa
BuildRequires:  flex bison gperf pkgconfig swig java-1.8.0-openjdk-devel clang which

%define debug_package %{nil}

%description
OpenAAA

%package java
Summary: OpenAAA Java Bindings
Group: Applications/System
%description java
OpenAAA Java Bindings

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

%package apache2
Summary: OpenAAA Apache2 Module
Group: Applications/System
%description apache2
OpenAAA Apache2 Module


%prep
%setup -q

%build
./scripts/java/home.sh linux
make defconfig -j1 CC=clang
make -j1 CC=clang

%install
echo "INSTALL_PATH=%{buildroot}%"
echo "INSTALL_MOD_PATH=%{buildroot}%{_libdir}"
make install INSTALL_PATH="%{buildroot}/usr" INSTALL_MOD_PATH="%{buildroot}%{_libdir}"
make modules_install INSTALL_MOD_PATH="%{buildroot}%{_libdir}"
find %{buildroot}

%clean
rm -rf %{buildroot}

#%post -p /sbin/ldconfig
#find %{buildroot}
#%postun -p /sbin/ldconfig
#find %{buildroot}

%files
%defattr(-, root, root)
%{_libdir}/*
%{_bindir}/*

%files java
%defattr(-, root, root)
%{_libdir}/libaaa-*.jar

%files vpn
%defattr(-, root, root)
%{_libdir}/openaaa/modules/vpn*

%files pkcs11
%defattr(-, root, root)
%{_libdir}/openaaa/modules/pkcs11*

%files apache2
%defattr(-, root, root)
%{_libdir}/openaaa/modules/mod_aaa*
