Name:           openaaa
Summary:        OpenAAA
Version:        %{_version}
Release:        1%{dist}
License:        MIT
Group:          Applications/System
Source0:        %{name}-%{version}.tar.gz
URL:            https://github.com/n13l/openaaa
BuildRequires:  flex bison gperf pkgconfig swig java-1.8.0-openjdk-devel wine

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

%prep
%setup -q

%build
make defconfig -j1
make -j1

%install
make install INSTALL_PATH="%{buildroot}%" INSTALL_MOD_PATH="%{buildroot}%{_libdir}"
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

%files java
%defattr(-, root, root)
%{_libdir}/libaaa-*.jar

%files vpn
%defattr(-, root, root)
%{_libdir}/openaaa/modules/vpn*

%files pkcs11
%defattr(-, root, root)
%{_libdir}/openaaa/modules/pkcs11*
