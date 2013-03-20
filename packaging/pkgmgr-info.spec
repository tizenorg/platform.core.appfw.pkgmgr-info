Name:       pkgmgr-info
Summary:    Packager Manager infomation api for package
Version:    0.0.88
Release:    1
Group:      System/Libraries
License:    Apache License, Version 2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires:	cmake
BuildRequires:	pkgconfig(dlog)
BuildRequires:	pkgconfig(vconf)
BuildRequires:	pkgconfig(sqlite3)
BuildRequires:	pkgconfig(db-util)
BuildRequires:  pkgconfig(libxml-2.0)

%define _unpackaged_files_terminate_build 0


%description
Packager Manager infomation api for packaging

Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig


%package devel
Summary:    Packager Manager infomation api (devel)
Group:		TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}

%description devel
Packager Manager infomation api (devel)


%package parser
Summary:    Library for manifest parser
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description parser
Library for manifest parser

%package parser-devel
Summary:    Dev package for libpkgmgr-parser
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}

%description parser-devel
Dev package for libpkgmgr-parser


%prep
%setup -q


%build
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}


make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install




%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig



%files
%manifest pkgmgr-info.manifest
%defattr(-,root,root,-)
%{_libdir}/libpkgmgr-info.so.*


%files devel
%defattr(-,root,root,-)
%{_includedir}/pkgmgr-info.h
%{_libdir}/pkgconfig/pkgmgr-info.pc
%{_libdir}/libpkgmgr-info.so


%files parser
%manifest pkgmgr-parser.manifest
%defattr(-,root,root,-)
%{_libdir}/libpkgmgr_parser.so.*
%{_prefix}/etc/package-manager/preload/preload_list.txt
%{_prefix}/etc/package-manager/preload/manifest.xsd
%{_prefix}/etc/package-manager/preload/xml.xsd
%{_prefix}/etc/package-manager/parser_path.conf


%files parser-devel
%defattr(-,root,root,-)
%{_includedir}/pkgmgr/pkgmgr_parser.h
%{_includedir}/pkgmgr/pkgmgr_parser_db.h
%{_libdir}/pkgconfig/pkgmgr-parser.pc
%{_libdir}/libpkgmgr_parser.so

