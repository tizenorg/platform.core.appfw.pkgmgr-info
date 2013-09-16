Name:       pkgmgr-info
Summary:    Packager Manager infomation api for package
Version:    0.0.134
Release:    1
Group:      Application Framework/Package Management
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: 	pkgmgr-info.manifest
BuildRequires:	cmake
BuildRequires:	pkgconfig(dlog)
BuildRequires:	pkgconfig(vconf)
BuildRequires:	pkgconfig(sqlite3)
BuildRequires:	pkgconfig(db-util)
BuildRequires:  pkgconfig(libxml-2.0)

%description
Packager Manager infomation api for packaging

%package devel
Summary:    Packager Manager infomation api (devel)
Requires:   %{name} = %{version}-%{release}
%description devel
Packager Manager infomation api (devel)

%package parser
Summary:    Library for manifest parser
Requires:   %{name} = %{version}-%{release}

%description parser
Library for manifest parser

%package parser-devel
Summary:    Dev package for libpkgmgr-parser
Requires:   %{name} = %{version}-%{release}

%description parser-devel
Dev package for libpkgmgr-parser


%prep
%setup -q
cp %{SOURCE1001} .

%build
%cmake .
make %{?jobs:-j%jobs}

%install
%make_install
mkdir -p %{buildroot}/opt/usr/apps/tmp
touch %{buildroot}/opt/usr/apps/tmp/pkgmgr_tmp.txt

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%post -n pkgmgr-info-parser -p /sbin/ldconfig

%postun  -n pkgmgr-info-parser -p /sbin/ldconfig

%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_libdir}/libpkgmgr-info.so.*
%dir %attr(771,app,app) /opt/usr/apps/tmp
/opt/usr/apps/tmp/pkgmgr_tmp.txt

%files devel
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_includedir}/pkgmgr-info.h
%{_libdir}/pkgconfig/pkgmgr-info.pc
%{_libdir}/libpkgmgr-info.so

%files parser
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_libdir}/libpkgmgr_parser.so.*
%{_sysconfdir}/package-manager/preload/preload_list.txt
%{_sysconfdir}/package-manager/preload/manifest.xsd
%{_sysconfdir}/package-manager/preload/xml.xsd
%{_sysconfdir}/package-manager/parser_path.conf
%{_sysconfdir}/package-manager/parserlib/metadata/mdparser_list.txt
%{_sysconfdir}/package-manager/parserlib/category/category_parser_list.txt

%files parser-devel
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_includedir}/pkgmgr/pkgmgr_parser.h
%{_includedir}/pkgmgr/pkgmgr_parser_db.h
%{_libdir}/pkgconfig/pkgmgr-parser.pc
%{_libdir}/libpkgmgr_parser.so
