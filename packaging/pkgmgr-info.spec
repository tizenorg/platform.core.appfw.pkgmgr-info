Name:       pkgmgr-info
Summary:    Packager Manager infomation api for package
Version:    0.0.134
Release:    0
Group:      Application Framework/Package Management
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: pkgmgr-info.manifest
BuildRequires: cmake
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(vconf)
BuildRequires: pkgconfig(sqlite3)
BuildRequires: pkgconfig(db-util)
BuildRequires: pkgconfig(libxml-2.0)
BuildRequires: pkgconfig(dbus-1)
BuildRequires: pkgconfig(dbus-glib-1)
BuildRequires: pkgconfig(libtzplatform-config)

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

# create the directory for hosting Read-Write application manifest files
mkdir -p %{buildroot}%{TZ_SYS_RW_PACKAGES}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%post -n pkgmgr-info-parser -p /sbin/ldconfig

%postun  -n pkgmgr-info-parser -p /sbin/ldconfig

%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_libdir}/libpkgmgr-info.so.*
%dir %{TZ_SYS_RW_PACKAGES}

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
%config %{_sysconfdir}/package-manager/preload/preload_list.txt
%config %{_sysconfdir}/package-manager/preload/manifest.xsd
%config %{_sysconfdir}/package-manager/preload/xml.xsd
%config %{_sysconfdir}/package-manager/parser_path.conf
%config %{_sysconfdir}/package-manager/parserlib/metadata/mdparser_list.txt
%config %{_sysconfdir}/package-manager/parserlib/category/category_parser_list.txt
%config %{_sysconfdir}/package-manager/parserlib/tag_parser_list.txt

%files parser-devel
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_includedir}/pkgmgr/pkgmgr_parser.h
%{_includedir}/pkgmgr/pkgmgr_parser_db.h
%{_libdir}/pkgconfig/pkgmgr-parser.pc
%{_libdir}/libpkgmgr_parser.so
