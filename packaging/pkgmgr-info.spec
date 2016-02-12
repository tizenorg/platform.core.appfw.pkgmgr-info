Name:       pkgmgr-info
Summary:    Packager Manager infomation api for package
Version:    0.1.0
Release:    1
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
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(bundle)
BuildRequires: pkgconfig(capi-system-info)

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
Requires:	pkgconfig(libtzplatform-config)

%description parser-devel
Dev package for libpkgmgr-parser


%prep
%setup -q
cp %{SOURCE1001} .

%build
MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
%cmake . -DFULLVER=%{version} -DMAJORVER=${MAJORVER}
%__make %{?jobs:-j%jobs}

%install
%make_install

mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
cp LICENSE %{buildroot}/usr/share/license/%{name}-parser

%post
/sbin/ldconfig

%postun -p /sbin/ldconfig

%post -n pkgmgr-info-parser -p /sbin/ldconfig

%postun  -n pkgmgr-info-parser -p /sbin/ldconfig

%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_libdir}/libpkgmgr-info.so.*
/usr/share/license/%{name}

%files devel
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_includedir}/pkgmgr-info.h
%{_includedir}/pkgmgrinfo_type.h
%{_includedir}/pkgmgrinfo_basic.h
%{_libdir}/pkgconfig/pkgmgr-info.pc
%{_libdir}/libpkgmgr-info.so

%files parser
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_libdir}/libpkgmgr_parser.so.*
%config %{_sysconfdir}/package-manager/preload/manifest.xsd
%config %{_sysconfdir}/package-manager/preload/xml.xsd
%config %{_sysconfdir}/package-manager/parser_path.conf
%config %{_sysconfdir}/package-manager/parserlib/metadata/mdparser_list.txt
%config %{_sysconfdir}/package-manager/parserlib/category/category_parser_list.txt
%config %{_sysconfdir}/package-manager/parserlib/tag_parser_list.txt
/usr/share/license/%{name}-parser

%files parser-devel
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_includedir}/pkgmgr/pkgmgr_parser.h
%{_includedir}/pkgmgr/pkgmgr_parser_db.h
%{_libdir}/pkgconfig/pkgmgr-parser.pc
%{_libdir}/libpkgmgr_parser.so
