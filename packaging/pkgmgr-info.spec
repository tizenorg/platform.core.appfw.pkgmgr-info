Name:       pkgmgr-info
Summary:    Packager Manager infomation api for package
Version:    0.0.144
Release:    1
Group:      Application Framework/Package Management
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires:	cmake
BuildRequires:	pkgconfig(dlog)
BuildRequires:	pkgconfig(vconf)
BuildRequires:	pkgconfig(sqlite3)
BuildRequires:	pkgconfig(db-util)
BuildRequires:pkgconfig(libxml-2.0)
BuildRequires:	pkgconfig(dbus-1)
BuildRequires:	pkgconfig(dbus-glib-1)
BuildRequires:	pkgconfig(deviced)

%description
Packager Manager infomation api for packaging

%package devel
Summary:    Packager Manager infomation api (devel)
Group:		Development/Libraries
Requires:   %{name} = %{version}-%{release}
%description devel
Packager Manager infomation api (devel)

%package parser
Summary:    Library for manifest parser
Group:      Application Framework/Package Management
Requires:   %{name} = %{version}-%{release}

%description parser
Library for manifest parser

%package parser-devel
Summary:    Dev package for libpkgmgr-parser
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description parser-devel
Dev package for libpkgmgr-parser


%prep
%setup -q

%build

%if 0%{?tizen_build_binary_release_type_eng}
export CFLAGS="$CFLAGS -DTIZEN_ENGINEER_MODE"
export CXXFLAGS="$CXXFLAGS ?DTIZEN_ENGINEER_MODE"
export FFLAGS="$FFLAGS -DTIZEN_ENGINEER_MODE"
%endif

%cmake .
make %{?jobs:-j%jobs}

%install
%make_install

mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
cp LICENSE %{buildroot}/usr/share/license/%{name}-devel
cp LICENSE %{buildroot}/usr/share/license/%{name}-parser
cp LICENSE %{buildroot}/usr/share/license/%{name}-parser-devel

%post

mkdir -p /opt/usr/apps/tmp
chown 5100:5100 /opt/usr/apps/tmp
chmod 771 /opt/usr/apps/tmp
chsmack -a '*' /opt/usr/apps/tmp
chsmack -t /opt/usr/apps/tmp

touch /opt/usr/apps/tmp/pkgmgr_tmp.txt

chsmack -a 'pkgmgr::db' /opt/usr/apps/tmp/pkgmgr_tmp.txt
chsmack -a '_' /usr/etc/package-manager

%postun


%files
%manifest pkgmgr-info.manifest
%defattr(-,root,root,-)
%{_libdir}/libpkgmgr-info.so.*
/usr/share/license/%{name}

%files devel
%defattr(-,root,root,-)
%{_includedir}/pkgmgr-info.h
%{_libdir}/pkgconfig/pkgmgr-info.pc
%{_libdir}/libpkgmgr-info.so
/usr/share/license/%{name}-devel

%files parser
%manifest pkgmgr-parser.manifest
%defattr(-,root,root,-)
%{_libdir}/libpkgmgr_parser.so.*
%{_prefix}/etc/package-manager/preload/preload_list.txt
%{_prefix}/etc/package-manager/preload/manifest.xsd
%{_prefix}/etc/package-manager/preload/xml.xsd
%{_prefix}/etc/package-manager/parser_path.conf
%{_prefix}/etc/package-manager/parserlib/metadata/metadata_parser_list.txt
%{_prefix}/etc/package-manager/parserlib/category/category_parser_list.txt
%{_prefix}/etc/package-manager/parserlib/tag_parser_list.txt
/usr/share/license/%{name}-parser

%files parser-devel
%defattr(-,root,root,-)
%{_includedir}/pkgmgr/pkgmgr_parser.h
%{_includedir}/pkgmgr/pkgmgr_parser_db.h
%{_libdir}/pkgconfig/pkgmgr-parser.pc
%{_libdir}/libpkgmgr_parser.so
/usr/share/license/%{name}-parser-devel
