
#export CFLAGS=""
#export LDFLAGS=""

cd `dirname $0`

PREFIX=/usr

rm -rf cmake_tmp
mkdir -p cmake_tmp
cd cmake_tmp

CFLAGS="${CFLAGS}" LDFLAGS="${LDFLAGS}" cmake .. -DCMAKE_INSTALL_PREFIX=${PREFIX} &&
make &&

# test
{
	export LD_LIBRARY_PATH=`pwd`
	cd test
#	./test_comm_client &
#	./test_comm_status_broadcast_server
#	./test_comm_socket &&
	./test_pkgmgr_installer
}
if [ "$?" == "0" ]; then
	echo "Test done."
else
	echo "Test failed!"
fi

