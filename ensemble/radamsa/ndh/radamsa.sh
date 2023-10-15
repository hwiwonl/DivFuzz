# mutation base file: a
# radamsa should be installed 

method=$1
crash_path=$2
target_binary=$3
tm_out=2
vmndh="/home/djlee/ctf/VMNDH-2k12/vmndh"
if [[ $1 && $2 && $3 ]]; 
then
	echo "[+] method: $1"
	echo "[+] crash_path: $2"
	echo "[+] target_binary: $3"
else
	echo "[-] ./script | method | crash_path | target_binary"
	exit
fi

if [ ! -d "$crash_path" ]; then
	echo "[-] Directory is not exist"
	exit
fi

while true
do
	rad="$(cat a |radamsa)"
	ret=$(timeout 2 $vmndh -file $target_binary -arg $rad 2>&1)

	if [ $? -eq 124 ]
	then
		echo "Timeout"
		continue
	fi

	if [[ $ret == *Aborted* || $ret == *Segfault* ]]
	then
	  uid=$(cat /dev/urandom | tr -dc "a-z" | fold -w 7 | head -n 1)
	  if [[ $ret == *Aborted* ]]; then
	    echo "Dump Aborted"
	    echo "$rad" > $crash_path/ab_$method'_'$uid
	    continue
	  fi
	  #echo "BBBBB"
	  if [[ $ret == *Segfault* ]]; then
	    echo "Dump SegFault"
	    echo "$rad" > $crash_path/seg_$method'_'$uid
	    continue
	  fi
	  #echo "CCCCC"
	  echo "Dump Misc"
	  echo "$rad" > $crash_path/misc_$method'_'$uid
	fi
done
