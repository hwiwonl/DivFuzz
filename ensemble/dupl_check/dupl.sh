# ex: ./script ./ ./b
path=$1
target_binary=$2
tm_out=8

if [[ $1 && $2 ]];
then
        echo "[+] Directory Path: $1"
        echo "[+] target_binary: $2"
else
        echo "[-] ./script path binary"
        exit
fi

if [ ! -d "$path" ]; then
        echo "[-] $path directory is not exist"
        exit
fi

for entry in "./"input*
do
	if [[ $entry == "./input*" ]]; then
		echo '[-] No file'
		break
	fi

	echo "[+] Entry: $entry"
	output="$(echo -ne "r < $entry \nbt" | timeout $tm_out gdb $target_binary -q 2>&1)"

	if [ $? -eq 124 ]
        then
                echo "[-] Timeout"
                continue
        fi

	echo "[+] output: $output"
	echo "[+] entry: $entry"

	if [[ $output == *SIGSEGV* || $output == *Aborted* ]];then
		echo "[+] SIGSEGV Detected"
		else
			echo "[-] End"
	fi
done
