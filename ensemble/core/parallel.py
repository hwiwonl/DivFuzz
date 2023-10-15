import os
import sys
import time
import argparse

def main():
	parser = argparse.ArgumentParser(description="afl-cLEMENCy parallel script")
	parser.add_argument("-i", required=True, type=str, dest="indir", help="input directory")
	parser.add_argument("-o", required=True, type=str, dest="outdir", help="output directory")
	parser.add_argument("-b", required=True, type=str, dest="challs" ,help="challenge binary")
	parser.add_argument("-c", required=True, type=int, dest="counts" ,help="counts of slaves")
	parser.add_argument("-x", required=False, type=str, dest="dict", default="", help="dictionary directory")

	args = parser.parse_args()

	if not args.dict:
		master_cmd = "export AFL_SKIP_CPUFREQ=1; nohup ./afl-fuzz -M master -i %s -o %s -m 1024 -R 50 -- ./clemency-emu.afl %s &" % (args.indir, args.outdir, args.challs)
		os.system(master_cmd)
		for num in range(args.counts):
			time.sleep(1.0)
			slave_cmd = "export AFL_SKIP_CPUFREQ=1; nohup ./afl-fuzz -S slave%d -i %s -o %s -m 1024 -R 50 -- ./clemency-emu.afl %s &" % (num+1, args.indir, args.outdir, args.challs)
			os.system(slave_cmd)
	else:
		master_cmd = "export AFL_SKIP_CPUFREQ=1; nohup ./afl-fuzz -M master -i %s -o %s -m 1024 -R 50 -- ./clemency-emu.afl %s -x %s &" % (args.indir, args.outdir, args.challs, args.dict)
		os.system(master_cmd)
		for num in range(args.counts):
			time.sleep(1.0)
			slave_cmd = "export AFL_SKIP_CPUFREQ=1; nohup ./afl-fuzz -S slave%d -i %s -o %s -m 1024 -R 50 -- ./clemency-emu.afl %s -x %s &" % (num+1, args.indir, args.outdir, args.challs, args.dict)
			os.system(slave_cmd)		

if __name__ == '__main__':
	main()

