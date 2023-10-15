import os
import sys
import argparse
import time
import requests
import glob

def main():
	parser = argparse.ArgumentParser(description="afl-cLEMENCy fuzzer crashes triage")
	parser.add_argument("-d", required=True, type=str, dest="dir", help="workings directory")

	args = parser.parse_args()
	crashes = []
	os.chdir(args.dir)
	while 1:
		for c in glob.glob("**/crashes/id*"):
			if c not in crashes:
				print c
				crashes.append(c)
		time.sleep(30)

if __name__ == "__main__":
	main()
