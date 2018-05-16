#	Author:		            PureReactions
#   Description:            Decodes configuration in Hussar/Sarhust variant
#   External Dependencies   cryptography, pefile
#   Reference(s):           


import sys
import pefile
from Crypto.Cipher import XOR

def run():
	p = pefile.PE(sys.argv[1])
	for i in p.sections:
		if i.Name == ".data\x00\x00\x00":
			conf_data = i.get_data()
		else:
			pass
	a = parse_config(conf_data)
	b = decode_data(a)
	config_print(b)

		
def parse_config(conf_data):
	off1 = conf_data.find('\xFC\xFF\xFF\xFF\xFF\xFF\xFF\xFF')
	off2 = conf_data.find('\x00\x00\x00\x00\x53\x00\x6F\x00\x66\x00\x74\x00\x77\x00\x61\x00\x72\x00\x65\x00\x5C\x00')
	id_1 = conf_data[off1+528:off1+560]
	off3 = conf_data.find(id_1)
	id_2 = conf_data[off3+64:off3+96]
	port = conf_data[off1-10:off1-8]
	C2 = conf_data[off1+8:off1+64]
	mutex = conf_data[off2-16:off2]
	id_1 = conf_data[off1+528:off1+560]
	return mutex,C2,port,id_1,id_2

def decode_data(a):
	d = []
	for i in a:
		if '\x00' in i:
			a = i.replace('\x00','')
			d.append(a)
		elif ('\xFF' in i and len(i) > 3):
			cipher = XOR.new('\xFF')
			a = cipher.decrypt(i).replace('\x00','')
			d.append(a)
		elif len(i) < 3:
			i = cipher.decrypt(i)
			i = (i[-1] + i[-2]).encode('hex')
			a = (int(i, 16))
			d.append(a)
	return(d)
		
def config_print(b):
	c = ["Mutex Created: ", "C2 Domain: ", "Port: ", "ID1: ", "ID2: "]
	for i,e in zip(c,b):
		print('\t' + i + str(e))
	


if __name__ == "__main__":
	run()