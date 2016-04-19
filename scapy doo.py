import scapy.all
import sys
import math

total = 0
paquetes = {}
ops = {}
#calculo de entropia, WARNING 2difult
gil = 0
def logear(x):
	try:
		global total
		global paquetes
		total += 1
		if x.type in paquetes.keys():
			paquetes[x.type] += 1
		else:
			paquetes[x.type] = 1;

		if x.type == 0x806:
			if x.op in ops.keys():
				if x.psrc in ops[x.op].keys():
					ops[x.op][x.psrc] += 1
				else:
					ops[x.op][x.psrc] = 1
			else:
				ops[x.op]={}
				if x.psrc in ops[x.op].keys():
					ops[x.op][x.psrc] += 1
				else:
					ops[x.op][x.psrc] = 1
	except:
		global gil
		gil += 1
		print gil
	


scapy.all.sniff(prn=lambda x: logear(x), offline=sys.argv[1])
def entropia(d):
	total, entropia = 0, 0
	for k in d:
		total += d[k]
	for k in d:
		p = float(d[k])/total
		entropia -= p*math.log(p,2)
	return entropia
	

print total
print entropia(paquetes)
for k in paquetes:
	print k, float(paquetes[k])/total
print ops