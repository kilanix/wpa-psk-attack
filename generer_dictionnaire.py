import itertools

chars = "abcdefghijklmnopqrstuvwxyz"
begin="aaaa"
f = open("combinaisons.txt", "a")
for item in itertools.product(chars,repeat=4):
	z=begin+"".join(item)+"\n"
	f.write(z)
f.close()
