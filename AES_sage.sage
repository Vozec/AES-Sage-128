from sage.crypto.mq.rijndael_gf import RijndaelGF
from binascii import unhexlify,hexlify
import os

class AES():
	def __init__(self,key):
		self.rijndaelGF = RijndaelGF(4, 4)
		self.hex2GF = lambda pt: self.rijndaelGF._hex_to_GF(pt)
		self.GF2hex = lambda ct: self.rijndaelGF._GF_to_hex(ct)
		self.add_round_key = lambda state,i: state + self.subkeys[i]
		self.subkeys = self.rijndaelGF.expand_key(self.hex2GF(hexlify(key).decode()))

	def pad(self,pt):
		pad_len = 16 - (len(pt) % 16)
		return pt + bytes([pad_len] * pad_len)

	def unpad(self,ct):
		return ct[:-ct[-1]]

	def enc_bloc(self,pt):
		assert len(pt) == 32
		state = self.hex2GF(pt)
		state = self.add_round_key(state,0)
		for i in range(9):
			state = self.rijndaelGF.sub_bytes(state)
			state = self.rijndaelGF.shift_rows(state)
			state = self.rijndaelGF.mix_columns(state)
			state = self.add_round_key(state,i+1)
		state = self.rijndaelGF.sub_bytes(state)
		state = self.rijndaelGF.shift_rows(state)
		state = self.add_round_key(state,10)
		return self.GF2hex(state)

	def dec_bloc(self,ct):
		assert len(ct) == 32
		state = self.hex2GF(ct)
		state = self.add_round_key(state,10)
		state = self.rijndaelGF.shift_rows(state, algorithm='decrypt')
		state = self.rijndaelGF.sub_bytes(state, algorithm='decrypt')
		for i in range(9,0,-1):
			state = self.add_round_key(state,i)
			state = self.rijndaelGF.mix_columns(state, algorithm='decrypt')
			state = self.rijndaelGF.shift_rows(state, algorithm='decrypt')
			state = self.rijndaelGF.sub_bytes(state, algorithm='decrypt')
		state = self.add_round_key(state,0)
		return self.GF2hex(state)

	def encrypt(self,ct):
		# ECB Mod because i'am lazy
		ct = hexlify(self.pad(ct)).decode()
		blocs = [ct[32*i:32*(i+1)] for i in range(len(ct)//32)]
		return unhexlify(bytes(''.join([self.enc_bloc(b) for b in blocs]),'utf-8'))

	def decrypt(self,pt):
		pt = hexlify(pt).decode()
		blocs = [pt[32*i:32*(i+1)] for i in range(len(pt)//32)]
		return self.unpad(unhexlify(bytes(''.join([self.dec_bloc(b) for b in blocs]),'utf-8')))

engine = AES(os.urandom(16))
plaintext = b'Custom_AES_For_Fun_&_CTF_Points!'
ct = engine.encrypt(plaintext)
pt = engine.decrypt(ct)

assert pt == plaintext