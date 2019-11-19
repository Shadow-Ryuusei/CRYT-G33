#include <bits/stdc++.h>
#include <strstream>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/hrtimer.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>

using namespace std;
using namespace CryptoPP;

int N = 5; //NUmber of users
int M = 6; //NUmber of secondary nodes

struct User{
	//user details
	int id;
	string pw;
	string tid;

	//construct the smart card
	string a;
	string b;
	string c;

	//amount
	string r;
};

struct  Sensor{
	int id;
	string a;
};

struct GatewayNode{
	string tid; //stores tid of the user
	string x; //secret key of the gateway node

	//for the smart card
	string au;
	string b;
	string c;

	//sensor node related
	int sid;
	string as;
};

ostringstream oss;

string makeupper(string s)
{
	for(char& c : s)
		c = toupper(c);

	return s;
}

string randomNumber(int bits, int flag)
{
	string temp;

	oss.clear();
	oss.str("");
	Integer x;

    AutoSeededRandomPool prng;
    x.Randomize(prng, bits);

    if(flag)
    {
		oss << std::hex << x;
		temp = oss.str();
		temp = temp.substr(0, (bits/4)-1);
		temp = makeupper(temp);

		reverse(temp.begin(), temp.end());
		temp.resize(bits/4, '0');
		reverse(temp.begin(), temp.end());
    }
	else
	{
		oss << std::dec << x;
		temp = oss.str();
		temp = makeupper(temp);
	}

	return temp;
}

//generating SHA3 hash
string generateHash(string source)
{
      SHA3_256 sha256;
      string hash = "";
      StringSource(source, true, new HashFilter(sha256, new HexEncoder(new StringSink(hash))));
      cout << "hash = " << hash << "'\n";
      return hash;
}

//used in the AES encryption/decryption
SecByteBlock iv(AES::BLOCKSIZE);

string aesEncryption(string key, string plaintext)
{
	AutoSeededRandomPool rnd;

	SecByteBlock sbb((const byte*)key.data(), key.size());
	rnd.GenerateBlock(iv, iv.size());

	string output;
	CTR_Mode<AES>::Encryption encrypt((const byte*)sbb,AES::DEFAULT_KEYLENGTH,(const byte*)iv);
	StringSource(plaintext, true, new StreamTransformationFilter(encrypt, new StringSink(output)));
	//cout << output << endl;
	cout << "Encrypted: " << output << endl;

	return output;
}

string aesDecryption(string key, string ciphertext)
{
	AutoSeededRandomPool rnd;

	SecByteBlock sbb((const byte*)key.data(), key.size());

	string res;
	CTR_Mode<AES>::Decryption decrypt((const byte*)sbb,AES::DEFAULT_KEYLENGTH,(const byte*)iv);
	StringSource(ciphertext, true, new StreamTransformationFilter(decrypt, new StringSink(res)));
	//cout << res << endl;
	cout << "Decrypted: " << res << endl;

	return res;
}

string exor(string a, string b)
{
	reverse(a.begin(), a.end());
	a.resize(64, '0');
	reverse(a.begin(), a.end());

	reverse(b.begin(), b.end());
	b.resize(64, '0');
	reverse(b.begin(), b.end());

	for(int i = 0; i < 64; ++i)
	{
		int bd = (b[i] <= '9' ? b[i] - '0' : b[i] - 'A' + 10);
		int ad = (a[i] <= '9' ? a[i] - '0' : a[i] - 'A' + 10);
		bd ^= ad;
		b[i] = (bd <= 9 ? bd + '0' : bd + 'A' - 10);
	}
	return b;
}

 int main()
 {
 	string temp; //user to store partial inputs when xoring or hashing, not specific
 	string input; //input variable for hash functions	

 	User u[N];

 	//USER REGISTRATION PHASE
 	for(int i=0; i<N; i++)
 	{
 		//User choosing his id
	 	u[i].id = i;

		//User choosing his pw
		u[i].pw = randomNumber(256, 1);

		//Possible tid generated for user by gatewaynode
		u[i].tid = randomNumber(256, 1);
	}

	//Gateway Node's COmputations
	GatewayNode gwn;
	gwn.x = randomNumber(256, 1); //creating secret key for the gwn

	//Randomly selecting the user who wants a smart card
	string uidstr = randomNumber(256, 0);
 	int uid = (int) (uidstr[4] - '0');
	uid = (uid) % 5;
	uidstr = to_string(uid); //uid in string format
	reverse(uidstr.begin(), uidstr.end());
	uidstr.resize(64, '0');
	reverse(uidstr.begin(), uidstr.end());

	string r = randomNumber(256, 1); //random number generated

	string tidstr = u[uid].tid; //tid in string format
	string uidpass = u[uid].pw; //password in string format

	//Computing a
	//A i = h ( h ( ID i ) || h ( PW i , r ))
	input = generateHash(uidstr) + generateHash(uidpass + r);
	gwn.au = generateHash(input);

	//computing b
	//B i = h ( TID i , X k ) ⊕ h ( PW i , r )
	gwn.b = exor(generateHash(tidstr + gwn.x), generateHash(uidpass + r));

	//computing c
	//C i = h ( ID i , X k ) ⊕ h ( h ( ID i ) ⊕ h ( PW i , r ))
	temp = exor(generateHash(uidstr), generateHash(uidpass + r));
	gwn.c = exor(generateHash(uidstr + gwn.x), generateHash(temp));

	//sends a, b, c back to the user via smart card
	u[uid].a = gwn.au;
	u[uid].b = gwn.b;
	u[uid].c = gwn.c;

	gwn.tid = u[uid].tid; //storing tid in gwn
	u[uid].r = r; //sends r back as well
	//END OF USER REGISTRATION PHASE

	//SENSOR NODE REGISTRATION PHASE
	Sensor senNodes[M];
	for(int i=0; i<M; i++)
		senNodes[i].id = i;
	
	//Randomly selecting the secondary node
	string sidstr = randomNumber(256, 0);
 	int sid = (int) (sidstr[4] - '0');
	sid = (sid) % 5;
	sidstr = to_string(sid);
	reverse(sidstr.begin(), sidstr.end());
	sidstr.resize(64, '0');
	reverse(sidstr.begin(), sidstr.end());

	//generating gwn.as
	//A j = h ( ID SN j ⊕ S ran )
	string sran = randomNumber(256, 1);
	gwn.as = generateHash(sidstr + sran);
	gwn.sid = sid;

	senNodes[sid].a = gwn.as;
	//SENSOR NODE REGISTRATION PHASE END

	//LOGIN PHASE BEGIN
	//step-1
	string a1 = generateHash(generateHash(uidstr) + generateHash(u[uid].pw + r)); //a1 = h ( h ( ID i ) , h ( PW i , r ))

	if(a1 == gwn.au)
	{
		//step-2
		string h1 = exor(gwn.b, generateHash(u[uid].pw + r)); //h1 = B i ⊕ h ( PW i , r )

		string temp = exor(generateHash(uidstr), generateHash(u[uid].pw + r)); 
		string h2 = exor(gwn.c, generateHash(temp)); //h2 = C i ⊕ h ( h ( ID i ) ⊕ h ( PW i , r ))

		string t1 = randomNumber(256, 1); //timestamp

		string key = generateHash(u[uid].tid + gwn.x); //key for aes, key = h ( TID i , X k )
		string plaintext = uidstr + t1 + u[uid].tid + u[uid].r; //plaintext = { ID i || T 1 || TID i || r i }
		string d = aesEncryption(key, plaintext); 

		string e = generateHash(generateHash(uidstr + gwn.x) + u[uid].r + t1); //e = h(h ( ID i || X k ) || r i || T 1 )


		//step-3
		d = aesDecryption(key, d);

		string t2 = randomNumber(256, 1); //timestamp 2

		//verify h ( h ( ID i || X k ) || r i || T 1 ) = E i
		if(e == generateHash(generateHash(uidstr + gwn.x) + u[uid].r + t1))
		{
			string rk = randomNumber(256, 1); //random number
			string key = generateHash( exor(sidstr, sran) ); //h ( ID SN ⊕ S ran )
			plaintext = exor(rk, u[uid].r) + u[uid].tid + t1 + t2; //(r k ⊕ r i || TID i || T 1 || T 2)

			string f = aesEncryption(key, plaintext);

			string gwnidstr = randomNumber(256, 0); //storing id of the gwn in string form
		 	int gwnid = (int) (gwnidstr[4] - '0');
			gwnid = (gwnid) % 5;
			gwnidstr = to_string(gwnid);
			reverse(gwnidstr.begin(), gwnidstr.end());
			gwnidstr.resize(64, '0');
			reverse(gwnidstr.begin(), gwnidstr.end());

			//G i = h ( TID i || ID SN j || h ( ID SN j ⊕ S ran ) || ID GW N || T 2 || r k ⊕ r i )
			string g = generateHash(u[uid].tid + sidstr + generateHash( exor(sidstr , sran)) + gwnidstr + t2 + exor(rk, u[uid].r)); 

			//step-4
			key = generateHash(sidstr + sran);
			f = aesDecryption(key, f);

			//g1 = h ( ID SN j || TID i || ID GW N || h ( ID SN j ⊕ S ran ) || T 2 || r k ⊕ r i )
			string g1 = generateHash((u[uid].tid + sidstr + generateHash( exor(sidstr , sran)) + gwnidstr + t2 + exor(rk, u[uid].r)));

			if(g1 == g)
			{
				string rj = randomNumber(256, 1); //random number
				string t3 = randomNumber(256, 1); //timestamp 3

				string sk = generateHash(exor(rk, exor(u[uid].r, rj)) + t1 + t2 + t3); //SK = h ( r k ⊕ r i ⊕ r j || T 1 || T 2 || T 3 )

				plaintext = rj + t3 + exor(rk, u[uid].r); //plaintext = ( r j || T 3 || r k ⊕ r i )
				string h = aesEncryption(key, plaintext); //same key

				string i = generateHash(sidstr + u[uid].tid + t3 + sk); //i = h ( ID SN j || TID i || T 3 || SK )

				//step-5

				f = aesDecryption(key, h); //decryption

				sk = generateHash(exor(rk, exor(u[uid].r, rj)) + t1 + t2 + t3); //SK = h ( r k ⊕ r i ⊕ r j , T 1 , T 2 , T 3 )

				//checks if h ( ID SN j , TID i , T 3 , SK ) = I 
				if(generateHash(sidstr + u[uid].tid + t3 + sk) == i)
				{
					string t4 = randomNumber(256, 1); //timestamp 4

					//plaintext = ( r k ⊕ r j || r i || ID SN j || ID GW N || T 2 || T 3 || T 4 )
					plaintext = exor(rk, rj) + u[uid].r + sidstr + gwnidstr + t2 + t3 + t4; 
					key = uidstr + gwn.x; //h ( ID i ,X k )
					string j = aesEncryption(key, plaintext); 

					string k = generateHash(sk + t4 + generateHash(u[uid].tid + gwn.x)); //K i = h ( SK, T 4 , h ( TID i , X k ))

					//step-6

					f = aesDecryption(key, j); //decrypts ( r k ⊕ r j || r i || ID SN j || ID GW N || T 2 || T 3 || T 4 ) using h ( ID i ,X k )

					sk = generateHash(exor(rk, exor(u[uid].r, rj)) + t1 + t2 + t3); //sk = h ( r k ⊕ r i ⊕ r j || T 1 || T 2 || T 3 )

					if(generateHash(sk + t4 + generateHash(u[uid].tid + gwn.x)) == t4)
						cout << "\nWash up after the successful handshake!\n";
					flag = 1;
				}
				else
					cout << "wrong2" << endl;
			}
			else
				cout << "wrong1" << endl;
		}
		else
			cout << "wrong" << endl;
	}
	else
		cout << "\n 'a' value didn't match \n";
 }
