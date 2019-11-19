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
	int id;
	string pw;
	string tid;

	string a;
	string b;
	string c;

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

string generateHash(string source)
{
      SHA3_256 sha256;
      string hash = "";
      StringSource(source, true, new HashFilter(sha256, new HexEncoder(new StringSink(hash))));
      //cout << "hash = " << hash << "'\n";
      return hash;
}

SecByteBlock iv(AES::BLOCKSIZE);

string aesEncryption(string key, string plaintext)
{
	AutoSeededRandomPool rnd;

	SecByteBlock sbb((const byte*)key.data(), key.size());
	rnd.GenerateBlock(iv, iv.size());

	string output;
	CTR_Mode<AES>::Encryption encrypt((const byte*)sbb,AES::DEFAULT_KEYLENGTH,(const byte*)iv);
	StringSource(plaintext, true, new StreamTransformationFilter(encrypt, new StringSink(output)));
	//cout << "Encrypted: " << output << endl;

	return output;
}

string aesDecryption(string key, string ciphertext)
{
	AutoSeededRandomPool rnd;

	SecByteBlock sbb((const byte*)key.data(), key.size());

	string res;
	CTR_Mode<AES>::Decryption decrypt((const byte*)sbb,AES::DEFAULT_KEYLENGTH,(const byte*)iv);
	StringSource(ciphertext, true, new StreamTransformationFilter(decrypt, new StringSink(res)));
	//cout << "Decrypted: " << res << endl;

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
 	string input;

 	User u[N];
 	int flag = 0;
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
	string uidpass = u[uid].pw;

	//Computing a
	input = generateHash(uidstr) + generateHash(uidpass + r);
	gwn.au = generateHash(input);

	//computing b
	gwn.b = exor(generateHash(tidstr + gwn.x), generateHash(uidpass + r));

	//computing c
	temp = exor(generateHash(uidstr), generateHash(uidpass + r));
	gwn.c = exor(generateHash(uidstr + gwn.x), generateHash(temp));

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

	//gen erating gwn.as
	string sran = randomNumber(256, 1);
	gwn.as = generateHash(sidstr + sran);
	gwn.sid = sid;

	senNodes[sid].a = gwn.as;
	//SENSOR NODE REGISTRATION PHASE END

	//LOGIN PHASE BEGIN
	//step-1
	string a1 = generateHash(generateHash(uidstr) + generateHash(u[uid].pw + r));

	if(a1 == gwn.au)
	{
		//step-2
		string h1 = exor(gwn.b, generateHash(u[uid].pw + r));

		string temp = exor(generateHash(uidstr), generateHash(u[uid].pw + r));
		string h2 = exor(gwn.c, generateHash(temp));

		string t1 = randomNumber(256, 1);

		string key = generateHash(u[uid].tid + gwn.x);
		string plaintext = uidstr + t1 + u[uid].tid + u[uid].r;
		string d = aesEncryption(key, plaintext);

		string e = generateHash(generateHash(uidstr + gwn.x) + u[uid].r + t1);


		//step-3
		d = aesDecryption(key, d);

		string t2 = randomNumber(256, 1);

		if(e == generateHash(generateHash(uidstr + gwn.x) + u[uid].r + t1))
		{
			string rk = randomNumber(256, 1);
			string key = generateHash( exor(sidstr, sran) );
			plaintext = exor(rk, u[uid].r) + u[uid].tid + t1 + t2;

			string f = aesEncryption(key, plaintext);

			string gwnidstr = randomNumber(256, 0);
		 	int gwnid = (int) (gwnidstr[4] - '0');
			gwnid = (gwnid) % 5;
			gwnidstr = to_string(gwnid);
			reverse(gwnidstr.begin(), gwnidstr.end());
			gwnidstr.resize(64, '0');
			reverse(gwnidstr.begin(), gwnidstr.end());

			string g = generateHash(u[uid].tid + sidstr + generateHash( exor(sidstr , sran)) + gwnidstr + t2 + exor(rk, u[uid].r));

			//step-4
			key = generateHash(sidstr + sran);
			f = aesDecryption(key, f);

			string g1 = generateHash((u[uid].tid + sidstr + generateHash( exor(sidstr , sran)) + gwnidstr + t2 + exor(rk, u[uid].r)));

			if(g1 == g)
			{
				string rj = randomNumber(256, 1);
				string t3 = randomNumber(256, 1);

				string sk = generateHash(exor(rk, exor(u[uid].r, rj)) + t1 + t2 + t3);

				plaintext = rj + t3 + exor(rk, u[uid].r);
				string h = aesEncryption(key, plaintext);

				string i = generateHash(sidstr + u[uid].tid + t3 + sk);

				//step-5

				f = aesDecryption(key, h);

				sk = generateHash(exor(rk, exor(u[uid].r, rj)) + t1 + t2 + t3);

				if(generateHash(sidstr + u[uid].tid + t3 + sk) == i)
				{
					string t4 = randomNumber(256, 1);
					plaintext = exor(rk, rj) + u[uid].r + sidstr + gwnidstr + t2 + t3 + t4;
					key = uidstr + gwn.x;
					string k = generateHash(sk + t4 + generateHash(u[uid].tid + gwn.x));

					string j = aesEncryption(key, plaintext);

					//step-6

					f = aesDecryption(key, j);

					sk = generateHash(exor(rk, exor(u[uid].r, rj)) + t1 + t2 + t3);

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
			cout << "wrong0" << endl;
	}
	else
		cout << "\n FML \n";

/*
	if(flag)
	{	
		int ch;
		string pass;
		int who;
		string whos;
		string slash;

		cout << endl << uid << endl << uidpass << endl;
		cout << "\nWanna Change PWD?\n1 for Yes, 0  for No\n\n";
		cin >> ch;

		if(ch)
		{
			cout << "ID plox\n";
			cin >> who;
			whos = to_string(who);

			cout << "Enter old PWD\n";
			cin >> pass;

			slash = generateHash(generateHash(whos) + generateHash(pass + r));
			cout << u[who].a << endl;
			if(u[who].a == slash)
			{	
				string pass1;
				cout << "Enter new PWD\n";
				cin >> pass1;

				u[who].a = generateHash(generateHash(whos) + generateHash(pass + r));

				u[who].b = exor(u[who].b, exor(generateHash(pass + r), generateHash(pass1 + r)));

				input = generateHash(exor(generateHash(whos), generateHash(pass + r)));

				input = exor(input, generateHash(exor(generateHash(whos), generateHash(pass1 + r))));

				u[who].c = exor(u[who].c, input);

				cout << "\nGood Job, PWD Updated\n";
			}
		}
	}
*/
	return 0;
 }
