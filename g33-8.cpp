#include <bits/stdc++.h>
#include <strstream>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/hrtimer.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

using namespace std;
using namespace CryptoPP;

const int N1 = 6;
const int N2 = 6;

#define long int64_t

struct Hub
{
	string mk;
	int id1[N1];
};

struct Sense
{
	int id2;
	string a;
	string b;

	int adj[N1] = {0};
};

struct Relay
{
	int id1;
	int id2;
	string a;
	string b;
};

ostringstream oss;

int buffer;

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
	SHA1 hash;
	byte digest[CryptoPP::SHA1::DIGESTSIZE];
	hash.CalculateDigest(digest, (const byte*)source.c_str(), source.size());
	string output;
	HexEncoder encoder;
	StringSink test = CryptoPP::StringSink(output);
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();
	return output;
 }

 string exor(string a, string b)
{
	reverse(a.begin(), a.end());
	a.resize(40, '0');
	reverse(a.begin(), a.end());

	reverse(b.begin(), b.end());
	b.resize(40, '0');
	reverse(b.begin(), b.end());

	for(int i = 0; i < 40; ++i)
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
	Hub contNode;

	contNode.mk = randomNumber(160, 1);
	// cout << contNode.mk << endl << endl;

	Sense secNodes[N2];
	Relay priNodes[N1];
	string k;
	string input;

	//
	for(int i = 0; i < 4; i++)
		secNodes[0].adj[i] = 1;

	secNodes[1].adj[0] = 1;
	secNodes[1].adj[4] = 1;

	secNodes[2].adj[3] = 1;
	secNodes[2].adj[5] = 1;

	secNodes[3].adj[4] = 1;

	secNodes[4].adj[5] = 1;

	for(int i = 0; i < 3; i++)
		secNodes[5].adj[i] = 1;
	//

	for(int i=0; i<N2; i++)
	{
		secNodes[i].id2 = i;

		k = randomNumber(160, 1);

		input = contNode.mk + k;
		secNodes[i].a = exor(to_string(secNodes[i].id2), generateHash(input));

		string temp;
		temp = exor(secNodes[i].a, k);
		secNodes[i].b = exor(contNode.mk, temp);

		priNodes[i].id1 = i;
		priNodes[i].id2 = i;
		priNodes[i].a = secNodes[i].a;
		priNodes[i].b = secNodes[i].b;

		contNode.id1[i] = i;
	}

	//CHoosing the second-level node
	string str2 = randomNumber(160, 0);
	int rid = (int) (str2[4] - '0');
	rid = rid % 5;
	str2 = to_string(rid);
	reverse(str2.begin(), str2.end());
	str2.resize(40, '0');
	reverse(str2.begin(), str2.end());


	int prim;

	for (int i = 0; i < N1; ++i)
	{
		if(secNodes[rid].adj[i])
		{
			prim = i;
			break;
		}
	}

	string str1 = to_string(prim);
	reverse(str1.begin(), str1.end());
	str1.resize(40, '0');
	reverse(str1.begin(), str1.end());

	string r = randomNumber(160, 1);

	string t = randomNumber(160, 1);

	string x = exor(str2, secNodes[rid].a);

	string y = exor(r, x);

	input = exor(str2, t) + r;
	string tid = generateHash(input);

	// cout << input << endl;

	int flag1 = 0;
	int flag2 = 0;
	for (int i = 0; i < N1; ++i)
	{
		if(prim == contNode.id1[i])
		{
			flag1 = 1;
			break;
		}
	}

	string k1;
	string x1;
	string r1;
	string id1;
	string tid1;

	if(flag1)
	{
		k1 = exor(contNode.mk, exor(secNodes[rid].a, secNodes[rid].b));
		x1 = generateHash(contNode.mk + k1);
		id1 = exor(secNodes[rid].a, x1);
		r1 = exor(y, x1);

		input = exor(t, id1) + r1;
		tid1 = generateHash(input);

		// cout << input << endl;

		if(tid == tid1)
			flag2 = 1;
	}
	else
		cout << "\nWRONG ID BITCH\n";
	string f;
	string alpha;
	string gamma;
	string k2;
	string eta;
	string myu;
	string beta;
	string sk;
	string a1;
	string b1;
	if(flag2)
	{
		// cout << "\nHI\n";

		f = randomNumber(160, 1);
		alpha = exor(x, f);
		gamma = exor(r, f);

		k2 = randomNumber(160,1);
		a1 = exor(str2, generateHash(contNode.mk + k2));

		input = exor(a1, k2);
		b1 = exor(contNode.mk, input);

		eta = exor(gamma, a1);
		myu = exor(gamma, b1);

		beta = generateHash(x + r + f + eta + myu);

		sk = generateHash(str2 + r + f + x);
	}
	else
		cout << "\nWRONG TID ASS\n";

	string f1 = exor(x, alpha);
	string beta1 = generateHash(x + r + f1 + eta + myu);

	string sk1;
	if(beta == beta1)
	{
		gamma = exor(r, f);
		a1 = exor(gamma, eta);
		b1 = exor(gamma, myu);
		sk1 = generateHash(str2 + r + f + x);

		secNodes[rid].a = a1;
		secNodes[rid].b = b1;
		priNodes[prim].a = secNodes[rid].a;
		priNodes[prim].b = secNodes[rid].b;

		// cout << "HELLO\n";
	}
	else
		cout << "\nINVALID BETA CUNT\n";
	return 0;
}
