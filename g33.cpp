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
const int N2 = 5;

#define long int64_t

struct Cont
{
	int idsSN[N2];
	string sidsSN[N2];
	string kpsSN[N2];
	string tscnsSN[N2];

	int idsPN[N1];
	string sidsPN[N1];
	string kpsPN[N1];
	string tscnsPN[N1];
};

struct Sense
{
	int id;
	string sid;
	string kp;
	string tscn;

	int adj[N1] = {0};
};

struct Relay
{
	int id;
	string sid;
	string kp;
	string tscn;
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

	// cout << "\nMEHHH\n" << a << " and len = " << a.length() << "\nMEEE\n";

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
	string mk = randomNumber(128, 1);
	// cout << mk << endl << endl;

	Cont contNode;
	Sense secNodes[N2];

	//setting the adjacent nodes for the corresponding secondary nodes
	for(int i = 0; i < 4; i++)
		secNodes[0].adj[i] = 1;

	secNodes[1].adj[0] = 1;
	secNodes[1].adj[4] = 1;


	secNodes[2].adj[3] = 1;
	secNodes[2].adj[5] = 1;

	secNodes[3].adj[4] = 1;

	secNodes[4].adj[5] = 1;
	//Finished with setting the adjacent nodes

	string str;
	string s;
	string input;
	string r;
	string p;

	for(int i=0; i<N2; i++)
	{
		secNodes[i].id = i;
		contNode.idsSN[i] = i;
		str = to_string(secNodes[i].id);

		str = makeupper(str);
		input = str + mk;
		secNodes[i].kp = generateHash(input);
		contNode.kpsSN[i] = secNodes[i].kp;

		// cout << secNodes[i].kp << endl;

		s = randomNumber(160, 1);
		input = str + s + secNodes[i].kp;
		secNodes[i].sid = generateHash(input);
		contNode.sidsSN[i] = secNodes[i].sid;

		// cout << secNodes[i].sid << endl;

		s = randomNumber(64, 1);
		secNodes[i].tscn = s;
		contNode.tscnsSN[i] = secNodes[i].tscn;

		// cout << secNodes[i].tscn << endl;
	}

	// cout << endl << endl << "Done with Secondary Nodes" << endl << endl;
	Relay priNodes[N1];

	for(int i=0; i<N1; i++)
	{
		priNodes[i].id = i;
		contNode.idsPN[i] = i;
		str = to_string(priNodes[i].id);

		input = str + mk;
		priNodes[i].kp = generateHash(input);
		contNode.kpsPN[i] = priNodes[i].kp;

		// cout << priNodes[i].kp << endl;

		s = randomNumber(160, 1);
		input = str + s + priNodes[i].kp;
		priNodes[i].sid = generateHash(input);
		contNode.sidsPN[i] = priNodes[i].sid;

		// cout << priNodes[i].sid << endl;

		s = randomNumber(64, 1);
		priNodes[i].tscn = s;
		contNode.tscnsPN[i] = priNodes[i].tscn;

		// cout << priNodes[i].tscn << endl << endl;
	}

	// cout << endl << endl << "Done with Primary Nodes" << endl << endl;

	// cout << "If it is an emergency, input 1. Otherwise, input 0" << endl;
	int situation;
	cin >> situation;

	if(situation)
	{
		//step 1
		string aidsn;
		int prim;

		str = randomNumber(64, 0);
		str.pop_back();
		int rid = (int) (str.back() - '0');
		rid = rid % 5;
		str = to_string(rid);

		r = randomNumber(40, 1);

		input = str + secNodes[rid].kp + r + secNodes[rid].tscn;
		aidsn = generateHash(input);

		string x = secNodes[rid].kp;
		x = exor(r, x);

		//step2
		for (int i = 0; i < N1; ++i)
		{
			if(secNodes[rid].adj[i])
			{
				prim = i;
				break;
			}
		}

		string str = to_string(prim);
		p = randomNumber(40, 1); //p
		
		input = str + priNodes[prim].kp + p + priNodes[prim].tscn;
		string aidpn = generateHash(input);
		string y = exor(p, priNodes[prim].kp);

		//step 3
		int flag1 = 0;
		int flag2 = 0;
		for (int i = 0; i < N1; ++i)
			if(priNodes[prim].tscn == contNode.tscnsPN[i])
				flag1 = 1;

		for (int i = 0; i < N2; ++i)
			if(secNodes[rid].tscn == contNode.tscnsSN[i])
				flag2 = 1;

		string aidpn1;
		string aidsn1;
		string r1;
		string p1;
		string sk;
		string sk1;
		string sk2;
		string m;
		string n;
		string v5;
		string v6;
		string ts;
		string ts1;

		int flag3 = 0;

		if(flag1 && flag2)
		{
			// cout << "Valid" << endl;
			// cout << "Selected " << prim << endl;

			p1 = exor(y, priNodes[prim].kp); //p*
			reverse(p1.begin(), p1.end());
			p1.resize(10);
			reverse(p1.begin(), p1.end());

			str = to_string(prim);
			input = str + priNodes[prim].kp + p1 + priNodes[prim].tscn;
			aidpn1 = generateHash(input);//aidpn1


			if(aidpn == aidpn1)
			{
				//string r1;
				r1 = exor(x, secNodes[rid].kp);//r*
				reverse(r1.begin(), r1.end());
				r1.resize(10);
				reverse(r1.begin(), r1.end());

				str = to_string(rid);
				input = str + secNodes[rid].kp + r1 + secNodes[rid].tscn;
				aidsn1 = generateHash(input);//aidsn(valid)

				if(aidsn == aidsn1)
				{
					m = randomNumber(64, 1);
					// cout << m << endl;

					n = randomNumber(64, 1);
					// cout << n << endl;

					input = secNodes[rid].kp + str + r1;
					ts = exor(m, generateHash(input));

					str = to_string(prim);
					input = priNodes[prim].kp + str + p1;
					ts1 = exor(n, generateHash(input));

					sk = randomNumber(160, 1);

					str = to_string(rid);
					input = secNodes[rid].kp + str + r1;
					sk1 = exor(sk, generateHash(input));

					str = to_string(prim);
					input = priNodes[prim].kp + str + p1;
					sk2 = exor(sk, generateHash(input));

					str = to_string(rid);
					input = sk1 + ts + secNodes[rid].kp + str + r1;
					v5 = generateHash(input);

					str = to_string(prim);
					input = sk2 + ts1 + priNodes[prim].kp + str + p1;
					v6 = generateHash(input);

					str = to_string(rid);
					input = secNodes[rid].kp + str + m;
					secNodes[rid].kp = generateHash(input);

					str = to_string(prim);
					input = priNodes[prim].kp + str + n;
					priNodes[prim].kp = generateHash(input);

					flag3 = 1;
				}
				else
					cout << "AID of secondary node is invalid" << endl;
			}
			else
				cout << "AID of primary node is invalid" << endl;
		}
		else
			cout << "Transaction numbers are invalid" << endl;

		//step 4
		if(flag3)
		{
			str = to_string(prim);
			input = sk2 + ts1 + priNodes[prim].kp + str + p;
			if(v6 == generateHash(input))
			{
				sk = exor(sk2, generateHash(priNodes[prim].kp + str + p));

				input = priNodes[prim].kp + str + p;
				n = exor(ts1, generateHash(input));

				input = priNodes[prim].kp + str + n;
				priNodes[prim].kp = generateHash(input);

				str = to_string(rid);
				input = sk1 + ts + secNodes[rid].kp + str + r;
				if(v5 == generateHash(input))
				{
					sk = exor(sk1, generateHash(secNodes[rid].kp + str + r));

					input = secNodes[rid].kp + str + r;
					n = exor(ts, generateHash(input));

					input = secNodes[rid].kp + str + m;
					secNodes[rid].kp = generateHash(input);
				}
			}
		}
	}	
	else
	{
		//Step 1
		string aidsn;
		string sk;

		str = randomNumber(64, 0);
		str.pop_back();
		int rid = (int) (str.back() - '0');
		rid = rid % 5;
		str = to_string(rid);

		s = randomNumber(40, 1);

		input = str + secNodes[rid].kp + s + secNodes[rid].tscn;
		aidsn = generateHash(input);
		input = str + secNodes[rid].kp + aidsn + s;
		sk = generateHash(input);

		string x = secNodes[rid].kp;
		x = exor(s, x);

		input = aidsn + sk + s;
		string v1 = generateHash(input);

		//Step 2
		string aidpn[6];
		string y[6];

		for (int i = 0; i < N1; ++i)
		{
			if(secNodes[rid].adj[i])
			{
				str = to_string(i);
				s = randomNumber(40, 1);

				input = str + priNodes[i].kp + s + priNodes[i].tscn;

				aidpn[i] = generateHash(input);

				y[i] = priNodes[i].kp;
				y[i] = exor(s, y[i]);
			}
		}

		//step3
		int prim;
		int flag1 = 0;
		int flag2 = 0;
		for(int i = 0; i < N1; i++)
		{
			if(secNodes[rid].adj[i])
			{
				for (int j = 0; j < N1; ++j)
				{
					if(priNodes[i].tscn == contNode.tscnsPN[j])
					{
						prim = i;
						flag1 = 1;
						break;
					}
				}
			}
		}


		for (int i = 0; i < N2; ++i)
		{
			if(secNodes[rid].tscn == contNode.tscnsSN[i])
			{
				flag2 = 1;
				break;
			}
		}

		string aidpn1;
		string aidsn1;
		string r1;
		string sk1;
		string v11;
		string m;
		string n;
		string v2;
		string v3;
		string ts;
		string tsopt;
		string s1;

		int flag3 = 0;

		if(flag1 && flag2)
		{
			// cout << "Valid" << endl;
			// cout << "Selected " << prim << endl;

			string y1 = y[prim];
			s1 = exor(y1, priNodes[prim].kp); //p*(iopt)
			reverse(s1.begin(), s1.end());
			s1.resize(10);
			reverse(s1.begin(), s1.end());

			str = to_string(prim);
			input = str + priNodes[prim].kp + s1 + priNodes[prim].tscn;
			aidpn1 = generateHash(input);//aidpn(opt)


			if(aidpn[prim] == aidpn1)
			{
				//string r1;
				r1 = exor(x, secNodes[rid].kp);//r*
				reverse(r1.begin(), r1.end());
				r1.resize(10);
				reverse(r1.begin(), r1.end());

				str = to_string(rid);
				input = str + secNodes[rid].kp + r1 + secNodes[rid].tscn;
				aidsn1 = generateHash(input);//aidsn(valid)

				if(aidsn == aidsn1)
				{
					//string sk1;
					input = str + secNodes[rid].kp + aidsn + r1;
					sk1 = generateHash(input);//sk*

					//string v11;
					input = aidsn + sk1 + r1;
					v11 = generateHash(input);//v1*

					if(v11 == v1)
					{
						m = randomNumber(64, 1);
						// cout << m << endl;

						n = randomNumber(64, 1);
						// cout << n << endl;

						ts = exor(m, generateHash(sk1 + str + r1));
						str = to_string(prim);
						tsopt = exor(n, generateHash(priNodes[prim].kp + str + s1));

						str = to_string(rid);
						v2 = generateHash(ts + sk1 + str);

						str = to_string(prim);
						v3 = tsopt + priNodes[prim].kp + str;

						v3 = generateHash(v3);

						str = to_string(rid);
						secNodes[rid].kp = generateHash(secNodes[rid].kp + str + m);
						flag3 = 1;
					}
					else
						cout << "SK is wrong" << endl;
				}
				else
					cout << "AID of secondary node is invalid" << endl;
			}
			else
				cout << "AID of primary node is invalid"<< endl;
		}
		else
			cout << "Transaction numbers invalid" << endl;

		if(flag3)
		{
			str = to_string(prim);
			string v31 = tsopt + priNodes[prim].kp + str;

			if(v3 == (generateHash(v31)))
			{
				input = priNodes[prim].kp + str + s1;
				input = generateHash(input);
				string tsopt1 = exor(input, tsopt);
				n = tsopt1;

				str = to_string(rid);
				input = ts + sk + str;
				input = generateHash(input);
				if(v2 == input)
				{
					input = sk + str + r1;
					input = generateHash(input);
					m = exor(ts, input);

					input = secNodes[rid].kp + str + m;
					secNodes[rid].kp = generateHash(input);
				}
				else
					cout << "Invalid ts\n";
			}
			else
				cout << "Invalid tsopt\n";
		}
		
	}
    return 0;
}
