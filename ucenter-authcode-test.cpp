// ucenter-authcode-test.cpp main
//

#include <stdio.h>
#include <tchar.h>

#include "./ucenter_authcode/ucenter_authcode.h"
#include <iostream>


int main(int argc, _TCHAR* argv[])
{
	std::string eng_key = "Adding the gist -r <id> command to read a gist";
	std::string eng = "Summary of pull requests, issues opened, and commits. Learn how we count contributions.?!{}[]\\/~!@#$#$%$^^%&*()_+";

	ucenter_authcode eng_ua(eng_key);
	std::string eng_en = eng_ua.encode(eng);
	std::string eng_de = eng_ua.decode(eng_en);

	std::cout << "eng:" << eng << std::endl;
	std::cout << "eng_en:" << eng_en << std::endl;
	std::cout << "eng_de:" << eng_de << std::endl;
	std::cout << "eng == eng_de:" << (eng == eng_de) << std::endl;

	std::string cn = "向MyCat数据库中插入一条String类型数据,程序使用？！《》｛｝【】“”’‘、·１２３４５６７８９０－＝＋—";

	std::string cn_en = eng_ua.encode(cn);
	std::string cn_de = eng_ua.decode(cn_en);

	std::cout << "cn:" << cn << std::endl;
	std::cout << "cn_en:" << cn_en << std::endl;
	std::cout << "cn_de:" << cn_de << std::endl;
	std::cout << "cn == cn_de:" << (cn == cn_de) << std::endl;

	return 0;
}

