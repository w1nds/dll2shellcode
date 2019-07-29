//dll2shellcode.cpp : Defines the entry point for the console application.

#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <string>
#include "makeshell.h"

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
using namespace boost::program_options;

int main(int argc, char* argv[])
{

	try
	{
		std::string strInpath;
		std::string strOutpath;
		int nType;
		std::string strShellpath;
		options_description desc{ "Options" };
		desc.add_options()
			("help,h", "produce help message")
			("in,i", value<std::string>(&strInpath), "input path")
			("type,t", value<int>(&nType)->default_value(1), "1: header file  2: naked function  3: binary file")
			("call,c", value<std::string>(&strShellpath), "call test,shellcode binary path")
			("out,o", value<std::string>(&strOutpath), "output path");
		variables_map vm;
		store(parse_command_line(argc, argv, desc), vm);
		notify(vm);

		if (vm.count("help"))
			std::cout << desc << '\n';
		else if (vm.count("in") && vm.count("out") && vm.count("type"))
		{
			MakeShellCode(strInpath.c_str(),strOutpath.c_str(),nType);
		}
		else if (vm.count("call"))
		{
			CallTest(strShellpath.c_str());
		}
		else if (argc == 2)
		{
			//当前目录生成 shellcode.h shell.dat naked.h
			boost::filesystem::path file_path(argv[1]);
			if (boost::filesystem::is_regular_file(file_path))
			{
				MakeShellCode(argv[1], (boost::filesystem::current_path() / "shellcode.h").string().c_str(), 1);
				MakeShellCode(argv[1], (boost::filesystem::current_path() / "naked.h").string().c_str(), 2);
				MakeShellCode(argv[1], (boost::filesystem::current_path() / "shell.dat").string().c_str(), 3);
			}
		}
	}
	catch (const error &ex)
	{
		std::cerr << ex.what() << '\n';
	}
	return 0;
}
