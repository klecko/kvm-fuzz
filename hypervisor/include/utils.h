#include <iostream>

void create_folder(const std::string& path);

std::string read_file(const std::string& filepath);

void write_file(const std::string& filepath, const std::string& content);

std::string md5(const std::string& s);

std::string md5(const uint8_t* buf, size_t length);

std::string md5_file(const std::string& filepath);

std::string to_hex(size_t num);