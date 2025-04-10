// cf_ddns.cpp
// Cloudflare DDNS Updater (C++) - Final version with logging, IPv4/IPv6, config, and service support

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <chrono>
#include <ctime>
#include <thread>
#include <json/json.h>
#include <curl/curl.h>
#include <unistd.h>
#include <limits.h>

namespace fs = std::filesystem;

std::string get_binary_directory() {
    char result[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", result, PATH_MAX);
    std::string path(result, (count > 0) ? count : 0);
    return fs::path(path).parent_path();
}

std::string load_file(const std::string& path) {
    std::ifstream in(path);
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t totalSize = size * nmemb;
    output->append((char*)contents, totalSize);
    return totalSize;
}

std::string get_public_ip(const std::string& url) {
    CURL* curl = curl_easy_init();
    std::string response;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        if (res != CURLE_OK) return "";
    }
    return response;
}

std::string get_current_dns_ip(const std::string& zone_id, const std::string& record_id, const std::string& api_token, bool is_ipv6) {
    CURL* curl = curl_easy_init();
    std::string response;
    if (curl) {
        std::string url = "https://api.cloudflare.com/client/v4/zones/" + zone_id + "/dns_records/" + record_id;
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, ("Authorization: Bearer " + api_token).c_str());
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res == CURLE_OK) {
            Json::CharReaderBuilder reader;
            Json::Value root;
            std::string errs;
            std::istringstream s(response);
            if (Json::parseFromStream(reader, s, &root, &errs)) {
                return root["result"]["content"].asString();
            }
        }
    }
    return "";
}

void log_message(const std::string& log_path, const std::string& message) {
    std::ofstream log(log_path, std::ios::app);
    std::time_t now = std::time(nullptr);
    log << "[" << std::put_time(std::localtime(&now), "%F %T") << "] " << message << std::endl;
}

void clean_old_logs(const std::string& log_dir, int retention_days) {
    auto now = std::chrono::system_clock::now();
    for (const auto& entry : fs::directory_iterator(log_dir)) {
        auto ftime = fs::last_write_time(entry.path());
        auto sys_time = decltype(ftime)::clock::to_time_t(ftime);
        auto file_age = std::chrono::duration_cast<std::chrono::hours>(now - std::chrono::system_clock::from_time_t(sys_time)).count() / 24;
        if (file_age > retention_days) {
            fs::remove(entry.path());
        }
    }
}

void update_record(const std::string& zone_id, const std::string& record_id, const std::string& name, const std::string& ip, const std::string& api_token, bool proxy, bool is_ipv6, const std::string& log_file) {
    CURL* curl = curl_easy_init();
    if (!curl) return;

    Json::Value root;
    root["type"] = is_ipv6 ? "AAAA" : "A";
    root["name"] = name;
    root["content"] = ip;
    root["ttl"] = 1;
    root["proxied"] = proxy;

    Json::StreamWriterBuilder writer;
    std::string json_data = Json::writeString(writer, root);

    std::string url = "https://api.cloudflare.com/client/v4/zones/" + zone_id + "/dns_records/" + record_id;
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, ("Authorization: Bearer " + api_token).c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");

    std::string response_string;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        log_message(log_file, "Updated " + name + " (" + (is_ipv6 ? "AAAA" : "A") + ") to " + ip);
    } else {
        log_message(log_file, "CURL error updating record: " + std::string(curl_easy_strerror(res)));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

int main() {
    std::string base_dir = get_binary_directory();
    std::string config_path = base_dir + "/config.json";
    std::string log_dir = base_dir + "/logs";
    std::string log_file = log_dir + "/ddns.log";

    fs::create_directories(log_dir);

    std::ifstream config_file(config_path);
    if (!config_file.is_open()) return 1;

    Json::Value config;
    Json::CharReaderBuilder reader;
    std::string errs;
    if (!Json::parseFromStream(reader, config_file, &config, &errs)) return 1;

    std::string api_token = config["api_token"].asString();
    int interval = config.get("check_interval", 300).asInt();
    int retention_days = config.get("log_retention_days", 30).asInt();

    clean_old_logs(log_dir, retention_days);

    while (true) {
        for (const auto& record : config["records"]) {
            std::string zone_id = record["zone_id"].asString();
            std::string record_id = record["record_id"].asString();
            std::string name = record["name"].asString();
            bool enable_ipv6 = record.get("enable_ipv6", false).asBool();
            bool enable_proxy = record.get("enable_proxy", false).asBool();

            std::string ipv4 = get_public_ip("https://api.ipify.org");
            std::string current_ipv4 = get_current_dns_ip(zone_id, record_id, api_token, false);
            if (!ipv4.empty() && ipv4 != current_ipv4) {
                update_record(zone_id, record_id, name, ipv4, api_token, enable_proxy, false, log_file);
            }

            if (enable_ipv6) {
                std::string ipv6 = get_public_ip("https://api6.ipify.org");
                std::string current_ipv6 = get_current_dns_ip(zone_id, record_id, api_token, true);
                if (!ipv6.empty() && ipv6 != current_ipv6) {
                    update_record(zone_id, record_id, name, ipv6, api_token, enable_proxy, true, log_file);
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(interval));
    }

    return 0;
}