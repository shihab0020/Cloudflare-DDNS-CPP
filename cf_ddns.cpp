#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <chrono>
#include <thread>
#include <ctime>
#include <filesystem>
#include <json/json.h>
#include <curl/curl.h>
#include <unistd.h>
#include <limits.h>
#include <mutex>

namespace fs = std::filesystem;

// Global mutex for thread-safe logging
std::mutex log_mutex;

std::string get_binary_directory() {
    char result[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", result, PATH_MAX);
    return fs::path(std::string(result, (count > 0) ? count : 0)).remove_filename().string();
}

std::string now_time() {
    std::time_t t = std::time(nullptr);
    char buf[100];
    std::strftime(buf, sizeof(buf), "%F %T", std::localtime(&t));
    return buf;
}

void log_to_file(const std::string& file, const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::ofstream log(file, std::ios::app);
    if (log) {
        log << "[" << now_time() << "] " << message << "\n";
    }
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t total = size * nmemb;
    output->append((char*)contents, total);
    return total;
}

std::string get_public_ip(bool ipv6 = false) {
    CURL* curl = curl_easy_init();
    std::string url = ipv6 ? "https://api6.ipify.org" : "https://api.ipify.org";
    std::string response;

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        if (res != CURLE_OK) return "";
    }

    return response;
}

std::string get_current_dns_ip(const std::string& token, const std::string& zone_id, const std::string& record_id) {
    CURL* curl = curl_easy_init();
    std::string url = "https://api.cloudflare.com/client/v4/zones/" + zone_id + "/dns_records/" + record_id;
    std::string response;

    if (curl) {
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, ("Authorization: Bearer " + token).c_str());
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        if (res != CURLE_OK) return "";
    }

    Json::Value json;
    Json::CharReaderBuilder builder;
    std::string errs;
    std::stringstream ss(response);
    Json::parseFromStream(builder, ss, &json, &errs);

    return json["success"].asBool() ? json["result"]["content"].asString() : "";
}

void update_dns_record(const std::string& token, const std::string& zone_id, const std::string& record_id,
                       const std::string& record_name, const std::string& ip, bool proxy, const std::string& type,
                       const std::string& log_file) {
    CURL* curl = curl_easy_init();
    if (!curl) return;

    std::string url = "https://api.cloudflare.com/client/v4/zones/" + zone_id + "/dns_records/" + record_id;

    Json::Value data;
    data["type"] = type;
    data["name"] = record_name;
    data["content"] = ip;
    data["ttl"] = 1;
    data["proxied"] = proxy;

    Json::StreamWriterBuilder writer;
    std::string json_data = Json::writeString(writer, data);

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, ("Authorization: Bearer " + token).c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");

    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        log_to_file(log_file, "Updated " + type + " record for " + record_name + " to " + ip);
    } else {
        log_to_file(log_file, "Failed to update " + record_name);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

void clean_old_logs(const std::string& dir, int max_days) {
    using namespace std::chrono;
    const auto now = system_clock::now();

    for (const auto& entry : fs::directory_iterator(dir)) {
        if (entry.is_regular_file()) {
            auto ftime = fs::last_write_time(entry);
            auto ftime_sys = time_point_cast<system_clock::duration>(
                ftime - decltype(ftime)::clock::now() + now);
            auto age_days = duration_cast<hours>(now - ftime_sys).count() / 24;
            if (age_days > max_days) {
                fs::remove(entry.path());
            }
        }
    }
}

int main() {
    std::string base_dir = get_binary_directory();
    std::string config_file = base_dir + "/config.json";
    std::string log_dir = base_dir + "/logs";
    std::string log_file = log_dir + "/ddns.log";

    fs::create_directories(log_dir);
    clean_old_logs(log_dir, 30);

    std::ifstream file(config_file);
    if (!file.is_open()) {
        log_to_file(log_file, "Could not open config.json");
        return 1;
    }

    Json::Value config;
    Json::CharReaderBuilder builder;
    std::string errs;
    Json::parseFromStream(builder, file, &config, &errs);
    file.close();

    std::string api_token = config["api_token"].asString();
    int interval = config.get("check_interval", 300).asInt();
    const Json::Value& records = config["records"];

    std::map<std::string, std::string> ip_cache;

    while (true) {
        for (const auto& rec : records) {
            std::string name = rec["record_name"].asString();
            std::string id = rec["record_id"].asString();
            std::string zone = rec["zone_id"].asString();
            bool proxy = rec.get("enable_proxy", false).asBool();

            if (rec.get("enable_ipv4", true).asBool()) {
                std::string type = "A";
                std::string ip = get_public_ip(false);
                if (!ip.empty() && ip_cache[name + "_A"] != ip) {
                    std::string current_ip = get_current_dns_ip(api_token, zone, id);
                    if (ip != current_ip) {
                        update_dns_record(api_token, zone, id, name, ip, proxy, type, log_file);
                        ip_cache[name + "_A"] = ip;
                    }
                }
            }

            if (rec.get("enable_ipv6", false).asBool()) {
                std::string type = "AAAA";
                std::string ip = get_public_ip(true);
                if (!ip.empty() && ip_cache[name + "_AAAA"] != ip) {
                    std::string current_ip = get_current_dns_ip(api_token, zone, id);
                    if (ip != current_ip) {
                        update_dns_record(api_token, zone, id, name, ip, proxy, type, log_file);
                        ip_cache[name + "_AAAA"] = ip;
                    }
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(interval));
    }

    return 0;
}
