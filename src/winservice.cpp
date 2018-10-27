/*
 * Copyright 2017, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * File:   winservice.cpp
 * Author: alex
 *
 * Created on June 6, 2017, 6:31 PM
 */

#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <popt.h>

#include "staticlib/io.hpp"
#include "staticlib/json.hpp"
#include "staticlib/ranges.hpp"
#include "staticlib/tinydir.hpp"
#include "staticlib/utils.hpp"
#include "staticlib/winservice.hpp"

#include "wilton/wilton.h"
#include "wilton/wilton_mustache.h"
#include "wilton/wilton_signal.h"
#include "wilton/wiltoncall.h"

#include "winservice_config.hpp"
#include "winservice_exception.hpp"
#include "winservice_options.hpp"

namespace { //anonymous

std::string current_exedir() {
    auto exepath = sl::utils::current_executable_path();
    auto exedir = sl::utils::strip_filename(exepath);
    std::replace(exedir.begin(), exedir.end(), '\\', '/');
    return exedir;
}

std::string replace_appdir(const std::string& str, const std::string& appdir) {
    auto values = sl::json::dumps({
        { "appdir", appdir }
    });
    char* out = nullptr;
    int out_len = 0;
    auto err = wilton_mustache_render(str.c_str(), static_cast<int>(str.length()),
            values.c_str(), static_cast<int>(values.length()), std::addressof(out), std::addressof(out_len));
    if (nullptr != err) {
        auto msg = TRACEMSG(err);
        wilton_free(err);
        throw wilton::launcher::winservice_exception(msg);
    }
    auto out_str = std::string(out, out_len);
    wilton_free(out);
    return out_str;
}

wilton::launcher::winservice_config load_config(const std::string& cpath) {
    std::string path = "";
    try {
        // get path
        path = [&cpath] () -> std::string {
            if (!cpath.empty()) {
                return cpath;
            }
            std::string exedir = current_exedir();
            return exedir + "../conf/config.json";
        }();

        // load file
        auto src = sl::tinydir::file_source(path);
        auto conf = sl::json::load(src);

        // substitute appdir in wilton paths
        auto& wconf = conf.getattr_or_throw("wilton", "wilton");
        auto& appdir_el = wconf.getattr_or_throw("applicationDirectory", "wilton.applicationDirectory");
        auto appdir = [&path, &appdir_el] () -> std::string {
            auto& val = appdir_el.as_string_nonempty_or_throw("wilton.applicationDirectory");
            if ("{{{appdir}}}" != val) {
                return val;
            }
            auto res = sl::utils::strip_filename(path) + "../";
            appdir_el.set_string(res);
            return res;
        } ();
        auto& rjsconf = wconf.getattr_or_throw("requireJs", "wilton.requireJs");
        auto& base_url = rjsconf.getattr_or_throw("baseUrl", "wilton.requireJs.baseUrl");
        auto base_url_replaced = replace_appdir(base_url.as_string_nonempty_or_throw("wilton.requireJs.baseUrl"), appdir);
        base_url.set_string(base_url_replaced);
        auto& paths = rjsconf.getattr_or_throw("paths", "wilton.requireJs.paths");
        for (auto& pa : paths.as_object_or_throw("wilton.requireJs.paths")) {
            auto pa_replaced = replace_appdir(pa.as_string_nonempty_or_throw("wilton.requireJs.paths._"), appdir);
            pa.val().set_string(pa_replaced);
        }
        
        // return partially parsed config
        return wilton::launcher::winservice_config(std::move(conf));
    } catch (const std::exception& e) {
        throw wilton::launcher::winservice_exception(TRACEMSG(e.what() + 
                "\nError loading config file, path: [" + path + "]"));
    }
}

std::vector<sl::json::field> collect_env_vars(char** envp) {
    auto res = std::vector<sl::json::field>();
    for (char** el = envp; *el != '\0'; el++) {
        auto var = std::string(*el);
        auto parts = sl::utils::split(var, '=');
        if (2 == parts.size()) {
            res.emplace_back(parts.at(0), parts.at(1));
        }
    }
    return res;
}

void dyload_module(const std::string& name) {
    auto err_dyload = wilton_dyload(name.c_str(), static_cast<int>(name.length()), nullptr, 0);
    if (nullptr != err_dyload) {
        auto msg = TRACEMSG(err_dyload);
        wilton_free(err_dyload);
        throw wilton::launcher::winservice_exception(msg);
    }
}

void init_wilton(wilton::launcher::winservice_config& sconf, char** envp) {
    auto& conf_obj = sconf.json_config.getattr_or_throw("wilton", "wilton");
    auto& conf_vec = conf_obj.as_object_or_throw("wilton");
    auto env_vars = collect_env_vars(envp);
    conf_vec.emplace_back("environmentVariables", std::move(env_vars));
    auto config = conf_obj.dumps();
    auto err = wiltoncall_init(config.c_str(), static_cast<int> (config.length()));
    if (nullptr != err) {
        auto msg = TRACEMSG(err);
        wilton_free(err);
        throw wilton::launcher::winservice_exception(msg);
    }
    // load script engine
    auto enginelib = "wilton_" + conf_obj["defaultScriptEngine"].as_string_nonempty_or_throw("defaultScriptEngine");
    dyload_module("wilton_logging");
    dyload_module("wilton_loader");
    dyload_module(enginelib);
}

void init_signals() {
    dyload_module("wilton_signal");
    auto err_init = wilton_signal_initialize();
    if (nullptr != err_init) {
        auto msg = TRACEMSG(err_init);
        wilton_free(err_init);
        throw wilton::launcher::winservice_exception(msg);
    }
}

void run_script(const wilton::launcher::winservice_config& conf, const std::string& cmd) {
    std::string in = sl::json::dumps({
        { "module", conf.startup_module },
        { "func", "main" },
        { "args", [&cmd] {
            auto vec = std::vector<sl::json::value>();
            vec.emplace_back(cmd);
            return vec;
        }()}
    });
    auto engine = conf.json_config["wilton"]["defaultScriptEngine"].as_string_nonempty_or_throw("defaultScriptEngine");
    char* out = nullptr;
    int out_len = 0;
    auto err = wiltoncall_runscript(engine.c_str(), static_cast<int> (engine.length()), in.c_str(), static_cast<int> (in.length()),
            std::addressof(out), std::addressof(out_len));
    if (nullptr != err) {
        auto msg = TRACEMSG(err);
        wilton_free(err);
        throw wilton::launcher::winservice_exception(msg);
    }
    if (nullptr != out) {
        auto res = std::string(out, static_cast<uint32_t> (out_len));
        wilton_free(out);
        if (out_len > 0) {
            std::cout << res << std::endl;
        }
    }
}

void install(const wilton::launcher::winservice_config& conf) {
    std::cout << "Installing service with config: [" + conf.to_json().dumps() + "]" << std::endl;
    if (!sl::utils::current_process_elevated()) {
        throw wilton::launcher::winservice_exception(TRACEMSG(
            "Service install error, must be run under elevated (Administrator) account"));
    }
    sl::utils::ensure_has_logon_as_service(conf.user);
    sl::winservice::install_service(conf.service_name, conf.display_name,
            ".\\" + conf.user, conf.password);
    sl::winservice::start_service(conf.service_name);
}

void uninstall(const wilton::launcher::winservice_config& conf) {
    std::cout << "Uninstalling service with config: [" + conf.to_json().dumps() + "]" << std::endl;
    if (!sl::utils::current_process_elevated()) {
        throw wilton::launcher::winservice_exception(TRACEMSG(
            "Service uninstall error, must be run under elevated (Administrator) account"));
    }
    sl::winservice::uninstall_service(conf.service_name);
}

void stop(const wilton::launcher::winservice_config& conf) {
    std::cout << "Stopping service, name: [" + conf.service_name + "]" << std::endl;
    sl::winservice::stop_service(conf.service_name);
}

void start_service_and_wait(const wilton::launcher::winservice_config& conf) {
    std::cout << "Starting service with config: [" + conf.to_json().dumps() + "]" << std::endl;
    auto cf = std::make_shared<wilton::launcher::winservice_config>(conf.clone());
    sl::winservice::start_service_and_wait(conf.service_name,
    [cf] {
        run_script(*cf, "start");
    },
    [cf] {
        run_script(*cf, "stop");
        std::cout << "Stopping service ..." << std::endl;
    },
    [](const std::string& msg) {
        std::cerr << msg << std::endl;
    });
    std::cout << "Service stopped" << std::endl;
}

} // namespace

int main(int argc, char** argv, char** envp) {

    // parse command line
    wilton::launcher::winservice_options opts(argc, argv);

    // check invalid options
    if (!opts.parse_error.empty()) {
        std::cerr << "ERROR: " << opts.parse_error << std::endl;
        poptPrintUsage(opts.ctx, stderr, 0);
        return 1;
    }

    // show help
    if (opts.help) {
        poptPrintHelp(opts.ctx, stdout, 0);
        return 0;
    }
    
    try {        
        wilton::launcher::winservice_config conf = load_config(opts.config);
        init_wilton(conf, envp);

        if (opts.install) {
            install(conf);
        } else if (opts.uninstall) {
            uninstall(conf);
        } else if (opts.stop) {
            stop(conf);
        } else if (opts.direct) {
            init_signals();
            run_script(conf, "start");
            wilton_signal_await();
            run_script(conf, "stop");
        } else { // SCM call            
            start_service_and_wait(conf);
        }

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 1;
    }
}
