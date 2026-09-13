#include "OidcPrintHost.hpp"

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <boost/beast/core/detail/base64.hpp>
#include <boost/nowide/fstream.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/format.hpp>
#include <boost/log/trivial.hpp>

#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <sstream>

#include "nlohmann/json.hpp"
#include "libslic3r/Utils.hpp"
#include "slic3r/GUI/I18N.hpp"
#include "slic3r/GUI/format.hpp"
#include "slic3r/GUI/GUI_App.hpp"

namespace Slic3r {

// A distinct loopback port from SimplyPrint's (21328) and OrcaCloudServiceAgent's (41172), so all
// three PKCE flows can coexist without a port clash if more than one is somehow triggered at once.
static constexpr boost::asio::ip::port_type CALLBACK_PORT = 21329;
static const std::string CALLBACK_URL = "http://localhost:21329/callback";
static const std::string DISCOVERY_PATH = "/.well-known/openid-configuration";
static const std::string DEFAULT_CLIENT_ID = "orcaslicer-example";

// CSPRNG-based verifier (OpenSSL RAND_bytes), unlike SimplyPrint's rand()-based one - the only
// part of SimplyPrint's PKCE implementation this class deliberately does not mirror as-is.
static std::string random_base64url(size_t num_bytes)
{
    std::vector<unsigned char> bytes(num_bytes);
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        // Extremely unlikely (would mean the platform's CSPRNG is unavailable); fall back to a
        // seeded PRNG rather than fail outright, matching the robustness of a login attempt that
        // should still work end to end even in that degraded case.
        srand(static_cast<unsigned>(time(nullptr)));
        for (auto& b : bytes) b = static_cast<unsigned char>(rand() % 0x100);
    }

    std::string out;
    out.resize(boost::beast::detail::base64::encoded_size(bytes.size()));
    out.resize(boost::beast::detail::base64::encode(&out[0], bytes.data(), bytes.size()));
    std::replace(out.begin(), out.end(), '+', '-');
    std::replace(out.begin(), out.end(), '/', '_');
    out.erase(std::remove(out.begin(), out.end(), '='), out.end());
    return out;
}

static std::string sha256_base64url(const std::string& input)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);

    std::string b64;
    b64.resize(boost::beast::detail::base64::encoded_size(sizeof(hash)));
    b64.resize(boost::beast::detail::base64::encode(&b64[0], hash, sizeof(hash)));
    std::replace(b64.begin(), b64.end(), '+', '-');
    std::replace(b64.begin(), b64.end(), '/', '_');
    b64.erase(std::remove(b64.begin(), b64.end(), '='), b64.end());
    return b64;
}

static std::string sha256_hex(const std::string& input)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char b : hash)
        oss << std::setw(2) << static_cast<int>(b);
    return oss.str();
}

static std::string url_encode(const std::vector<std::pair<std::string, std::string>>& query)
{
    std::vector<std::string> q;
    q.reserve(query.size());
    std::transform(query.begin(), query.end(), std::back_inserter(q), [](const auto& kv) {
        return Http::url_encode(kv.first) + "=" + Http::url_encode(kv.second);
    });
    return boost::algorithm::join(q, "&");
}

static void set_auth(Http& http, const std::string& access_token) { http.header("Authorization", "Bearer " + access_token); }

OidcPrintHost::OidcPrintHost(DynamicPrintConfig* config)
    : m_backend_url(config->opt_string("print_host"))
    , m_scope(config->opt_string("oidc_scope"))
{
    m_client_id = GUI::wxGetApp().app_config->get("oidc_client_id");
    if (m_client_id.empty())
        m_client_id = DEFAULT_CLIENT_ID;

    // Credentials are cached per (backend, client, requested scope), so two Physical Printer
    // profiles pointed at the same backend but requesting different printers' scopes never share
    // (or clobber) each other's token.
    const std::string hash = sha256_hex(m_backend_url + "|" + m_client_id + "|" + m_scope).substr(0, 24);
    cred_file = (boost::filesystem::path(data_dir()) / ("oidc_oauth_" + hash + ".json")).make_preferred().string();
    load_oauth_credential();
}

bool OidcPrintHost::ensure_discovery() const
{
    if (m_discovery_done)
        return !m_token_endpoint.empty();
    m_discovery_done = true;

    if (m_backend_url.empty())
        return false;

    std::string body;
    Http::get(m_backend_url + DISCOVERY_PATH)
        .timeout_connect(5)
        .timeout_max(10)
        .on_complete([&body](std::string b, unsigned) { body = std::move(b); })
        .on_error([](std::string, std::string error, unsigned status) {
            BOOST_LOG_TRIVIAL(error) << boost::format("OidcPrintHost: discovery failed: %1%, HTTP %2%") % error % status;
        })
        .perform_sync();

    const auto j = nlohmann::json::parse(body, nullptr, false, true);
    if (j.is_discarded())
        return false;

    m_authorization_endpoint = j.value("authorization_endpoint", "");
    m_token_endpoint         = j.value("token_endpoint", "");
    return !m_authorization_endpoint.empty() && !m_token_endpoint.empty();
}

GUI::OAuthParams OidcPrintHost::get_oauth_params() const
{
    if (!ensure_discovery())
        return GUI::OAuthParams();

    const auto verifier  = random_base64url(32);
    const auto challenge = sha256_base64url(verifier);
    const auto state     = random_base64url(16);

    const std::vector<std::pair<std::string, std::string>> query_parameters{
        {"response_type", "code"},
        {"client_id", m_client_id},
        {"redirect_uri", CALLBACK_URL},
        {"code_challenge", challenge},
        {"code_challenge_method", "S256"},
        {"scope", m_scope},
        {"state", state},
    };
    const char sep = m_authorization_endpoint.find('?') == std::string::npos ? '?' : '&';
    const auto login_url = m_authorization_endpoint + sep + url_encode(query_parameters);

    return GUI::OAuthParams{
        login_url,
        m_client_id,
        CALLBACK_PORT,
        CALLBACK_URL,
        m_scope,
        "code",
        m_backend_url,
        m_backend_url,
        m_token_endpoint,
        verifier,
        state,
    };
}

void OidcPrintHost::load_oauth_credential()
{
    cred.clear();
    if (!boost::filesystem::exists(cred_file))
        return;

    try {
        nlohmann::json j;
        boost::nowide::ifstream ifs(cred_file);
        ifs >> j;
        ifs.close();

        cred["access_token"]  = j.at("access_token").get<std::string>();
        cred["refresh_token"] = j.at("refresh_token").get<std::string>();
    } catch (std::exception& err) {
        BOOST_LOG_TRIVIAL(error) << __FUNCTION__ << ": parse " << cred_file << " failed, reason = " << err.what();
        cred.clear();
    }
}

void OidcPrintHost::save_oauth_credential(const GUI::OAuthResult& result) const
{
    nlohmann::json j;
    j["access_token"]  = result.access_token;
    j["refresh_token"] = result.refresh_token;

    boost::nowide::ofstream c;
    c.open(cred_file, std::ios::out | std::ios::trunc);
    c << j.dump(1, '\t') << std::endl;
    c.close();
}

void OidcPrintHost::log_out() const { boost::nowide::remove(cred_file.c_str()); }

wxString OidcPrintHost::get_test_ok_msg() const { return _(L("Connected to the printer-manager backend successfully!")); }

wxString OidcPrintHost::get_test_failed_msg(wxString& msg) const
{
    return GUI::format_wxstr("%s: %s", _L("Could not connect to the printer-manager backend"), msg.Truncate(256));
}

bool OidcPrintHost::do_api_call(std::function<Http(bool)>                               build_request,
                                 std::function<bool(std::string, unsigned)>              on_complete,
                                 std::function<bool(std::string, std::string, unsigned)> on_error) const
{
    auto it = cred.find("access_token");
    if (it == cred.end())
        return false;

    bool res = true;

    const auto create_request = [&build_request, &res, &on_complete](const std::string& access_token, bool is_retry) {
        auto http = build_request(is_retry);
        set_auth(http, access_token);
        http.on_complete([&](std::string body, unsigned http_status) { res = on_complete(body, http_status); });
        return http;
    };

    create_request(it->second, false)
        .on_error([&res, &on_error, this, &create_request](std::string body, std::string error, unsigned http_status) {
            if (http_status != 401) {
                res = on_error(body, error, http_status);
                return;
            }

            BOOST_LOG_TRIVIAL(info) << "OidcPrintHost: access token rejected (401), attempting refresh";
            auto refresh_it = cred.find("refresh_token");
            if (refresh_it == cred.end() || !ensure_discovery()) {
                res = on_error(body, error, http_status);
                return;
            }

            Http::post(m_token_endpoint)
                .timeout_connect(5)
                .timeout_max(5)
                .form_add("grant_type", "refresh_token")
                .form_add("client_id", m_client_id)
                .form_add("refresh_token", refresh_it->second)
                .on_complete([this, &res, &on_error, &create_request](std::string body, unsigned) {
                    GUI::OAuthResult r;
                    GUI::OAuthJob::parse_token_response(body, false, r);
                    if (!r.success) {
                        BOOST_LOG_TRIVIAL(error) << "OidcPrintHost: failed to refresh access token: " << r.error_message;
                        res = on_error(body, r.error_message, 401);
                        return;
                    }
                    this->save_oauth_credential(r);
                    create_request(r.access_token, true)
                        .on_error([&res, &on_error](std::string body, std::string error, unsigned http_status) {
                            res = on_error(body, error, http_status);
                        })
                        .perform_sync();
                })
                .on_error([&res, &on_error](std::string body, std::string error, unsigned http_status) {
                    res = on_error(body, error, http_status);
                })
                .perform_sync();
        })
        .perform_sync();

    return res;
}

bool OidcPrintHost::test(wxString& curl_msg) const
{
    if (cred.find("access_token") == cred.end())
        return false;

    return do_api_call(
        [this](bool) { return Http::get(m_backend_url + "/status"); },
        [](std::string, unsigned) { return true; },
        [&curl_msg](std::string body, std::string error, unsigned status) {
            curl_msg = GUI::format_wxstr("%s (HTTP %d)", error, status);
            return false;
        });
}

bool OidcPrintHost::upload(PrintHostUpload upload_data, ProgressFn prorgess_fn, ErrorFn error_fn, InfoFn info_fn) const
{
    if (cred.find("access_token") == cred.end()) {
        error_fn(_L("Not signed in to the printer-manager backend. Use the Test button to sign in."));
        return false;
    }

    const auto filename = upload_data.upload_path.filename().string();
    const bool want_start_print = upload_data.post_action == PrintHostPostUploadAction::StartPrint;

    bool ok = do_api_call(
        [this, &upload_data, &filename, &prorgess_fn](bool) {
            auto http = Http::post(m_backend_url + "/upload");
            http.form_add_file("file", upload_data.source_path, filename);
            http.on_progress([&prorgess_fn](Http::Progress progress, bool& cancel) { prorgess_fn(std::move(progress), cancel); });
            return http;
        },
        [](std::string body, unsigned status) { return true; },
        [this, &error_fn](std::string body, std::string error, unsigned status) {
            error_fn(format_error(body, error, status));
            return false;
        });

    if (ok && want_start_print) {
        ok = do_api_call(
            [this](bool) { return Http::post(m_backend_url + "/print"); },
            [](std::string, unsigned) { return true; },
            [this, &error_fn](std::string body, std::string error, unsigned status) {
                error_fn(format_error(body, error, status));
                return false;
            });
    }

    return ok;
}

} // namespace Slic3r
