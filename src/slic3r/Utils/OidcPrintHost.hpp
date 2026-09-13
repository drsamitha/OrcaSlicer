#ifndef slic3r_OidcPrintHost_hpp_
#define slic3r_OidcPrintHost_hpp_

#include "PrintHost.hpp"
#include "slic3r/GUI/Jobs/OAuthJob.hpp"

namespace Slic3r {

class DynamicPrintConfig;

// Generic Authorization Code + PKCE print host for any backend that implements the same small
// contract an OctoPrint/PrusaLink host does not need: a discovery document at
// "<print_host>/.well-known/openid-configuration" (so this class never hardcodes a gateway
// product's own paths), a bearer-token-protected /status /upload /print /stop API, and a
// /device page for the embedded Device tab. Modeled directly on SimplyPrint (the other PKCE
// PrintHost already shipping in Orca) - see SimplyPrint.hpp/.cpp for the pattern this mirrors.
//
// Unlike SimplyPrint, which talks to one fixed cloud service, every value that identifies *which*
// backend and *which* printer on it is external to this class:
//   - the backend base URL is `print_host` (a normal per-profile field, auto-filled by
//     PhysicalPrinterDialog from AppConfig's "oidc_backend_url" so every OIDC profile points at
//     the same one backend by default)
//   - the requested access is `oidc_scope` (a new per-Physical-Printer-profile field, e.g.
//     "p1:status p1:upload p1:trigger") - the backend derives which printer this profile talks to
//     entirely from this scope string, Orca never knows a printer's name/model/capabilities.
class OidcPrintHost : public PrintHost
{
    std::string m_backend_url;
    std::string m_scope;
    std::string m_client_id;

    std::string cred_file;
    std::map<std::string, std::string> cred;

    // Populated lazily (from get_host() + "/.well-known/openid-configuration") the first time
    // they're needed, then cached for the lifetime of this instance.
    mutable std::string m_authorization_endpoint;
    mutable std::string m_token_endpoint;
    mutable bool m_discovery_done{false};

    bool ensure_discovery() const;
    void load_oauth_credential();

    bool do_api_call(std::function<Http(bool /*is_retry*/)>                                                           build_request,
                     std::function<bool(std::string /* body */, unsigned /* http_status */)>                          on_complete,
                     std::function<bool(std::string /* body */, std::string /* error */, unsigned /* http_status */)> on_error) const;

public:
    explicit OidcPrintHost(DynamicPrintConfig* config);
    ~OidcPrintHost() override = default;

    const char* get_name() const override { return "OIDC"; }
    bool can_test() const override { return true; }
    bool has_auto_discovery() const override { return false; }
    bool is_cloud() const override { return true; }
    std::string get_host() const override { return m_backend_url; }

    bool             is_pkce_oauth() const override { return true; }
    GUI::OAuthParams get_oauth_params() const override;
    void             save_oauth_credential(const GUI::OAuthResult& result) const override;
    std::string      get_access_token() const override
    {
        auto it = cred.find("access_token");
        return it != cred.end() ? it->second : std::string();
    }

    wxString                   get_test_ok_msg() const override;
    wxString                   get_test_failed_msg(wxString& msg) const override;
    bool                       test(wxString& curl_msg) const override;
    PrintHostPostUploadActions get_post_upload_actions() const override
    {
        return PrintHostPostUploadAction::StartPrint | PrintHostPostUploadAction::QueuePrint;
    }
    bool                       upload(PrintHostUpload upload_data, ProgressFn prorgess_fn, ErrorFn error_fn, InfoFn info_fn) const override;
    bool                       is_logged_in() const override { return cred.find("access_token") != cred.end(); }
    void                       log_out() const override;
};

} // namespace Slic3r

#endif
