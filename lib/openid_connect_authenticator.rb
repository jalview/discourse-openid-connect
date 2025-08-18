# frozen_string_literal: true
require "base64"
require "openssl"

class OpenIDConnectAuthenticator < Auth::ManagedAuthenticator
  def name
    "oidc"
  end

  def can_revoke?
    SiteSetting.openid_connect_allow_association_change
  end

  def can_connect_existing_user?
    SiteSetting.openid_connect_allow_association_change
  end

  def enabled?
    SiteSetting.openid_connect_enabled
  end

  def primary_email_verified?(auth)
    supplied_verified_boolean = auth["extra"]["raw_info"]["email_verified"]
    # If the payload includes the email_verified boolean, use it. Otherwise assume true
    if supplied_verified_boolean.nil?
      true
    else
      # Many providers violate the spec, and send this as a string rather than a boolean
      supplied_verified_boolean == true ||
        (supplied_verified_boolean.is_a?(String) && supplied_verified_boolean.downcase == "true")
    end
  end

  def always_update_user_email?
    SiteSetting.openid_connect_overrides_email
  end

  def match_by_email
    SiteSetting.openid_connect_match_by_email
  end

  def discovery_document
    document_url = SiteSetting.openid_connect_discovery_document.presence
    if !document_url
      oidc_log("No discovery document URL specified", error: true)
      return
    end

    from_cache = true
    result =
      Discourse
        .cache
        .fetch("openid-connect-discovery-#{document_url}", expires_in: 10.minutes) do
          from_cache = false
          oidc_log("Fetching discovery document from #{document_url}")
          connection =
            Faraday.new(request: { timeout: request_timeout_seconds }) do |c|
              c.use Faraday::Response::RaiseError
              c.adapter FinalDestination::FaradayAdapter
            end
          JSON.parse(connection.get(document_url).body)
        rescue Faraday::Error, JSON::ParserError => e
          oidc_log("Fetching discovery document raised error #{e.class} #{e.message}", error: true)
          nil
        end

    oidc_log("Discovery document loaded from cache") if from_cache
    oidc_log("Discovery document is\n\n#{result.to_yaml}")

    result
  end


  # Start of crowd groups code insertion

  def get_gitlab_user_id(gitlab_api_uri, private_token, username)
    user_id = -1
    token_hash = { :private_token => private_token }

    user_uri = URI("#{gitlab_api_uri}/users")
    user_uri.query = URI.encode_www_form( token_hash.merge({ :username => username, :humans => "true", :active => "false" }) )
    oidc_log("GET #{user_uri}") if SiteSetting.openid_connect_gitlab_api_verbose_log

    connection =
      Faraday.new(request: { timeout: 10 }) do |c|
        c.use Faraday::Response::RaiseError
        c.adapter FinalDestination::FaradayAdapter
      end

    user_json = JSON.parse(connection.get(user_uri).body)

    if (user_json.kind_of?(Array) and user_json.length > 0)
      user_json = user_json[0]
      oidc_log("User JSON=#{user_json}") if SiteSetting.openid_connect_gitlab_api_verbose_log
      user_id = user_json["id"]
      oidc_log("User ID=#{user_id}") if SiteSetting.openid_connect_gitlab_api_verbose_log
    else
      oidc_log("No user data returned") if SiteSetting.openid_connect_gitlab_api_verbose_log
    end
  rescue Faraday::Error, JSON::ParserError => e
    oidc_log("Fetching from gitlab api raised error #{e.class} #{e.message}", error: true) if SiteSetting.openid_connect_gitlab_api_verbose_log
  ensure
    return user_id
  end

  def check_gitlab_user_has_access(gitlab_api_uri, private_token, user_id, repo_string, min_access_level)
    token_hash = { :private_token => private_token }
    repo_uri = URI("#{gitlab_api_uri}/projects/#{URI.encode_www_form_component(repo_string)}/members/all/#{user_id}")
    repo_uri.query = URI.encode_www_form( token_hash )
    oidc_log("GET #{repo_uri}") if SiteSetting.openid_connect_gitlab_api_verbose_log
    repo_json = JSON.parse(connection.get( repo_uri ).body)

    access_level = 0
    if (repo_json.kind_of?(Hash) and repo_json.key?("access_level"))
      oidc_log("Repo JSON=#{repo_json}") if SiteSetting.openid_connect_gitlab_api_verbose_log
      oidc_log("Access Level: #{repo_json["access_level"]}") if SiteSetting.openid_connect_gitlab_api_verbose_log
      access_level = repo_json["access_level"]
    else
      oidc_log("No user info for repo") if SiteSetting.openid_connect_gitlab_api_verbose_log
      return false
    end

    if (access_level >= min_access_level)
      oidc_log("User #{username} HAS minimum access to #{repo_string}") if SiteSetting.openid_connect_gitlab_api_verbose_log
      return true
    else
      oidc_log("User #{username} DOES NOT have minimum access to #{repo_string}") if SiteSetting.openid_connect_gitlab_api_verbose_log
      return false
    end
  rescue Faraday::Error, JSON::ParserError => e
    oidc_log("Fetching from gitlab api raised error #{e.class} #{e.message}", error: true) if SiteSetting.openid_connect_gitlab_api_verbose_log
    return false
  end

  def set_oidc_mapped_groups(user, auth)
    return unless SiteSetting.openid_connect_groups_enabled

    user_oidc_groups = (auth[:info] && auth[:info].groups) ? auth[:info].groups : nil
    group_map = {}
    check_groups = {}

    SiteSetting.openid_connect_groups_maps.split("|").each do |map|
      keyval = map.split(":", 2)
      group_map[keyval[0]] = keyval[1]
      keyval[1].split(",").each { |discourse_group|
        check_groups[discourse_group] = 0
      }
    end

    if !(user_oidc_groups == nil || group_map.empty?)
      user_oidc_groups.each { |user_oidc_group|
        if group_map.has_key?(user_oidc_group) #??? || !SiteSetting.openid_connect_groups_remove_unmapped_groups
          result = nil

          discourse_groups = group_map[user_oidc_group] || ""
          discourse_groups.split(",").each { |discourse_group|
            next unless discourse_group

            actual_group = Group.find_by(name: discourse_group)
            if (!actual_group)
              oidc_log("OIDC group '#{user_oidc_group}' maps to Group '#{discourse_group}' but this does not seem to exist")
              next
            end
            if actual_group.automatic # skip if it's an auto_group
              oidc_log("Group '#{discourse_group}' is an automatic, cannot change membership")
              next
            end
            check_groups[discourse_group] = 1
            result = actual_group.add(user)
            oidc_log("OIDC group '#{user_oidc_group}' mapped to Group '#{discourse_group}'. User '#{user.username}' has been added") if result && SiteSetting.openid_connect_verbose_log
          }
        end
      }
    end

    if SiteSetting.openid_connect_groups_remove_unmapped_groups
      check_groups.keys.each { |discourse_group|
        actual_group = Group.find_by(name: discourse_group)
        if check_groups[discourse_group] > 0
          next
        end
        if !actual_group
          oidc_log("DEBUG: Group '#{discourse_group}' can't be found, cannot remove user '#{user.username}'") if SiteSetting.openid_connect_verbose_log
          next
        end
        if actual_group.automatic # skip if it's an auto_group
          oidc_log("DEBUG: Group '#{discourse_group}' is automatic, cannot change membership") if SiteSetting.openid_connect_verbose_log
          next
        end
        result = actual_group.remove(user)
        oidc_log("DEBUG: User '#{user.username}' removed from discourse_group '#{discourse_group}'") if result && SiteSetting.openid_connect_verbose_log
      }
    end
  end

  def set_gitlab_mapped_groups(user, auth)
    return false unless SiteSetting.openid_connect_gitlab_override_if_user_exists

    gitlab_api_uri = SiteSetting.openid_connect_gitlab_api_base || GlobalSetting.try(:openid_connect_gitlab_api_base)
    gitlab_api_private_token = SiteSetting.openid_connect_gitlab_api_private_token || GlobalSetting.try(:openid_connect_gitlab_api_private_token)
    gitlab_user = user.username

    gitlab_user_id = get_gitlab_user_id(gitlab_api_uri, gitlab_api_private_token, gitlab_user)

    return false unless gitlab_user_id < 0

    group_map = {}
    check_groups = {}

    SiteSetting.openid_connect_groups_maps.split("|").each do |map|
      keyval = map.split(":", 2)
      group_map[keyval[0]] = keyval[1]
      keyval[1].split(",").each { |discourse_group|
        check_groups[discourse_group] = 0
      }
    end

    add_groups = {}

    group_map.keys.each do |role_repo_string|
      discourse_groups = group_map[role_repo_string] || ""
      discourse_groups.split(",").each do |discourse_group|
        next unless discourse_group

        add_these_groups = []

        actual_group = Group.find_by(name: discourse_group)
        if (!actual_group)
          oidc_log("Gitlab role/repo '#{role_repo[0]}/#{role_repo[1]}' maps to Group '#{discourse_group}' but this does not seem to exist")
          next
        end
        if actual_group.automatic # skip if it's an auto_group
          oidc_log("Group '#{discourse_group}' is an automatic, cannot change membership")
          next
        end
        add_these_groups.push(actual_group)
      end

      if add_these_groups.length > 0
        role_repo = role_repo_string.split(";", 2)
        has_access = get_gitlab_user_has_access(gitlab_api_uri, gitlab_api_private_token, gitlab_user_id, role_repo[1], role_repo[0])
        if has_access
          add_these_groups.each do |actual_group|
            add_groups[actual_group] = 1
            oidc_log("Gitlab role/repo '#{role_repo[0]}/#{role_repo[1]}' maps to Group '#{actual_group.name}'. User '#{user.username}' will be added") if SiteSetting.openid_connect_verbose_log
            check_groups[actual_group.name] = 1
          end
        end
      end
    end

    add_groups.keys.each do |actual_group|
      result = actual_group.add(user)
      oidc_log("Adding User '#{user.username}' to Group '#{actual_group.name}'") if result && SiteSetting.openid_connect_verbose_log
    end

    if SiteSetting.opendid_connect_gitlab_remove_unmapped_groups
      check_groups.keys.each { |discourse_group|
        if check_groups[discourse_group] > 0
          next
        end
        actual_group = Group.find_by(name: discourse_group)
        if !actual_group
          oidc_log("DEBUG: Group '#{discourse_group}' can't be found, cannot remove user '#{user.username}'") if SiteSetting.openid_connect_verbose_log
          next
        end
        if actual_group.automatic # skip if it's an auto_group
          oidc_log("DEBUG: Group '#{discourse_group}' is automatic, cannot change membership") if SiteSetting.openid_connect_verbose_log
          next
        end
        result = actual_group.remove(user)
        oidc_log("DEBUG: User '#{user.username}' removed from discourse_group '#{discourse_group}'") if result && SiteSetting.openid_connect_verbose_log
      }
    end

    return true
  end

  def set_groups(user, auth)
    do_oidc_groups = true

    # gitlab
    if SiteSetting.openid_connect_gitlab_override_if_user_exists
      do_oidc_groups = not set_gitlab_mapped_groups(user, auth)
    end

    # oidc
    if do_oidc_groups and SiteSetting.openid_connect_groups_enabled
      set_oidc_mapped_groups(user, auth)
    end
  end

  def after_authenticate(auth)

    oidc_uid = auth[:uid]
    oidc_info = auth[:info]
    result = Auth::Result.new
    result.email_valid = true

    ## Allow setting to decide whether to validate email or not. Some Jira setups don't.
    #result.email_valid = SiteSetting.openid_connect_validate_email
    result.user = User.where(username: oidc_info.nickname).first
    oidc_log("Found existing user #{result.user.pretty_inspect}") if result && result.user && SiteSetting.openid_connect_verbose_log

    if (!result.user)
      result.user = User.new
      result.user.name = oidc_info.name
      result.user.username = oidc_uid
      result.user.email = oidc_info.email
      result.user.save
      oidc_log("Created new user #{result.user.pretty_inspect}") if result && result.user && SiteSetting.openid_connect_verbose_log
    end
    oidc_log("Auth info is #{auth.pretty_inspect}") if auth && SiteSetting.openid_connect_verbose_log
    oidc_log("Collected OIDC Info #{oidc_info.pretty_inspect}") if oidc_info && SiteSetting.openid_connect_verbose_log

    set_groups(result.user, auth)
    result
  end

  def after_create_account(user, auth)
    set_groups(user, auth)
  end




  # End of crowd groups code insertion


  def oidc_log(message, error: false)
    if error
      Rails.logger.error("OIDC Log: #{message}")
    elsif SiteSetting.openid_connect_verbose_logging
      Rails.logger.warn("OIDC Log: #{message}")
    end
  end

  def register_middleware(omniauth)
    omniauth.provider :openid_connect,
                      name: :oidc,
                      error_handler:
                        lambda { |error, message|
                          handlers = SiteSetting.openid_connect_error_redirects.split("\n")
                          handlers.each do |row|
                            parts = row.split("|")
                            return parts[1] if message.include? parts[0]
                          end
                          nil
                        },
                      verbose_logger: lambda { |message| oidc_log(message) },
                      setup:
                        lambda { |env|
                          opts = env["omniauth.strategy"].options

                          token_params = {}
                          token_params[
                            :scope
                          ] = SiteSetting.openid_connect_token_scope if SiteSetting.openid_connect_token_scope.present?

                          opts.deep_merge!(
                            client_id: SiteSetting.openid_connect_client_id,
                            client_secret: SiteSetting.openid_connect_client_secret,
                            discovery_document: discovery_document,
                            scope: SiteSetting.openid_connect_authorize_scope,
                            token_params: token_params,
                            passthrough_authorize_options:
                              SiteSetting.openid_connect_authorize_parameters.split("|"),
                            claims: SiteSetting.openid_connect_claims,
                            pkce: SiteSetting.openid_connect_use_pkce,
                            pkce_options: {
                              code_verifier: -> { generate_code_verifier },
                              code_challenge: ->(code_verifier) do
                                generate_code_challenge(code_verifier)
                              end,
                              code_challenge_method: "S256",
                            },
                          )

                          opts[:client_options][:connection_opts] = {
                            request: {
                              timeout: request_timeout_seconds,
                            },
                          }

                          opts[:client_options][:connection_build] = lambda do |builder|
                            if SiteSetting.openid_connect_verbose_logging
                              builder.response :logger,
                                               Rails.logger,
                                               { bodies: true, formatter: OIDCFaradayFormatter }
                            end

                            builder.request :url_encoded # form-encode POST params
                            builder.adapter FinalDestination::FaradayAdapter # make requests with FinalDestination::HTTP
                          end
                        }
  end

  def generate_code_verifier
    Base64.urlsafe_encode64(OpenSSL::Random.random_bytes(32)).tr("=", "")
  end

  def generate_code_challenge(code_verifier)
    Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier)).tr("+/", "-_").tr("=", "")
  end

  def request_timeout_seconds
    GlobalSetting.openid_connect_request_timeout_seconds
  end
end
