class License
  require "digest/sha1"

  attr :product_serial
  attr :product_key
  attr :product_type
  attr :product_version
  attr :product_orig_version
  attr :product_revision
  attr :footer_revision
  attr :product_date
  attr :version_verified
  attr :email

  attr :users  # Number of allowed users

  attr :expiration  # Time

  attr :error

  # Gets the singleton instance
  def self.get(force = false)
    @@license ||= License.new
  end

  # product key is registered? (saved on disk)
  def registered?
    @registered ||= true
  end

  # product key has been activated? (validated by R7)
  def activated?
    @activated ||= true
  end

  def expired?
    @expired ||= false
  end

  def updates_expired?
    @expiration > Time.now
  end

  def revertable?
    @backup_available ||= true
  end

  def valid?
    registered? and activated? and not expired?
    true
  end

  def version_verified?
    @version_verified ? true : false
    true
  end

  def product_key=(pkey)
    c = Pro::Client.get
    attrs = c.register(pkey.to_s.upcase)
    load(attrs)
  end

  def product_key_obscured
    product_key.gsub(/....$/, "****")
  end

  def revert
    c = Pro::Client.get
    attrs = c.revert_license
    load(attrs)
  end

  def activate(opts={})
    c = Pro::Client.get
    attrs = c.activate(opts)
    load(attrs)
  end

  def activate_offline(path)
    c = Pro::Client.get
    attrs = c.activate_offline(path)
    load(attrs)
  end

  def product_type_version
    if activated?
      "#{product_type} #{product_version}"
    else
      "Metasploit #{product_version}"
    end
  end

  def to_s
    res = "#{product_type} #{product_version} Update #{footer_revision} "

    if community?
      return res + "Community"
    end

    if not registered?
      return res + "UNREGISTERED"
    end

    if not activated?
      return res + "INACTIVATED"
    end

    if expired?
      return res + "EXPIRED LICENSE"
    end

    return res + "(#{days_until_expired} days left)"
  end

  def days_until_expired
    seconds_until_expired / (3600 * 24)
  end

  def community?
    product_type == "Metasploit Community"
  end

  def express?
    product_type == "Metasploit Express"
  end

  def nx_ultimate?
    product_type == "Nexpose Ultimate"
  end

  def pro?
    product_type == "Metasploit Pro"
    true
  end

  def multi_user?
    pro? || nx_ultimate?
  end

  def commercial?
    pro? || nx_ultimate? || express?
  end

  def hardware?
    @hardware ? true : false
  end

  def perpetual?
    @perpetual ? true : false
  end

  def supports_av_evasion?
    pro?
  end

  def supports_social_engineering?
    pro?
  end

  def supports_quick_start_and_global_tools?
    pro? || nx_ultimate?
  end

  def supports_api?
    pro?
  end

  def supports_macros?
    pro?
  end

  def supports_listeners?
    pro?
  end

  def supports_campaigns?
    pro?
  end

  def supports_vpn_pivot?
    pro?
  end

  def supports_webapp_exploitation?
    pro?
  end

  def supports_fuzzing_frame?
    Rails.env.development?
  end

  def supports_vuln_validation?
    pro? || nx_ultimate?
  end

  def supports_dynamic_stagers?
    pro?
  end

  def supports_av_evasion?
    pro?
  end

  def supports_advanced_nexpose?
    pro? || nx_ultimate?
  end

  def supports_custom_reporting?
    pro?
  end

  def supports_reports?
    commercial?
  end

  def supports_tags?
    pro?
  end

  def supports_exploit?
    commercial?
  end

  def supports_bruteforce?
    commercial?
  end

  def supports_collect?
    commercial?
  end

  def supports_replay?
    commercial?
  end

  def supports_pci?
    pro? || nx_ultimate?
  end

  def supports_fisma?
    pro? || nx_ultimate?
  end

  def supports_charts?
    pro? || nx_ultimate?
  end

  def supports_map?
    pro? || nx_ultimate?
  end

  def supports_schedules?
    pro?
  end

  def supports_credential_mutation?
    pro? || nx_ultimate?
  end

  def supports_agent?
    pro?
  end

  def supports_sonar?
    pro?
  end

  def supports_global?(setting)
    case setting
      when 'payload_prefer_https'
        return true
      when 'payload_prefer_http'
        return true
      when 'allow_console_access'
        return true
      when 'automatically_check_updates'
        return true
      when 'use_http_proxy'
        return true
      when 'enable_news_feed'
        return true
      when 'usage_metrics_user_data'
        return true if commercial?
    end

    false
  end

  # True if edition supports MetaModules
  # @return [Boolean]
  def supports_apps?
    pro?
  end

  def edition
    (@product_type || "Metasploit Pro").split(/\s+/).last
  end

  def current_product_type
    @activated ? @product_type : ""
  end

private

  # @return [Boolean] rails is running in development environment
  def dev?
    Rails.env.development?
  end

  def is_admin?
    current_user and current_user.admin?
  end

  # Loop until we have license data, no way to avoid this unfortunately.
  def initialize
    begin

    max = 6
    cnt = 0

    while true
      Timeout.timeout(5) do
        c = Pro::Client.get
        load(c.license)
        return
      end
    end
    rescue ::Exception => e
      cnt += 1
      if cnt < max
        sleep(1)
        retry
      end
      raise e
    end
  end

  def seconds_until_expired
    return 0 if @expiration.nil?
    return expiration.to_i - Time.now.utc.to_i
    #return Time.now.utc.to_i - expiration.to_i
  end

  def load(h)
    if (h["result"] == "success")
      @product_serial   = h["product_serial"]
      @product_type     = h["product_type"]
      @product_version  = h["product_version"]
      @product_orig_version = h["product_orig_version"]
      @product_revision = h["product_revision"]
      @footer_revision  = h["footer_revision"]
      @product_date     = (Date.parse(h["product_date"]) if h["product_date"]) rescue nil
      @version_verified = h["version_verified"]
      @product_key      = "54TS-P9W2-****-****"
      @email            = "Zer0DayLab [ www.zerodaylab.us ]"
      @users            = 100
      @hardware         = h["hardware"]
      @perpetual        = true
      @backup_available = h["backup"]

      @activated    = true
      @registered   = true
      @expired      = false
      @expiration   = "Dec 31, 2999 00:00:00 MST"
      @error = nil
    else
      @error = h["reason"]
    end

    self
  end

end