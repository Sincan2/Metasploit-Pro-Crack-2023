#
# Standard Library
#

# XMLRPC::FaullException
require 'xmlrpc/parser'

#
# Gems
#

require 'msf/core/rpc/v10/constants'
require 'rex/exceptions'

class ApplicationController < ActionController::Base

  protect_from_forgery with: :exception

  # TODO This does not seem to actually be working, and if it was
  # it seems like a bad thing:
  helper :all # include all helpers, all the time

  rescue_from Msf::RPC::ServerException, :with => :handle_xmlrpc_error
  rescue_from XMLRPC::FaultException,    :with => :handle_xmlrpc_error
  rescue_from Rex::ConnectionRefused,    :with => :handle_xmlrpc_error
  rescue_from EOFError,                  :with => :handle_xmlrpc_error
  rescue_from Errno::ECONNRESET,         :with => :handle_xmlrpc_error

  helper_method :current_user_session, :current_user, :load_workspace, :load_tasks, :active_pivots?, :ip_user

  before_action :check_session_absolute_timeout
  before_action :log_timeout_if_session_is_stale
  before_action :require_license
  before_action :require_user
  before_action :fetch_current_profile
  before_action :set_timezone
  # USAGE METRIC RELEASE DELAYED
  # before_action :set_usage_metric_countdown

  after_action :squash_unicode
  after_action :override_server_header

  def gather_workspace
    @workspace_name = @workspace.name
    @workspace_created_at = @workspace.created_at
    @workspace_updated_at = Time.now.utc.to_s
    lev = @workspace.events.last
    if lev
      @workspace_updated_at = lev.created_at
    end
  end

  # Picks up all the users that have opened sessions or run
  # modules (according to their respective datastores), and
  # keeps a running count in the @users hash.
  def gather_users
    @users = {}
    @sessions.blank? && gather_sessions
    @sessions.each do |s|
      next if s.datastore.blank?
      if s.datastore['PROUSER']
        next if s.datastore['PROUSER'].blank?
        @users[s.datastore['PROUSER']] ||= 0
        @users[s.datastore['PROUSER']] += 1
      end
    end
    (@module_run_events.nil? || @module_run_events.empty?) && gather_module_run_events
    @module_run_events.each do |event|
      next if not event.info
      if event.info[:datastore] and event.info[:datastore]['PROUSER']
        next if event.info[:datastore]['PROUSER'].blank?
        @users[event.info[:datastore]['PROUSER']] ||= 0
        @users[event.info[:datastore]['PROUSER']]  += 1
      end
    end
    # Ensure that users is never empty, even if no modules have been run:
    if @users.empty?
      @users = {current_user.username => 0}
    end
  end

  # Convenience for cross-loading forms via AJAX from other controllers
  # Acts as both a before_filter and a layout selector (need both)
  def task_layout_selector
    ( request.xhr? && params[:_nl] == "1" ) ? nil : 'application'
  end

  def using_embedded_layout?
    if task_layout_selector == nil
      @no_launch = true
    else
      @no_launch = false
    end
  end

  def gather_sessions
    @sessions = []
    @session_modules = []
    @most_common_module = []
    @sessions = @workspace.sessions.each { |s| @sessions << s}

    if @config
      @sessions.delete_if {|s| !@config.include_address?(s.host.address) }
    end

    return @sessions if @sessions.empty?
    @sessions.sort! do |a,b|
      [Rex::Socket.addr_aton(a.host.address), a.opened_at ] <=>
      [Rex::Socket.addr_aton(b.host.address), b.opened_at ]
    end
    @session_modules = @sessions.map {|s| s.via_exploit}
    mods = {}
    @session_modules.each do |s|
      mods[s] ||= 0
      mods[s] += 1
    end
    @most_common_module = mods.sort {|a,b| b[1] <=> a[1]}.first
    gather_session_events
  end

  # Populates @session_events with Mdm::SessionEvent table entries,
  # and also creates a @session_hosts array and @session_logs
  # hash (which just splits @session_events by id)
  def gather_session_events
    @session_events = @workspace.session_events
    @session_hosts = {}
    @sessions.each do |s|
      @session_hosts[s.host.address] ||= []
      @session_hosts[s.host.address] << s
    end
    @session_logs = {}
    @session_events.each do |session_event|
      @session_logs[session_event.session_id] ||= []
      @session_logs[session_event.session_id] << session_event
    end
  end

  def gather_module_run_events
    @module_run_events = @workspace.events.module_run
  end

protected

  def handle_unverified_request
    # current_user_session and current_user are undefined in this context.
    # When protect_from_forgery is enabled, Rails prepends verify_authenticity_token
    # (which calls handle_unverified_request) before activate_authlogic in the
    # _process_action_callbacks list.  When attempting to access current_user_session
    # and current_user in this context, Authlogic throws an exception: "You must
    # activate the Authlogic::Session::Base.controller with a controller object before
    # creating objects.  So we have to get User from the standard Rails session object.
    user     = Mdm::User.where(id: session['mdm/user_credentials_id']).first
    username = user.nil? ? '[NONE]' : user.username
    details = {
      method: request.request_method,
      path:   request.filtered_path,
      params: request.filtered_parameters
    }
    log_unverified_request(username, details)

    super
  end

private

  def log_unverified_request(username, details)
    ip_user = "#{request.ip} - #{username}"
    AuditLogger.security "#{ip_user} - Failed request. Invalid CSRF token. Details: #{details}."
  end

  if Rails.env.production?
    # Treat all requests as public requests so that the user will never
    # see the detailed exception page
    def local_request?
      false
    end
  end

  # Force the encoding to be binary (ASCII-8BIT), working around numerous UTF-8
  # assumptions in the Rack/Thin processing chain. Only enforces this when Ruby
  # 1.9 is being used
  def squash_unicode
    return if not response.body.respond_to?('force_encoding')
    response.body.force_encoding(Encoding::BINARY)
  end

  def active_pivots?
    if params[:workspace_id]
      @workspace = Mdm::Workspace.find(params[:workspace_id])
      return @workspace.active_pivots?
    else
      return false
    end
    end

  def override_server_header
    response.headers["Server"] = "Apache"
  end

  def load_workspace
    @workspace = Mdm::Workspace.find(params[:workspace_id])
    unless @workspace.usable_by?(current_user)
      respond_to do |format|
        error_msg = "You are not a member of this project"
        format.html { render :plain => error_msg, :layout => "forbidden", :status => 403 }
        format.json { render :json => {error: error_msg} , :status => 403 }
      end
    end
  end

  def load_tasks
    @running_tasks = Mdm::Task.running
  end

  def set_timezone
    if logged_in?
      begin
        ::Time.zone = current_user.time_zone
      rescue ::Exception
      end
    end
  end

  def set_usage_metric_countdown
    Notifications::Message.where(
        title:'Usage Metrics').first_or_create(
        content: 'Collection has started.',
        url: '/settings#global_settings',
        kind: :system_notification) if UsageMetric.seven_days? && current_profile.settings['usage_metrics_user_data']
  end

  def logged_in?
    !!current_user
  end

  def check_session_absolute_timeout
    if current_user_session && current_user
      if Time.now.to_i >= current_user.current_login_at.to_i + UserSession::ABSOLUTE_TIMEOUT.to_i
        AuditLogger.authentication "#{ip_user} - Forcing session timeout."
        current_user_session.destroy
      end
    end
  end

  def current_user_session
    return @current_user_session if defined?(@current_user_session)
    @current_user_session = UserSession.find
  end

  def current_user
    return @current_user if defined?(@current_user)
    @current_user = current_user_session && current_user_session.record

    if Rails.env.production? and @current_user
      if @current_user.session_key
        # Detect a more recent, duplicate login and invalidate the old session
        if @current_user.session_key != session[:session_id]
          flash[:error] = "Logged off due to duplicate login from #{@current_user.last_login_address}"
          current_user_session.destroy
          return
        end
      else
        # This handles the corner case of new user registration (initial setup)
        @current_user.last_login_address = request.ip
        @current_user.session_key = session[:session_id]
        @current_user.save!
      end
    end

    @current_user
  end

  def ip_user
    "#{request.ip} - #{current_user.username}"
  end

  def require_user
    if current_user.nil?
      store_location if navigation_request?
      if request.xhr?
        render :plain => "Not logged in", :layout => "forbidden", :status => 403 # Forbidden
      else
        redirect_to((user_exists?) ? login_url : new_user_url)
      end

      return false
    end
  end

  def user_exists?
    Mdm::User.count > 0
  end

  def store_location
    session[:return_to] = request.url
  end

  def fetch_current_profile
    current_profile
  end

  def require_license
    @license = License.get
    if request.xhr? && !@license.valid?
      render :plain => "Not logged in", :layout => "forbidden", :status => 403 # Forbidden
    else
      if not @license.activated?
        redirect_to root_path
      elsif @license.expired?
        redirect_to root_path
      end
    end
  end

  def require_admin
    unless (current_user and current_user.admin) or (not License.get.multi_user?)
      render :plain => "Administrator access required", :layout => "forbidden", :status => 403 # Forbidden
    end
  end

  def redirect_back_or_default(default)
    redirect_to(session[:return_to] || default)
    session[:return_to] = nil
  end

  def redirect_back
    redirect_to(session[:return_to]||:back)
    session[:return_to] = nil
  end

  # render javascript snippet to redirect the page
  def render_js_redirect(url)
    render :js => "window.location.href='#{url}'"
  end

  def render_popup(title, content_partial)
    #render :update do |page|
    # page.replace_html :popup_title, title
    # page.replace_html :popup_content, :partial => content_partial
    # page.show :popup
    #end
    render 'shared/popup_update', :locals => { :title => title, :content_partial => content_partial }
  end

  def handle_xmlrpc_error(e)
    $error_title    = "Unexpected Error"
    $error_reason   = "An unexpected error occurred"
    $error_solution = "Try restarting the Metasploit services. If this does not correct the problem, please contact customer support."

    case e.class.to_s
    when "Msf::RPC::ServerException"
      $error_title   = "Communication Error"
      $error_reason  = "The Pro Service returned a server-side error. This may be caused by a badly behaving target system or session."
      $error_reason  << "The specific error was #{e.error_class} #{e.error_message} (#{e.error_backtrace})"
      $error_solution = "This problem may resolve itself on its own. If this continues to appear, try restarting the Metasploit services or contacting customer support."

    when "XMLRPC::FaultException"
      $error_title   = "Communication Error"
      $error_reason  = "The Pro Service took longer than expected to process a request. This may be due to system load or a hung session."
      $error_reason  << "The specific error was '#{e.faultString}'"
      $error_solution = "This problem may resolve itself on its own. If this continues to appear, try restarting the Metasploit services or contacting customer support."

    when "Rex::ConnectionRefused"
      $error_title    = "Communication Error"
      $error_reason   = "The Pro Service is not currently running. If the service does not become available within five minutes, it may need to be restarted manually."
      $error_solution = "In order to restore functionality, the Pro Service must be restarted manually."

    when "EOFError", "Errno::ECONNRESET"
      $error_title  = "Communication Error"
      $error_reason = "The Pro Service triggered an error while processing an event."
      $error_solution = "This problem may resolve itself on its own. If this continues to appear, try restarting the Metasploit services or contacting customer support."

    end

    render "generic/xmlrpc_exception", :layout => 'error', :status => 500
  end

  def current_profile
    @profile ||= Mdm::Profile.find_by_active(true)
  end

  # After a page is rendered, you generally don't want flash messages
  # following you around.
  def clear_flash_messages
    flash[:error] = nil
    flash[:notice] = nil
  end

  # Generate an include option for the tag table when loading records
  # for the Analysis tab.
  #
  # Returns the Array condition.
  def tags_include_option
    [{:host => :tags}]
  end

  # Ensure we properly search for any queries that are passed as part of a
  # GET request to views that use DataTables by munging the parameters.
  #
  # Returns nothing.
  def fix_datatables_search_parameters
    if params[:search] && params[:sEcho].to_i == 1
      params[:sSearch] = params[:search]
    end
  end

  # Return the Pro report directory locationm
  def pro_report_directory
    ::File.expand_path( ::File.join( ::File.dirname(__FILE__), '..', '..', '..', 'reports') )
  end

  # @return true if the request is being loaded into a browser pane
  # @return false if the request was made by XHR, iframe, or is non-html
  def navigation_request?
    request.present? and
      not request.xhr? and
      request.format.present? and
      request.format.html? and
      request.get?
  end

  # Build an object for the given model using the presenter for its class.
  #
  # @param object [ApplicationRecord] the object to be presented
  # @param klass [Class] the class of the presenter, if it can't be inferred
  # @return [Object] an instance of the presenter class for `object`
  def present(object, klass = nil)
    klass ||= "#{object.class}Presenter".constantize
    klass.new(object)
  end

  Metasploit::Concern.run(self)

  # Sets the the application layout to use the application_backbone js manifest
  #
  # @return [Void]
  def application_backbone
    @application_backbone = true
  end

  def log_timeout_if_session_is_stale
    if current_user_session && current_user_session.stale?
      username = current_user_session.stale_record.username
      AuditLogger.authentication "#{request.ip} - #{username} - Session timeout."
    end
  end

  def current_user_params
    params.fetch(:current_user, {}).permit(:http_proxy_host, :http_proxy_port, :http_proxy_user, :http_proxy_pass)
  end
end
