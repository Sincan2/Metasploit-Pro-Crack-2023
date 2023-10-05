module Metasploit::Pro::Engine::Rpc::Tasks

  # List all live tasks on all workspaces
  # XXX: rewrite to use the database
  def rpc_task_list
    ret = {}
    self.tasks.each_pair do |task_id, task|
      ret[task_id] = {
        'status'      => task.status.to_s,
        'error'       => task.error || '',
        'created_at'  => task.created_at.to_i,
        'progress'    => task.progress,
        'description' => task.description,
        'info'        => task.info,
        'workspace'   => task.workspace,
        'username'    => task.username,
        'result'      => task.result || '',
        'path'        => task.path || '',
        'size'        => (::File.size(task.path) rescue 0)
      }
    end
    ret
  end

  # Return the status for a specific task
  # XXX: rewrite to use the database
  def rpc_task_status(task_id)
    ret = {}

    task_id = task_id.to_s
    task    = self.tasks[task_id]
    if (task)
      ret[task_id] = {
        'status'      => task.status.to_s,
        'error'       => task.error || '',
        'created_at'  => task.created_at.to_i,
        'progress'    => task.progress,
        'description' => task.description,
        'info'        => task.info,
        'workspace'   => task.workspace,
        'username'    => task.username,
        'result'      => task.result || '',
        'path'        => task.path || '',
        'size'        => (::File.size(task.path) rescue 0)
      }
    else
      ret[task_id] = {'status' => 'invalid', 'error' => ''}
    end
    ret
  end

  # 'Pause' a task
  def rpc_task_pause(task_id)
    ret = {}
    if tasks[task_id].present?
      _pause_module_task(task_id)
      tasks.delete(task_id)
      ret['status'] = Mdm::Task.find(task_id).state
    else
      ret['status'] = 'invalid task_id'
    end

    ret
  end

  # 'Resume' a task
  def rpc_task_resume(task_id)
    fail "Must provide task_id in config hash" unless task_id.present?

    ret = {}

    mdm_task     = Mdm::Task.find(task_id)
    task_refname = mdm_task.module

    if mdm_task.present?
      resume_config = mdm_task.options.merge({'task_id' => mdm_task.id})
      _resume_module_task(resume_config, task_refname, mdm_task.description)
      ret['status'] = "Resuming task #{mdm_task.id}"
    else
      ret['status'] = "Could not find Mdm::Task with ID '#{task_id}'"
    end

    ret
  end

  # Forcibly stop a specific task
  def rpc_task_stop(task_id)
    task_id = task_id.to_s
    ret     = {'task' => task_id}
    if tasks[task_id].present?
      tasks[task_id].requested_task_action = ::Pro::ProTask::STOP
      tasks[task_id].stop
      tasks.delete(task_id)
      ret['status'] = 'stopped'
    else
      ret['status'] = 'invalid'
    end

    ret
  end

  # Delete the data file corresponding to a task
  # XXX: Fix callers
  def rpc_task_delete_log(task_id)
    r = _find_task(task_id)
    ::FileUtils.rm_f(r.path)
    {'status' => 'success'}
  end


  # Download the task log for a specific task
  def rpc_task_log(task_id)
    x = _find_task(task_id)
    r = _task_to_hash(x)

    r[:log] = ''
    if x.path and ::File.exist?(x.path)
      ::File.open(x.path, "rb") do |fd|
        r[:log] << fd.read(fd.stat.size)
      end
    end
    r
  end

  def rpc_start_discover(conf={})
    _start_module_task(conf, "pro/discover", "Discovering")
  end

  def rpc_start_webscan(conf={})
    _start_module_task(conf, "pro/webscan", "Scanning")
  end

  def rpc_start_webaudit(conf={})
    _start_module_task(conf, "pro/webaudit", "Auditing")
  end

  def rpc_start_bruteforce(conf={})
    _start_module_task(conf, "pro/bruteforce/simple_guess", "Bruteforcing")
  end

  def rpc_start_exploit(conf={})
    _start_module_task(conf, "pro/exploit", "Exploiting")
  end

  def rpc_start_websploit(conf={})
    _start_module_task(conf, "pro/websploit", "Exploiting")
  end

  def rpc_start_import(conf={})
    _start_module_task(conf, "pro/import", "Importing")
  end

  def rpc_start_cleanup(conf={})
    _start_module_task(conf, "pro/cleanup", "Cleaning Up")
  end

  def rpc_start_upgrade_sessions(conf={})
    _start_module_task(conf, "pro/upgrade_sessions", "Upgrading Sessions")
  end

  def rpc_start_collect(conf={})
    _start_module_task(conf, "pro/collect", "Collecting")
  end

  def rpc_start_single(conf={})
    _start_module_task(conf, "pro/single", "Launching")
  end

  def rpc_start_download(conf={})
    _start_module_task(conf, "pro/download", "Downloading")
  end

  def rpc_start_upload(conf={})
    _start_module_task(conf, "pro/upload", "Uploading")
  end

  def rpc_start_nexpose(conf={})
    _start_module_task(conf, "pro/nexpose", "Nexpose")
  end

  # Start a new-style social engineering campaign
  def rpc_start_se_campaign(conf={})
    _start_module_task(conf, "pro/social_engineering/campaign_commander", "Social Engineering Campaign")
  end

  def rpc_start_quick_pentest_wizard(conf={})
    _start_module_task(conf, "pro/wizard/quick_pentest", "Quick Pentest")
  end

  def rpc_start_vuln_validation_wizard(conf={})
    _start_module_task(conf, "pro/wizard/vuln_validation", "Vulnerability Validation")
  end

  def rpc_resume_vuln_validation_wizard(conf={})
    _resume_module_task(conf, "pro/wizard/vuln_validation", "Vulnerability Validation")
  end

  def rpc_start_scan_and_import(conf={})
    _start_module_task(conf,"pro/nexpose/scan_and_import", "Nexpose Scan and Import")
  end


  def rpc_start_web_app_test(conf={})
    _start_module_task(conf, "pro/wizard/web_app_test", "Web App Test")
  end

  def rpc_start_nexpose_asset_group_push(conf={})
    _start_module_task(conf, "pro/nexpose_asset_group_push", "Nexpose Asset Group Push")
  end

  def rpc_start_nexpose_exception_push(conf={})
    _start_module_task(conf, "pro/nexpose_exception_push", "Nexpose Exception Push")
  end

  def rpc_start_nexpose_exception_and_validation_push_v2(conf={})
    _start_module_task(conf, "pro/nexpose/push_exceptions_and_validations", "Nexpose Push Exceptions and Validations")
  end

  def rpc_generate_exe(conf={})
    _start_module_task(conf, "pro/phish_generate_exe", "Generate Executable")
  end

  def rpc_portable_file_generate(conf={})
    _start_module_task(conf, "pro/social_engineering/portable_file_generate", "Generate File")
  end

  def rpc_start_tunnel(conf={})
    _start_module_task(conf, "pro/tunnel", "Tunneling")
  end

  def rpc_start_listener(conf={})
    _start_module_task(conf, "pro/listener", "Listening")
  end

  def rpc_start_replay(conf={})
    _start_module_task(conf, "pro/replay", "Replaying")
  end

  def rpc_start_single_password_testing(conf={})
    _start_module_task(conf, 'pro/apps/single_password/commander', 'Single Password Testing')
  end

  def rpc_start_pass_the_hash(conf={})
    _start_module_task(conf, 'pro/apps/pass_the_hash', 'Pass the Hash')
  end

  def rpc_start_ssh_key_testing(conf={})
    _start_module_task(conf, 'pro/apps/ssh_key', 'SSH Key Testing')
  end

  def rpc_start_credential_intrusion(conf={})
    _start_module_task(conf, 'pro/apps/credential_intrusion/commander', 'Known Credential Intrusion')
  end

  def rpc_start_passive_network_discovery(conf={})
    _start_module_task(conf, "pro/apps/passive_network_discovery", "Passive Network Discovery")
  end

  def rpc_start_validate_login(conf={})
    _start_module_task(conf, "pro/bruteforce/validate_login", "Validate Single Login")
  end

  def rpc_start_brute_force_reuse(conf={})
    _start_module_task(conf, "pro/bruteforce/reuse", "Credentials Reuse")
  end

  def rpc_start_attempt_session(conf={})
    _start_module_task(conf,"pro/bruteforce/attempt_session", "Attempt Session Login")
  end

  def rpc_start_brute_force_quick(conf={})
    _start_module_task(conf, "pro/bruteforce/quick", "Bruteforce")
  end

  def rpc_start_sonar_import(conf={})
    _start_module_task(conf, "pro/sonar/import", "Sonar Import")
  end

  def rpc_start_sonar_discovery(conf={})
    _start_module_task(conf, "pro/sonar/host_discovery", "Sonar Host Discovery")
  end

  def rpc_start_rc_launch(conf={})
    _start_module_task(conf, "pro/rc_launch", "Run Resource Script")
  end

  private

  def _find_task(task_id)
    ::ApplicationRecord.connection_pool.with_connection {
      r = ::Mdm::Task.find(task_id.to_i)
      error(500, "Invalid Task ID") if not r
      r
    }
  end

  # Create a {Hash} representation of an {Mdm::Task}
  # @param task [Mdm::Task]
  def _task_to_hash(task)
    r                = {}
    r[:id]           = task.id
    r[:workspace]    = task.workspace.name
    r[:created_by]   = task.created_by
    r[:module]       = task.module
    r[:completed_at] = task.completed_at.to_i
    r[:path]         = task.path
    r[:size] = ::File.size(task.path) rescue 0
    r[:info]        = task.info
    r[:description] = task.description
    r[:progress]    = task.progress
    r[:options]     = task.options
    r[:error]       = task.error
    r[:created_at]  = task.created_at.to_i
    r[:updated_at]  = task.updated_at.to_i
    r[:result]      = task.result
    r[:module_uuid] = task.module_uuid
    r
  end

  # @param task_id [Integer] the ID of the {Mdm::Task}, which doubles as the ID of the {ProTask}
  def _pause_module_task(task_id)
    pro_task = tasks[task_id]
    if pro_task.present? && pro_task.record.running?
      pro_task.requested_task_action = Pro::ProTask::PAUSE
      pro_task.metasploit_module.datastore[Pro::ProTask::REQUESTED_TASK_ACTION_DS_KEY] = Pro::ProTask::PAUSE
      pro_task.pause
    else
      {'status' => 'No running task found with provided ID'}
    end
  end

  # RPC method called to start a task
  # @param conf [Hash] original config hash passed to RPC call
  # @param mod [String] A Metasploit3#fullname
  # @param desc [String] description of the module being used by the task
  # @return [Hash]
  def _start_module_task(conf, module_refname, desc)
    _kick_off_module_task(conf, module_refname, desc, Pro::ProTask::START)
  end

  # RPC method called to resume a task
  # @param conf [Hash] original config hash passed to RPC call
  # @param mod [String] A Metasploit3#fullname
  # @param desc [String] description of the module being used by the task
  # @return [Hash]
  def _resume_module_task(conf, module_refname, desc)
    _kick_off_module_task(conf, module_refname, desc, Pro::ProTask::RESUME)
  end

  # Configures and kicks off a discrete job of Metasploit work, designated by the module name in +mod+,
  # using the configuration parameters in +conf+
  # Creates an {Mdm::Task} record if necessary, using an existing one if that one is passed in by ID.
  # @param conf [Hash] original config hash passed to RPC call
  # @param mod [String] A Metasploit3#fullname
  # @param desc [String] description of the module being used by the task
  # @return [Hash]
  def _kick_off_module_task(conf, module_refname, desc, requested_task_action)
    expanded_config   = calculated_config(conf, module_refname, desc)
    metasploit_module = task_module(expanded_config, requested_task_action)
    pro_task_proc     = task_proc(metasploit_module, expanded_config)

    pro_task = configured_pro_task(expanded_config, pro_task_proc)
    pro_task.requested_task_action = requested_task_action
    pro_task.metasploit_module = metasploit_module

    error("500", "Invalid ProTask config") unless pro_task.valid?

    ret = framework.esnecil_invalid?
    if ret and module_refname !~ /\/(cleanup|collect|discover|webscan|webaudit|bruteforce|exploit|websploit|import|upgrade_sessions|single|download|upload|nexpose|se_campaign|pentest_wizard|validation_wizard|scan_and_import|web_app_test|nexpose_asset_group_push|nexpose_exception_push|nexpose_exception_and_validation_push_v2|generate_exe|portable_file_generate|tunnel|listener|replay|single_password_testing|pass_the_hash|ssh_key_testing|credential_intrusion|passive_network_discovery|validate_login|brute_force_reuse|attempt_session|brute_force_quick|sonar_import|sonar_discovery|rc_launch)/
      pro_task.error = ret
      pro_task.proc  = Proc.new { |*args|}
    end

    pro_task.start
    Thread.current.priority = 10
    {'task_id' => pro_task.task_id}
  end

  # Creates a config hash that will be used in other calls, combining original and
  # calculated values.
  # @param conf [Hash] the original hash from the RPC call
  # @return [H
  def calculated_config(conf, module_refname, desc)
    username  = task_username(conf)
    workspace = task_workspace(conf)
    error("500", "Invalid Workspace") if workspace.blank?

    # Create a new hash that has all the original RPC config plus some calculated
    # values.
    expanded_config = {
      description: desc,
      module_refname: module_refname,
      task_id: conf['task_id'],
      username: username,
      workspace: workspace,
      rpc_config: conf
    }

    expanded_config.merge(mdm_task: task_record(expanded_config))
  end

  # @param task_id [Integer] the ID of the {Mdm::Task}, which doubles as the ID of the {ProTask}
  # @param module_refname [String] the Metasploit3#fullname of the module
  # @return [String]
  def task_log_file(task, module_refname)
    file_name = "#{task.created_at.strftime("%Y-%m-%dT%H-%M-%S")}_task_#{module_refname.gsub("/", ".")}_#{task.id}.txt"
    File.expand_path(File.join(_base_directory('task'), file_name))
  end

  # @param conf [Hash] the configuration hash containing original params plus calculated values
  # @option conf [Hash] :rpc_config the original RPC params
  # @option conf [Mdm::Workspace] :workspace the workspace where this task is running
  # @option conf [String] :username the name of the {Mdm::User} that kicked off this task
  # @option conf [String] :module_refname the {Metasploit3#fullname} of the module we are running with the {ProTask}
  def task_module(conf={}, requested_task_action=Pro::ProTask::START)
    module_refname    = conf.fetch(:module_refname)
    trecord           = conf.fetch(:mdm_task)
    username          = conf.fetch(:username)
    workspace         = conf.fetch(:workspace).name # this will get used by *name* in the module

    metasploit_module = framework.auxiliary.create(module_refname)

    if metasploit_module.blank?
      raise RuntimeError, "Module #{module_refname} could not be loaded"
    end

    # Open the file in append mode in case we are resuming
    metasploit_module.init_ui(nil, Rex::Ui::Text::Output::File.new(trecord.path, 'ab'))

    if (conf[:rpc_config]['ips'])
      metasploit_module.datastore['RHOSTS'] = conf[:rpc_config]['ips'].join(" ")
    end

    metasploit_module.datastore['TimestampOutput'] = true
    metasploit_module.datastore['WORKSPACE']       = workspace
    metasploit_module.datastore['PROUSER']         = username
    metasploit_module.datastore[Pro::ProTask::REQUESTED_TASK_ACTION_DS_KEY] = requested_task_action

    # Prefix all DS options with 'DS'
    conf[:rpc_config].each_key do |k|
      if (k =~ /^DS_/)
        metasploit_module.datastore[k.sub(/^DS_/, '')] = conf[:rpc_config][k]
      end
    end

    metasploit_module
  end

  # @param metasploit_module [Metasploit3] the MSF module being run by the task
  # @param conf [Hash] the configuration hash containing original params plus calculated values
  # @option conf [Hash] :rpc_config the original RPC params
  # @return [Proc] the Proc that will be executed by the ProTask
  def task_proc(metasploit_module, conf={})
    Proc.new do |task, args|

      # Drop the priority of the ProTask#thread running this Proc
      Thread.current.priority = -10

      ::ApplicationRecord.connection_pool.with_connection {
        Mdm::Task.find(conf[:mdm_task].id).update_attribute(:module_uuid, metasploit_module.uuid)
      }

      # Pass down all the things
      metasploit_module[:conf] = conf[:rpc_config]
      metasploit_module[:task] = task
      metasploit_module[:args] = args

      # Run the task with auxiliary's run_simple, overriding
      # the ProTask's module to be the replicant instance that
      # gets passed in as the block local variable to run_simple's Proc arg
      metasploit_module.run_simple do |msf_module_replicant|
        metasploit_module = task.metasploit_module = msf_module_replicant
      end

      if metasploit_module.error
        # Set the task-level error
        trace = []
        metasploit_module.error.backtrace.each do |line|
          break if line =~ /lib.msf.base.simple.auxiliary.rb/
          trace << line.gsub!(/.*\/pro\//, '/pro/')
        end
        task.error = "Module Exception: #{metasploit_module.error} #{trace.join("\n")}"
      end
    end
  end

  # Finds or creates the {Mdm::Task} that the DB uses to track this ProTask, including setting up the log file
  # @param conf [Hash] the configuration hash containing original params plus calculated values
  # @option conf [Hash] :rpc_config the original RPC params
  # @param original_conf [Hash] the conf from the RPC call
  # @return [Mdm::Task]
  def task_record(conf)
    ::ApplicationRecord.connection_pool.with_connection {
      mdm_task = if conf[:task_id].present?
                   Mdm::Task.find(conf[:task_id].to_i)  # Comes over RPC bridge as a string
                 else
                   Mdm::Task.create(
                     :workspace_id => conf.fetch(:workspace).id,
                     :created_by   => conf.fetch(:username),
                     :module       => conf.fetch(:module_refname),
                     :description  => conf.fetch(:description),
                     :options      => conf[:rpc_config],
                     :progress     => 0
                   )
                 end
      log_file_path = task_log_file(mdm_task, conf.fetch(:module_refname))
      mdm_task.update_attribute(:path, log_file_path)
      mdm_task
    }
  end

  # The name of the {Mdm::User} that kicked off this task or 'unknown'
  # @param conf [Hash] the original conf from the RPC call
  # @return [String]
  def task_username(conf={})
    conf['username'] || 'unknown'
  end

  # The {Mdm::Workspace} where this will be happening.
  # String is used here because for historical reasons (msfconsole interface), {Mdm::Workspaces} are
  # sometimes passed by name.
  # @param conf [Hash] the original conf from the RPC call
  # @return [Hash] returns :name [String] and :object [Mdm::Workspace] forms of an MSF Workspace
  def task_workspace(conf={})
    Mdm::Workspace.where(name: conf.fetch('workspace')).try(:first)
  end


  # @param conf [Hash] the configuration hash containing original params plus calculated values
  # @option conf [Hash] :rpc_config the original RPC params
  # @param proc [Proc] represents the job to be done by this RPC call
  # @return [Pro::ProTask]
  def configured_pro_task(conf, proc)
    pro_task_id = tasks.create(conf[:mdm_task], proc)
    pro_task    = tasks[pro_task_id]

    pro_task.workspace        = conf[:rpc_config]['workspace'] # TODO: make this use a real Mdm::Workspace...
    pro_task.username         = conf[:username]
    pro_task.description      = conf[:description]

    pro_task
  end

end
