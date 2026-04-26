"""
Download ALL EVTX attack sample fixtures from sbousseaden/EVTX-ATTACK-SAMPLES.

Run ONCE — files are cached at tests/fixtures/evtx/<Category>/<file>.evtx and
never re-downloaded. Re-run to fetch any newly-added samples; use --force to
re-download everything.

    py tests/download_evtx_fixtures.py
    py tests/download_evtx_fixtures.py --force   # re-download all

The fixture tree is gitignored (binary blobs, ~200 MB total).
audit_evtx_coverage.py and test_evtx_real_samples.py read from this same tree.
"""

import argparse
import sys
import urllib.error
import urllib.request
from pathlib import Path

_RAW_BASE = (
    'https://raw.githubusercontent.com/sbousseaden/'
    'EVTX-ATTACK-SAMPLES/master/'
)

_FIXTURE_DIR = Path(__file__).parent / 'fixtures' / 'evtx'

# Complete list of EVTX files in sbousseaden/EVTX-ATTACK-SAMPLES (2026-04-26).
# Stored preserving folder structure to avoid filename collisions across categories.
ALL_SAMPLES = [
    'AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx',
    'AutomatedTestingTools/Malware/rundll32_cmd_schtask.evtx',
    'AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx',
    'AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx',
    'AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx',
    'AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx',
    'AutomatedTestingTools/WinDefender_Events_1117_1116_AtomicRedTeam.evtx',
    'AutomatedTestingTools/panache_sysmon_vs_EDRTestingScript.evtx',
    'Command and Control/DE_RDP_Tunnel_5156.evtx',
    'Command and Control/DE_RDP_Tunneling_4624.evtx',
    'Command and Control/DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx',
    'Command and Control/DE_sysmon-3-rdp-tun.evtx',
    'Command and Control/bits_openvpn.evtx',
    'Command and Control/tunna_iis_rdp_smb_tunneling_sysmon_3.evtx',
    'Credential Access/4794_DSRM_password_change_t1098.evtx',
    'Credential Access/ACL_ForcePwd_SPNAdd_User_Computer_Accounts.evtx',
    'Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx',
    'Credential Access/CA_DCSync_4662.evtx',
    'Credential Access/CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.evtx',
    'Credential Access/CA_PetiPotam_etw_rpc_efsr_5_6.evtx',
    'Credential Access/CA_chrome_firefox_opera_4663.evtx',
    'Credential Access/CA_hashdump_4663_4656_lsass_access.evtx',
    'Credential Access/CA_keefarce_keepass_credump.evtx',
    'Credential Access/CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx',
    'Credential Access/CA_protectedstorage_5145_rpc_masterkey.evtx',
    'Credential Access/CA_sysmon_hashdump_cmd_meterpreter.evtx',
    'Credential Access/CA_teamviewer-dumper_sysmon_10.evtx',
    'Credential Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx',
    'Credential Access/MSSQL_multiple_failed_logon_EventID_18456.evtx',
    'Credential Access/Powershell_4104_MiniDumpWriteDump_Lsass.evtx',
    'Credential Access/Sysmon13_MachineAccount_Password_Hash_Changed_via_LsarSetSecret.evtx',
    'Credential Access/Sysmon_13_Local_Admin_Password_Changed.evtx',
    'Credential Access/Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805.evtx',
    'Credential Access/Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC.evtx',
    'Credential Access/babyshark_mimikatz_powershell.evtx',
    'Credential Access/dc_applog_ntdsutil_dfir_325_326_327.evtx',
    'Credential Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx',
    'Credential Access/etw_rpc_zerologon.evtx',
    'Credential Access/kerberos_pwd_spray_4771.evtx',
    'Credential Access/phish_windows_credentials_powershell_scriptblockLog_4104.evtx',
    'Credential Access/ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx',
    'Credential Access/remote_pwd_reset_rpc_mimikatz_postzerologon_target_DC.evtx',
    'Credential Access/remote_sam_registry_access_via_backup_operator_priv.evtx',
    'Credential Access/sysmon17_18_kekeo_tsssp_default_np.evtx',
    'Credential Access/sysmon_10_11_lsass_memdump.evtx',
    'Credential Access/sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx',
    'Credential Access/sysmon_10_1_memdump_comsvcs_minidump.evtx',
    'Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx',
    'Credential Access/sysmon_13_keylogger_directx.evtx',
    'Credential Access/sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx',
    'Credential Access/sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx',
    'Credential Access/sysmon_rdrleakdiag_lsass_dump.evtx',
    'Credential Access/tutto_malseclogon.evtx',
    'Defense Evasion/DE_104_system_log_cleared.evtx',
    'Defense Evasion/DE_1102_security_log_cleared.evtx',
    'Defense Evasion/DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.evtx',
    'Defense Evasion/DE_EventLog_Service_Crashed.evtx',
    'Defense Evasion/DE_Fake_ComputerAccount_4720.evtx',
    'Defense Evasion/DE_KernelDebug_and_TestSigning_ON_Security_4826.evtx',
    'Defense Evasion/DE_Powershell_CLM_Disabled_Sysmon_12.evtx',
    'Defense Evasion/DE_ProcessHerpaderping_Sysmon_11_10_1_7.evtx',
    'Defense Evasion/DE_UAC_Disabled_Sysmon_12_13.evtx',
    'Defense Evasion/DE_WinEventLogSvc_Crash_System_7036.evtx',
    'Defense Evasion/DE_remote_eventlog_svc_crash_byt3bl33d3r_sysmon_17_1_3.evtx',
    'Defense Evasion/DE_renamed_psexec_service_sysmon_17_18.evtx',
    'Defense Evasion/DE_suspicious_remote_eventlog_svc_access_5145.evtx',
    'Defense Evasion/DE_xp_cmdshell_enabled_MSSQL_EID_15457.evtx',
    'Defense Evasion/DSE_bypass_BYOV_TDL_dummydriver_sysmon_6_7_13.evtx',
    'Defense Evasion/Sysmon 7  Update Session Orchestrator Dll Hijack.evtx',
    'Defense Evasion/Sysmon 7 dllhijack_cdpsshims_CDPSvc.evtx',
    'Defense Evasion/Sysmon_10_Evasion_Suspicious_NtOpenProcess_CallTrace.evtx',
    'Defense Evasion/Sysmon_12_DE_AntiForensics_MRU_DeleteKey.evtx',
    'Defense Evasion/Win_4985_T1186_Process_Doppelganging.evtx',
    'Defense Evasion/apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13.evtx',
    'Defense Evasion/de_PsScriptBlockLogging_disabled_sysmon12_13.evtx',
    'Defense Evasion/de_hiding_files_via_attrib_cmdlet.evtx',
    'Defense Evasion/de_portforward_netsh_rdp_sysmon_13_1.evtx',
    'Defense Evasion/de_powershell_execpolicy_changed_sysmon_13.evtx',
    'Defense Evasion/de_sysmon_13_VBA_Security_AccessVBOM.evtx',
    'Defense Evasion/de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx',
    'Defense Evasion/evasion_codeinj_odzhan_conhost_sysmon_10_1.evtx',
    'Defense Evasion/evasion_codeinj_odzhan_spoolsv_sysmon_10_1.evtx',
    'Defense Evasion/faxhell_sysmon_7_1_18_3_bindshell_dllhijack.evtx',
    'Defense Evasion/meterpreter_migrate_to_explorer_sysmon_8.evtx',
    'Defense Evasion/process_suspend_sysmon_10_ga_800.evtx',
    'Defense Evasion/sideloading_wwlib_sysmon_7_1_11.evtx',
    'Defense Evasion/sysmon_10_1_ppid_spoofing.evtx',
    'Defense Evasion/sysmon_13_rdp_settings_tampering.evtx',
    'Defense Evasion/sysmon_2_11_evasion_timestomp_MACE.evtx',
    'Discovery/4799_remote_local_groups_enumeration.evtx',
    'Discovery/Discovery_Remote_System_NamedPipes_Sysmon_18.evtx',
    'Discovery/dicovery_4661_net_group_domain_admins_target.evtx',
    'Discovery/discovery_UEFI_Settings_rweverything_sysmon_6.evtx',
    'Discovery/discovery_bloodhound.evtx',
    'Discovery/discovery_enum_shares_target_sysmon_3_18.evtx',
    'Discovery/discovery_local_user_or_group_windows_security_4799_4798.evtx',
    'Discovery/discovery_meterpreter_ps_cmd_process_listing_sysmon_10.evtx',
    'Discovery/discovery_psloggedon.evtx',
    'Discovery/discovery_sysmon_18_Invoke_UserHunter_NetSessionEnum_DC-srvsvc.evtx',
    'Discovery/discovery_sysmon_3_Invoke_UserHunter_SourceMachine.evtx',
    'Execution/Exec_sysmon_meterpreter_reversetcp_msipackage.evtx',
    'Execution/Exec_via_cpl_Application_Experience_EventID_17_ControlPanelApplet.evtx',
    'Execution/Sysmon_Exec_CompiledHTML.evtx',
    'Execution/Sysmon_meterpreter_ReflectivePEInjection_to_notepad_.evtx',
    'Execution/evasion_execution_imageload_wuauclt_lolbas.evtx',
    'Execution/exec_driveby_cve-2018-15982_sysmon_1_10.evtx',
    'Execution/exec_msxsl_xsl_sysmon_1_7.evtx',
    'Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx',
    'Execution/exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler.evtx',
    'Execution/exec_sysmon_1_11_lolbin_rundll32_shdocvw_openurl.evtx',
    'Execution/exec_sysmon_1_11_lolbin_rundll32_zipfldr_RouteTheCall.evtx',
    'Execution/exec_sysmon_1_7_jscript9_defense_evasion.evtx',
    'Execution/exec_sysmon_1_ftp.evtx',
    'Execution/exec_sysmon_1_lolbin_pcalua.evtx',
    'Execution/exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx',
    'Execution/exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX.evtx',
    'Execution/exec_sysmon_1_rundll32_pcwutl_LaunchApplication.evtx',
    'Execution/exec_sysmon_lobin_regsvr32_sct.evtx',
    'Execution/exec_wmic_xsl_internet_sysmon_3_1_11.evtx',
    'Execution/execution_evasion_visual_studio_prebuild_event.evtx',
    'Execution/revshell_cmd_svchost_sysmon_1.evtx',
    'Execution/rogue_msi_url_1040_1042.evtx',
    'Execution/susp_explorer_exec.evtx',
    'Execution/susp_explorer_exec_root_cmdline_@rimpq_@CyberRaiju.evtx',
    'Execution/sysmon_11_1_lolbas_downldr_desktopimgdownldr.evtx',
    'Execution/sysmon_1_11_rundll32_cpl_ostap.evtx',
    'Execution/sysmon_exec_from_vss_persistence.evtx',
    'Execution/sysmon_lolbas_rundll32_zipfldr_routethecall_shell.evtx',
    'Execution/sysmon_lolbin_bohops_vshadow_exec.evtx',
    'Execution/sysmon_mshta_sharpshooter_stageless_meterpreter.evtx',
    'Execution/sysmon_vbs_sharpshooter_stageless_meterpreter.evtx',
    'Execution/sysmon_zipexec.evtx',
    'Execution/temp_scheduled_task_4698_4699.evtx',
    'Execution/windows_bits_4_59_60_lolbas desktopimgdownldr.evtx',
    'Lateral Movement/DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx',
    'Lateral Movement/ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx',
    'Lateral Movement/LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx',
    'Lateral Movement/LM_5145_Remote_FileCopy.evtx',
    'Lateral Movement/LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx',
    'Lateral Movement/LM_ImageLoad_NFSH_Sysmon_7.evtx',
    'Lateral Movement/LM_NewShare_Added_Sysmon_12_13.evtx',
    'Lateral Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx',
    'Lateral Movement/LM_REMCOM_5145_TargetHost.evtx',
    'Lateral Movement/LM_Remote_Service01_5145_svcctl.evtx',
    'Lateral Movement/LM_Remote_Service02_7045.evtx',
    'Lateral Movement/LM_ScheduledTask_ATSVC_target_host.evtx',
    'Lateral Movement/LM_WMIC_4648_rpcss.evtx',
    'Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx',
    'Lateral Movement/LM_add_new_namedpipe_tp_nullsession_registry_turla_like_ttp.evtx',
    'Lateral Movement/LM_dcom_shwnd_shbrwnd_mmc20_failed_traces_system_10016.evtx',
    'Lateral Movement/LM_impacket_docmexec_mmc_sysmon_01.evtx',
    'Lateral Movement/LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn.evtx',
    'Lateral Movement/LM_renamed_psexecsvc_5145.evtx',
    'Lateral Movement/LM_sysmon_1_12_13_3_tsclient_SharpRdp.evtx',
    'Lateral Movement/LM_sysmon_3_12_13_1_SharpRDP.evtx',
    'Lateral Movement/LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.evtx',
    'Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx',
    'Lateral Movement/LM_sysmon_remote_task_src_powershell.evtx',
    'Lateral Movement/LM_tsclient_startup_folder.evtx',
    'Lateral Movement/LM_typical_IIS_webshell_sysmon_1_10_traces.evtx',
    'Lateral Movement/LM_winrm_exec_sysmon_1_winrshost.evtx',
    'Lateral Movement/LM_winrm_target_wrmlogs_91_wsmanShellStarted_poorLog.evtx',
    'Lateral Movement/LM_wmi_PoisonHandler_Mr-Un1k0d3r_sysmon_1_13.evtx',
    'Lateral Movement/LM_wmiexec_impacket_sysmon_whoami.evtx',
    'Lateral Movement/LM_xp_cmdshell_MSSQL_Events.evtx',
    'Lateral Movement/MSSQL_15281_xp_cmdshell_exec_failed_attempt.evtx',
    'Lateral Movement/RemotePowerShell_MS_Windows-Remote_Management_EventID_169.evtx',
    'Lateral Movement/dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx',
    'Lateral Movement/lateral_movement_startup_3_11.evtx',
    'Lateral Movement/lm_remote_registry_sysmon_1_13_3.evtx',
    'Lateral Movement/lm_sysmon_18_remshell_over_namedpipe.evtx',
    'Lateral Movement/net_share_drive_5142.evtx',
    'Lateral Movement/powercat_revShell_sysmon_1_3.evtx',
    'Lateral Movement/remote task update 4624 4702 same logonid.evtx',
    'Lateral Movement/remote_file_copy_system_proc_file_write_sysmon_11.evtx',
    'Lateral Movement/sharprdp_sysmon_7_mstscax.dll.evtx',
    'Lateral Movement/smb_bi_auth_conn_spoolsample.evtx',
    'Lateral Movement/smbmap_upload_exec_sysmon.evtx',
    'Lateral Movement/spoolsample_5145.evtx',
    'Lateral Movement/sysmon_1_exec_via_sql_xpcmdshell.evtx',
    'Lateral Movement/wmi_remote_registry_sysmon.evtx',
    'Other/emotet/exec_emotet_ps_4104.evtx',
    'Other/emotet/exec_emotet_ps_800_get-item.evtx',
    'Other/emotet/exec_emotet_ps_800_invoke-item.evtx',
    'Other/emotet/exec_emotet_ps_800_new-item.evtx',
    'Other/emotet/exec_emotet_ps_800_new-object.evtx',
    'Other/emotet/exec_emotet_sysmon_1.evtx',
    'Other/maldoc_mshta_via_shellbrowserwind_rundll32.evtx',
    'Other/rdpcorets_148_mst120_bluekeep_rpdscan_full.evtx',
    'Persistence/DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl.evtx',
    'Persistence/Network_Service_Guest_added_to_admins_4732.evtx',
    'Persistence/Persistence_Shime_Microsoft-Windows-Application-Experience_Program-Telemetry_500.evtx',
    'Persistence/Persistence_Winsock_Catalog Change EventId_1.evtx',
    'Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx',
    'Persistence/persist_bitsadmin_Microsoft-Windows-Bits-Client-Operational.evtx',
    'Persistence/persist_firefox_comhijack_sysmon_11_13_7_1.evtx',
    'Persistence/persist_turla_outlook_backdoor_comhijack.evtx',
    'Persistence/persist_valid_account_guest_rid_hijack.evtx',
    'Persistence/persistence_SilentProcessExit_ImageHijack_sysmon_13_1.evtx',
    'Persistence/persistence_accessibility_features_osk_sysmon1.evtx',
    'Persistence/persistence_hidden_local_account_sysmon.evtx',
    'Persistence/persistence_pendingGPO_sysmon_13.evtx',
    'Persistence/persistence_security_dcshadow_4742.evtx',
    'Persistence/persistence_startup_UserShellStartup_Folder_Changed_sysmon_13.evtx',
    'Persistence/persistence_sysmon_11_13_1_shime_appfix.evtx',
    'Persistence/sysmon_13_1_persistence_via_winlogon_shell.evtx',
    'Persistence/sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx',
    'Persistence/sysmon_1_smss_child_proc_bootexecute_setupexecute.evtx',
    'Persistence/sysmon_20_21_1_CommandLineEventConsumer.evtx',
    'Persistence/sysmon_local_account_creation_and_added_admingroup_12_13.evtx',
    'Persistence/wmighost_sysmon_20_21_1.evtx',
    'Privilege Escalation/4624 LT3 AnonymousLogon Localhost - JuicyPotato.evtx',
    'Privilege Escalation/4765_sidhistory_add_t1178.evtx',
    'Privilege Escalation/CVE-2020-0796_SMBV3Ghost_LocalPrivEsc_Sysmon_3_1_10.evtx',
    'Privilege Escalation/EfsPotato_sysmon_17_18_privesc_seimpersonate_to_system.evtx',
    'Privilege Escalation/Invoke_TokenDuplication_UAC_Bypass4624.evtx',
    'Privilege Escalation/NTLM2SelfRelay-med0x2e-security_4624_4688.evtx',
    'Privilege Escalation/PrivEsc_CVE-2020-1313_Sysmon_13_UScheduler_Cmdline.evtx',
    'Privilege Escalation/PrivEsc_Imperson_NetSvc_to_Sys_Decoder_Sysmon_1_17_18.evtx',
    'Privilege Escalation/PrivEsc_NetSvc_SessionToken_Retrival_via_localSMB_Auth_5145.evtx',
    'Privilege Escalation/PrivEsc_SeImpersonatePriv_enabled_back_for_upnp_localsvc_4698.evtx',
    'Privilege Escalation/RogueWinRM.evtx',
    'Privilege Escalation/Runas_4624_4648_Webshell_CreateProcessAsUserA.evtx',
    'Privilege Escalation/Sysmon_13_1_UACBypass_SDCLTBypass.evtx',
    'Privilege Escalation/Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx',
    'Privilege Escalation/Sysmon_UACME_22.evtx',
    'Privilege Escalation/Sysmon_UACME_23.evtx',
    'Privilege Escalation/Sysmon_UACME_30.evtx',
    'Privilege Escalation/Sysmon_UACME_32.evtx',
    'Privilege Escalation/Sysmon_UACME_33.evtx',
    'Privilege Escalation/Sysmon_UACME_34.evtx',
    'Privilege Escalation/Sysmon_UACME_36_FileCreate.evtx',
    'Privilege Escalation/Sysmon_UACME_37_FileCreate.evtx',
    'Privilege Escalation/Sysmon_UACME_38.evtx',
    'Privilege Escalation/Sysmon_UACME_39.evtx',
    'Privilege Escalation/Sysmon_UACME_41.evtx',
    'Privilege Escalation/Sysmon_UACME_43.evtx',
    'Privilege Escalation/Sysmon_UACME_45.evtx',
    'Privilege Escalation/Sysmon_UACME_53.evtx',
    'Privilege Escalation/Sysmon_UACME_54.evtx',
    'Privilege Escalation/Sysmon_UACME_56.evtx',
    'Privilege Escalation/Sysmon_UACME_63.evtx',
    'Privilege Escalation/Sysmon_UACME_64.evtx',
    'Privilege Escalation/Sysmon_uacme_58.evtx',
    'Privilege Escalation/System_7045_namedpipe_privesc.evtx',
    'Privilege Escalation/UACME_59_Sysmon.evtx',
    'Privilege Escalation/UACME_61_Changepk.evtx',
    'Privilege Escalation/eop_appcontainer_il_broker_filewrite.evtx',
    'Privilege Escalation/privesc_KrbRelayUp_windows_4624.evtx',
    'Privilege Escalation/privesc_registry_symlink_CVE-2020-1377.evtx',
    'Privilege Escalation/privesc_roguepotato_sysmon_17_18.evtx',
    'Privilege Escalation/privesc_rotten_potato_from_webshell_metasploit_sysmon_1_8_3.evtx',
    'Privilege Escalation/privesc_seimpersonate_tosys_spoolsv_sysmon_17_18.evtx',
    'Privilege Escalation/privesc_spoolfool_mahdihtm_sysmon_1_11_7_13.evtx',
    'Privilege Escalation/privesc_spoolsv_spl_file_write_sysmon11.evtx',
    'Privilege Escalation/privesc_sysmon_cve_20201030_spooler.evtx',
    'Privilege Escalation/privesc_unquoted_svc_sysmon_1_11.evtx',
    'Privilege Escalation/privexchange_dirkjan.evtx',
    'Privilege Escalation/samaccount_spoofing_CVE-2021-42287_CVE-2021-42278_DC_securitylogs.evtx',
    'Privilege Escalation/security_4624_4673_token_manip.evtx',
    'Privilege Escalation/sysmon_11_1_15_WScriptBypassUAC.evtx',
    'Privilege Escalation/sysmon_11_1_7_uacbypass_cliconfg.evtx',
    'Privilege Escalation/sysmon_11_7_1_uacbypass_windirectory_mocking.evtx',
    'Privilege Escalation/sysmon_13_1_12_11_perfmonUACBypass.evtx',
    'Privilege Escalation/sysmon_13_1_compmgmtlauncherUACBypass.evtx',
    'Privilege Escalation/sysmon_13_1_meterpreter_getsystem_NamedPipeImpersonation.evtx',
    'Privilege Escalation/sysmon_1_11_exec_as_system_via_schedtask.evtx',
    'Privilege Escalation/sysmon_1_13_11_cmstp_ini_uacbypass.evtx',
    'Privilege Escalation/sysmon_1_13_UACBypass_AppPath_Control.evtx',
    'Privilege Escalation/sysmon_1_7_11_mcx2prov_uacbypass.evtx',
    'Privilege Escalation/sysmon_1_7_11_migwiz.evtx',
    'Privilege Escalation/sysmon_1_7_11_sysprep_uacbypass.evtx',
    'Privilege Escalation/sysmon_1_7_elevate_uacbypass_sysprep.evtx',
    'Privilege Escalation/sysmon_privesc_from_admin_to_system_handle_inheritance.evtx',
    'Privilege Escalation/sysmon_privesc_psexec_dwell.evtx',
    'Privilege Escalation/sysmon_uacbypass_CDSSync_schtask_hijack_byeintegrity5.evtx',
    'Privilege Escalation/win10_4703_SeDebugPrivilege_enabled.evtx',
    'UACME_59_Sysmon.evtx',
]


def local_path(repo_path: str) -> Path:
    """Return the local cache path for a given repo-relative path."""
    return _FIXTURE_DIR / repo_path


def download_all(force: bool = False) -> None:
    ok = skipped = failed = 0

    for repo_path in ALL_SAMPLES:
        dest = local_path(repo_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        if dest.exists() and not force:
            skipped += 1
            continue

        url = _RAW_BASE + urllib.request.quote(repo_path, safe='/')
        print(f'  fetch {repo_path} ... ', end='', flush=True)
        try:
            urllib.request.urlretrieve(url, dest)
            size_kb = dest.stat().st_size // 1024
            print(f'ok ({size_kb} KB)')
            ok += 1
        except urllib.error.URLError as exc:
            dest.unlink(missing_ok=True)
            print(f'FAILED: {exc}')
            failed += 1

    print(f'\n{ok} downloaded, {skipped} already cached, {failed} failed.')
    if failed:
        sys.exit(1)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument('--force', action='store_true',
                    help='Re-download files even if already cached')
    args = ap.parse_args()
    download_all(force=args.force)
