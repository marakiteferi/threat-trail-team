import { useState } from 'react'
import {
  Shield,
  Code,
  User,
  Globe,
  Copy,
  Check,
  AlertTriangle,
  Cpu,
  FileText,
  Key,
  Terminal,
  Database,
  Filter,
  GitBranch,
} from 'lucide-react'

const EVENT_DESCRIPTIONS = {
  4625: 'Failed Logon — An account failed to authenticate',
  4624: 'Successful Logon — An account was successfully authenticated',
  4648: 'Logon Using Explicit Credentials (RunAs / Lateral Movement)',
  4662: 'Directory Service Access — Operation performed on an AD object (DCSync check)',
  4672: 'Special Privileges Assigned — Administrative logon detected',
  4688: 'Process Creation — A new executable or command was spawned',
  4689: 'Process Termination — An executable exited',
  4697: 'Service Installed in the System (Security Log)',
  4768: 'Kerberos TGT Requested (AS-REQ)',
  4769: 'Kerberos Service Ticket Requested (TGS-REQ / Kerberoasting check)',
  5140: 'Network Share Object Accessed (SMB Lateral Movement)',
  5145: 'Network Share Object Checked for Access',
  7045: 'New Windows Service Installed (System Log — PsExec / SMBExec)',
  4103: 'PowerShell Module / Pipeline Execution Details',
  4104: 'PowerShell ScriptBlock Logging (De-obfuscated Script Code)',
  1102: 'Audit Log Cleared — Security log was intentionally wiped',
  1: 'Sysmon Event 1: Process Creation',
  3: 'Sysmon Event 3: Network Connection Detected',
  7: 'Sysmon Event 7: Image / DLL Loaded',
  8: 'Sysmon Event 8: CreateRemoteThread Detected',
  10: 'Sysmon Event 10: Process Access (LSASS / Credential Dumping check)',
  11: 'Sysmon Event 11: File Created',
  12: 'Sysmon Event 12: Registry Object Added or Deleted',
  13: 'Sysmon Event 13: Registry Value Set',
  17: 'Sysmon Event 17: Named Pipe Created',
  18: 'Sysmon Event 18: Named Pipe Connected',
  22: 'Sysmon Event 22: DNS Query Executed',
}

const LOGON_TYPES = {
  '2': 'Type 2: Interactive (Local Console)',
  '3': 'Type 3: Network (SMB / RPC / WinRM / PsExec / DCOM)',
  '4': 'Type 4: Batch (Scheduled Task)',
  '5': 'Type 5: Service (Service Startup)',
  '7': 'Type 7: Unlock',
  '8': 'Type 8: NetworkCleartext',
  '9': 'Type 9: NewCredentials (RunAs /netonly / Pass-the-Hash)',
  '10': 'Type 10: RemoteInteractive (RDP)',
  '11': 'Type 11: CachedInteractive',
}

const STATUS_CODES = {
  '0xC000006D': 'STATUS_LOGON_FAILURE (Bad username or password)',
  '0xC000006A': 'STATUS_WRONG_PASSWORD (Valid user, wrong password)',
  '0xC0000234': 'STATUS_ACCOUNT_LOCKED_OUT',
  '0xC0000072': 'STATUS_ACCOUNT_DISABLED',
  '0xC0000064': 'STATUS_NO_SUCH_USER (User does not exist)',
}

const ENCRYPTION_TYPES = {
  '0x17': '0x17 — RC4-HMAC (Legacy / Weak — High Kerberoasting Risk!)',
  '23': '0x17 (23) — RC4-HMAC (Legacy / Weak — High Kerberoasting Risk!)',
  '0x12': '0x12 — AES256-CTS-HMAC-SHA1-96 (Modern Standard)',
  '18': '0x12 (18) — AES256-CTS-HMAC-SHA1-96 (Modern Standard)',
  '0x11': '0x11 — AES128-CTS-HMAC-SHA1-96',
}

const GRANTED_ACCESS_FLAGS = {
  '0x1010': '0x1010 (PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION — Classic Mimikatz!)',
  '0x1410': '0x1410 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION — Credential Dump!)',
  '0x1438': '0x1438 (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION — Mimikatz)',
  '0x1fffff': '0x1FFFFF (PROCESS_ALL_ACCESS — Full Memory Access)',
}

const AD_REPLICATION_GUIDS = {
  '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes (DCSync)',
  '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes-All (DCSync Secret Dump!)',
  '89e95b76-444d-4c62-991a-0facbeda640c': 'DS-Replication-Get-Changes-In-Filtered-Set',
}

function extractFromText(text, pattern) {
  if (!text || typeof text !== 'string') return null
  const match = text.match(pattern)
  if (match && match[1]) {
    const val = match[1].trim()
    return val && val !== '-' ? val : null
  }
  return null
}

function cleanVal(val) {
  if (val === undefined || val === null) return null
  const s = String(val).trim()
  return s === '' || s === '-' ? null : s
}

export default function LogInspector({ log, onPivot }) {
  const [activeTab, setActiveTab] = useState('parsed')
  const [copiedKey, setCopiedKey] = useState(null)

  const raw = log.raw_event_data || {}
  const msg = raw.Message || ''
  const eventId = log.event_id || raw.EventID || 0
  const eventDesc = EVENT_DESCRIPTIONS[eventId] || `Windows Event ${eventId}`

  const copyValue = (key, val) => {
    if (!val || val === '-') return
    navigator.clipboard.writeText(String(val))
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 1600)
  }

  const triggerPivot = (value, label) => {
    if (!value || value === '-' || !onPivot) return
    onPivot(String(value).trim(), label)
  }

  // 1. Identity & Session Correlation Fields
  const subjectUser =
    cleanVal(raw.SubjectUserName) ||
    extractFromText(msg, /Subject:[\s\S]*?Account Name:\s*([^\r\n\t]+)/)
  const subjectDomain =
    cleanVal(raw.SubjectDomainName) ||
    extractFromText(msg, /Subject:[\s\S]*?Account Domain:\s*([^\r\n\t]+)/)
  const subjectLogonId =
    cleanVal(raw.SubjectLogonId) ||
    extractFromText(msg, /Subject:[\s\S]*?Logon ID:\s*([^\r\n\t]+)/)

  const targetUser =
    cleanVal(raw.TargetUserName) ||
    cleanVal(raw.AccountName) ||
    cleanVal(raw.User) ||
    cleanVal(log.username) ||
    extractFromText(msg, /New Logon:[\s\S]*?Account Name:\s*([^\r\n\t]+)/) ||
    extractFromText(msg, /Account For Which Logon Failed:[\s\S]*?Account Name:\s*([^\r\n\t]+)/) ||
    extractFromText(msg, /Account Information:[\s\S]*?Account Name:\s*([^\r\n\t]+)/)

  const targetDomain =
    cleanVal(raw.TargetDomainName) ||
    cleanVal(raw.AccountDomain) ||
    cleanVal(raw.Domain) ||
    extractFromText(msg, /Account Domain:\s*([^\r\n\t]+)/)

  const targetLogonId =
    cleanVal(raw.TargetLogonId) ||
    extractFromText(msg, /New Logon:[\s\S]*?Logon ID:\s*([^\r\n\t]+)/)

  const logonTypeRaw = cleanVal(raw.LogonType) || extractFromText(msg, /Logon Type:\s*([0-9]+)/)
  const logonTypeDesc = logonTypeRaw ? (LOGON_TYPES[String(logonTypeRaw)] || `Type ${logonTypeRaw}`) : null
  const authPackage = cleanVal(raw.AuthenticationPackageName) || extractFromText(msg, /Authentication Package:\s*([^\r\n\t]+)/)
  const privileges = cleanVal(raw.PrivilegeList) || extractFromText(msg, /Privileges:\s*([^\r\n]+)/)

  // 2. Network & Host Fields
  const sourceIp =
    cleanVal(log.source_ip) ||
    cleanVal(raw.IpAddress) ||
    cleanVal(raw.SourceAddress) ||
    cleanVal(raw.SourceIp) ||
    extractFromText(msg, /Source Network Address:\s*([^\r\n\t]+)/) ||
    extractFromText(msg, /Client Address:\s*([^\r\n\t]+)/)
  const sourcePort = cleanVal(raw.SourcePort) || cleanVal(raw.IpPort) || extractFromText(msg, /Source Port:\s*([^\r\n\t]+)/)
  const destIp = cleanVal(raw.DestinationIp) || cleanVal(raw.DestAddress)
  const destPort = cleanVal(raw.DestinationPort) || cleanVal(raw.DestPort)
  const destHost = cleanVal(raw.DestinationHostname) || cleanVal(raw.QueryName)
  const workstation =
    cleanVal(log.target_host) ||
    cleanVal(raw.Hostname) ||
    cleanVal(raw.Computer) ||
    cleanVal(raw.WorkstationName) ||
    extractFromText(msg, /Workstation Name:\s*([^\r\n\t]+)/)

  // 3. Process Lineage, Command Line & Sysmon ProcessAccess (Events 1, 10, 4688, 7)
  const processImage =
    cleanVal(raw.Image) ||
    cleanVal(raw.NewProcessName) ||
    cleanVal(raw.SourceImage) ||
    cleanVal(raw.ProcessName) ||
    cleanVal(raw.Application) ||
    extractFromText(msg, /New Process Name:\s*([^\r\n\t]+)/)
  const parentImage =
    cleanVal(raw.ParentImage) ||
    cleanVal(raw.ParentProcessName) ||
    cleanVal(raw.CreatorProcessName) ||
    extractFromText(msg, /Creator Process Name:\s*([^\r\n\t]+)/)
  const targetImage = cleanVal(raw.TargetImage)
  const commandLine =
    cleanVal(raw.CommandLine) ||
    cleanVal(raw.ProcessCommandLine) ||
    extractFromText(msg, /Process Command Line:\s*([^\r\n]+)/)
  const parentCommandLine = cleanVal(raw.ParentCommandLine)
  const processGuid = cleanVal(raw.ProcessGuid) || cleanVal(raw.SourceProcessGUID)
  const parentProcessGuid = cleanVal(raw.ParentProcessGuid)
  const processId = cleanVal(raw.ProcessId) || cleanVal(raw.NewProcessId) || cleanVal(raw.SourceProcessId)
  const grantedAccess = cleanVal(raw.GrantedAccess)
  const callTrace = cleanVal(raw.CallTrace)
  const imageLoaded = cleanVal(raw.ImageLoaded)

  // 4. Kerberos, AD Replication (DCSync), Services, Shares & Registry (Events 4769, 4662, 7045, 4697, 13, 17, 5140)
  const serviceName =
    cleanVal(raw.ServiceName) ||
    extractFromText(msg, /Service Name:\s*([^\r\n\t]+)/)
  const serviceFileName =
    cleanVal(raw.ImagePath) ||
    cleanVal(raw.ServiceFileName) ||
    extractFromText(msg, /Service File Name:\s*([^\r\n\t]+)/)
  const ticketEnc =
    cleanVal(raw.TicketEncryptionType) ||
    extractFromText(msg, /Ticket Encryption Type:\s*(0x[0-9a-fA-F]+|[0-9]+)/)
  const ticketOptions =
    cleanVal(raw.TicketOptions) ||
    extractFromText(msg, /Ticket Options:\s*(0x[0-9a-fA-F]+)/)
  const adProperties =
    cleanVal(raw.Properties) ||
    extractFromText(msg, /Properties:\s*([^\r\n]+)/)
  const adObjectName =
    cleanVal(raw.ObjectName) ||
    extractFromText(msg, /Object Name:\s*([^\r\n\t]+)/)
  const accessMask =
    cleanVal(raw.AccessMask) ||
    extractFromText(msg, /Access Mask:\s*(0x[0-9a-fA-F]+)/)
  const registryObject = cleanVal(raw.TargetObject)
  const registryDetails = cleanVal(raw.Details)
  const pipeOrShare = cleanVal(raw.PipeName) || cleanVal(raw.ShareName) || cleanVal(raw.RelativeTargetName)

  // 5. PowerShell Telemetry (Events 4104, 4103)
  const scriptBlockText =
    cleanVal(raw.ScriptBlockText) ||
    cleanVal(raw.Payload) ||
    cleanVal(raw.ContextInfo)

  // 6. Failure Codes
  const failureReason = cleanVal(raw.FailureReason) || extractFromText(msg, /Failure Reason:\s*([^\r\n\t]+)/)
  const statusCode = cleanVal(raw.Status) || extractFromText(msg, /Status:\s*(0x[0-9a-fA-F]+)/)
  const subStatusCode = cleanVal(raw.SubStatus) || extractFromText(msg, /Sub Status:\s*(0x[0-9a-fA-F]+)/)

  // Decode known AD Replication GUIDs if present
  const matchedReplicationGuids = Object.entries(AD_REPLICATION_GUIDS).filter(
    ([guid]) => (adProperties && adProperties.toLowerCase().includes(guid)) || (msg && msg.toLowerCase().includes(guid))
  )

  const renderFieldValue = (label, value, highlight = false, badgeNote = null) => {
    if (!value) return null
    const keyId = `${label}:${value}`
    return (
      <div className="card-row" key={label}>
        <span className="field-label">{label}:</span>
        <span className={`field-value ${highlight ? 'highlight' : ''}`} style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          <span className="code-pill break-all">{value}</span>
          {badgeNote && (
            <span style={{ fontSize: '0.72rem', color: '#fbbf24', background: 'rgba(245, 158, 11, 0.14)', padding: '1px 6px', borderRadius: 4 }}>
              {badgeNote}
            </span>
          )}
          {onPivot && (
            <button
              type="button"
              className="copy-chip-btn"
              onClick={(e) => { e.stopPropagation(); triggerPivot(value, label) }}
              title={`Filter logs by ${label}: ${value}`}
              style={{ borderColor: 'rgba(56, 189, 248, 0.4)', color: '#38bdf8' }}
            >
              <Filter size={10} style={{ display: 'inline', marginRight: 3 }} />
              Pivot
            </button>
          )}
          <button
            type="button"
            className="copy-chip-btn"
            onClick={(e) => { e.stopPropagation(); copyValue(keyId, value) }}
            title="Copy value"
          >
            {copiedKey === keyId ? <Check size={10} /> : <Copy size={10} />}
          </button>
        </span>
      </div>
    )
  }

  return (
    <div className="log-inspector">
      <div className="inspector-header">
        <div className="inspector-title" style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span className={`inspector-badge ${eventId === 4624 ? 'badge-success' : 'badge-danger'}`}>
            Event {eventId}
          </span>
          <strong>{eventDesc}</strong>
          {/* Quick Correlation Buttons */}
          {onPivot && (targetLogonId || subjectLogonId) && (
            <button
              type="button"
              className="copy-chip-btn"
              onClick={() => triggerPivot(targetLogonId || subjectLogonId, 'Logon Session ID')}
              title="Find all events in this Logon Session (LogonId)"
              style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#34d399', borderColor: '#10b98155' }}
            >
              <Key size={11} style={{ display: 'inline', marginRight: 4 }} />
              Trace Logon Session ({targetLogonId || subjectLogonId})
            </button>
          )}
          {onPivot && (processGuid || parentProcessGuid) && (
            <button
              type="button"
              className="copy-chip-btn"
              onClick={() => triggerPivot(processGuid || parentProcessGuid, 'ProcessGuid')}
              title="Trace child & parent events sharing this ProcessGuid"
              style={{ background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc', borderColor: '#a855f755' }}
            >
              <GitBranch size={11} style={{ display: 'inline', marginRight: 4 }} />
              Trace Process Tree
            </button>
          )}
        </div>

        <div className="inspector-tabs">
          <button
            type="button"
            className={`inspector-tab-btn ${activeTab === 'parsed' ? 'active' : ''}`}
            onClick={() => setActiveTab('parsed')}
          >
            <Shield size={13} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} />
            Forensic Triage View
          </button>
          <button
            type="button"
            className={`inspector-tab-btn ${activeTab === 'raw' ? 'active' : ''}`}
            onClick={() => setActiveTab('raw')}
          >
            <Code size={13} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} />
            Raw Event JSON
          </button>
        </div>
      </div>

      {activeTab === 'parsed' && (
        <div className="inspector-content">
          <div className="inspector-grid">
            {/* Card 1: Identity & Session */}
            <div className="inspector-card">
              <h4>
                <User size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
                Identity & Session Context
              </h4>
              {renderFieldValue(
                'Subject User (Actor)',
                subjectUser,
                true,
                subjectUser?.endsWith('$') ? 'Machine Account ($)' : null
              )}
              {renderFieldValue('Subject Domain', subjectDomain)}
              {renderFieldValue('Subject Logon ID', subjectLogonId)}
              {renderFieldValue(
                'Target / Account User',
                targetUser,
                true,
                targetUser?.endsWith('$') ? 'Machine Account ($)' : null
              )}
              {renderFieldValue('Target Domain', targetDomain)}
              {renderFieldValue('Target Logon ID', targetLogonId)}
              {renderFieldValue('Logon Type', logonTypeDesc)}
              {renderFieldValue('Auth Package', authPackage)}
              {renderFieldValue('Privileges', privileges)}
            </div>

            {/* Card 2: Network & Endpoint */}
            <div className="inspector-card">
              <h4>
                <Globe size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
                Network & Endpoint Telemetry
              </h4>
              {renderFieldValue('Workstation / Host', workstation, true)}
              {renderFieldValue('Source IP', sourceIp, true)}
              {renderFieldValue('Source Port', sourcePort)}
              {renderFieldValue('Destination IP', destIp, true)}
              {renderFieldValue('Destination Port', destPort, true)}
              {renderFieldValue('Destination Host / DNS', destHost)}
              <div className="card-row">
                <span className="field-label">UTC Timestamp:</span>
                <span className="field-value text-dim">{new Date(log.timestamp).toLocaleString()}</span>
              </div>
            </div>

            {/* Card 3: Process Lineage & Memory Access (Shown when process telemetry exists) */}
            {(processImage || parentImage || targetImage || commandLine || grantedAccess || imageLoaded) && (
              <div className="inspector-card">
                <h4>
                  <Cpu size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
                  Process Lineage & Memory Access
                </h4>
                {renderFieldValue('Parent Process (ParentImage)', parentImage, true)}
                {renderFieldValue('Process / SourceImage', processImage, true)}
                {renderFieldValue('Target Process (TargetImage)', targetImage, true)}
                {renderFieldValue('Process ID (PID)', processId)}
                {renderFieldValue('Process GUID', processGuid)}
                {renderFieldValue('Parent Process GUID', parentProcessGuid)}
                {renderFieldValue(
                  'GrantedAccess Mask',
                  grantedAccess,
                  true,
                  GRANTED_ACCESS_FLAGS[grantedAccess?.toLowerCase()] || GRANTED_ACCESS_FLAGS[grantedAccess]
                )}
                {renderFieldValue('Loaded DLL / Image', imageLoaded)}
                {renderFieldValue('Call Trace', callTrace)}
              </div>
            )}

            {/* Card 4: Kerberos, AD Replication (DCSync), Service & Registry Artifacts */}
            {(serviceName || serviceFileName || ticketEnc || adProperties || adObjectName || registryObject || pipeOrShare) && (
              <div className="inspector-card">
                <h4>
                  <Database size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
                  AD, Kerberos, Service & Registry Artifacts
                </h4>
                {renderFieldValue('Service Name / SPN', serviceName, true)}
                {renderFieldValue('Service Binary Path', serviceFileName, true)}
                {renderFieldValue(
                  'Ticket Encryption Type',
                  ticketEnc,
                  true,
                  ENCRYPTION_TYPES[ticketEnc?.toLowerCase()] || ENCRYPTION_TYPES[ticketEnc]
                )}
                {renderFieldValue('Ticket Options', ticketOptions)}
                {renderFieldValue('AD Object Name', adObjectName)}
                {renderFieldValue('Access Mask', accessMask)}
                {renderFieldValue('AD Properties / GUIDs', adProperties, true)}
                {matchedReplicationGuids.map(([guid, desc]) => (
                  <div className="card-row" key={guid}>
                    <span className="field-label" style={{ color: '#ef4444' }}>⚠️ Replication GUID:</span>
                    <span className="field-value" style={{ color: '#fca5a5', fontWeight: 600 }}>
                      {guid} → {desc}
                    </span>
                  </div>
                ))}
                {renderFieldValue('Registry TargetObject', registryObject, true)}
                {renderFieldValue('Registry Value / Details', registryDetails)}
                {renderFieldValue('Named Pipe / SMB Share', pipeOrShare, true)}
              </div>
            )}

            {/* Card 5: Authentication Failure Details */}
            {(failureReason || statusCode || subStatusCode) && (
              <div className="inspector-card failure-card">
                <h4>
                  <AlertTriangle size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
                  Authentication Failure Diagnostics
                </h4>
                {renderFieldValue('Failure Reason', failureReason)}
                {renderFieldValue('Status Code', statusCode, false, STATUS_CODES[statusCode])}
                {renderFieldValue('SubStatus Code', subStatusCode, false, STATUS_CODES[subStatusCode])}
              </div>
            )}
          </div>

          {/* Command Line Callout (if present) */}
          {(commandLine || parentCommandLine) && (
            <div className="inspector-message" style={{ marginTop: 12 }}>
              <h5>
                <Terminal size={13} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle', color: '#38bdf8' }} />
                Executed Command Line Telemetry
              </h5>
              {parentCommandLine && (
                <div style={{ marginBottom: 6, fontSize: '0.8rem', color: '#94a3b8' }}>
                  <strong>Parent Cmd:</strong> <code>{parentCommandLine}</code>
                </div>
              )}
              {commandLine && (
                <div className="message-box" style={{ borderLeft: '3px solid #38bdf8', fontFamily: 'monospace' }}>
                  {commandLine}
                </div>
              )}
            </div>
          )}

          {/* PowerShell ScriptBlock Callout (if present) */}
          {scriptBlockText && (
            <div className="inspector-message" style={{ marginTop: 12 }}>
              <h5>
                <Terminal size={13} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle', color: '#c084fc' }} />
                PowerShell ScriptBlock / Payload Content (Event {eventId})
              </h5>
              <div className="message-box" style={{ borderLeft: '3px solid #c084fc', fontFamily: 'monospace' }}>
                {scriptBlockText}
              </div>
            </div>
          )}

          {/* Raw Windows Message Text */}
          {msg && (
            <div className="inspector-message" style={{ marginTop: 12 }}>
              <h5>
                <FileText size={13} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} />
                Windows Event Message
              </h5>
              <div className="message-box">{msg}</div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'raw' && (
        <div className="inspector-raw-container">
          <div className="raw-actions">
            <span className="text-dim">Full Windows Event JSON telemetry</span>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => copyValue('raw_json', JSON.stringify(raw, null, 2))}
            >
              {copiedKey === 'raw_json' ? (
                <><Check size={12} style={{ display: 'inline', marginRight: 4 }} /> Copied JSON</>
              ) : (
                <><Copy size={12} style={{ display: 'inline', marginRight: 4 }} /> Copy JSON</>
              )}
            </button>
          </div>
          <pre className="raw-event-code">{JSON.stringify(raw, null, 2)}</pre>
        </div>
      )}
    </div>
  )
}