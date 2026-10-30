import { Link } from "react-router-dom";

// DRAFT — describes what this application actually collects (see docs/DATA_MAP.md).
// The operating organization must review and complete it (controller name, contact,
// retention periods, legal basis) with legal counsel before relying on it.
export default function PrivacyPage() {
  return (
    <div className="min-h-screen bg-gray-50 px-4 py-10">
      <div className="max-w-2xl mx-auto bg-white rounded-xl border border-gray-200 p-6 shadow-sm text-sm text-gray-700 space-y-4">
        <h1 className="text-xl font-semibold text-gray-900">Privacy Notice</h1>
        <p className="text-xs text-gray-400">Draft — to be completed by your organization.</p>

        <h2 className="font-semibold text-gray-900">What this tool does</h2>
        <p>
          NetAudit is your organization's internal security audit tool. It scans networks and, where an
          agent is installed on your device, checks that device for malware and security misconfiguration.
        </p>

        <h2 className="font-semibold text-gray-900">Data collected</h2>
        <ul className="list-disc pl-5 space-y-1">
          <li>Account data: email address, display name, role, hashed password (or directory identity if you sign in with Active Directory), last login time.</li>
          <li>Device data: IP address, hostname, operating system, open ports and services, and — from the agent — running processes, installed software, firewall status and the paths and names of files flagged as malware.</li>
          <li>Network captures made by IT administrators may contain traffic content from the network being inspected.</li>
          <li>Security findings and, if enabled by your administrator, AI-generated remediation text.</li>
        </ul>

        <h2 className="font-semibold text-gray-900">Who receives it</h2>
        <p>
          Data stays within your organization's NetAudit installation. If your administrator enables an
          external AI provider, finding and device details (such as hostname, IP address and file paths) are sent to that
          provider to generate remediation advice. Notifications may be sent to email, Slack or Teams if configured.
        </p>

        <h2 className="font-semibold text-gray-900">Retention and your rights</h2>
        <p>
          Retention periods and how to request access, correction or deletion of your data are set by your
          organization. Contact your IT administrator or data protection contact.
        </p>

        <Link to="/login" className="text-blue-600 hover:text-blue-700 font-medium">← Back to sign in</Link>
      </div>
    </div>
  );
}
