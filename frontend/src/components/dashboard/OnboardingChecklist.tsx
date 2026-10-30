import { useState } from "react";
import { Link } from "react-router-dom";
import {
  CheckCircle, Circle, ChevronDown, ChevronUp,
  Sparkles, Scan, Monitor, Users, X, Copy, Check
} from "lucide-react";
import { useOnboarding } from "../../hooks/useOnboarding";
import { useAuthStore } from "../../store/authStore";

export default function OnboardingChecklist() {
  const { status, isLoading } = useOnboarding();
  const [dismissed, setDismissed] = useState(
    () => localStorage.getItem("onboarding_dismissed") === "true"
  );
  const [expanded, setExpanded] = useState<string | null>("ai");

  const dismiss = () => {
    localStorage.setItem("onboarding_dismissed", "true");
    setDismissed(true);
  };

  if (isLoading || dismissed || status.all_done) return null;

  const completedCount = [
    status.ai_configured,
    status.first_scan_done,
    status.agent_connected,
    status.users_invited,
  ].filter(Boolean).length;

  return (
    <div className="bg-white rounded-xl border border-blue-100 shadow-sm mb-6 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 bg-gradient-to-r from-blue-50 to-indigo-50 border-b border-blue-100">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold">
            {completedCount}/4
          </div>
          <div>
            <div className="font-semibold text-gray-900 text-sm">Get NetAudit set up</div>
            <div className="text-xs text-gray-500">
              {4 - completedCount} step{4 - completedCount !== 1 ? "s" : ""} remaining
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {/* Progress bar */}
          <div className="w-24 h-1.5 bg-blue-100 rounded-full hidden sm:block">
            <div
              className="h-full bg-blue-500 rounded-full transition-all duration-500"
              style={{ width: `${(completedCount / 4) * 100}%` }}
            />
          </div>
          <button
            onClick={dismiss}
            className="text-gray-400 hover:text-gray-600 p-1 rounded"
            title="Dismiss setup guide"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Steps */}
      <div className="divide-y divide-gray-50">
        <Step
          id="ai"
          icon={<Sparkles className="w-4 h-4" />}
          title="Configure AI provider"
          description="Choose Claude, OpenAI, Gemini, or local Ollama for remediation advice."
          done={status.ai_configured}
          expanded={expanded === "ai"}
          onToggle={() => setExpanded(expanded === "ai" ? null : "ai")}
        >
          <p className="text-sm text-gray-600 mb-3">
            Go to Settings and pick your AI provider. Ollama works fully offline — no API key needed.
            For the best remediation quality, use Claude or GPT-4o.
          </p>
          <Link
            to="/settings"
            className="inline-flex items-center gap-1.5 text-sm text-blue-600 hover:text-blue-700 font-medium"
          >
            Open Settings →
          </Link>
        </Step>

        <Step
          id="scan"
          icon={<Scan className="w-4 h-4" />}
          title="Run your first scan"
          description="Discover what's on your network and identify security issues."
          done={status.first_scan_done}
          expanded={expanded === "scan"}
          onToggle={() => setExpanded(expanded === "scan" ? null : "scan")}
        >
          <p className="text-sm text-gray-600 mb-3">
            Click <strong>New Scan</strong> on the dashboard. Start with a Port Scan on your
            internal range (e.g. <code className="bg-gray-100 px-1 rounded text-xs">192.168.1.0/24</code>).
            It typically takes 2–5 minutes.
          </p>
          <Link
            to="/dashboard"
            className="inline-flex items-center gap-1.5 text-sm text-blue-600 hover:text-blue-700 font-medium"
          >
            Go to Dashboard →
          </Link>
        </Step>

        <Step
          id="agent"
          icon={<Monitor className="w-4 h-4" />}
          title="Install the agent on an employee device"
          description="Enables virus scanning and self-service scans for end users."
          done={status.agent_connected}
          expanded={expanded === "agent"}
          onToggle={() => setExpanded(expanded === "agent" ? null : "agent")}
        >
          <AgentInstallStep />
        </Step>

        <Step
          id="users"
          icon={<Users className="w-4 h-4" />}
          title="Invite your IT team"
          description="Add engineers and viewers so your whole team can see findings."
          done={status.users_invited}
          expanded={expanded === "users"}
          onToggle={() => setExpanded(expanded === "users" ? null : "users")}
        >
          <p className="text-sm text-gray-600 mb-3">
            Add IT Engineers and Viewers so your whole team can monitor findings and
            action remediation. End users can also be added with restricted access
            to scan only their own device.
          </p>
          <Link
            to="/users"
            className="inline-flex items-center gap-1.5 text-sm text-blue-600 hover:text-blue-700 font-medium"
          >
            Manage Users →
          </Link>
        </Step>
      </div>
    </div>
  );
}

// ─── Step component ───────────────────────────────────────────────

function Step({
  id, icon, title, description, done, expanded, onToggle, children,
}: {
  id: string;
  icon: React.ReactNode;
  title: string;
  description: string;
  done: boolean;
  expanded: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className={done ? "opacity-60" : ""}>
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-4 px-5 py-4 hover:bg-gray-50 transition-colors text-left"
      >
        <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${
          done
            ? "bg-green-100 text-green-600"
            : "bg-blue-50 text-blue-600"
        }`}>
          {done ? <CheckCircle className="w-4 h-4" /> : icon}
        </div>
        <div className="flex-1 min-w-0">
          <div className={`text-sm font-medium ${done ? "line-through text-gray-400" : "text-gray-800"}`}>
            {title}
          </div>
          <div className="text-xs text-gray-400 mt-0.5 truncate">{description}</div>
        </div>
        {!done && (
          expanded
            ? <ChevronUp className="w-4 h-4 text-gray-400 flex-shrink-0" />
            : <ChevronDown className="w-4 h-4 text-gray-400 flex-shrink-0" />
        )}
        {done && <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0" />}
      </button>

      {expanded && !done && (
        <div className="px-5 pb-5 ml-12">
          {children}
        </div>
      )}
    </div>
  );
}

// ─── Agent install step with token copy ───────────────────────────

function AgentInstallStep() {
  const { user } = useAuthStore();
  const [copied, setCopied] = useState(false);

  // Build install command pointing at current host
  const dashboardUrl = `${window.location.protocol}//${window.location.host}`;
  const installCmd = `python agent.py configure --url ${dashboardUrl} --token YOUR_TOKEN_FROM_DASHBOARD`;

  const copy = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="space-y-3">
      <p className="text-sm text-gray-600">
        Install Python and ClamAV on the employee's machine, then run:
      </p>

      {/* Step 1: pip install */}
      <div>
        <p className="text-xs font-medium text-gray-500 mb-1">1. Install dependencies</p>
        <CopyableCode code="pip install httpx psutil structlog" />
      </div>

      {/* Step 2: Get token */}
      <div>
        <p className="text-xs font-medium text-gray-500 mb-1">2. Get the user's agent token</p>
        <p className="text-xs text-gray-500">
          In <Link to="/users" className="text-blue-500 hover:underline">Users</Link>, find the
          user's account → they can generate their token from the end-user portal at{" "}
          <code className="bg-gray-100 px-1 rounded text-xs">{dashboardUrl}/my-device</code>
        </p>
      </div>

      {/* Step 3: configure */}
      <div>
        <p className="text-xs font-medium text-gray-500 mb-1">3. Configure and start the agent</p>
        <CopyableCode
          code={`python agent.py configure --url ${dashboardUrl} --token PASTE_TOKEN_HERE\npython agent.py start`}
        />
      </div>

      <p className="text-xs text-gray-400">
        Windows users can run <code className="bg-gray-100 px-1 rounded">install_windows.bat</code> instead.
        On Linux, use the included systemd service file.
      </p>
    </div>
  );
}

function CopyableCode({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);

  const copy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="relative group">
      <pre className="bg-gray-900 text-green-400 text-xs rounded-lg px-3 py-2.5 overflow-x-auto font-mono leading-relaxed pr-8">
        {code}
      </pre>
      <button
        onClick={copy}
        className="absolute top-2 right-2 p-1 rounded text-gray-500 hover:text-gray-300 transition-colors opacity-0 group-hover:opacity-100"
        title="Copy"
      >
        {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
      </button>
    </div>
  );
}
