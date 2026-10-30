import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { api } from "../utils/api";
import toast from "react-hot-toast";
import {
  Sparkles, Eye, EyeOff, CheckCircle, AlertTriangle,
  Shield, Users, Plus, Trash2, ChevronRight, Loader, Network,
  Building2, Upload, X, Download, Monitor, Terminal, Apple,
} from "lucide-react";

type Tab = "org" | "ai" | "ldap" | "unifi" | "agent";

const TAB_LABELS: Record<Tab, { icon: React.ReactNode; label: string }> = {
  org:   { icon: <Building2 className="w-3.5 h-3.5" />, label: "Organization" },
  ai:    { icon: <Sparkles className="w-3.5 h-3.5" />,  label: "AI Provider" },
  ldap:  { icon: <Shield className="w-3.5 h-3.5" />,    label: "LDAP / Active Directory" },
  unifi: { icon: <Network className="w-3.5 h-3.5" />,   label: "UniFi Integration" },
  agent: { icon: <Download className="w-3.5 h-3.5" />,  label: "Agent Downloads" },
};

export default function SettingsPage() {
  const [tab, setTab] = useState<Tab>("org");

  return (
    <div className="p-6 max-w-2xl">
      <h1 className="text-2xl font-semibold text-gray-900 mb-6">Settings</h1>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 border-b border-gray-200">
        {(["org", "ai", "ldap", "unifi", "agent"] as Tab[]).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px ${
              tab === t
                ? "border-blue-600 text-blue-600"
                : "border-transparent text-gray-500 hover:text-gray-700"
            }`}
          >
            <span className="flex items-center gap-1.5">
              {TAB_LABELS[t].icon}
              {TAB_LABELS[t].label}
            </span>
          </button>
        ))}
      </div>

      {tab === "org" ? <OrgSettings /> : tab === "ai" ? <AISettings /> : tab === "ldap" ? <LDAPSettings /> : tab === "unifi" ? <UniFiSettings /> : <AgentDownloads />}
    </div>
  );
}

// ─── Organization Settings tab ────────────────────────────────────

function OrgSettings() {
  const queryClient = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [preview, setPreview] = useState<string | null>(null);

  const { data: profile, isLoading } = useQuery({
    queryKey: ["org-profile"],
    queryFn: () => api.get("/api/settings/organization").then(r => r.data),
  });

  const { register, handleSubmit, reset } = useForm({ values: profile });

  useEffect(() => {
    if (profile) reset(profile);
  }, [profile, reset]);

  const saveMutation = useMutation({
    mutationFn: (data: any) => api.put("/api/settings/organization", data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["org-profile"] });
      toast.success("Organization name saved");
    },
    onError: () => toast.error("Failed to save"),
  });

  const logoMutation = useMutation({
    mutationFn: (file: File) => {
      const form = new FormData();
      form.append("file", file);
      return api.post("/api/settings/organization/logo", form, {
        headers: { "Content-Type": "multipart/form-data" },
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["org-profile"] });
      setPreview(null);
      toast.success("Logo uploaded");
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || "Upload failed"),
  });

  const deleteMutation = useMutation({
    mutationFn: () => api.delete("/api/settings/organization/logo"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["org-profile"] });
      setPreview(null);
      toast.success("Logo removed");
    },
  });

  function onFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => setPreview(ev.target?.result as string);
    reader.readAsDataURL(file);
  }

  function onUpload() {
    const file = fileRef.current?.files?.[0];
    if (file) logoMutation.mutate(file);
  }

  if (isLoading) return <div className="text-sm text-gray-400 py-8 text-center">Loading…</div>;

  const currentLogo = preview || (profile?.has_logo ? profile.logo_data : null);

  return (
    <div className="space-y-6">
      {/* Org name */}
      <form onSubmit={handleSubmit(d => saveMutation.mutate(d))}>
        <section className="bg-white rounded-xl border border-gray-200 p-5">
          <h2 className="font-medium text-gray-900 mb-1">Organization Name</h2>
          <p className="text-sm text-gray-500 mb-4">
            Shown in reports and the site header. Only IT admins can change this.
          </p>
          <input
            {...register("name")}
            className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 mb-4"
            placeholder="Acme Corp"
          />
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={saveMutation.isPending}
              className="px-5 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium text-sm disabled:opacity-50"
            >
              {saveMutation.isPending ? "Saving…" : "Save name"}
            </button>
          </div>
        </section>
      </form>

      {/* Logo */}
      <section className="bg-white rounded-xl border border-gray-200 p-5">
        <h2 className="font-medium text-gray-900 mb-1">Organization Logo</h2>
        <p className="text-sm text-gray-500 mb-4">
          Appears on PDF reports. PNG or JPG, max 2 MB.
        </p>

        {currentLogo ? (
          <div className="flex items-start gap-4 mb-4">
            <img
              src={currentLogo}
              alt="Org logo"
              className="h-16 w-auto max-w-[160px] object-contain border border-gray-100 rounded-lg p-1.5 bg-gray-50"
            />
            <div className="flex flex-col gap-2">
              {preview && (
                <button
                  onClick={onUpload}
                  disabled={logoMutation.isPending}
                  className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700 disabled:opacity-50"
                >
                  {logoMutation.isPending ? <Loader className="w-3.5 h-3.5 animate-spin" /> : <Upload className="w-3.5 h-3.5" />}
                  {logoMutation.isPending ? "Uploading…" : "Save logo"}
                </button>
              )}
              {!preview && (
                <button
                  onClick={() => fileRef.current?.click()}
                  className="flex items-center gap-1.5 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg text-sm hover:bg-gray-50"
                >
                  <Upload className="w-3.5 h-3.5" />
                  Replace
                </button>
              )}
              <button
                onClick={() => {
                  if (preview) { setPreview(null); if (fileRef.current) fileRef.current.value = ""; }
                  else deleteMutation.mutate();
                }}
                disabled={deleteMutation.isPending}
                className="flex items-center gap-1.5 px-4 py-2 text-red-600 border border-red-200 rounded-lg text-sm hover:bg-red-50 disabled:opacity-50"
              >
                <X className="w-3.5 h-3.5" />
                {preview ? "Cancel" : deleteMutation.isPending ? "Removing…" : "Remove logo"}
              </button>
            </div>
          </div>
        ) : (
          <div
            onClick={() => fileRef.current?.click()}
            className="border-2 border-dashed border-gray-200 rounded-xl p-8 text-center cursor-pointer hover:border-blue-300 hover:bg-blue-50/30 transition-colors"
          >
            <Upload className="w-8 h-8 text-gray-300 mx-auto mb-2" />
            <p className="text-sm text-gray-500">Click to upload a logo</p>
            <p className="text-xs text-gray-400 mt-1">PNG, JPG — max 2 MB</p>
          </div>
        )}

        <input
          ref={fileRef}
          type="file"
          accept="image/*"
          className="hidden"
          onChange={onFileChange}
        />
      </section>
    </div>
  );
}

// ─── AI Settings tab ──────────────────────────────────────────────

const AI_PROVIDERS = [
  { id: "claude",  name: "Claude",        vendor: "Anthropic",  models: ["claude-sonnet-4-20250514", "claude-opus-4-20250514"], needsKey: true },
  { id: "openai",  name: "OpenAI",        vendor: "OpenAI",     models: ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"],              needsKey: true },
  { id: "gemini",  name: "Gemini",        vendor: "Google",     models: ["gemini-1.5-pro", "gemini-1.5-flash"],                needsKey: true },
  { id: "ollama",  name: "Ollama (Local)", vendor: "Local — no data leaves your network", models: ["llama3", "mistral", "mixtral", "phi3"], needsKey: false },
];

function AISettings() {
  const [showKey, setShowKey] = useState(false);
  const queryClient = useQueryClient();

  const { data: orgSettings } = useQuery({
    queryKey: ["org-settings"],
    queryFn: () => api.get("/api/settings").then(r => r.data),
  });

  const { register, handleSubmit, watch } = useForm({ values: orgSettings });
  const selectedProvider = watch("ai_provider") || orgSettings?.ai_provider || "ollama";
  const providerConfig = AI_PROVIDERS.find(p => p.id === selectedProvider);

  const saveMutation = useMutation({
    mutationFn: (data: any) => api.put("/api/settings", data),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["org-settings"] }); toast.success("Settings saved"); },
    onError: () => toast.error("Failed to save settings"),
  });

  const testMutation = useMutation({
    mutationFn: () => api.post("/api/settings/test-ai"),
    onSuccess: (res) => {
      if (res.data.success) toast.success(`AI connection successful (${res.data.model || res.data.provider})`);
      else toast.error(`AI test failed: ${res.data.error}`);
    },
  });

  return (
    <form onSubmit={handleSubmit(d => saveMutation.mutate(d))} className="space-y-6">
      <section className="bg-white rounded-xl border border-gray-200 p-5">
        <h2 className="font-medium text-gray-900 mb-4">AI Provider</h2>
        <p className="text-sm text-gray-500 mb-5">
          Choose which AI service generates remediation instructions. Ollama keeps all data on your network.
        </p>
        <div className="grid grid-cols-2 gap-3 mb-5">
          {AI_PROVIDERS.map(provider => (
            <label key={provider.id} className="cursor-pointer">
              <input type="radio" value={provider.id} {...register("ai_provider")} className="sr-only" />
              <div className={`border rounded-lg p-3.5 transition-colors ${
                selectedProvider === provider.id ? "border-blue-500 bg-blue-50" : "border-gray-200 hover:border-gray-300"
              }`}>
                <div className="font-medium text-sm text-gray-800">{provider.name}</div>
                <div className="text-xs text-gray-400 mt-0.5">{provider.vendor}</div>
                {!provider.needsKey && (
                  <div className="flex items-center gap-1 mt-2 text-xs text-green-600">
                    <CheckCircle className="w-3 h-3" /> No API key needed
                  </div>
                )}
              </div>
            </label>
          ))}
        </div>

        {providerConfig && (
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-1.5">Model</label>
            <select {...register("ai_model")} className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500">
              {providerConfig.models.map(m => <option key={m} value={m}>{m}</option>)}
            </select>
          </div>
        )}

        {providerConfig?.needsKey && (
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-1.5">{providerConfig.name} API Key</label>
            <div className="relative">
              <input type={showKey ? "text" : "password"} {...register("ai_api_key")}
                placeholder={orgSettings?.has_api_key ? "••••••••••••••••" : "sk-..."}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 pr-10 text-sm font-mono focus:ring-2 focus:ring-blue-500" />
              <button type="button" onClick={() => setShowKey(!showKey)} className="absolute right-3 top-2.5 text-gray-400 hover:text-gray-600">
                {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            <p className="text-xs text-gray-400 mt-1">Stored encrypted at rest. Never transmitted to third parties.</p>
          </div>
        )}

        {selectedProvider === "ollama" && (
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-1.5">Ollama URL</label>
            <input {...register("ai_ollama_url")} placeholder="http://ollama:11434"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-blue-500" />
          </div>
        )}

        <button type="button" onClick={() => testMutation.mutate()} disabled={testMutation.isPending}
          className="text-sm text-blue-600 hover:text-blue-700 disabled:opacity-50 flex items-center gap-1.5">
          {testMutation.isPending && <Loader className="w-3 h-3 animate-spin" />}
          {testMutation.isPending ? "Testing…" : "Test connection →"}
        </button>
      </section>

      <div className="flex justify-end">
        <button type="submit" disabled={saveMutation.isPending}
          className="px-5 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium text-sm disabled:opacity-50">
          {saveMutation.isPending ? "Saving…" : "Save settings"}
        </button>
      </div>
    </form>
  );
}

// ─── LDAP Settings tab ────────────────────────────────────────────

const ROLE_OPTIONS = [
  { value: "it_admin",    label: "IT Admin" },
  { value: "it_engineer", label: "IT Engineer" },
  { value: "it_viewer",   label: "IT Viewer" },
  { value: "end_user",    label: "End User" },
];

function LDAPSettings() {
  const [showPassword, setShowPassword] = useState(false);
  const [roleMappings, setRoleMappings] = useState<Array<{ dn: string; role: string }>>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const queryClient = useQueryClient();

  const { data: ldapConfig, isLoading } = useQuery({
    queryKey: ["ldap-config"],
    queryFn: () => api.get("/api/settings/ldap").then(r => r.data),
  });

  // Initialise roleMappings when config loads
  const roleMappingsInitialised = useRef(false);
  useEffect(() => {
    if (ldapConfig && !roleMappingsInitialised.current) {
      const mappings = Object.entries(ldapConfig.role_mappings || {}).map(([dn, role]) => ({
        dn, role: role as string,
      }));
      setRoleMappings(mappings);
      roleMappingsInitialised.current = true;
    }
  }, [ldapConfig]);

  const { register, handleSubmit, watch } = useForm({ values: ldapConfig });
  const ldapEnabled = watch("enabled");

  const saveMutation = useMutation({
    mutationFn: (data: any) => api.put("/api/settings/ldap", {
      ...data,
      role_mappings: Object.fromEntries(roleMappings.map(m => [m.dn, m.role])),
    }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["ldap-config"] }); toast.success("LDAP settings saved"); },
    onError: (err: any) => toast.error(err.response?.data?.detail || "Failed to save"),
  });

  const testMutation = useMutation({
    mutationFn: () => api.post("/api/settings/ldap/test"),
    onSuccess: (res) => {
      if (res.data.success) toast.success(res.data.message);
      else toast.error(res.data.message);
    },
  });

  const { data: searchResults, isFetching: searching } = useQuery({
    queryKey: ["ldap-search", searchQuery],
    queryFn: () => api.get(`/api/settings/ldap/search?q=${encodeURIComponent(searchQuery)}`).then(r => r.data),
    enabled: searchQuery.length >= 2 && ldapConfig?.enabled,
  });

  if (isLoading) return <div className="text-sm text-gray-400 py-8 text-center">Loading…</div>;

  return (
    <form onSubmit={handleSubmit(d => saveMutation.mutate(d))} className="space-y-6">

      {/* Enable toggle */}
      <section className="bg-white rounded-xl border border-gray-200 p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="font-medium text-gray-900">Active Directory / LDAP</h2>
            <p className="text-sm text-gray-500 mt-0.5">
              Allow your team to log in with their existing corporate credentials.
            </p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input type="checkbox" {...register("enabled")} className="sr-only peer" />
            <div className="w-11 h-6 bg-gray-200 peer-focus:ring-2 peer-focus:ring-blue-300 rounded-full peer peer-checked:bg-blue-600 after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:after:translate-x-5" />
          </label>
        </div>

        {ldapEnabled && (
          <div className="pt-4 border-t border-gray-100 space-y-4">
            {/* Server */}
            <div className="grid grid-cols-2 gap-4">
              <div className="col-span-2">
                <label className="block text-sm font-medium text-gray-700 mb-1.5">LDAP Server URL</label>
                <input {...register("server")} placeholder="ldap://dc01.company.com or ldaps://dc01.company.com:636"
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-blue-500" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1.5">Base DN</label>
                <input {...register("base_dn")} placeholder="DC=company,DC=com"
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-blue-500" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1.5">User Search Base</label>
                <input {...register("user_search_base")} placeholder="OU=Users,DC=company,DC=com (or leave blank)"
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-blue-500" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1.5">Service Account DN</label>
                <input {...register("bind_dn")} placeholder="CN=netaudit,OU=Service Accounts,DC=company,DC=com"
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-blue-500" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1.5">Service Account Password</label>
                <div className="relative">
                  <input type={showPassword ? "text" : "password"} {...register("bind_password")}
                    placeholder={ldapConfig?.has_bind_password ? "••••••••••" : "Enter password"}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 pr-10 text-sm focus:ring-2 focus:ring-blue-500" />
                  <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-3 top-2.5 text-gray-400">
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            </div>

            {/* User filter */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1.5">User search filter</label>
              <input {...register("user_filter")} placeholder="(sAMAccountName={username})"
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-blue-500" />
              <p className="text-xs text-gray-400 mt-1">Use <code className="bg-gray-100 px-1 rounded">{"{username}"}</code> as placeholder. Active Directory: <code className="bg-gray-100 px-1 rounded">(sAMAccountName={"{username}"})</code> OpenLDAP: <code className="bg-gray-100 px-1 rounded">(uid={"{username}"})</code></p>
            </div>

            {/* Attribute mapping */}
            <div className="grid grid-cols-3 gap-3">
              {[["email_attr","Email attribute","mail"],["name_attr","Display name attribute","displayName"],["groups_attr","Groups attribute","memberOf"]].map(([field, label, placeholder]) => (
                <div key={field}>
                  <label className="block text-xs font-medium text-gray-600 mb-1">{label}</label>
                  <input {...register(field as any)} placeholder={placeholder}
                    className="w-full border border-gray-200 rounded-lg px-2.5 py-1.5 text-xs font-mono focus:ring-1 focus:ring-blue-500" />
                </div>
              ))}
            </div>

            {/* TLS options */}
            <div className="flex gap-6">
              <label className="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                <input type="checkbox" {...register("use_tls")} className="rounded" />
                Use TLS/StartTLS
              </label>
              <label className="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                <input type="checkbox" {...register("tls_verify")} className="rounded" />
                Verify TLS certificate
              </label>
            </div>

            {/* Test connection */}
            <div className="flex items-center gap-3 pt-2">
              <button type="button" onClick={() => testMutation.mutate()} disabled={testMutation.isPending}
                className="flex items-center gap-1.5 text-sm text-blue-600 hover:text-blue-700 disabled:opacity-50">
                {testMutation.isPending && <Loader className="w-3 h-3 animate-spin" />}
                {testMutation.isPending ? "Testing…" : "Test connection →"}
              </button>
            </div>
          </div>
        )}
      </section>

      {/* Role mappings */}
      {ldapEnabled && (
        <section className="bg-white rounded-xl border border-gray-200 p-5">
          <div className="flex items-center justify-between mb-1">
            <h2 className="font-medium text-gray-900">Group → Role Mappings</h2>
            <button type="button" onClick={() => setRoleMappings(m => [...m, { dn: "", role: "end_user" }])}
              className="flex items-center gap-1.5 text-xs text-blue-600 hover:text-blue-700">
              <Plus className="w-3.5 h-3.5" /> Add mapping
            </button>
          </div>
          <p className="text-xs text-gray-500 mb-4">
            Map AD groups to NetAudit roles. Users in no mapped group default to End User.
          </p>

          {roleMappings.length === 0 ? (
            <div className="text-center py-6 text-sm text-gray-400 border border-dashed border-gray-200 rounded-lg">
              No role mappings yet — add one above
            </div>
          ) : (
            <div className="space-y-2">
              {roleMappings.map((mapping, i) => (
                <div key={i} className="flex gap-2 items-center">
                  <input
                    value={mapping.dn}
                    onChange={e => setRoleMappings(m => m.map((item, idx) => idx === i ? { ...item, dn: e.target.value } : item))}
                    placeholder="CN=IT-Admins,OU=Groups,DC=company,DC=com"
                    className="flex-1 border border-gray-200 rounded-lg px-3 py-2 text-xs font-mono focus:ring-1 focus:ring-blue-500"
                  />
                  <ChevronRight className="w-4 h-4 text-gray-300 flex-shrink-0" />
                  <select
                    value={mapping.role}
                    onChange={e => setRoleMappings(m => m.map((item, idx) => idx === i ? { ...item, role: e.target.value } : item))}
                    className="border border-gray-200 rounded-lg px-2.5 py-2 text-xs focus:ring-1 focus:ring-blue-500"
                  >
                    {ROLE_OPTIONS.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
                  </select>
                  <button type="button" onClick={() => setRoleMappings(m => m.filter((_, idx) => idx !== i))}
                    className="text-gray-300 hover:text-red-400 p-1">
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {/* LDAP user search / import */}
      {ldapEnabled && ldapConfig?.enabled && (
        <section className="bg-white rounded-xl border border-gray-200 p-5">
          <h2 className="font-medium text-gray-900 mb-1">Find & Import Users</h2>
          <p className="text-xs text-gray-500 mb-3">
            Search your directory to preview which users can log in and what role they'll receive.
            Users are auto-provisioned on first login — no import needed.
          </p>
          <div className="relative mb-3">
            <input
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search by name, username, or email…"
              className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm focus:ring-2 focus:ring-blue-500"
            />
            {searching && <Loader className="w-4 h-4 animate-spin text-gray-400 absolute right-3 top-2.5" />}
          </div>
          {searchResults?.results?.length > 0 && (
            <div className="border border-gray-100 rounded-lg overflow-hidden">
              <table className="w-full text-xs">
                <thead className="bg-gray-50">
                  <tr>
                    {["Display name","Email","Username","Role"].map(h => (
                      <th key={h} className="px-3 py-2 text-left font-medium text-gray-500">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {searchResults.results.map((user: any) => (
                    <tr key={user.username}>
                      <td className="px-3 py-2 font-medium text-gray-800">{user.display_name}</td>
                      <td className="px-3 py-2 text-gray-500">{user.email}</td>
                      <td className="px-3 py-2 font-mono text-gray-500">{user.username}</td>
                      <td className="px-3 py-2">
                        <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                          user.role === "it_admin" ? "bg-blue-100 text-blue-700" :
                          user.role === "it_engineer" ? "bg-indigo-100 text-indigo-700" :
                          user.role === "it_viewer" ? "bg-purple-100 text-purple-700" :
                          "bg-gray-100 text-gray-600"
                        }`}>
                          {ROLE_OPTIONS.find(r => r.value === user.role)?.label || user.role}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {searchQuery.length >= 2 && !searching && searchResults?.results?.length === 0 && (
            <p className="text-sm text-gray-400 text-center py-4">No users found matching "{searchQuery}"</p>
          )}
        </section>
      )}

      <div className="flex justify-end">
        <button type="submit" disabled={saveMutation.isPending}
          className="px-5 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium text-sm disabled:opacity-50">
          {saveMutation.isPending ? "Saving…" : "Save LDAP settings"}
        </button>
      </div>
    </form>
  );
}

// ─── UniFi Settings tab ───────────────────────────────────────────

function UniFiSettings() {
  const [showKey, setShowKey] = useState(false);
  const queryClient = useQueryClient();

  const { data: unifiConfig, isLoading } = useQuery({
    queryKey: ["unifi-config"],
    queryFn: () => api.get("/api/settings/unifi").then(r => r.data),
  });

  const { register, handleSubmit, watch } = useForm({ values: unifiConfig });
  const host = watch("host") || "";

  const saveMutation = useMutation({
    mutationFn: (data: any) => api.put("/api/settings/unifi", data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["unifi-config"] });
      toast.success("UniFi settings saved");
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || "Failed to save"),
  });

  const testMutation = useMutation({
    mutationFn: () => api.post("/api/settings/unifi/test"),
    onSuccess: (res) => {
      if (res.data.success) toast.success(res.data.message);
      else toast.error(`Connection failed: ${res.data.message}`);
    },
  });

  if (isLoading) return <div className="text-sm text-gray-400 py-8 text-center">Loading…</div>;

  return (
    <form onSubmit={handleSubmit(d => saveMutation.mutate(d))} className="space-y-6">
      <section className="bg-white rounded-xl border border-gray-200 p-5">
        <div className="flex items-start justify-between mb-1">
          <div>
            <h2 className="font-medium text-gray-900">UniFi Network Integration</h2>
            <p className="text-sm text-gray-500 mt-0.5">
              Connect to a UDM Pro or UniFi Network Application to enrich device topology data.
              Scans work without this — it only adds extra device classification.
            </p>
          </div>
          {unifiConfig?.enabled && (
            <span className="flex items-center gap-1 text-xs text-green-600 bg-green-50 px-2 py-1 rounded-full mt-1 flex-shrink-0">
              <CheckCircle className="w-3 h-3" /> Connected
            </span>
          )}
        </div>

        <div className="pt-4 mt-3 border-t border-gray-100 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1.5">UDM Pro / Controller URL</label>
            <input
              {...register("host")}
              placeholder="https://192.168.1.1"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-blue-500"
            />
            <p className="text-xs text-gray-400 mt-1">
              Use the IP or hostname of your UDM Pro. Self-signed certificates are accepted.
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1.5">API Key</label>
            <div className="relative">
              <input
                type={showKey ? "text" : "password"}
                {...register("api_key")}
                placeholder={unifiConfig?.has_api_key ? "••••••••••••••••" : "Paste your UniFi API key"}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 pr-10 text-sm font-mono focus:ring-2 focus:ring-blue-500"
              />
              <button type="button" onClick={() => setShowKey(!showKey)} className="absolute right-3 top-2.5 text-gray-400 hover:text-gray-600">
                {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            <p className="text-xs text-gray-400 mt-1">
              Generate in UniFi OS → Settings → API Keys. Stored encrypted at rest.
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1.5">Site name</label>
            <input
              {...register("site")}
              placeholder="default"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-blue-500"
            />
            <p className="text-xs text-gray-400 mt-1">
              Leave as <code className="bg-gray-100 px-1 rounded">default</code> unless you have multiple UniFi sites.
            </p>
          </div>

          <div className="flex items-center gap-3 pt-2">
            <button
              type="button"
              onClick={() => testMutation.mutate()}
              disabled={testMutation.isPending || !host}
              className="flex items-center gap-1.5 text-sm text-blue-600 hover:text-blue-700 disabled:opacity-50"
            >
              {testMutation.isPending && <Loader className="w-3 h-3 animate-spin" />}
              {testMutation.isPending ? "Testing…" : "Test connection →"}
            </button>
          </div>
        </div>
      </section>

      <div className="bg-blue-50 rounded-xl border border-blue-100 p-4 text-sm text-blue-800">
        <strong>Optional:</strong> Without UniFi integration, NetAudit still discovers all devices via Nmap.
        Adding your UDM Pro enables richer device names, exact device types (switch vs AP vs gateway),
        and separates infrastructure from end-user devices on the network map.
      </div>

      <div className="flex justify-end">
        <button type="submit" disabled={saveMutation.isPending}
          className="px-5 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium text-sm disabled:opacity-50">
          {saveMutation.isPending ? "Saving…" : "Save UniFi settings"}
        </button>
      </div>
    </form>
  );
}

// ─── Agent Downloads tab ──────────────────────────────────────────

const PLATFORMS = [
  {
    id: "windows",
    label: "Windows",
    icon: <Monitor className="w-6 h-6 text-blue-500" />,
    badge: "bg-blue-50 text-blue-700 border-blue-200",
    requirements: ["Python 3.9+ from python.org", "ClamAV for Windows (optional, for virus scanning)"],
    install: [
      "Run install_windows.ps1 as Administrator (auto-installs everything)",
      "Or manually: pip install httpx structlog",
      "python agent.py configure --url YOUR_DASHBOARD --token YOUR_TOKEN",
      "python agent.py install   (registers as Scheduled Task)",
    ],
  },
  {
    id: "linux",
    label: "Linux",
    icon: <Terminal className="w-6 h-6 text-green-500" />,
    badge: "bg-green-50 text-green-700 border-green-200",
    requirements: ["Python 3.9+ (usually pre-installed)", "sudo apt install clamav clamav-freshclam"],
    install: [
      "pip3 install httpx structlog",
      "python3 agent.py configure --url YOUR_DASHBOARD --token YOUR_TOKEN",
      "sudo python3 agent.py install   (registers as systemd service)",
    ],
  },
  {
    id: "macos",
    label: "macOS",
    icon: <Apple className="w-6 h-6 text-gray-600" />,
    badge: "bg-gray-50 text-gray-700 border-gray-200",
    requirements: ["Python 3.9+ (pre-installed on macOS 12+)", "brew install clamav (optional, for virus scanning)"],
    install: [
      "pip3 install httpx structlog",
      "python3 agent.py configure --url YOUR_DASHBOARD --token YOUR_TOKEN",
      "python3 agent.py install   (registers as LaunchAgent)",
    ],
  },
];

function AgentDownloads() {
  const [downloading, setDownloading] = useState<string | null>(null);

  async function download(platform: string) {
    setDownloading(platform);
    try {
      const res = await api.get(`/api/agent/download/${platform}`, { responseType: "blob" });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement("a");
      a.href = url;
      a.download = `netaudit-agent-${platform}.zip`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      toast.error("Download failed");
    } finally {
      setDownloading(null);
    }
  }

  return (
    <div className="space-y-6">
      <section className="bg-white rounded-xl border border-gray-200 p-5">
        <h2 className="font-medium text-gray-900 mb-1">NetAudit Agent</h2>
        <p className="text-sm text-gray-500">
          The agent installs on employee machines and servers. It enables virus scanning,
          system auditing, and automatic check-ins with the dashboard. Each user needs
          an agent token — generate one from <strong>Users → (select user) → Agent Token</strong>.
        </p>
      </section>

      <div className="grid gap-4">
        {PLATFORMS.map(p => (
          <section key={p.id} className="bg-white rounded-xl border border-gray-200 p-5">
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-center gap-3">
                {p.icon}
                <div>
                  <h3 className="font-medium text-gray-900">{p.label}</h3>
                  <span className={`inline-block text-xs px-2 py-0.5 rounded-full border mt-0.5 ${p.badge}`}>
                    netaudit-agent-{p.id}.zip
                  </span>
                </div>
              </div>
              <button
                onClick={() => download(p.id)}
                disabled={downloading === p.id}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors disabled:opacity-50 flex-shrink-0"
              >
                {downloading === p.id
                  ? <Loader className="w-4 h-4 animate-spin" />
                  : <Download className="w-4 h-4" />}
                {downloading === p.id ? "Downloading…" : "Download"}
              </button>
            </div>

            <div className="mt-4 grid grid-cols-2 gap-4 text-sm">
              <div>
                <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Requirements</p>
                <ul className="space-y-1">
                  {p.requirements.map(r => (
                    <li key={r} className="flex items-start gap-1.5 text-gray-600 text-xs">
                      <span className="text-gray-300 mt-0.5">•</span> {r}
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Quick install</p>
                <ol className="space-y-1">
                  {p.install.map((step, i) => (
                    <li key={i} className="flex items-start gap-1.5 text-xs text-gray-600">
                      <span className="text-gray-400 flex-shrink-0">{i + 1}.</span>
                      <code className="font-mono bg-gray-50 px-1 rounded text-gray-700 leading-relaxed">{step}</code>
                    </li>
                  ))}
                </ol>
              </div>
            </div>
          </section>
        ))}
      </div>

      <div className="bg-amber-50 border border-amber-100 rounded-xl p-4 text-sm text-amber-800">
        <strong>Zip contents:</strong> Each download includes <code className="bg-amber-100 px-1 rounded">agent.py</code>,
        the platform installer file, and a <code className="bg-amber-100 px-1 rounded">README.txt</code> with
        step-by-step instructions pre-filled with your dashboard URL.
      </div>
    </div>
  );
}
