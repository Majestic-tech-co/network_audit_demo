// ─── UsersPage.tsx ─────────────────────────────────────────────────
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../utils/api";
import { useState } from "react";
import { UserPlus, Shield } from "lucide-react";
import toast from "react-hot-toast";

const ROLES = ["it_admin","it_engineer","it_viewer","end_user"];
const ROLE_LABELS: Record<string,string> = {
  it_admin: "IT Admin", it_engineer: "IT Engineer",
  it_viewer: "IT Viewer", end_user: "End User"
};

export default function UsersPage() {
  const [showCreate, setShowCreate] = useState(false);
  const [newUser, setNewUser] = useState({ email:"", username:"", password:"", role:"end_user", assigned_device_ip:"" });
  const queryClient = useQueryClient();

  const { data: users } = useQuery({
    queryKey: ["users"],
    queryFn: () => api.get("/api/users").then(r => r.data),
  });

  const createMutation = useMutation({
    mutationFn: (data: any) => api.post("/api/users", data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users"] });
      setShowCreate(false);
      setNewUser({ email:"", username:"", password:"", role:"end_user", assigned_device_ip:"" });
      toast.success("User created");
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || "Failed to create user"),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, is_active }: any) => api.patch(`/api/users/${id}`, { is_active }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
  });

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-semibold text-gray-900">Users</h1>
        <button onClick={() => setShowCreate(!showCreate)}
          className="flex items-center gap-2 px-4 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium">
          <UserPlus className="w-4 h-4" /> Add user
        </button>
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="bg-white rounded-xl border border-gray-200 p-5 mb-6">
          <h2 className="font-medium text-gray-900 mb-4">New User</h2>
          <div className="grid grid-cols-2 gap-4 mb-4">
            {[["Email","email","email"],["Username","username","text"],["Password","password","password"],["Device IP (optional)","assigned_device_ip","text"]].map(([label,field,type]) => (
              <div key={field}>
                <label className="block text-sm font-medium text-gray-700 mb-1">{label}</label>
                <input type={type} value={(newUser as any)[field]}
                  onChange={e => setNewUser(u => ({ ...u, [field]: e.target.value }))}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500" />
              </div>
            ))}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Role</label>
              <select value={newUser.role} onChange={e => setNewUser(u => ({ ...u, role: e.target.value }))}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm">
                {ROLES.map(r => <option key={r} value={r}>{ROLE_LABELS[r]}</option>)}
              </select>
            </div>
          </div>
          <div className="flex gap-3">
            <button onClick={() => createMutation.mutate(newUser)} disabled={createMutation.isPending}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50">
              {createMutation.isPending ? "Creating…" : "Create user"}
            </button>
            <button onClick={() => setShowCreate(false)} className="px-4 py-2 border border-gray-200 rounded-lg text-sm text-gray-600 hover:bg-gray-50">
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Users table */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 border-b border-gray-100">
            <tr>
              {["User","Role","Device IP","Status","Last login"].map(h => (
                <th key={h} className="px-4 py-3 text-left text-xs font-medium text-gray-500">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {users?.map((u: any) => (
              <tr key={u.id} className={`hover:bg-gray-50 ${!u.is_active ? "opacity-50" : ""}`}>
                <td className="px-4 py-3">
                  <div className="font-medium text-gray-800">{u.username}</div>
                  <div className="text-xs text-gray-400">{u.email}</div>
                </td>
                <td className="px-4 py-3">
                  <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                    u.role.startsWith("it") ? "bg-blue-100 text-blue-700" : "bg-gray-100 text-gray-600"}`}>
                    {ROLE_LABELS[u.role]}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs font-mono text-gray-500">{u.assigned_device_ip || "—"}</td>
                <td className="px-4 py-3">
                  <button onClick={() => toggleMutation.mutate({ id: u.id, is_active: !u.is_active })}
                    className={`text-xs px-2 py-0.5 rounded-full font-medium ${u.is_active ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"}`}>
                    {u.is_active ? "Active" : "Disabled"}
                  </button>
                </td>
                <td className="px-4 py-3 text-xs text-gray-400">
                  {u.last_login ? new Date(u.last_login).toLocaleDateString() : "Never"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
