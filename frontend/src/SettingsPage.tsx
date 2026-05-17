import { useRef, useState, type ReactNode } from "react";
import { avatarSrc, changePassword, updateProfile, uploadAvatar, type UserProfile } from "./api";
import { useTheme } from "./theme";

const C = {
  card: "var(--ng-card)",
  border: "var(--ng-border)",
  blue: "var(--ng-blue)",
  green: "var(--ng-green)",
  red: "var(--ng-red)",
  muted: "var(--ng-muted)",
  text: "var(--ng-text)",
};

type NavId = "dashboard" | "live" | "analytics" | "alerts" | "reports" | "settings";

export function SettingsPage({
  user,
  activeNav,
  onNavigate,
  onLogout,
  onUserUpdate,
  AppShell,
}: {
  user: UserProfile;
  activeNav: NavId;
  onNavigate: (id: NavId) => void;
  onLogout: () => void;
  onUserUpdate: (user: UserProfile) => void;
  AppShell: (props: {
    user: UserProfile;
    activeNav: NavId;
    onNavigate: (id: NavId) => void;
    onLogout: () => void;
    children: ReactNode;
  }) => ReactNode;
}) {
  const { theme, setTheme } = useTheme();
  const fileRef = useRef<HTMLInputElement>(null);

  const [fullName, setFullName] = useState(user.full_name);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [profileMsg, setProfileMsg] = useState("");
  const [profileErr, setProfileErr] = useState("");
  const [passwordMsg, setPasswordMsg] = useState("");
  const [passwordErr, setPasswordErr] = useState("");
  const [avatarErr, setAvatarErr] = useState("");
  const [busy, setBusy] = useState<"profile" | "password" | "avatar" | null>(null);

  const avatarUrl = avatarSrc(user.avatar_url);
  const initial = user.full_name?.trim()?.[0]?.toUpperCase() ?? user.email[0]?.toUpperCase() ?? "?";

  const saveProfile = async () => {
    setProfileMsg("");
    setProfileErr("");
    if (fullName.trim().length < 2) {
      setProfileErr("Name must be at least 2 characters.");
      return;
    }
    setBusy("profile");
    try {
      const res = await updateProfile({ full_name: fullName.trim() });
      onUserUpdate(res.user);
      setProfileMsg("Profile updated.");
    } catch (e) {
      setProfileErr(e instanceof Error ? e.message : "Failed to update profile");
    } finally {
      setBusy(null);
    }
  };

  const savePassword = async () => {
    setPasswordMsg("");
    setPasswordErr("");
    if (newPassword.length < 6) {
      setPasswordErr("New password must be at least 6 characters.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setPasswordErr("Passwords do not match.");
      return;
    }
    setBusy("password");
    try {
      await changePassword({ current_password: currentPassword, new_password: newPassword });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setPasswordMsg("Password updated.");
    } catch (e) {
      setPasswordErr(e instanceof Error ? e.message : "Failed to update password");
    } finally {
      setBusy(null);
    }
  };

  const onAvatarPick = async (file: File | undefined) => {
    if (!file) return;
    setAvatarErr("");
    setBusy("avatar");
    try {
      const res = await uploadAvatar(file);
      if (res.user) onUserUpdate(res.user);
    } catch (e) {
      setAvatarErr(e instanceof Error ? e.message : "Failed to upload image");
    } finally {
      setBusy(null);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  return (
    <AppShell user={user} activeNav={activeNav} onNavigate={onNavigate} onLogout={onLogout}>
      <div className="grid gap-4 lg:grid-cols-2 lg:gap-6">
        <section className="rounded-[10px] border p-4 shadow-lg sm:p-6" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <h2 className="text-base font-semibold sm:text-lg" style={{ color: C.text }}>
            Appearance
          </h2>
          <p className="mt-1 text-sm" style={{ color: C.muted }}>
            Choose how NetGuard AI looks on this device.
          </p>
          <div className="mt-4 flex gap-2">
            {(["dark", "light"] as const).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setTheme(t)}
                className="flex-1 rounded-lg border px-3 py-2.5 text-sm font-medium capitalize transition"
                style={{
                  borderColor: theme === t ? C.blue : C.border,
                  backgroundColor: theme === t ? "rgba(0, 123, 255, 0.12)" : "transparent",
                  color: theme === t ? C.text : C.muted,
                }}
              >
                {t}
              </button>
            ))}
          </div>
        </section>

        <section className="rounded-[10px] border p-4 shadow-lg sm:p-6" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <h2 className="text-base font-semibold sm:text-lg" style={{ color: C.text }}>
            Profile photo
          </h2>
          <div className="mt-4 flex flex-wrap items-center gap-4">
            {avatarUrl ? (
              <img src={avatarUrl} alt="" className="h-16 w-16 rounded-full object-cover ring-2 ring-[var(--ng-border)]" />
            ) : (
              <span
                className="flex h-16 w-16 items-center justify-center rounded-full text-xl font-semibold text-white"
                style={{ backgroundColor: C.border }}
              >
                {initial}
              </span>
            )}
            <div>
              <input
                ref={fileRef}
                type="file"
                accept="image/jpeg,image/png,image/webp,image/gif"
                className="hidden"
                onChange={(e) => onAvatarPick(e.target.files?.[0])}
              />
              <button
                type="button"
                disabled={busy === "avatar"}
                onClick={() => fileRef.current?.click()}
                className="rounded-lg px-4 py-2 text-sm font-medium text-white transition hover:opacity-90 disabled:opacity-50"
                style={{ backgroundColor: C.blue }}
              >
                {busy === "avatar" ? "Uploading…" : "Upload image"}
              </button>
              <p className="mt-2 text-xs" style={{ color: C.muted }}>
                JPEG, PNG, WebP, or GIF. Max 2 MB.
              </p>
            </div>
          </div>
          {avatarErr && (
            <p className="mt-2 text-sm" style={{ color: C.red }}>
              {avatarErr}
            </p>
          )}
        </section>

        <section className="rounded-[10px] border p-4 shadow-lg sm:p-6 lg:col-span-2" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <h2 className="text-base font-semibold sm:text-lg" style={{ color: C.text }}>
            Account
          </h2>
          <p className="mt-1 text-sm" style={{ color: C.muted }}>
            Signed in as {user.email}
          </p>
          <label className="mt-4 block text-sm font-medium" style={{ color: C.muted }}>
            Display name
          </label>
          <input className="ng-input mt-1.5" value={fullName} onChange={(e) => setFullName(e.target.value)} />
          {profileErr && (
            <p className="mt-2 text-sm" style={{ color: C.red }}>
              {profileErr}
            </p>
          )}
          {profileMsg && (
            <p className="mt-2 text-sm" style={{ color: C.green }}>
              {profileMsg}
            </p>
          )}
          <button
            type="button"
            disabled={busy === "profile"}
            onClick={saveProfile}
            className="mt-4 rounded-lg px-4 py-2.5 text-sm font-semibold text-white transition hover:opacity-90 disabled:opacity-50"
            style={{ backgroundColor: C.blue }}
          >
            {busy === "profile" ? "Saving…" : "Save name"}
          </button>
        </section>

        <section className="rounded-[10px] border p-4 shadow-lg sm:p-6 lg:col-span-2" style={{ backgroundColor: C.card, borderColor: C.border }}>
          <h2 className="text-base font-semibold sm:text-lg" style={{ color: C.text }}>
            Change password
          </h2>
          <input
            className="ng-input mt-4"
            type="password"
            placeholder="Current password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
          />
          <input
            className="ng-input mt-3"
            type="password"
            placeholder="New password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
          />
          <input
            className="ng-input mt-3"
            type="password"
            placeholder="Confirm new password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
          />
          {passwordErr && (
            <p className="mt-2 text-sm" style={{ color: C.red }}>
              {passwordErr}
            </p>
          )}
          {passwordMsg && (
            <p className="mt-2 text-sm" style={{ color: C.green }}>
              {passwordMsg}
            </p>
          )}
          <button
            type="button"
            disabled={busy === "password"}
            onClick={savePassword}
            className="mt-4 rounded-lg px-4 py-2.5 text-sm font-semibold text-white transition hover:opacity-90 disabled:opacity-50"
            style={{ backgroundColor: C.blue }}
          >
            {busy === "password" ? "Updating…" : "Update password"}
          </button>
        </section>
      </div>
    </AppShell>
  );
}
