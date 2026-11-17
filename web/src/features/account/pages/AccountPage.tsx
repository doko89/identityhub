import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useSessionStore } from "@/shared/stores/session";
import { UploadField } from "@/features/uploads/components/UploadField";
import { Avatar, AvatarFallback, AvatarImage } from "@/shared/ui/avatar";
import { Badge } from "@/shared/ui/badge";
import { Card, CardContent, CardDescription, CardHeader } from "@/shared/ui/card";
import { Separator } from "@/shared/ui/separator";
import { Skeleton } from "@/shared/ui/skeleton";

// Account overview: who is signed in, links to the self-service pages,
// and the avatar uploader (POST /api/uploads, result shown inline).
export function AccountPage() {
  const loadSession = useSessionStore((s) => s.load);
  const user = useSessionStore((s) => s.user);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const u = await loadSession();
      if (cancelled) return;
      if (u === null) {
        window.location.href = "/login?next=/account";
        return;
      }
      setReady(true);
    })();
    return () => {
      cancelled = true;
    };
  }, [loadSession]);

  return (
    <main className="mx-auto w-full max-w-xl px-4 py-6">
      <p className="text-sm">
        <Link to="/" className="text-primary hover:underline">
          ← Back to dashboard
        </Link>
      </p>
      <Card className="mt-4">
        <CardHeader>
          <h1 className="text-xl leading-none font-semibold">Account</h1>
          <CardDescription>Your profile and sign-in settings.</CardDescription>
        </CardHeader>
        <CardContent>
          {!ready || user === null ? (
            <div className="flex items-center gap-3" aria-label="Loading">
              <Skeleton className="size-10 rounded-full" />
              <div className="flex flex-1 flex-col gap-2">
                <Skeleton className="h-4 w-32" />
                <Skeleton className="h-3 w-48" />
              </div>
            </div>
          ) : (
            <div className="flex flex-col gap-4">
              <div className="flex items-center gap-3">
                <Avatar className="size-10">
                  {user.avatar_url !== "" && <AvatarImage src={user.avatar_url} alt="" />}
                  <AvatarFallback>{initials(user.display_name || user.username)}</AvatarFallback>
                </Avatar>
                <div>
                  <p className="text-sm font-semibold">{user.display_name || user.username}</p>
                  <p className="text-sm text-muted-foreground">
                    {user.username} · {user.email}
                  </p>
                </div>
                <div className="ml-auto flex gap-2">
                  <Badge variant="secondary">{user.source}</Badge>
                  {user.is_admin && <Badge>admin</Badge>}
                </div>
              </div>
              <Separator />
              <nav className="flex flex-col gap-2 text-sm" aria-label="Account settings">
                <Link to="/account/password" className="text-primary hover:underline">
                  Change password
                </Link>
                <Link to="/account/mfa" className="text-primary hover:underline">
                  Two-step verification
                </Link>
              </nav>
              <Separator />
              <UploadField
                id="avatar-upload"
                assetType="avatar"
                label="Profile picture"
                description="JPEG, PNG or WebP, max 10 MB. The image is stored and its URL is shown below."
                initialUrl={user.avatar_url}
              />
            </div>
          )}
        </CardContent>
      </Card>
    </main>
  );
}

function initials(name: string): string {
  const parts = name.trim().split(/\s+/);
  const first = parts[0]?.slice(0, 1) ?? "";
  const second = parts.length > 1 ? (parts[1]?.slice(0, 1) ?? "") : "";
  return (first + second).toUpperCase() || "?";
}
