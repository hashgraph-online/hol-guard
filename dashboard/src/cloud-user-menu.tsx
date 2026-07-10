import { useCallback, useEffect, useRef, useState } from 'react';
import { HiMiniCloud, HiMiniChevronDown, HiMiniClipboardDocument, HiMiniCheck } from 'react-icons/hi2';
import type { GuardCloudUserProfile } from './guard-types';

function formatEmailDisplay(email: string): string {
  const trimmed = email.trim();
  if (trimmed.length <= 24) return trimmed;
  const atIndex = trimmed.indexOf('@');
  if (atIndex > 0 && atIndex < trimmed.length - 1) {
    const localPart = trimmed.slice(0, atIndex);
    const domain = trimmed.slice(atIndex);
    if (localPart.length > 10) {
      return `${localPart.slice(0, 8)}…${domain}`;
    }
  }
  return `${trimmed.slice(0, 12)}…`;
}

function resolveInitials(name: string, email: string): string {
  const trimmed = name.trim();
  if (trimmed) {
    const parts = trimmed.split(/\s+/);
    if (parts.length >= 2) {
      return `${parts[0][0]}${parts[parts.length - 1][0]}`.toUpperCase();
    }
    return trimmed.slice(0, 2).toUpperCase();
  }
  return email.trim().slice(0, 2).toUpperCase();
}

function resolveDisplayName(profile: GuardCloudUserProfile): string {
  const name = profile.display_name?.trim();
  if (name) return name;
  return profile.email.split('@')[0];
}

export function CloudUserMenu(props: {
  userProfile: GuardCloudUserProfile | null | undefined;
  workspaceId: string | null | undefined;
  collapsed?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const handleClickOutside = useCallback((event: MouseEvent) => {
    if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
      setOpen(false);
      setCopied(false);
    }
  }, []);

  useEffect(() => {
    if (open) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [open, handleClickOutside]);

  const handleCopyWorkspaceId = useCallback(async () => {
    if (!props.workspaceId) return;
    try {
      await navigator.clipboard.writeText(props.workspaceId);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard unavailable */
    }
  }, [props.workspaceId]);

  if (!props.userProfile) {
    if (props.collapsed) {
      return (
        <div className="flex justify-center pb-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-200">
            <HiMiniCloud className="h-4 w-4 text-slate-400" />
          </div>
        </div>
      );
    }
    return null;
  }

  const displayName = resolveDisplayName(props.userProfile);
  const initials = resolveInitials(props.userProfile.display_name || '', props.userProfile.email);

  if (props.collapsed) {
    return (
      <div ref={containerRef} className="flex justify-center pb-2">
        <button
          type="button"
          onClick={() => setOpen((prev) => !prev)}
          className="relative flex h-8 w-8 items-center justify-center overflow-hidden rounded-full ring-2 ring-brand-blue/30 transition hover:ring-brand-blue/60"
          title={`${displayName} (${props.userProfile.email})`}
          aria-label={`Cloud user: ${displayName}`}
        >
          {props.userProfile.avatar_url ? (
            <img
              src={props.userProfile.avatar_url}
              alt=""
              className="h-full w-full object-cover"
            />
          ) : (
            <span className="text-xs font-bold text-brand-blue">{initials}</span>
          )}
        </button>
        {open && (
          <div
            className="absolute bottom-16 left-16 z-50 w-56 rounded-xl border border-slate-200 bg-white p-3 shadow-lg"
          >
            <div className="space-y-1 text-center">
              <p className="text-xs font-semibold text-brand-dark">{displayName}</p>
              <p className="text-[10px] text-slate-500">{formatEmailDisplay(props.userProfile.email)}</p>
              {props.workspaceId ? (
                <button
                  type="button"
                  onClick={handleCopyWorkspaceId}
                  className="mt-2 flex w-full items-center justify-center gap-1.5 rounded-lg bg-slate-50 px-2 py-1.5 text-[10px] font-mono text-slate-600 transition hover:bg-slate-100"
                >
                  {copied ? (
                    <HiMiniCheck className="h-3 w-3 text-green-600" />
                  ) : (
                    <HiMiniClipboardDocument className="h-3 w-3" />
                  )}
                  {props.workspaceId.slice(0, 8)}…
                </button>
              ) : null}
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div ref={containerRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        className="flex w-full items-center gap-2 rounded-xl px-2 py-1.5 transition hover:bg-slate-100"
        aria-expanded={open}
        aria-label={`Cloud user: ${displayName}`}
      >
        <div className="relative flex h-8 w-8 shrink-0 items-center justify-center overflow-hidden rounded-full ring-2 ring-brand-blue/20">
          {props.userProfile.avatar_url ? (
            <img
              src={props.userProfile.avatar_url}
              alt=""
              className="h-full w-full object-cover"
            />
          ) : (
            <span className="text-xs font-bold text-brand-blue">{initials}</span>
          )}
        </div>
        <div className="flex min-w-0 flex-1 flex-col">
          <span className="truncate text-xs font-semibold text-brand-dark">{displayName}</span>
          <span className="truncate text-[10px] text-slate-500">{formatEmailDisplay(props.userProfile.email)}</span>
        </div>
        <HiMiniChevronDown
          className={`h-3.5 w-3.5 shrink-0 text-slate-400 transition-transform ${open ? 'rotate-180' : ''}`}
        />
      </button>
      {open && (
        <div className="absolute bottom-full left-0 right-0 mb-1 rounded-xl border border-slate-200 bg-white p-3 shadow-lg">
          <div className="space-y-2">
            <div className="flex items-center gap-1.5">
              <HiMiniCloud className="h-3 w-3 text-brand-blue" />
              <p className="font-mono text-[9px] font-semibold uppercase tracking-widest text-brand-blue">
                HOL Guard Cloud
              </p>
            </div>
            <div className="border-t border-slate-100 pt-2">
              <p className="text-[10px] font-medium uppercase tracking-wider text-slate-400">Workspace ID</p>
              {props.workspaceId ? (
                <button
                  type="button"
                  onClick={handleCopyWorkspaceId}
                  className="mt-1 flex w-full items-center justify-between gap-2 rounded-lg bg-slate-50 px-2 py-1.5 font-mono text-[10px] text-slate-600 transition hover:bg-slate-100"
                >
                  <span className="truncate">{props.workspaceId}</span>
                  {copied ? (
                    <HiMiniCheck className="h-3 w-3 shrink-0 text-green-600" />
                  ) : (
                    <HiMiniClipboardDocument className="h-3 w-3 shrink-0 text-slate-400" />
                  )}
                </button>
              ) : (
                <p className="mt-1 text-[10px] text-slate-400">Not available</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
