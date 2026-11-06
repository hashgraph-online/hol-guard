import QRCode from "react-qr-code";

import type { GuardApprovalGateTotpEnrollment } from "./guard-api";

export function buildTotpQrImageOptions(): { bgColor: string; fgColor: string; level: "L" | "M" | "Q" | "H"; size: number } {
  return {
    bgColor: "#ffffff",
    fgColor: "#121a3a",
    level: "M",
    size: 160,
  };
}

export function formatTotpManualKey(value: string | null | undefined): string {
  return (value ?? "").replace(/[\s-]+/g, "").replace(/(.{4})/g, "$1 ").trim();
}

export function formatTotpEnrollmentExpiry(value: string | null | undefined): string {
  if (!value) return "Enrollment expiration unknown.";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Enrollment expiration unknown.";
  return `Enrollment expires at ${date.toLocaleString()}.`;
}

export function TotpEnrollmentQrPanel({ enrollment }: { enrollment: GuardApprovalGateTotpEnrollment }) {
  const qrOptions = buildTotpQrImageOptions();

  return (
    <div className="rounded-xl border border-brand-blue/15 bg-gradient-to-br from-brand-blue/[0.08] via-white to-white p-4">
      <div className="grid gap-4 md:grid-cols-[180px_minmax(0,1fr)] md:items-center">
        <div
          className="flex min-h-[180px] items-center justify-center rounded-2xl border border-white bg-white p-3 shadow-sm"
          aria-label="Scan this QR code in Google Authenticator or another TOTP app"
        >
          <QRCode
            value={enrollment.otpauth_uri}
            size={qrOptions.size}
            level={qrOptions.level}
            bgColor={qrOptions.bgColor}
            fgColor={qrOptions.fgColor}
            role="img"
            aria-label="Scan this QR code in Google Authenticator or another TOTP app"
          />
        </div>
        <div className="space-y-3">
          <div>
            <p className="text-sm font-semibold text-brand-dark">Scan with your authenticator app</p>
            <p className="mt-1 text-xs leading-5 text-slate-500">
              Open Google Authenticator, 1Password, Authy, or iCloud Passwords. Choose add account, scan this code,
              then enter the six-digit code below to finish setup.
            </p>
          </div>
          <ol className="grid gap-2 text-xs text-slate-600">
            <li className="flex gap-2"><span className="font-semibold text-brand-blue">1.</span> Scan QR code.</li>
            <li className="flex gap-2"><span className="font-semibold text-brand-blue">2.</span> Confirm account says HOL Guard.</li>
            <li className="flex gap-2"><span className="font-semibold text-brand-blue">3.</span> Type current six-digit code and verify.</li>
          </ol>
          <details className="rounded-lg border border-slate-200 bg-white px-3 py-2">
            <summary className="cursor-pointer text-xs font-semibold text-brand-dark">Cannot scan? Use manual key</summary>
            <p className="mt-2 select-all break-all font-mono text-xs tracking-wide text-brand-dark">
              {formatTotpManualKey(enrollment.manual_key)}
            </p>
          </details>
          <p className="text-[11px] text-slate-500">{formatTotpEnrollmentExpiry(enrollment.expires_at)}</p>
        </div>
      </div>
    </div>
  );
}
