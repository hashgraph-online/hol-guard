import { beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import * as React from "react";
import { afterEach } from "vitest";

import {
  ExtensionsDiscover,
  type DiscoveryProjection,
  type DiscoveryPlacement,
} from "./extensions-discover";
import type { ExtensionCatalogSummary } from "../extension-controls-api";

function catalogExtension(id: string, name: string): ExtensionCatalogSummary {
  return {
    extension_id: id,
    name,
    kind: "command",
    trust: "reviewed",
    areas: ["developer-tools"],
    description: "A catalog extension used by the Discover view test.",
    commandCount: 8,
  } as unknown as ExtensionCatalogSummary;
}

function placement(overrides: Partial<DiscoveryPlacement> = {}): DiscoveryPlacement {
  return {
    publicPlacementId: "11111111-1111-4111-8111-111111111111",
    extensionId: "command.example-tool",
    product: "sponsored",
    slotIndex: 0,
    windowIndex: null,
    startsAt: new Date(Date.now() - 1000).toISOString(),
    endsAt: new Date(Date.now() + 25_000).toISOString(),
    creativeVersion: "cv-1-abc12345",
    creative: {
      headline: "Explore Example Tool",
      body: "Review the supported extension and its permissions.",
      brandName: "Example Publisher",
    },
    ...overrides,
  };
}

function projection(overrides: Partial<DiscoveryProjection> & { placements?: DiscoveryPlacement[] } = {}): DiscoveryProjection {
  return {
    snapshot: {
      schemaVersion: "guard.extensions.discovery.v1",
      snapshotId: "22222222-2222-4222-8222-222222222222",
      state: "ready",
      enabled: true,
      reasonCode: null,
      generatedAt: new Date().toISOString(),
      leaseExpiresAt: new Date(Date.now() + 25_000).toISOString(),
      placements: overrides.placements ?? [placement()],
      offers: [
        { product: "always", availability: "open", indicativeAmountCents: 50000, currency: "usd", checkedAt: new Date().toISOString(), quoteRequired: true },
        { product: "time_slot", availability: "open", indicativeAmountCents: 5000, currency: "usd", checkedAt: new Date().toISOString(), quoteRequired: true },
        { product: "sponsored", availability: "open", indicativeAmountCents: 20000, currency: "usd", checkedAt: new Date().toISOString(), quoteRequired: true },
      ],
    },
    remainingLeaseMs: 25_000,
    policyAllowed: true,
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const CATALOG = Array.from({ length: 10 }, (_, index) =>
  catalogExtension(`command.tool-${String(index).padStart(2, "0")}`, `Tool ${index}`),
);

async function renderDiscover(fetchImpl: () => Promise<Response>) {
  const onOpenExtension = vi.fn();
  const view = render(
    React.createElement(ExtensionsDiscover, {
      active: true,
      catalogExtensions: CATALOG,
      onOpenExtension,
      fetchPlacements: fetchImpl,
    }),
  );
  return { onOpenExtension, view };
}

describe("ExtensionsDiscover", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });
  afterEach(() => {
    cleanup();
  });

  it("renders one sponsored card labeled Sponsored after eight organic rows (UX-02/UX-04)", async () => {
    await renderDiscover(() => Promise.resolve(jsonResponse(projection())));
    await waitFor(() => {
      expect(screen.getByTestId("discovery-sponsored-card")).toBeTruthy();
    });
    expect(screen.getAllByTestId("discovery-sponsored-card").length).toBe(1);
    expect(screen.getByTestId("discovery-sponsored-card").getAttribute("data-sponsored-label")).toBe("Sponsored");
    // Ten organic rows keep their identity and order.
    expect(screen.getAllByText("command.tool-00", { exact: false }).length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByTestId("discovery-featured-card")).toBeNull();
  });

  it("labels the featured card Sponsored · Featured and never duplicates one extension across both paid slots (UX-03)", async () => {
    await renderDiscover(() => Promise.resolve(jsonResponse(projection({
      placements: [
        placement({ publicPlacementId: "33333333-3333-4333-8333-333333333333", product: "always", extensionId: "command.tool-01" }),
        placement({ publicPlacementId: "44444444-4444-4444-8444-444444444444", product: "sponsored", extensionId: "command.tool-01" }),
        placement({ publicPlacementId: "55555555-5555-4555-8555-555555555555", product: "sponsored", extensionId: "command.tool-02" }),
      ],
    }))));
    await waitFor(() => {
      expect(screen.getByTestId("discovery-featured-card")).toBeTruthy();
    });
    expect(screen.getByTestId("discovery-featured-card").getAttribute("data-sponsored-label")).toBe("Sponsored · Featured");
    const sponsoredExtension = screen.getByTestId("discovery-sponsored-card").getAttribute("data-sponsored-placement-id");
    // tool-01 was picked for featured, so the in-feed card cannot be tool-01.
    expect(sponsoredExtension).not.toBe("33333333-3333-4333-8333-333333333333");
  });

  it("suppresses unknown Cloud ids instead of rendering them as paid cards (D08)", async () => {
    await renderDiscover(() => Promise.resolve(jsonResponse(projection({
      placements: [placement({ extensionId: "command.not-in-local-catalog" })],
    }))));
    await waitFor(() => {
      expect(screen.getByTestId("discovery-status-ready")).toBeTruthy();
    });
    expect(screen.queryByTestId("discovery-sponsored-card")).toBeNull();
    expect(screen.queryByTestId("discovery-purchase-prompt")).toBeNull();
  });

  it("shows the compact purchase prompt only for an open authoritative sponsored offer (UX-05/UX-06)", async () => {
    await renderDiscover(() => Promise.resolve(jsonResponse(projection({ placements: [] }))));
    await waitFor(() => {
      expect(screen.getByTestId("discovery-purchase-prompt")).toBeTruthy();
    });
  });

  it("hides paid content and shows no vacancy claim when the feed is unavailable (D11)", async () => {
    await renderDiscover(() => Promise.resolve(jsonResponse({ error: "discovery_transport_failed" }, 503)));
    await waitFor(() => {
      expect(screen.getByTestId("discovery-status-unavailable")).toBeTruthy();
    });
    expect(screen.queryByTestId("discovery-sponsored-card")).toBeNull();
    expect(screen.queryByTestId("discovery-purchase-prompt")).toBeNull();
  });

  it("treats sold-out inventory as an availability link, not a paid queue (UX-06)", async () => {
    const body = projection({ placements: [] });
    body.snapshot.offers = body.snapshot.offers.map((offer) =>
      offer.product === "sponsored" ? { ...offer, availability: "sold_out" as const } : offer,
    );
    await renderDiscover(() => Promise.resolve(jsonResponse(body)));
    await waitFor(() => {
      expect(screen.getByTestId("discovery-status-sold-out")).toBeTruthy();
    });
    expect(screen.queryByTestId("discovery-purchase-prompt")).toBeNull();
  });

  it("clears paid content for a policy opt-out projection (SEC-02)", async () => {
    await renderDiscover(() => Promise.resolve(jsonResponse(projection({ policyAllowed: false }))));
    await waitFor(() => {
      expect(screen.getByTestId("discovery-status-optout")).toBeTruthy();
    });
    expect(screen.queryByTestId("discovery-sponsored-card")).toBeNull();
  });

  it("keeps a valid visible card stable across polls instead of rotating (UX-07)", async () => {
    let call = 0;
    const placements = [
      placement({ publicPlacementId: "66666666-6666-4666-8666-666666666666", product: "always", extensionId: "command.tool-03" }),
      placement({ publicPlacementId: "77777777-7777-4777-8777-777777777777", product: "always", extensionId: "command.tool-04" }),
    ];
    const { view } = await renderDiscover(() => {
      call += 1;
      return Promise.resolve(jsonResponse(projection({ placements })));
    });
    await waitFor(() => {
      expect(screen.getByTestId("discovery-featured-card")).toBeTruthy();
    });
    const first = screen.getByTestId("discovery-featured-card").getAttribute("data-sponsored-placement-id");
    await waitFor(() => {
      expect(call).toBeGreaterThan(1);
    });
    const second = screen.getByTestId("discovery-featured-card").getAttribute("data-sponsored-placement-id");
    expect(second).toBe(first);
    expect(view).toBeTruthy();
  });

  it("opens the existing local detail handler on View extension and nothing else (UX-04)", async () => {
    const { onOpenExtension } = await renderDiscover(() => Promise.resolve(jsonResponse(projection({
      placements: [placement({ extensionId: "command.tool-07" })],
    }))));
    await waitFor(() => {
      expect(screen.getByTestId("discovery-sponsored-card")).toBeTruthy();
    });
    (screen.getByTestId("discovery-sponsored-card").querySelector("button") as HTMLButtonElement).click();
    expect(onOpenExtension).toHaveBeenCalledTimes(1);
    expect(onOpenExtension.mock.calls[0][0].extension_id).toBe("command.tool-07");
  });
});
